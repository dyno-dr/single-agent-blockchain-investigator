"""
backend/tools/tracing_engine.py
─────────────────────────────────────────────────────────────────────────────
Tool: TracingEngineTool

PURPOSE:
  Implements the bounded BFS (breadth-first search) multi-hop tracer.
  Given a set of seed wallets from the trace_scorer_node, expands the
  transaction graph up to `max_depth` hops while the PruningEngine
  enforces budget and entity stop-rules at every hop.

ALGORITHM:
  1. Initialise the frontier with scored seed candidates from Layer 1.
  2. For each wallet in the frontier:
       a. Consult PruningEngine — TRACE / SKIP / HALT
       b. If TRACE: fetch transactions, add counterparties to next-hop queue
       c. If HALT: record terminal node with entity label, do not expand
       d. If SKIP: discard silently
  3. Repeat until depth budget exhausted or node budget hit.
  4. Emit graph_nodes and graph_edges for the visualization layer.

DESIGN DECISIONS:
  1. BFS over DFS: breadth-first ensures we fully explore depth D before
     going to D+1. This matches the architecture spec and is more predictable
     for the node budget.
  2. The PruningEngine is injected (not instantiated here) so tests can
     substitute a deterministic version without mocking Etherscan.
  3. Graph nodes carry entity_type and halt_reason annotations so the
     visualization layer can render terminal nodes distinctly (e.g. show
     "Binance Hot Wallet" label on the node where tracing stopped).
  4. The tool adds its graph data to state.graph_nodes / graph_edges via
     the return dict. The graph_builder tool later adds the root wallet
     and full edge set to this.
"""

from __future__ import annotations

from collections import deque
import datetime as dt
from typing import Any

import structlog

from backend.blockchain.etherscan_client import EtherscanClient
from backend.blockchain.models import RawEtherscanTransaction, WalletProfile
from backend.blockchain.normalizer import normalize_wallet_profile
from backend.forensics.pruning_engine import PruneDecision, PruningEngine
from backend.tools.base import BaseTool

logger = structlog.get_logger(__name__)

_BLOCKS_PER_DAY = 6500
_ETH_GENESIS = dt.datetime(2015, 7, 30, tzinfo=dt.UTC)


class TracingEngineTool(BaseTool):
    """
    Bounded BFS multi-hop transaction tracer.

    Expands the trace graph from seed candidates up to max_depth hops.
    PruningEngine enforces per-hop budget and entity stop-rules.

    Usage:
        tool = TracingEngineTool()
        result = await tool.run(
            seed_candidates=[...],
            root_wallet=address,
            existing_profiles={...},
            traced_wallets=set(),
            max_depth=2,
            lookback_days=90,
            max_transactions=200,
            settings=settings,
            http_client=http_client,
            rate_limiter=rate_limiter,
        )
        # result: {wallet_profiles, graph_nodes, graph_edges, wallets_traced}
    """

    name = "tracing_engine"
    description = (
        "Bounded BFS multi-hop tracer. Follows suspicious wallets up to "
        "max_depth hops using PruningEngine stop-rules."
    )

    def __init__(self) -> None:
        self._pruner = PruningEngine()

    async def run(
        self,
        *,
        seed_candidates: list[dict[str, Any]],
        root_wallet: str,
        existing_profiles: dict[str, WalletProfile],
        traced_wallets: set[str],
        max_depth: int,
        lookback_days: int,
        max_transactions: int,
        settings: Any,
        http_client: Any,
        rate_limiter: Any,
        **_kwargs: Any,
    ) -> dict[str, Any]:
        """
        Run the bounded BFS tracer from seed candidates.

        Args:
            seed_candidates:    Scored candidates from TraceScorerTool.
            root_wallet:        Root wallet address (depth 0).
            existing_profiles:  Already-fetched WalletProfiles (avoid re-fetch).
            traced_wallets:     Wallets already expanded (cycle prevention).
            max_depth:          Maximum hop depth (1–3).
            lookback_days:      Lookback window for fetching transactions.
            max_transactions:   Max transactions per wallet fetch.
            settings:           Application settings.
            http_client:        Shared httpx.AsyncClient.
            rate_limiter:       EtherscanRateLimiter instance.

        Returns:
            Dict with:
                wallet_profiles: Updated dict of all fetched WalletProfiles
                graph_nodes:     List of graph node dicts
                graph_edges:     List of graph edge dicts
                wallets_traced:  Set of wallets expanded during this run
        """
        client = EtherscanClient(
            settings=settings,
            http_client=http_client,
            rate_limiter=rate_limiter,
        )

        now = dt.datetime.now(dt.UTC)
        days_since_genesis = (now - _ETH_GENESIS).days
        start_block = max(0, days_since_genesis * _BLOCKS_PER_DAY - lookback_days * _BLOCKS_PER_DAY)
        fetch_limit = min(max_transactions, 1000)

        # Working sets
        profiles = dict(existing_profiles)
        all_traced = set(traced_wallets) | {root_wallet}
        newly_traced: set[str] = set()
        graph_nodes: list[dict[str, Any]] = []
        graph_edges: list[dict[str, Any]] = []

        # Ensure root node exists
        graph_nodes.append(_make_node(root_wallet, is_root=True))

        # BFS queue: (wallet, depth, source_wallet, tx_hash, value_eth)
        queue: deque[tuple[str, int, str, str, float]] = deque()
        for candidate in seed_candidates:
            tx = candidate.get("tx")
            if tx is None:
                continue
            counterparty = candidate["wallet"]
            queue.append((
                counterparty,
                1,
                root_wallet,
                tx.hash if tx else "",
                candidate.get("value_eth", 0.0),
            ))

        while queue:
            wallet, depth, source, tx_hash, value_eth = queue.popleft()

            if depth > max_depth:
                continue

            # Fetch profile if not already available
            profile = profiles.get(wallet)
            if profile is None:
                try:
                    raw_dicts = await client.get_transactions(
                        wallet=wallet,
                        start_block=start_block,
                        offset=fetch_limit,
                    )
                    balance_wei = int(await client.get_wallet_balance(wallet))
                    raw_txs = [RawEtherscanTransaction(**t) for t in raw_dicts]
                    profile = normalize_wallet_profile(
                        address=wallet,
                        balance_wei=balance_wei,
                        raw_transactions=raw_txs,
                        raw_token_transfers=[],
                        fetched_at=now,
                        fetch_errors=[],
                    )
                    profiles[wallet] = profile
                except Exception as exc:
                    logger.warning("tracer_fetch_failed", wallet=wallet, error=str(exc))
                    profile = None

            # Pruning decision
            decision = self._pruner.evaluate(
                candidate_wallet=wallet,
                value_eth=value_eth,
                profile=profile,
                traced_wallets=all_traced,
                total_node_count=len(graph_nodes),
                settings=settings,
            )

            # Always add the node to graph (even HALT nodes — they show where money went)
            entity_type = _get_entity_type(profile)
            halt_reason = None

            if decision == PruneDecision.HALT:
                halt_reason = f"Known entity: {entity_type}"
                logger.debug("tracer_halt", wallet=wallet, reason=halt_reason)
            elif decision == PruneDecision.SKIP:
                logger.debug("tracer_skip", wallet=wallet)
                continue  # Don't add SKIP nodes to the graph

            # Add node and edge
            node = _make_node(
                wallet,
                entity_type=entity_type,
                halt_reason=halt_reason,
                is_root=False,
            )
            graph_nodes.append(node)
            graph_edges.append({
                "source": source,
                "target": wallet,
                "tx_hash": tx_hash,
                "value_eth": value_eth,
                "depth": depth,
            })

            if decision == PruneDecision.HALT:
                continue  # Don't expand HALT nodes

            # Mark as traced to prevent re-expansion
            all_traced.add(wallet)
            newly_traced.add(wallet)

            # Expand: queue next-hop counterparties if depth allows
            if profile and depth < max_depth:
                for tx in profile.transactions:
                    if tx.direction.upper() == "OUTGOING":
                        counterparty = tx.to_address
                    elif tx.direction.upper() == "INCOMING":
                        counterparty = tx.from_address
                    else:
                        continue

                    if not counterparty or counterparty == wallet:
                        continue

                    queue.append((
                        counterparty,
                        depth + 1,
                        wallet,
                        tx.hash,
                        tx.value_eth,
                    ))

        logger.info(
            "tracer_complete",
            root=root_wallet,
            nodes=len(graph_nodes),
            edges=len(graph_edges),
            newly_traced=len(newly_traced),
        )

        return {
            "wallet_profiles": profiles,
            "graph_nodes": graph_nodes,
            "graph_edges": graph_edges,
            "wallets_traced": newly_traced,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Graph node helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_node(
    address: str,
    *,
    is_root: bool = False,
    entity_type: str = "unknown",
    halt_reason: str | None = None,
) -> dict[str, Any]:
    """Construct a graph node dict."""
    label = f"{address[:6]}…{address[-4:]}" if len(address) >= 10 else address
    return {
        "id": address,
        "label": label,
        "type": entity_type,
        "is_root": is_root,
        "is_flagged": False,        # updated by graph_builder after detector runs
        "halt_reason": halt_reason,
    }


def _get_entity_type(profile: WalletProfile | None) -> str:
    """Extract the most prominent entity type from a WalletProfile."""
    if profile is None:
        return "unknown"
    for tx in profile.transactions:
        for entity_type in (tx.from_entity_type, tx.to_entity_type):
            if entity_type and entity_type != "unknown":
                return entity_type
    return "unknown"
