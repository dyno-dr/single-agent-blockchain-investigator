"""
backend/forensics/pruning_engine.py
─────────────────────────────────────────────────────────────────────────────
PruningEngine — decides which wallets to trace deeper during hop traversal.

PURPOSE:
    The PruningEngine applies hard stop-rules to every candidate wallet
    before the tracer expands it. Without pruning, the trace graph grows
    exponentially: a wallet with 100 counterparties at depth 1 becomes
    10,000 at depth 2 (O(N^d) explosion).

PRUNING DECISIONS (four values, evaluated in order — first match wins):
    EXPAND  → wallet passes all checks; add to next-hop queue
    SKIP    → wallet is below value threshold, already visited, or budget
              exhausted; discard without recording a halt reason
    HALT    → terminal node — known CEX / DEX / bridge / mixer; stop tracing
              here but RECORD the node in the graph with entity annotation
              so the forensic finding ("funds reached Binance Hot Wallet") is
              preserved in the report
    SAMPLE  → wallet has abnormally high fan-out (spider / mixing pattern);
              take only the top-N edges by value and record the node as
              HIGH_FAN_OUT_SAMPLED so the report can flag it

DESIGN DECISIONS:
    1.  Four decisions (EXPAND / SKIP / HALT / SAMPLE) map exactly to the
        architecture spec's PruningDecision enum. SAMPLE is the key addition
        over a binary TRACE/SKIP scheme — it lets the tracer make partial
        progress on high-fanout nodes rather than either exploding or dropping
        them silently.
    2.  All thresholds come from Settings so they are tunable without code
        changes. The only hardcoded value is _HALT_ENTITY_TYPES, which is
        stable enough to be a constant.
    3.  HALT nodes are still returned as GraphNode entries with a halt_reason
        annotation. The graph builder marks them as terminal. The forensic
        signal (e.g. "funds reached Tornado Cash 1 ETH Pool") is never lost.
    4.  The engine is stateless — no DB connections, no HTTP calls. Tests
        inject it directly without any mock setup.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

import structlog

from backend.blockchain.models import WalletProfile

logger = structlog.get_logger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Decision enum
# ─────────────────────────────────────────────────────────────────────────────


class PruneDecision(str, Enum):
    """
    Result of a single PruningEngine.evaluate() call.

    EXPAND  — proceed; expand this wallet to the next hop.
    SKIP    — discard this edge (dust, cycle, budget).
    HALT    — hard stop; record node as terminal with entity annotation.
    SAMPLE  — high fan-out; take top-N edges by value only.
    """
    EXPAND = "EXPAND"
    SKIP   = "SKIP"
    HALT   = "HALT"
    SAMPLE = "SAMPLE"


# Entity types from known_entities.json that warrant a hard HALT
_HALT_ENTITY_TYPES: frozenset[str] = frozenset({
    "known_cex",
    "bridge",
    "mixer_suspected",
})

# Entity types that trigger SAMPLE (DEX / aggregator — high fan-out but not terminal)
_SAMPLE_ENTITY_TYPES: frozenset[str] = frozenset({
    "known_dex",
})


# ─────────────────────────────────────────────────────────────────────────────
# PruneResult — returned alongside the decision for graph annotation
# ─────────────────────────────────────────────────────────────────────────────


class PruneResult:
    """
    Bundles a PruneDecision with optional metadata for graph annotation.

    Attributes:
        decision:     The pruning decision (EXPAND / SKIP / HALT / SAMPLE).
        reason:       Human-readable reason string for graph node annotation.
        entity_type:  Entity type string if HALT/SAMPLE triggered by entity.
        entity_label: Entity label (e.g. "Binance Hot Wallet 1") if known.
        sample_size:  For SAMPLE decisions — how many top edges to keep.
    """

    __slots__ = ("decision", "entity_label", "entity_type", "reason", "sample_size")

    def __init__(
        self,
        decision: PruneDecision,
        reason: str = "",
        entity_type: str | None = None,
        entity_label: str | None = None,
        sample_size: int | None = None,
    ) -> None:
        self.decision = decision
        self.reason = reason
        self.entity_type = entity_type
        self.entity_label = entity_label
        self.sample_size = sample_size

    def __repr__(self) -> str:
        return (
            f"PruneResult(decision={self.decision!r}, reason={self.reason!r}, "
            f"entity_type={self.entity_type!r})"
        )


# ─────────────────────────────────────────────────────────────────────────────
# PruningEngine
# ─────────────────────────────────────────────────────────────────────────────


class PruningEngine:
    """
    Stateless engine that decides EXPAND / SKIP / HALT / SAMPLE for each
    candidate wallet encountered during multi-hop trace traversal.

    Usage:
        engine = PruningEngine()
        result = engine.evaluate(
            candidate_wallet=address,
            value_eth=tx_value,
            profile=profile,            # None if not yet fetched
            traced_wallets=seen_set,
            total_node_count=current_count,
            settings=settings,
        )
        if result.decision == PruneDecision.HALT:
            # record terminal node with result.entity_label
        elif result.decision == PruneDecision.SAMPLE:
            # take only top result.sample_size edges by value
        elif result.decision == PruneDecision.EXPAND:
            # queue for next hop
        # PruneDecision.SKIP → discard silently
    """

    def evaluate(
        self,
        candidate_wallet: str,
        value_eth: float,
        profile: WalletProfile | None,
        traced_wallets: set[str],
        total_node_count: int,
        settings: Any,
    ) -> PruneResult:
        """
        Evaluate a single candidate wallet and return a pruning decision.

        Rules are evaluated in priority order — first match wins.

        Args:
            candidate_wallet:   Lowercase address being evaluated.
            value_eth:          ETH value of the transaction leading here.
            profile:            WalletProfile if already fetched, else None.
            traced_wallets:     Wallets already expanded in this investigation.
            total_node_count:   Current graph node count (for budget check).
            settings:           Application Settings for threshold values.

        Returns:
            PruneResult containing the decision and annotation metadata.
        """
        inv = settings.investigation
        min_value: float = getattr(inv, "DEFAULT_MIN_TRACE_VALUE_ETH",
                                   getattr(inv, "min_trace_value_eth", 0.05))
        max_nodes: int   = getattr(inv, "DEFAULT_MAX_TRACE_NODES",
                                   getattr(inv, "max_trace_nodes", 500))
        max_fanout: int  = getattr(inv, "DEFAULT_MAX_FAN_OUT_PER_NODE",
                                   getattr(inv, "max_fan_out_per_node", 50))
        sample_size: int = max(5, max_fanout // 5)   # take top-20% of fanout

        # ── Rule 1: Cycle prevention — already traced ────────────────────────
        if candidate_wallet in traced_wallets:
            logger.debug("prune_cycle", wallet=candidate_wallet)
            return PruneResult(PruneDecision.SKIP, reason="already_traced")

        # ── Rule 2: Dust filter ───────────────────────────────────────────────
        if value_eth < min_value:
            logger.debug(
                "prune_dust",
                wallet=candidate_wallet,
                value_eth=value_eth,
                threshold=min_value,
            )
            return PruneResult(
                PruneDecision.SKIP,
                reason=f"dust: {value_eth:.6f} ETH < threshold {min_value} ETH",
            )

        # ── Rule 3: Node budget exhausted ────────────────────────────────────
        if total_node_count >= max_nodes:
            logger.debug(
                "prune_budget",
                wallet=candidate_wallet,
                count=total_node_count,
                max=max_nodes,
            )
            return PruneResult(
                PruneDecision.SKIP,
                reason=f"budget_exhausted: {total_node_count}/{max_nodes} nodes",
            )

        # ── Rules requiring the wallet profile ───────────────────────────────
        if profile is not None:

            # ── Rule 4: Known entity HALT ─────────────────────────────────────
            for tx in profile.transactions:
                for entity_type, entity_label in (
                    (tx.from_entity_type, tx.from_entity_label),
                    (tx.to_entity_type, tx.to_entity_label),
                ):
                    if entity_type in _HALT_ENTITY_TYPES:
                        logger.debug(
                            "prune_halt_entity",
                            wallet=candidate_wallet,
                            entity_type=entity_type,
                            entity_label=entity_label,
                        )
                        return PruneResult(
                            PruneDecision.HALT,
                            reason=f"known_entity:{entity_type}",
                            entity_type=entity_type,
                            entity_label=entity_label or entity_type,
                        )

            # ── Rule 5: DEX / aggregator — SAMPLE ────────────────────────────
            for tx in profile.transactions:
                for entity_type, entity_label in (
                    (tx.from_entity_type, tx.from_entity_label),
                    (tx.to_entity_type, tx.to_entity_label),
                ):
                    if entity_type in _SAMPLE_ENTITY_TYPES:
                        logger.debug(
                            "prune_sample_dex",
                            wallet=candidate_wallet,
                            entity_type=entity_type,
                            sample_size=sample_size,
                        )
                        return PruneResult(
                            PruneDecision.SAMPLE,
                            reason=f"dex_router:{entity_type}",
                            entity_type=entity_type,
                            entity_label=entity_label or entity_type,
                            sample_size=sample_size,
                        )

            # ── Rule 6: High fan-out wallet — SAMPLE ─────────────────────────
            if profile.stats.unique_counterparties > max_fanout:
                logger.debug(
                    "prune_sample_fanout",
                    wallet=candidate_wallet,
                    counterparties=profile.stats.unique_counterparties,
                    max_fanout=max_fanout,
                    sample_size=sample_size,
                )
                return PruneResult(
                    PruneDecision.SAMPLE,
                    reason=(
                        f"high_fanout:{profile.stats.unique_counterparties}"
                        f">{max_fanout}"
                    ),
                    sample_size=sample_size,
                )

        # ── Default: expand ───────────────────────────────────────────────────
        return PruneResult(PruneDecision.EXPAND, reason="ok")

    def filter_candidates(
        self,
        candidates: list[dict[str, Any]],
        traced_wallets: set[str],
        total_node_count: int,
        settings: Any,
    ) -> list[dict[str, Any]]:
        """
        Filter and sort a list of candidate wallets for the next trace hop.

        Candidates that receive EXPAND are kept; all others are dropped from
        the queue (though HALT/SAMPLE nodes are still recorded by the caller).

        Each candidate dict must contain:
            wallet (str)            — address
            value_eth (float)       — transaction value in ETH
            profile (WalletProfile | None)

        Returns candidates sorted by value_eth descending (follow the money).

        Args:
            candidates:       Raw candidate list from the tracer.
            traced_wallets:   Already-traced wallets.
            total_node_count: Current node budget consumption.
            settings:         Application settings.

        Returns:
            Filtered and sorted list ready for next-hop expansion.
        """
        to_expand: list[dict[str, Any]] = []

        for candidate in candidates:
            result = self.evaluate(
                candidate_wallet=candidate["wallet"],
                value_eth=candidate.get("value_eth", 0.0),
                profile=candidate.get("profile"),
                traced_wallets=traced_wallets,
                total_node_count=total_node_count + len(to_expand),
                settings=settings,
            )
            candidate["prune_result"] = result

            if result.decision == PruneDecision.EXPAND:
                to_expand.append(candidate)

        # Sort: highest-value flows first
        to_expand.sort(key=lambda c: c.get("value_eth", 0.0), reverse=True)
        return to_expand
