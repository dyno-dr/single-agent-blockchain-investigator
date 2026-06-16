"""
backend/agent/nodes/tracer_node.py
─────────────────────────────────────────────────────────────────────────────
TRACER node: executes the bounded BFS multi-hop trace using TracingEngineTool.

POSITION IN GRAPH:
  trace_scorer → TRACER → detector

WHAT IT DOES:
  1. Reads wallets_to_trace (queued by trace_scorer_node).
  2. Calls TracingEngineTool which runs the bounded BFS expansion.
  3. Accumulates new WalletProfiles into wallet_profiles.
  4. Accumulates graph nodes and edges into state.
  5. Marks all traced wallets in traced_wallets (append-only).

DESIGN DECISIONS:
  1. This node only runs if wallets_to_trace is non-empty and depth >= 2.
     The graph edge from trace_scorer bypasses this node for depth=1.
  2. The tracer processes ALL queued candidates in one pass. For Phase 3's
     linear graph, this is depth-1 tracing (root → hop1). Phase 4 will add
     a loop edge for deeper traversal.
  3. Graph nodes/edges from the tracer are appended to state, not replaced.
     The graph_builder tool in reporter_node does the final deduplication.
  4. The root wallet (depth 0) is always added as a graph node by the
     tracer tool, ensuring it appears in the visualized graph.
"""

from __future__ import annotations

from typing import Any

import structlog

from backend.agent.state import AgentState, ReasoningStep
from backend.tools.tracing_engine import TracingEngineTool
from backend.utils import utc_now_iso

logger = structlog.get_logger(__name__)

_tracing_tool = TracingEngineTool()


async def tracer_node(state: AgentState) -> dict[str, Any]:
    """
    Execute bounded BFS multi-hop tracing for queued candidate wallets.

    Reads:  state.wallets_to_trace, state.wallet_profiles, state.traced_wallets
    Writes: state.wallet_profiles, state.graph_nodes, state.graph_edges,
            state.traced_wallets

    Args:
        state: Current AgentState.

    Returns:
        Partial state update dict.
    """
    wallets_to_trace = state.get("wallets_to_trace", [])
    wallet_profiles = dict(state.get("wallet_profiles", {}))
    traced_wallets = set(state.get("traced_wallets", []))
    root_wallet = state["wallet_address"]
    depth = state.get("depth", 1)
    lookback_days = state["lookback_days"]
    max_transactions = state["max_transactions"]
    settings = state["settings"]
    http_client = state["http_client"]
    rate_limiter = state["rate_limiter"]

    # Only trace wallets not already profiled
    pending = [w for w in wallets_to_trace if w not in wallet_profiles]

    if not pending:
        logger.debug("tracer_node_nothing_to_trace", root=root_wallet)
        step = ReasoningStep(
            step="TRACER",
            action="No new wallets to trace",
            observation="All queued wallets already profiled or empty queue.",
            timestamp=utc_now_iso(),
        )
        return {
            "current_phase": "TRACING",
            "reasoning_log": [step],
        }

    logger.info(
        "tracer_node_start",
        root=root_wallet,
        candidates=len(pending),
        depth=depth,
    )

    try:
        result = await _tracing_tool.run(
            seed_candidates=[{"wallet": w, "tx": None, "value_eth": 0.0} for w in pending],
            root_wallet=root_wallet,
            existing_profiles=wallet_profiles,
            traced_wallets=traced_wallets,
            max_depth=max(1, depth - 1),   # hops remaining after root is profiled
            lookback_days=lookback_days,
            max_transactions=min(max_transactions, 200),  # budget per hop wallet
            settings=settings,
            http_client=http_client,
            rate_limiter=rate_limiter,
        )

        new_profiles = result["wallet_profiles"]
        new_nodes = result["graph_nodes"]
        new_edges = result["graph_edges"]
        newly_traced = result["wallets_traced"]

        # Merge new profiles into existing dict
        merged_profiles = {**wallet_profiles, **new_profiles}

        logger.info(
            "tracer_node_complete",
            root=root_wallet,
            new_wallets=len(newly_traced),
            new_nodes=len(new_nodes),
            new_edges=len(new_edges),
        )

        step = ReasoningStep(
            step="TRACER",
            action=f"Traced {len(newly_traced)} new wallet(s) via BFS",
            observation=(
                f"Fetched {len(new_profiles) - len(wallet_profiles)} new profiles. "
                f"Graph: +{len(new_nodes)} nodes, +{len(new_edges)} edges."
            ),
            timestamp=utc_now_iso(),
        )

        return {
            "current_phase": "TRACING",
            "wallet_profiles": merged_profiles,
            "graph_nodes": new_nodes,
            "graph_edges": new_edges,
            "traced_wallets": list(newly_traced),
            "current_depth": state.get("current_depth", 0) + 1,
            "reasoning_log": [step],
        }

    except Exception as exc:
        logger.error("tracer_node_failed", root=root_wallet, error=str(exc))
        step = ReasoningStep(
            step="TRACER",
            action="Tracing failed",
            observation=f"Error: {exc}",
            timestamp=utc_now_iso(),
        )
        return {
            "current_phase": "TRACING",
            "errors": [f"Tracer failed: {exc}"],
            "reasoning_log": [step],
        }