"""
backend/agent/nodes/trace_scorer_node.py
─────────────────────────────────────────────────────────────────────────────
TRACE_SCORER node: Layer 1 (deterministic math) + Layer 2 (planner-validated)
candidate selection. Determines which wallets to queue for multi-hop tracing.

POSITION IN GRAPH:
  profiler → TRACE_SCORER → tracer (if depth ≥ 2 and candidates > 0)
                          → detector (if depth == 1 or no candidates)

WHAT IT DOES:
  1. For each wallet in wallet_profiles, calls TraceScorerTool to rank
     its outgoing/incoming counterparties by the 3-layer priority score.
  2. Filters candidates through PruningEngine (Layer 3 pre-screen) to
     discard dust and known entities before even queuing them.
  3. Merges candidates from all wallets into wallets_to_trace, respecting
     the top-K cap per depth level.
  4. Adds new candidate addresses to graph_nodes so the graph grows.

DESIGN DECISIONS:
  1. This node runs between profiler and tracer. It is a pure scoring step —
     no Etherscan calls, no LLM calls. All I/O happens in profiler/tracer.
  2. For depth=1 investigations, this node emits an empty candidates list.
     The graph edge logic routes directly to detector in that case.
  3. wallets_to_trace uses operator.add (append-only) so this node only
     adds new wallets — it never removes existing ones.
"""

from __future__ import annotations

from typing import Any

import structlog

from backend.agent.state import AgentState, ReasoningStep
from backend.forensics.pruning_engine import PruneDecision, PruningEngine
from backend.tools.trace_scorer import TraceScorerTool
from backend.utils import utc_now_iso

logger = structlog.get_logger(__name__)

_scorer_tool = TraceScorerTool()
_pruner = PruningEngine()


async def trace_scorer_node(state: AgentState) -> dict[str, Any]:
    """
    Score and queue candidate wallets for the next trace hop.

    Reads:  state.wallet_profiles, state.forensics_reports, state.depth
    Writes: state.wallets_to_trace (appended), state.graph_nodes (appended)

    Args:
        state: Current AgentState.

    Returns:
        Partial state update dict.
    """
    depth = state.get("depth", 1)
    current_depth = state.get("current_depth", 0)
    trace_strategy = state.get("trace_strategy", "FORWARD_ONLY")
    wallet_profiles = state.get("wallet_profiles", {})
    forensics_reports = state.get("forensics_reports", {})
    traced_wallets = set(state.get("traced_wallets", []))
    settings = state["settings"]

    # depth=1 means root wallet only — no tracing needed
    if depth < 2:
        logger.debug("trace_scorer_skip_depth_1")
        step = ReasoningStep(
            step="TRACE_SCORER",
            action="Skipped — depth=1, no tracing required",
            observation="Investigation configured for root wallet only.",
            timestamp=utc_now_iso(),
        )
        return {
            "current_phase": "TRACING",
            "reasoning_log": [step],
        }

    all_candidates: list[str] = []
    new_graph_nodes: list[dict[str, Any]] = []
    scored_count = 0

    for wallet, profile in wallet_profiles.items():
        if wallet in traced_wallets:
            continue

        try:
            ranked = await _scorer_tool.run(
                profile=profile,
                trace_strategy=trace_strategy,
                traced_wallets=traced_wallets,
                forensics_reports=forensics_reports,
                depth=depth,
                settings=settings,
            )
        except Exception as exc:
            logger.warning("trace_scorer_node_tool_failed", wallet=wallet, error=str(exc))
            continue

        scored_count += len(ranked)

        for candidate in ranked:
            candidate_wallet = candidate["wallet"]
            value_eth = candidate.get("value_eth", 0.0)

            # Pre-screen through PruningEngine before queuing
            decision = _pruner.evaluate(
                candidate_wallet=candidate_wallet,
                value_eth=value_eth,
                profile=None,  # profile not fetched yet — just check budget/dust
                traced_wallets=traced_wallets | set(all_candidates),
                total_node_count=len(new_graph_nodes),
                settings=settings,
            )

            if decision == PruneDecision.TRACE:
                all_candidates.append(candidate_wallet)
                new_graph_nodes.append({
                    "id": candidate_wallet,
                    "label": f"{candidate_wallet[:6]}…{candidate_wallet[-4:]}",
                    "type": "unknown",
                    "is_root": False,
                    "is_flagged": False,
                    "trace_score": candidate.get("trace_score", 0.0),
                    "depth": current_depth + 1,
                })
            elif decision == PruneDecision.HALT:
                # Still add to graph as terminal node
                new_graph_nodes.append({
                    "id": candidate_wallet,
                    "label": f"{candidate_wallet[:6]}…{candidate_wallet[-4:]}",
                    "type": "known_entity",
                    "is_root": False,
                    "is_flagged": False,
                    "halt_reason": "Known entity — tracing halted",
                    "depth": current_depth + 1,
                })

    logger.info(
        "trace_scorer_node_complete",
        root=state["wallet_address"],
        scored=scored_count,
        queued=len(all_candidates),
        strategy=trace_strategy,
    )

    step = ReasoningStep(
        step="TRACE_SCORER",
        action=f"Scored candidates; queued {len(all_candidates)} for tracing",
        observation=(
            f"Strategy: {trace_strategy}. "
            f"Scored {scored_count} candidates, queued {len(all_candidates)}."
        ),
        timestamp=utc_now_iso(),
    )

    return {
        "current_phase": "TRACING",
        "wallets_to_trace": all_candidates,
        "graph_nodes": new_graph_nodes,
        "reasoning_log": [step],
    }