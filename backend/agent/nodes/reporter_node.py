"""
backend/agent/nodes/reporter_node.py
─────────────────────────────────────────────────────────────────────────────
REPORTER node — builds a ReportContext (bounded LLM input) from AgentState,
calls ReportGeneratorTool, and writes the report back into state.

MAP-REDUCE CONTEXT BOUNDARY (architecture spec §4.4):
    This node is responsible for the Map step:
        Full AgentState  →  StateCondenser  →  ReportContext  →  LLM

    Raw transaction arrays, full trace hop lists, and the uncompressed
    reasoning_log NEVER reach the LLM. The ReportContext enforces this
    at the type level — the report_generator tool only accepts a
    ReportContext, not a raw AgentState.

DESIGN DECISIONS:
    1.  StateCondenser (state_condensor.py) performs the Map step, reducing
        the full AgentState to a bounded ReportContext object.
    2.  The LLM call is isolated in ReportGeneratorTool so it can be tested
        independently of the graph.
    3.  If the LLM call fails, ReportGeneratorTool returns a deterministic
        fallback report — the investigation is never blocked.
    4.  The reporter also calls GraphBuilderTool to produce node-link JSON
        with node_count so the frontend can select the right renderer.
"""

from __future__ import annotations

from typing import Any

import structlog

from backend.agent.state import AgentState, ReasoningStep
from backend.agent.state_condenser import condense_state
from backend.forensics.models import ReportContext
from backend.tools.graph_builder import GraphBuilderTool
from backend.tools.report_generator import ReportGeneratorTool
from backend.utils import utc_now_iso

logger = structlog.get_logger(__name__)

_report_tool = ReportGeneratorTool()
_graph_tool  = GraphBuilderTool()


async def reporter_node(state: AgentState) -> dict[str, Any]:
    """
    Condense state to ReportContext, call Gemini, produce report + graph.

    Args:
        state: Current AgentState. forensics_reports and wallet_profiles
               must be populated before this node runs.

    Returns:
        Partial state update with report_title, report_summary,
        report_findings, report_recommendations, graph_nodes, graph_edges.
    """
    wallet     = state["wallet_address"]
    risk_score = state.get("risk_score", 0.0)
    risk_level = state.get("risk_level", "LOW")
    settings   = state["settings"]

    # ── Map step: condense full state → bounded ReportContext ─────────────────
    report_context: ReportContext = condense_state(state)

    logger.info(
        "reporter_context_built",
        wallet=wallet,
        triggered_rules=len(report_context.triggered_rules),
        wallets_analyzed=report_context.wallets_analyzed,
        risk_score=round(report_context.risk_score, 1),
    )

    # ── LLM call via ReportGeneratorTool (only receives ReportContext) ────────
    report_result = await _report_tool.run(
        report_context=report_context,
        settings=settings,
    )

    # ── Build graph data for visualization ────────────────────────────────────
    graph_result = await _graph_tool.run(
        root_wallet=wallet,
        graph_nodes=state.get("graph_nodes", []),
        graph_edges=state.get("graph_edges", []),
        forensics_reports=state.get("forensics_reports", {}),
        settings=settings,
    )

    step = ReasoningStep(
        step="REPORTER",
        action="Generated forensic report via ReportContext boundary",
        observation=(
            f"Risk: {risk_level} ({risk_score:.1f}). "
            f"{len(report_context.triggered_rules)} finding(s). "
            f"Graph: {graph_result.get('node_count', 0)} nodes."
        ),
        timestamp=utc_now_iso(),
    )

    return {
        "current_phase":          "REPORTING",
        "report_title":           report_result["title"],
        "report_summary":         report_result["summary"],
        "report_findings":        report_result.get("findings", []),
        "report_recommendations": report_result["recommendations"],
        "graph_nodes":            graph_result.get("nodes", []),
        "graph_edges":            graph_result.get("edges", []),
        "reasoning_log":          [step],
    }
