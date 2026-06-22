"""
backend/agent/state.py
─────────────────────────────────────────────────────────────────────────────
AgentState is the shared memory of the LangGraph investigation graph.

Every node reads from and writes to this state. LangGraph merges updates
from each node using the reducer annotations below.

DESIGN DECISIONS:
  1. TypedDict (not Pydantic) because LangGraph requires TypedDict for state.
  2. Annotated fields use `operator.add` as the reducer for list fields —
     nodes append to them rather than overwriting.
  3. `wallet_profiles` is a dict keyed by wallet address so any node can
     look up any profile without scanning a list.
  4. The `errors` list accumulates non-fatal errors across nodes. Fatal
     errors set `status = "FAILED"` and halt the graph via edge logic.
  5. `reasoning_log` accumulates the agent's step-by-step decisions for
     persistence and auditability.
"""

from __future__ import annotations

import operator
from typing import Annotated, Any, TypedDict

from backend.blockchain.models import WalletProfile
from backend.forensics.models import ForensicsReport


class ReasoningStep(TypedDict):
    """One entry in the agent's reasoning log."""
    step: str
    action: str
    observation: str
    timestamp: str


class AgentState(TypedDict):
    """
    Shared state passed between all LangGraph agent nodes.

    Fields are populated incrementally as nodes execute. Early nodes
    (profiler, tx_fetch) populate the input data; later nodes
    (detector, reporter) consume it and add their output.
    """

    # ── Investigation identity ────────────────────────────────────────────────
    investigation_id: str
    wallet_address: str
    depth: int
    lookback_days: int
    max_transactions: int
    chain: str

    # ── Lifecycle ─────────────────────────────────────────────────────────────
    status: str                         # PENDING | RUNNING | COMPLETE | FAILED
    current_phase: str                  # Phase enum value
    error_message: str | None

    # ── Blockchain data ───────────────────────────────────────────────────────
    # keyed by wallet_address (lowercase)
    wallet_profiles: dict[str, WalletProfile]

    # ── Trace graph ───────────────────────────────────────────────────────────
    # Wallets queued for tracing at next depth level
    wallets_to_trace: Annotated[list[str], operator.add]
    # Wallets already traced (prevent revisiting)
    traced_wallets: Annotated[list[str], operator.add]
    # Current trace depth (0 = root wallet only)
    current_depth: int
    # Layer-1 scored candidate dicts emitted by trace_scorer_node for planner
    trace_candidates: Annotated[list[dict[str, Any]], operator.add]

    # ── Forensics ─────────────────────────────────────────────────────────────
    # keyed by wallet_address
    forensics_reports: dict[str, ForensicsReport]
    risk_score: float
    risk_level: str

    # ── Trace strategy (from PLANNER node) ───────────────────────────────────
    trace_strategy: str                 # TraceStrategy enum value
    planner_reasoning: str
    trace_directive: dict[str, Any]

    # ── Report ────────────────────────────────────────────────────────────────
    report_title: str
    report_summary: str
    report_findings: Annotated[list[dict[str, Any]], operator.add]
    report_recommendations: Annotated[list[str], operator.add]

    # ── Graph data (for visualization) ───────────────────────────────────────
    graph_nodes: Annotated[list[dict[str, Any]], operator.add]
    graph_edges: Annotated[list[dict[str, Any]], operator.add]

    # ── Reasoning log ─────────────────────────────────────────────────────────
    reasoning_log: Annotated[list[ReasoningStep], operator.add]

    # ── Non-fatal errors ──────────────────────────────────────────────────────
    errors: Annotated[list[str], operator.add]

    # ── Pass-through context for nodes ───────────────────────────────────────
    settings: Any                       # Settings instance
    http_client: Any                    # httpx.AsyncClient
    rate_limiter: Any                   # EtherscanRateLimiter


def make_initial_state(
    investigation_id: str,
    wallet_address: str,
    depth: int,
    lookback_days: int,
    max_transactions: int,
    settings: Any,
    http_client: Any,
    rate_limiter: Any,
) -> AgentState:
    """
    Create the initial AgentState for a new investigation.

    Args:
        investigation_id: UUID of the DB investigation record.
        wallet_address:   Target wallet (lowercase).
        depth:            Trace depth (1–3).
        lookback_days:    Transaction lookback window.
        max_transactions: Max transactions to fetch per wallet.
        settings:         Application Settings instance.
        http_client:      Shared httpx.AsyncClient.
        rate_limiter:     EtherscanRateLimiter instance.

    Returns:
        Fully initialised AgentState ready to enter the graph.
    """

    return AgentState(
        investigation_id=investigation_id,
        wallet_address=wallet_address.lower(),
        depth=depth,
        lookback_days=lookback_days,
        max_transactions=max_transactions,
        chain="ETHEREUM",
        status="RUNNING",
        current_phase="INIT",
        error_message=None,
        wallet_profiles={},
        wallets_to_trace=[wallet_address.lower()],
        traced_wallets=[],
        current_depth=0,
        trace_candidates=[],
        forensics_reports={},
        risk_score=0.0,
        risk_level="LOW",
        trace_strategy="FORWARD_ONLY",
        planner_reasoning="",
        trace_directive={},
        report_title="",
        report_summary="",
        report_findings=[],
        report_recommendations=[],
        graph_nodes=[],
        graph_edges=[],
        reasoning_log=[],
        errors=[],
        settings=settings,
        http_client=http_client,
        rate_limiter=rate_limiter,
    )
