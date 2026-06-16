"""
backend/agent/state_condenser.py
─────────────────────────────────────────────────────────────────────────────
StateCondenser — Map step of the Map-Reduce context boundary.

PURPOSE:
    Reduces the full AgentState (which may contain hundreds of raw transactions,
    thousands of trace hops, and long reasoning logs) to a bounded ReportContext
    object. The ReportContext is the ONLY thing the LLM ever receives.

    This enforces the architecture spec's Map-Reduce context boundary:
        Full AgentState  →  condense_state()  →  ReportContext  →  LLM

WHAT IS COMPRESSED:
    - List[CleanTransaction]       → counts, totals, largest values (scalars)
    - List[CleanTokenTransfer]     → counts only
    - List[TraceHop]               → TraceSummary (counts + notable destinations)
    - Full reasoning_log           → last 5 steps, joined as plain text (~500 tokens)

WHAT IS PRESERVED VERBATIM:
    - All triggered RuleResult objects (short structured finding objects)
    - Risk score and risk level
    - Balance and wallet age
    - Entity contact flags (mixer, CEX, bridge)
    - Evidence tx hash references (hashes only — not full tx objects)

DESIGN DECISIONS:
    1. condense_state() is a pure function — it takes state and returns
       ReportContext. No I/O, no side effects. Safe to call in tests directly.
    2. Returns a ReportContext Pydantic model (not a dict) so the type system
       enforces the context boundary at compile time.
    3. File renamed from state_condensor.py → state_condenser.py (spelling fix).
"""

from __future__ import annotations

from typing import Any

import structlog

from backend.forensics.models import (
    ReportContext,
    RuleResult,
    TraceSummary,
)

logger = structlog.get_logger(__name__)


def condense_state(state: dict[str, Any]) -> ReportContext:
    """
    Reduce full AgentState to a bounded ReportContext for the LLM.

    Args:
        state: Full AgentState dict from the LangGraph agent.

    Returns:
        ReportContext — the only input the LLM is allowed to receive.
    """
    wallet_address: str = state.get("wallet_address", "")
    investigation_id: str = state.get("investigation_id", "")
    risk_score: float = float(state.get("risk_score", 0.0))
    risk_level: str = state.get("risk_level", "LOW")
    wallet_profiles: dict[str, Any] = state.get("wallet_profiles", {})
    forensics_reports: dict[str, Any] = state.get("forensics_reports", {})
    traced_wallets: list[str] = state.get("traced_wallets", [])
    reasoning_log: list[Any] = state.get("reasoning_log", [])
    graph_nodes: list[dict[str, Any]] = state.get("graph_nodes", [])
    errors: list[str] = state.get("errors", [])

    # ── Root wallet profile scalars ───────────────────────────────────────────
    root_profile = wallet_profiles.get(wallet_address)
    balance_eth = 0.0
    total_transactions = 0
    incoming_count = 0
    outgoing_count = 0
    largest_outgoing_eth = 0.0
    unique_counterparties = 0
    wallet_age_days = 0.0
    known_entity_label: str | None = None

    if root_profile is not None:
        balance_eth = float(getattr(root_profile, "balance_eth", 0.0))
        stats = getattr(root_profile, "stats", None)
        if stats is not None:
            total_transactions = getattr(stats, "total_transactions", 0)
            incoming_count = getattr(stats, "incoming_count", 0)
            outgoing_count = getattr(stats, "outgoing_count", 0)
            largest_outgoing_eth = float(getattr(stats, "largest_outgoing_eth", 0.0))
            unique_counterparties = getattr(stats, "unique_counterparties", 0)
            wallet_age_days = float(getattr(stats, "wallet_age_days", 0.0))
        # Try to get entity label
        for tx in getattr(root_profile, "transactions", []):
            for label in (
                getattr(tx, "from_entity_label", None),
                getattr(tx, "to_entity_label", None),
            ):
                if label:
                    known_entity_label = label
                    break
            if known_entity_label:
                break

    # ── Forensic findings — collected across all wallets ──────────────────────
    triggered_rules: list[RuleResult] = []
    evidence_refs: dict[str, list[str]] = {}
    mixer_contact = False
    cex_contact = False
    bridge_contact = False

    for _wallet, report in forensics_reports.items():
        for finding in getattr(report, "findings", []):
            triggered_rules.append(finding)
            rule_id = getattr(finding, "rule_id", "unknown")
            tx_hash = getattr(finding, "tx_hash", None)
            if tx_hash:
                evidence_refs.setdefault(rule_id, []).append(tx_hash)

        mixer_contact = mixer_contact or bool(getattr(report, "mixer_interaction", False))
        cex_contact = cex_contact or bool(getattr(report, "known_cex_interaction", False))
        bridge_contact = bridge_contact or bool(getattr(report, "bridge_interaction", False))

    # ── Trace graph summary ───────────────────────────────────────────────────
    total_wallets_traced = len(set(traced_wallets))
    flagged_wallets = sum(
        1 for r in forensics_reports.values()
        if getattr(r, "findings", [])
    )

    # Count entity type contacts in graph nodes
    mixer_contacts = 0
    cex_contacts = 0
    bridge_contacts = 0
    high_fanout_nodes = 0
    notable_destinations: list[str] = []

    for node in graph_nodes:
        node_type = node.get("type", "unknown")
        halt_reason = node.get("halt_reason") or ""
        if "mixer" in node_type.lower() or "mixer" in halt_reason.lower():
            mixer_contacts += 1
        if "cex" in node_type.lower() or "cex" in halt_reason.lower():
            cex_contacts += 1
        if "bridge" in node_type.lower() or "bridge" in halt_reason.lower():
            bridge_contacts += 1
        if "fanout" in halt_reason.lower() or "sample" in halt_reason.lower():
            high_fanout_nodes += 1
        entity_label = node.get("entity_label") or node.get("halt_reason")
        if entity_label and len(notable_destinations) < 10:
            notable_destinations.append(entity_label)

    # Derive max_depth_reached from graph nodes
    max_depth_reached = max(
        (node.get("depth", 0) for node in graph_nodes), default=0
    )

    trace_summary = TraceSummary(
        total_wallets_traced=total_wallets_traced,
        max_depth_reached=max_depth_reached,
        flagged_wallets=flagged_wallets,
        mixer_contacts=mixer_contacts,
        cex_contacts=cex_contacts,
        bridge_contacts=bridge_contacts,
        high_fanout_nodes=high_fanout_nodes,
        notable_destinations=notable_destinations[:10],
    )

    # ── Reasoning log summary — last 5 steps, ~500 tokens ────────────────────
    recent_steps = reasoning_log[-5:] if len(reasoning_log) > 5 else reasoning_log
    reasoning_parts = []
    for step in recent_steps:
        if hasattr(step, "step"):
            # ReasoningStep model
            reasoning_parts.append(
                f"[{step.step}] {step.action} → {step.observation}"
            )
        elif isinstance(step, dict):
            reasoning_parts.append(
                f"[{step.get('step', '?')}] {step.get('action', '')} → {step.get('observation', '')}"
            )
    reasoning_log_summary = "\n".join(reasoning_parts)

    logger.debug(
        "state_condensed",
        root_wallet=wallet_address,
        wallets=len(wallet_profiles),
        findings=len(triggered_rules),
        reasoning_steps_included=len(recent_steps),
    )

    return ReportContext(
        investigation_id=investigation_id,
        wallet_address=wallet_address,
        chain="ETHEREUM",
        risk_score=risk_score,
        risk_level=risk_level,
        balance_eth=balance_eth,
        total_transactions=total_transactions,
        incoming_count=incoming_count,
        outgoing_count=outgoing_count,
        largest_outgoing_eth=largest_outgoing_eth,
        unique_counterparties=unique_counterparties,
        wallet_age_days=wallet_age_days,
        known_entity_label=known_entity_label,
        triggered_rules=triggered_rules,
        evidence_refs=evidence_refs,
        trace_summary=trace_summary,
        mixer_contact=mixer_contact,
        cex_contact=cex_contact,
        bridge_contact=bridge_contact,
        reasoning_log_summary=reasoning_log_summary,
        errors=errors,
        wallets_analyzed=len(wallet_profiles),
    )