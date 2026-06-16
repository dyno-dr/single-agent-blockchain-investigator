"""
backend/agent/nodes/planner.py
─────────────────────────────────────────────────────────────────────────────
PLANNER node — uses Gemini to analyse the root wallet profile and produce
a typed TraceDirective that constrains every subsequent tracer hop.

THREE-LAYER TRACE SELECTION — this node is Layer 2:
    Layer 1 (TraceScorer)  — deterministic math; ranks every outgoing tx
    Layer 2 (PLANNER/LLM)  — constrained reasoning; selects strategy + hops   ← HERE
    Layer 3 (PruningEngine) — per-hop deterministic; EXPAND/SKIP/HALT/SAMPLE

WHAT THE LLM DOES:
    - Receives: wallet_profile summary, tx_stats, triggered rule names,
      and the top-K Layer-1 ScoredCandidates (hashes + values + scores).
    - Outputs: a JSON object with strategy (fixed enum) + justification.
    - The strategy enum is validated client-side; any invalid value triggers
      TraceDirective.fallback() — the investigation is never blocked by a
      bad LLM response.

DESIGN DECISIONS:
    1.  The LLM is given a FIXED ENUM of strategy names. It cannot invent
        new strategies. This is the "constrained LLM" pattern from the spec.
    2.  The raw transactions[] list is NEVER sent to the LLM — only tx_stats
        (aggregated) and the top-K scored candidate hashes. This is the
        Map-Reduce context boundary enforced at this node.
    3.  The entire TraceDirective (strategy, hashes, justification,
        is_fallback flag) is logged to reasoning_log and persisted in the
        trace_directives table so every LLM decision is fully auditable.
    4.  Temperature=0.0 for the planner — deterministic strategy selection.
    5.  max_output_tokens=512 — the response is short JSON; no need for more.
"""

from __future__ import annotations

import json
from typing import Any

import structlog

from backend.agent.state import AgentState, ReasoningStep
from backend.forensics.models import ScoredCandidate, TraceDirective
from backend.utils import utc_now_iso

logger = structlog.get_logger(__name__)

_PLANNER_PROMPT = """\
You are a blockchain forensic analyst. Based on the wallet profile and scored \
transaction candidates below, select the most appropriate trace strategy.

WALLET: {wallet}
BALANCE: {balance_eth} ETH
TRANSACTIONS — total: {total_txs} | incoming: {incoming} | outgoing: {outgoing}
LARGEST OUTGOING: {largest_out} ETH
UNIQUE COUNTERPARTIES: {counterparties}
WALLET AGE: {age_days} days
KNOWN ENTITY INTERACTIONS: {entities}

TRIGGERED FORENSIC RULES: {triggered_rules}

TOP SCORED CANDIDATES (Layer-1 ranking):
{candidates_text}

AVAILABLE STRATEGIES:
  FORWARD_ONLY       — trace outgoing flows. Use when wallet is sending to many new addresses.
  BACKWARD_ONLY      — trace incoming flows. Use when wallet received large/suspicious amounts.
  BIDIRECTIONAL      — trace both. Use for complex hub wallets with high in+out volume.
  FORWARD_THEN_PIVOT — trace forward, pivot at suspicious destinations.
  SKIP               — no tracing warranted. Use for dormant or dust-only wallets.

Respond ONLY with valid JSON — no markdown, no explanation:
{{"strategy": "<STRATEGY>", "justification": "<one concise sentence explaining the choice>"}}\
"""


async def planner_node(state: AgentState) -> dict[str, Any]:
    """
    Layer-2 LLM strategy selection — produces a bounded TraceDirective.

    Reads the root wallet profile and the Layer-1 scored candidates from
    state, calls Gemini to select a TraceStrategy, validates the output,
    and writes the TraceDirective back into state.

    Args:
        state: Current AgentState. wallet_profiles must be populated by
               the profiler_node before this node runs.

    Returns:
        Partial state update containing:
            trace_strategy    (str — for graph edge routing)
            planner_reasoning (str — human-readable justification)
            trace_directive   (dict — serialised TraceDirective for TRACER)
            reasoning_log     (list[ReasoningStep])
    """
    wallet   = state["wallet_address"]
    settings = state["settings"]
    profiles = state.get("wallet_profiles", {})
    profile  = profiles.get(wallet)

    # ── Collect Layer-1 candidates from state ────────────────────────────────
    # trace_scorer_node stores them as list[dict] (JSON-serialisable for state)
    raw_candidates: list[dict] = state.get("trace_candidates", [])  # type: ignore[assignment]
    scored_candidates: list[ScoredCandidate] = [
        ScoredCandidate(**c) for c in raw_candidates
    ] if raw_candidates else []

    # ── Fallback guard — no profile ──────────────────────────────────────────
    if profile is None:
        logger.warning("planner_no_profile", wallet=wallet)
        directive = TraceDirective.fallback(
            top_candidates=scored_candidates,
            reason="no wallet profile available",
        )
        return _build_return(wallet, directive)

    stats = profile.stats

    # Collect known entity labels from profile transactions
    entity_labels: set[str] = set()
    for tx in profile.transactions:
        for label in (tx.from_entity_label, tx.to_entity_label):
            if label:
                entity_labels.add(label)

    # Collect triggered rule names from forensics_reports (if DETECTOR ran first)
    triggered_rule_names: list[str] = []
    for _, report in state.get("forensics_reports", {}).items():
        for finding in report.findings:
            if finding.triggered:
                triggered_rule_names.append(finding.rule_name)

    # Format top-5 candidates for the prompt
    top5 = sorted(scored_candidates, key=lambda c: c.final_score, reverse=True)[:5]
    if top5:
        cand_lines = [
            f"  {i+1}. {c.tx_hash[:12]}… → {c.counterparty_address[:10]}… | "
            f"{c.value_eth:.4f} ETH | score={c.final_score:.3f}"
            + (f" | entity={c.to_entity_label}" if c.to_entity_label else "")
            for i, c in enumerate(top5)
        ]
        candidates_text = "\n".join(cand_lines)
    else:
        candidates_text = "  (no outgoing transactions found)"

    prompt = _PLANNER_PROMPT.format(
        wallet=wallet,
        balance_eth=round(profile.balance_eth, 4),
        total_txs=stats.total_transactions,
        incoming=stats.incoming_count,
        outgoing=stats.outgoing_count,
        largest_out=round(stats.largest_outgoing_eth, 4),
        counterparties=stats.unique_counterparties,
        age_days=round(stats.wallet_age_days, 1),
        entities=", ".join(entity_labels) if entity_labels else "None",
        triggered_rules=(
            ", ".join(triggered_rule_names) if triggered_rule_names else "None"
        ),
        candidates_text=candidates_text,
    )

    # ── LLM call ─────────────────────────────────────────────────────────────
    directive: TraceDirective | None = None

    try:
        from langchain_core.messages import HumanMessage
        from langchain_google_genai import ChatGoogleGenerativeAI

        llm = ChatGoogleGenerativeAI(
            model=settings.llm.model,
            google_api_key=settings.llm.google_api_key,
            temperature=0.0,
            max_output_tokens=512,
        )

        response = await llm.ainvoke([HumanMessage(content=prompt)])
        text = response.content.strip()

        # Strip markdown fences (common Gemini habit)
        if text.startswith("```"):
            parts = text.split("```")
            text = parts[1]
            if text.lower().startswith("json"):
                text = text[4:]
            text = text.strip()

        parsed = json.loads(text)
        raw_strategy    = str(parsed.get("strategy", "")).upper()
        raw_justification = str(parsed.get("justification", ""))

        # Validate — if strategy is unknown, TraceDirective validator will raise
        directive = TraceDirective(
            strategy=raw_strategy,
            max_hops=min(state.get("depth", 2), 3),
            priority_tx_hashes=[c.tx_hash for c in top5],
            justification=raw_justification,
            is_fallback=False,
        )

        logger.info(
            "planner_strategy_selected",
            wallet=wallet,
            strategy=directive.strategy,
            justification=directive.justification,
        )

    except Exception as exc:
        logger.warning("planner_llm_failed", wallet=wallet, error=str(exc))
        directive = TraceDirective.fallback(
            top_candidates=scored_candidates,
            reason=str(exc),
        )

    return _build_return(wallet, directive)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _build_return(wallet: str, directive: TraceDirective) -> dict[str, Any]:
    """Package the TraceDirective into a LangGraph-compatible state dict."""
    step = ReasoningStep(
        step="PLANNER",
        action=f"TraceDirective: {directive.strategy}"
               + (" [FALLBACK]" if directive.is_fallback else ""),
        observation=directive.justification,
        timestamp=utc_now_iso(),
    )
    return {
        "trace_strategy":    directive.strategy,
        "planner_reasoning": directive.justification,
        # Stored as dict so LangGraph can serialise it to state
        "trace_directive":   directive.model_dump(),
        "current_phase":     "INIT",
        "reasoning_log":     [step],
    }
