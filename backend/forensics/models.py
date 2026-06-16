"""
backend/forensics/models.py
─────────────────────────────────────────────────────────────────────────────
Pydantic models for the forensics engine output layer.

PURPOSE:
    Defines every structured data contract that flows between the forensics
    engine, the agent nodes, and the LLM report generator. Nothing in this
    file touches the database or the Etherscan API — these are pure data
    transfer objects that enforce type safety across the entire pipeline.

MODEL FAMILIES:

    Rule output:
        RuleResult      — single rule evaluation result
        ForensicsReport — aggregate of all rules for one wallet

    Trace planner output (Layer 2 — PLANNER node):
        TraceDirective  — LLM strategy decision + bounded parameters
        ScoredCandidate — Layer 1 ranked transaction candidate

    Report generator input (Map-Reduce context boundary):
        TraceSummary    — bounded trace graph summary passed to LLM
        ReportContext   — the ONLY input the reporter_node / report_generator
                          tool is allowed to receive; raw tx arrays never
                          cross this boundary

DESIGN DECISIONS:
    1.  All models are frozen=True. State flowing through the LangGraph
        pipeline must be immutable — nodes produce new state, never mutate.
    2.  TraceDirective enforces the strategy as a plain string validated
        against VALID_STRATEGIES rather than importing the TraceStrategy
        enum, preventing circular imports between forensics and constants.
    3.  ReportContext is deliberately lean. Every field is either a scalar,
        a count, or a short string. Raw List[Transaction] arrays are never
        included — that is the Map-Reduce safety guarantee from the arch spec.
    4.  ScoredCandidate captures all four Layer-1 score components so the
        trace_directives DB table can store them for research auditability.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator

# ─────────────────────────────────────────────────────────────────────────────
# Rule evaluation output
# ─────────────────────────────────────────────────────────────────────────────


class RuleResult(BaseModel):
    """
    Output of a single forensic rule evaluation.

    Produced by each rule's evaluate() method and collected by
    ForensicsEngine.run(). Passed to RiskScorer and persisted as
    evidence rows in the evidence table.

    OBSERVATION / EVIDENCE / REASONING CONTRACT:
        Every triggered finding must be explainable along three axes,
        per the project's explainability requirement:
          - Observation: `description` — what was observed in plain language.
          - Evidence:    `details` (+ `tx_hash`, `block_number`, `value_eth`)
                         — the concrete data backing the observation.
          - Reasoning:   `reasoning` — why this observation matters for
                         forensic/AML analysis (the "so what").
        This third field was previously only present as prose inside each
        rule's class docstring; it is now a first-class structured field so
        it can be surfaced in the persisted report, the LLM prompt, and any
        downstream consumer (frontend, PyVis tooltip, evaluation tooling)
        without re-deriving it from source code comments.
    """

    model_config = {"frozen": True}

    rule_id: str
    rule_name: str
    rule_category: str

    triggered: bool
    severity: str                         # LOW | MEDIUM | HIGH | CRITICAL
    description: str                      # ── Observation ──
    details: dict[str, Any] = Field(default_factory=dict)   # ── Evidence ──
    reasoning: str = ""                   # ── Reasoning ──

    wallet_address: str
    tx_hash: str | None = None
    block_number: int | None = None
    value_eth: str | None = None

    detected_at: datetime | None = None


class ForensicsReport(BaseModel):
    """
    Aggregate output of the ForensicsEngine for one wallet.

    Contains all triggered RuleResults plus computed summary statistics.
    Passed to RiskScorer to compute the final risk score.
    """

    model_config = {"frozen": True}

    wallet_address: str
    findings: list[RuleResult] = Field(default_factory=list)

    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0

    mixer_interaction: bool = False
    known_cex_interaction: bool = False
    bridge_interaction: bool = False

    @classmethod
    def from_results(
        cls,
        wallet_address: str,
        results: list[RuleResult],
    ) -> ForensicsReport:
        """Build a ForensicsReport from a flat list of RuleResults."""
        triggered = [r for r in results if r.triggered]
        counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for r in triggered:
            if r.severity in counts:
                counts[r.severity] += 1
        return cls(
            wallet_address=wallet_address,
            findings=triggered,
            critical_count=counts["CRITICAL"],
            high_count=counts["HIGH"],
            medium_count=counts["MEDIUM"],
            low_count=counts["LOW"],
        )


# ─────────────────────────────────────────────────────────────────────────────
# Layer-1 trace scorer output
# ─────────────────────────────────────────────────────────────────────────────


class ScoredCandidate(BaseModel):
    """
    Layer-1 scored transaction candidate produced by TraceScorer.

    Each outgoing transaction from the root wallet is evaluated and scored
    against four weighted dimensions. The PLANNER node receives the top-K
    of these (by final_score DESC) and selects its TraceDirective from them.

    All four score components are stored in the trace_directives DB table
    for research reproducibility.
    """

    model_config = {"frozen": True}

    tx_hash: str
    counterparty_address: str
    value_eth: float

    value_score: float = Field(ge=0.0, le=1.0)
    recency_score: float = Field(ge=0.0, le=1.0)
    novelty_score: float = Field(ge=0.0, le=1.0)
    rule_score: float = Field(ge=0.0, le=1.0)

    final_score: float = Field(ge=0.0, le=1.0)

    timestamp: datetime | None = None
    to_entity_label: str | None = None
    to_entity_type: str | None = None


# ─────────────────────────────────────────────────────────────────────────────
# Layer-2 PLANNER output — TraceDirective
# ─────────────────────────────────────────────────────────────────────────────

VALID_STRATEGIES: frozenset[str] = frozenset({
    "FORWARD_ONLY",
    "BACKWARD_ONLY",
    "BIDIRECTIONAL",
    "FORWARD_THEN_PIVOT",
    "SKIP",
})


class TraceDirective(BaseModel):
    """
    Structured output of the PLANNER node (Layer-2 LLM decision).

    The PLANNER receives the wallet profile, tx_stats, triggered rules,
    and the top-K ScoredCandidates from Layer 1. It outputs a TraceDirective
    that constrains exactly what the TRACER node is allowed to do.

    DESIGN:
        - strategy is validated against VALID_STRATEGIES. Any invalid LLM
          output is rejected and the fallback (FORWARD_ONLY, max_hops=2,
          priority_tx_hashes=top-3 by score) is applied. The fallback is
          deterministic and logged in reasoning_log.
        - priority_tx_hashes is the subset of Layer-1 candidates the LLM
          believes are most worth tracing. The TRACER only expands these.
        - justification is logged to the trace_directives table and the
          reasoning_log for full auditability.
    """

    model_config = {"frozen": True}

    strategy: str
    max_hops: int = Field(default=2, ge=1, le=3)
    priority_tx_hashes: list[str] = Field(default_factory=list)
    justification: str = ""
    is_fallback: bool = False

    @field_validator("strategy")
    @classmethod
    def validate_strategy(cls, v: str) -> str:
        upper = v.upper()
        if upper not in VALID_STRATEGIES:
            raise ValueError(
                f"Invalid TraceStrategy '{v}'. "
                f"Must be one of: {sorted(VALID_STRATEGIES)}"
            )
        return upper

    @classmethod
    def fallback(
        cls,
        top_candidates: list[ScoredCandidate],
        reason: str = "LLM output invalid",
    ) -> TraceDirective:
        """
        Build the safe fallback TraceDirective.

        Used when the LLM returns non-JSON, an invalid strategy enum value,
        or raises an exception. Takes the top-3 candidates by final_score.

        Args:
            top_candidates: Layer-1 scored candidates (sliced to top 3).
            reason:         Why the fallback was triggered (for logging).

        Returns:
            Deterministic TraceDirective with FORWARD_ONLY strategy.
        """
        top3 = sorted(
            top_candidates, key=lambda c: c.final_score, reverse=True
        )[:3]
        return cls(
            strategy="FORWARD_ONLY",
            max_hops=2,
            priority_tx_hashes=[c.tx_hash for c in top3],
            justification=f"Fallback applied: {reason}",
            is_fallback=True,
        )


# ─────────────────────────────────────────────────────────────────────────────
# Map-Reduce context boundary — ReportContext
# ─────────────────────────────────────────────────────────────────────────────


class TraceSummary(BaseModel):
    """
    Bounded summary of the trace graph — one field within ReportContext.

    The full trace graph can contain hundreds of nodes and edges. TraceSummary
    distils it to the counts and notable destinations that the LLM needs
    without exceeding context budget.
    """

    model_config = {"frozen": True}

    total_wallets_traced: int = 0
    max_depth_reached: int = 0
    flagged_wallets: int = 0
    mixer_contacts: int = 0
    cex_contacts: int = 0
    bridge_contacts: int = 0
    high_fanout_nodes: int = 0
    notable_destinations: list[str] = Field(
        default_factory=list,
        description="Entity labels of notable HALT destinations. Max 10.",
    )


class ReportContext(BaseModel):
    """
    The ONLY input the ReportGeneratorTool and reporter_node may receive.

    This is the Map-Reduce context boundary defined in the architecture spec.
    Raw transaction arrays, trace hop arrays, and full reasoning logs are
    explicitly excluded — they are compressed into scalars and summaries
    before this boundary.

    WHAT IS INCLUDED:
        - Wallet identity + risk assessment (scalars)
        - Aggregated transaction statistics (no raw tx objects)
        - All triggered rule findings (short structured RuleResult objects)
        - Trace graph summary (TraceSummary — counts + notable destinations)
        - Evidence reference hashes (tx_hash strings only, not full objects)
        - A pre-compressed reasoning log summary (~500 tokens max)

    WHAT IS EXPLICITLY EXCLUDED:
        - List[CleanTransaction]    (raw transaction arrays)
        - List[CleanTokenTransfer]  (raw token transfer arrays)
        - List[TraceHop]            (raw trace hop arrays)
        - Full reasoning_log        (compressed to reasoning_log_summary)
    """

    model_config = {"frozen": True}

    investigation_id: str
    wallet_address: str
    chain: str = "ETHEREUM"

    risk_score: float = Field(ge=0.0, le=100.0)
    risk_level: str

    # Wallet summary — aggregates only
    balance_eth: float = 0.0
    total_transactions: int = 0
    incoming_count: int = 0
    outgoing_count: int = 0
    largest_outgoing_eth: float = 0.0
    unique_counterparties: int = 0
    wallet_age_days: float = 0.0
    known_entity_label: str | None = None

    # Forensics findings
    triggered_rules: list[RuleResult] = Field(default_factory=list)

    # Evidence references — tx hashes only
    evidence_refs: dict[str, list[str]] = Field(
        default_factory=dict,
        description="rule_id → [tx_hash, ...] mapping. Hashes only.",
    )

    # Trace graph summary
    trace_summary: TraceSummary = Field(default_factory=TraceSummary)

    # Entity contact flags
    mixer_contact: bool = False
    cex_contact: bool = False
    bridge_contact: bool = False

    # Compressed reasoning log (~500 tokens max)
    reasoning_log_summary: str = ""

    # Non-fatal errors accumulated during the investigation (was previously
    # dropped at the StateCondenser boundary, causing the LLM to incorrectly
    # report "an error occurred" any time reasoning_log_summary was merely
    # non-empty — see report_generator.py errors= prompt parameter).
    errors: list[str] = Field(default_factory=list)

    wallets_analyzed: int = 1
