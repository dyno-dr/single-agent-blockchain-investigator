"""
backend/schemas/report.py
─────────────────────────────────────────────────────────────────────────────
Pydantic schemas for report and finding responses.

PURPOSE:
  Defines the typed shapes of report API responses. The report is the primary
  deliverable of an investigation — the frontend renders it as the analyst
  dashboard and it can be exported as a PDF.

DESIGN DECISIONS:
  1. `FindingSchema` mirrors the `evidence` table shape and is embedded as
     a list inside `ReportResponse.findings`.
  2. `ReportResponse` is intentionally flat (no nested investigation object)
     to keep the API surface simple. The investigation_id field lets callers
     cross-reference.
  3. Graph data is an opaque `dict` at this schema level. The visualization
     layer (Phase 3) defines its internal structure. Keeping it opaque here
     means the schema doesn't need updating when the graph format evolves.
  4. `recommendations` is optional — the Phase 2 route stub returns an empty
     list; the LLM layer (Phase 3) populates it.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

# ─────────────────────────────────────────────────────────────────────────────
# Finding (evidence item)
# ─────────────────────────────────────────────────────────────────────────────


class FindingSchema(BaseModel):
    """
    A single forensic finding (evidence item) embedded in a report.

    Attributes:
        id: UUID4 evidence record ID. None when sourced from a report's
            findings_json (RuleResult dumps don't carry a DB primary key).
        rule_id: Forensic rule identifier (e.g. RULE-001).
        rule_name: Human-readable rule name.
        rule_category: Rule category (TRANSFER_PATTERN, TIMING, etc.).
        severity: Finding severity (LOW | MEDIUM | HIGH | CRITICAL).
        description: Observation — human-readable description of what was detected.
        details: Evidence — rule-specific JSON evidence details.
        reasoning: Reasoning — why this finding is forensically significant.
        wallet_address: Wallet the finding applies to.
        tx_hash: Transaction hash if finding is tx-specific.
        block_number: Block number of the triggering transaction.
        value_eth: ETH value involved.
        detected_at: ISO 8601 UTC timestamp when rule fired.
    """

    id: str | None = None
    rule_id: str
    rule_name: str
    rule_category: str | None = None
    severity: str
    description: str
    details: dict[str, Any] | None = None
    reasoning: str | None = None
    wallet_address: str
    tx_hash: str | None = None
    block_number: int | None = None
    value_eth: str | None = None
    detected_at: str | None = None

    model_config = {"from_attributes": True}


# ─────────────────────────────────────────────────────────────────────────────
# Report
# ─────────────────────────────────────────────────────────────────────────────


class ReportResponse(BaseModel):
    """
    Full investigation report returned by GET /report/{investigation_id}.

    Attributes:
        id: UUID4 report ID.
        investigation_id: FK to the parent investigation.
        title: Generated report title.
        summary: Executive summary paragraph.
        findings: List of forensic findings (evidence items).
        recommendations: List of recommendation strings (Phase 3).
        graph_data: Nodes + edges for the visualization layer.
        risk_score: Final risk score (0.0–100.0).
        risk_level: Risk level (LOW | MEDIUM | HIGH | CRITICAL).
        evidence_count: Total number of evidence items.
        generated_at: ISO 8601 UTC timestamp.
        model_used: LLM model string used to generate the summary.
    """

    id: str
    investigation_id: str
    title: str
    summary: str
    findings: list[FindingSchema] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    graph_data: dict[str, Any] | None = None
    risk_score: float
    risk_level: str
    evidence_count: int
    generated_at: str
    model_used: str | None = None

    model_config = {"from_attributes": True}


class ReportListResponse(BaseModel):
    """
    Paginated list of report summaries (without findings detail).

    Used by GET /history to show a lightweight list.
    """

    items: list[ReportResponse]
    total: int
    page: int
    page_size: int
    pages: int
