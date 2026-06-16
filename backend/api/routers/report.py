"""
backend/api/routers/report.py
─────────────────────────────────────────────────────────────────────────────
GET /report/{investigation_id} — fetch the report for a completed investigation

PURPOSE:
  Returns the forensic report for a completed investigation. Phase 2 returns
  a stub report (no findings, placeholder summary). Phase 3 populates the
  report via the LangGraph agent REPORTING node.
"""

from __future__ import annotations

from typing import Annotated

import structlog
from fastapi import APIRouter, Depends, HTTPException, status

from backend.dependencies import AuthDep
from backend.persistence.database import get_db
from backend.persistence.repositories import InvestigationRepository, ReportRepository
from backend.schemas.report import FindingSchema, ReportResponse
from backend.utils import utc_now_iso

import aiosqlite

logger = structlog.get_logger(__name__)

router = APIRouter(tags=["Report"])

DbDep = Annotated[aiosqlite.Connection, Depends(get_db)]


# ─────────────────────────────────────────────────────────────────────────────
# GET /report/{investigation_id}
# ─────────────────────────────────────────────────────────────────────────────


@router.get(
    "/report/{investigation_id}",
    response_model=ReportResponse,
    summary="Get investigation report",
    description=(
        "Returns the forensic report for a completed investigation. "
        "Returns 404 if the investigation does not exist. "
        "Returns 425 Too Early if the investigation is still running."
    ),
    responses={
        404: {"description": "Investigation not found."},
        425: {"description": "Investigation not yet complete."},
    },
)
async def get_report(
    investigation_id: str,
    db: DbDep,
    _auth: AuthDep,
) -> ReportResponse:
    """
    Return the forensic report for a completed investigation.

    In Phase 2, if no report record exists yet (agent not wired), a stub
    report is synthesized from the investigation record for forward
    compatibility.

    Args:
        investigation_id: UUID4 investigation session ID.

    Returns:
        ReportResponse with findings, risk score, and summary.

    Raises:
        HTTPException 404: If the investigation ID is not found.
        HTTPException 425: If the investigation is still PENDING or RUNNING.
    """
    inv_repo = InvestigationRepository(db)
    report_repo = ReportRepository(db)

    inv = await inv_repo.get(investigation_id)
    if inv is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{investigation_id}' not found.",
        )

    if inv["status"] in ("PENDING", "RUNNING"):
        raise HTTPException(
            status_code=425,  # Too Early
            detail=(
                f"Investigation '{investigation_id}' is still {inv['status']}. "
                "Poll GET /investigate/{id} and retry when status is COMPLETE."
            ),
        )

    if inv["status"] == "FAILED":
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                f"Investigation '{investigation_id}' failed: "
                f"{inv.get('error_message', 'Unknown error')}."
            ),
        )

    # Try to get a persisted report first (Phase 3+ populates this)
    report = await report_repo.get_by_investigation(investigation_id)
    if report is not None:
        findings_raw = report.get("findings_json") or []
        findings = [FindingSchema(**f) for f in findings_raw]
        recommendations = report.get("recommendations_json") or []
        return ReportResponse(
            id=report["id"],
            investigation_id=investigation_id,
            title=report["title"],
            summary=report["summary"],
            findings=findings,
            recommendations=recommendations,
            graph_data=report.get("graph_data"),
            risk_score=float(report["risk_score"]),
            risk_level=report["risk_level"],
            evidence_count=report["evidence_count"],
            generated_at=report["generated_at"],
            model_used=report.get("model_used"),
        )

    # Phase 2 stub: synthesise a minimal report from the investigation record
    risk_score = float(inv.get("risk_score") or 0.0)
    risk_level = inv.get("risk_level") or "LOW"

    return ReportResponse(
        id=f"stub-{investigation_id}",
        investigation_id=investigation_id,
        title=f"Investigation Report — {inv['wallet_address'][:10]}…",
        summary=(
            "Phase 2 stub report. Forensic rule evaluation and LLM summary "
            "will be available once the agent layer (Phase 3) is complete."
        ),
        findings=[],
        recommendations=[],
        graph_data=None,
        risk_score=risk_score,
        risk_level=risk_level,
        evidence_count=0,
        generated_at=utc_now_iso(),
        model_used=None,
    )