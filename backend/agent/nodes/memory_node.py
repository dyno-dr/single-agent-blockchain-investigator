"""
backend/agent/nodes/memory_node.py
─────────────────────────────────────────────────────────────────────────────
MEMORY node: persists all agent outputs to the database at investigation
completion. This is the final node before the graph exits.

Persists:
  - Investigation status, risk score, risk level
  - All evidence items (one row per forensic finding)
  - The full report (title, summary, findings, recommendations)
  - The agent's reasoning log
"""

from __future__ import annotations

from typing import Any

import structlog

from backend.agent.state import AgentState, ReasoningStep
from backend.persistence.database import get_db_conn
from backend.persistence.repositories import (
    EvidenceRepository,
    InvestigationRepository,
    ReportRepository,
)
from backend.utils import utc_now_iso

logger = structlog.get_logger(__name__)


async def memory_node(state: AgentState) -> dict[str, Any]:
    """
    Persist all investigation results to the database.

    Args:
        state: Fully populated AgentState after all other nodes have run.

    Returns:
        Partial state update setting status=COMPLETE and current_phase=DONE.
    """
    investigation_id = state["investigation_id"]
    wallet = state["wallet_address"]
    risk_score = state.get("risk_score", 0.0)
    risk_level = state.get("risk_level", "LOW")
    reports = state.get("forensics_reports", {})
    settings = state["settings"]

    db = get_db_conn()
    inv_repo = InvestigationRepository(db)
    evidence_repo = EvidenceRepository(db)
    report_repo = ReportRepository(db)

    # ── Persist evidence items ────────────────────────────────────────────────
    evidence_items: list[dict[str, Any]] = []
    total_evidence = 0

    for w, forensics_report in reports.items():
        for finding in forensics_report.findings:
            evidence_items.append({
                "investigation_id": investigation_id,
                "rule_id": finding.rule_id,
                "rule_name": finding.rule_name,
                "rule_category": finding.rule_category,
                "severity": finding.severity,
                "description": finding.description,
                "details": dict(finding.details),
                "wallet_address": w,
                "tx_hash": finding.tx_hash,
                "block_number": finding.block_number,
                "value_eth": finding.value_eth,
            })

    if evidence_items:
        try:
            await evidence_repo.create_batch(evidence_items)
            total_evidence = len(evidence_items)
            logger.info(
                "memory_evidence_persisted",
                count=total_evidence,
                investigation_id=investigation_id,
            )
        except Exception as exc:
            logger.error(
                "memory_evidence_persist_failed",
                error=str(exc),
                investigation_id=investigation_id,
            )

    # ── Persist report ────────────────────────────────────────────────────────
    model_used = settings.llm.model if settings else None

    try:
        existing = await report_repo.get_by_investigation(investigation_id)
        if existing is None:
            graph_nodes = state.get("graph_nodes", [])
            graph_edges = state.get("graph_edges", [])
            await report_repo.create(
                investigation_id=investigation_id,
                title=state.get("report_title", "Investigation Report"),
                summary=state.get("report_summary", ""),
                findings=state.get("report_findings", []),
                risk_score=risk_score,
                risk_level=risk_level,
                evidence_count=total_evidence,
                recommendations=state.get("report_recommendations", []),
                graph_data={
                    "nodes": graph_nodes,
                    "edges": graph_edges,
                    "node_count": len(graph_nodes),
                    "edge_count": len(graph_edges),
                },
                model_used=model_used,
            )
            logger.info("memory_report_persisted", investigation_id=investigation_id)
    except Exception as exc:
        logger.error(
            "memory_report_persist_failed",
            error=str(exc),
            investigation_id=investigation_id,
        )

    # ── Persist reasoning log + final status ─────────────────────────────────
    reasoning_log = [dict(s) for s in state.get("reasoning_log", [])]

    try:
        await inv_repo.save_reasoning(investigation_id, reasoning_log)
        await inv_repo.update_status(
            investigation_id,
            status="COMPLETE",
            risk_score=risk_score,
            risk_level=risk_level,
        )
        await inv_repo.update_phase(investigation_id, phase="DONE")

        logger.info(
            "memory_investigation_complete",
            investigation_id=investigation_id,
            risk_score=risk_score,
            risk_level=risk_level,
        )
    except Exception as exc:
        logger.error(
            "memory_status_update_failed",
            error=str(exc),
            investigation_id=investigation_id,
        )

    step = ReasoningStep(
        step="MEMORY",
        action="Persisted all results to database",
        observation=(
            f"Evidence: {total_evidence} items. "
            f"Risk: {risk_level} ({risk_score:.1f}/100)."
        ),
        timestamp=utc_now_iso(),
    )

    return {
        "status": "COMPLETE",
        "current_phase": "DONE",
        "reasoning_log": [step],
    }
