"""
backend/agent/nodes/detector_node.py
─────────────────────────────────────────────────────────────────────────────
DETECTOR node: runs all 7 forensic rules against every wallet profile
collected so far, computes the risk score, and updates state.
"""

from __future__ import annotations

from typing import Any

import structlog

from backend.agent.state import AgentState, ReasoningStep
from backend.forensics.engine import ForensicsEngine
from backend.forensics.risk_scorer import compute_risk_score
from backend.utils import utc_now_iso

logger = structlog.get_logger(__name__)

_engine = ForensicsEngine()


async def detector_node(state: AgentState) -> dict[str, Any]:
    """
    Run forensic rules against all collected wallet profiles.

    Args:
        state: Current AgentState (wallet_profiles must be populated).

    Returns:
        Partial state update with forensics_reports, risk_score, risk_level.
    """
    settings = state["settings"]
    profiles = state.get("wallet_profiles", {})
    existing_reports = dict(state.get("forensics_reports", {}))

    if not profiles:
        logger.warning("detector_no_profiles")
        return {
            "current_phase": "DETECTING",
            "forensics_reports": existing_reports,
            "risk_score": 0.0,
            "risk_level": "LOW",
        }

    total_findings = 0
    max_risk_score = 0.0
    max_risk_level = "LOW"

    for wallet, profile in profiles.items():
        if wallet in existing_reports:
            continue  # already evaluated

        report = _engine.run(profile, settings)
        existing_reports[wallet] = report
        total_findings += len(report.findings)

        score, level = compute_risk_score(report, settings)
        if score > max_risk_score:
            max_risk_score = score
            max_risk_level = level

        logger.info(
            "detector_wallet_scored",
            wallet=wallet,
            findings=len(report.findings),
            risk_score=score,
            risk_level=level,
        )

    step = ReasoningStep(
        step="DETECTOR",
        action=f"Evaluated {len(profiles)} wallet(s)",
        observation=(
            f"Found {total_findings} total findings. "
            f"Max risk: {max_risk_score:.1f} ({max_risk_level})"
        ),
        timestamp=utc_now_iso(),
    )

    return {
        "current_phase": "DETECTING",
        "forensics_reports": existing_reports,
        "risk_score": max_risk_score,
        "risk_level": max_risk_level,
        "reasoning_log": [step],
    }