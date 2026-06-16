"""
backend/tools/suspicion_detector.py
─────────────────────────────────────────────────────────────────────────────
Tool: SuspicionDetectorTool

PURPOSE:
  Agent-layer wrapper around ForensicsEngine + RiskScorer. Runs all 7
  forensic rules against every wallet profile collected during the
  investigation and returns a summary dict suitable for the reporter_node.

  This tool is called by detector_node and is the bridge between raw
  WalletProfiles and structured forensics output.

WHAT IT DOES:
  1. Iterates every WalletProfile in the provided dict.
  2. Calls ForensicsEngine.run(profile, settings) for each wallet.
  3. Computes risk score + level via compute_risk_score().
  4. Returns the highest risk score across all wallets (the investigation-level risk).

DESIGN DECISIONS:
  1. The tool does NOT modify state directly — it returns a result dict.
     detector_node merges the result into AgentState.
  2. If a wallet has already been evaluated (already in existing_reports),
     it is skipped to avoid double-counting.
  3. The tool collects entity interaction flags (mixer, CEX, bridge) across
     all wallets and sets them as top-level result fields for the reporter.
"""

from __future__ import annotations

from typing import Any

import structlog

from backend.blockchain.models import WalletProfile
from backend.forensics.engine import ForensicsEngine
from backend.forensics.models import ForensicsReport
from backend.forensics.risk_scorer import compute_risk_score
from backend.tools.base import BaseTool

logger = structlog.get_logger(__name__)

_engine = ForensicsEngine()


class SuspicionDetectorTool(BaseTool):
    """
    Runs all 7 forensic rules against every collected WalletProfile.

    Usage:
        tool = SuspicionDetectorTool()
        result = await tool.run(
            wallet_profiles=profiles_dict,
            existing_reports=reports_dict,
            settings=settings,
        )
        # result: {forensics_reports, risk_score, risk_level,
        #          mixer_interaction, cex_interaction, bridge_interaction}
    """

    name = "suspicion_detector"
    description = (
        "Run all 7 forensic rules against every collected wallet profile "
        "and compute the investigation-level risk score."
    )

    async def run(
        self,
        *,
        wallet_profiles: dict[str, WalletProfile],
        existing_reports: dict[str, ForensicsReport],
        settings: Any,
        **_kwargs: Any,
    ) -> dict[str, Any]:
        """
        Evaluate forensic rules across all wallet profiles.

        Args:
            wallet_profiles:  Dict mapping address → WalletProfile.
            existing_reports: Already-evaluated ForensicsReports (skipped).
            settings:         Application settings for rule thresholds.

        Returns:
            Dict with:
                forensics_reports   : Updated dict mapping address → ForensicsReport
                risk_score          : Highest risk score across all wallets (0–100)
                risk_level          : Corresponding risk level string
                total_findings      : Total findings count across all wallets
                mixer_interaction   : True if any wallet touched a mixer
                cex_interaction     : True if any wallet touched a CEX
                bridge_interaction  : True if any wallet touched a bridge
        """
        reports = dict(existing_reports)
        max_risk_score = 0.0
        max_risk_level = "LOW"
        total_findings = 0
        any_mixer = False
        any_cex = False
        any_bridge = False

        for wallet, profile in wallet_profiles.items():
            if wallet in reports:
                # Already evaluated — still count toward totals
                rep = reports[wallet]
                score, level = compute_risk_score(rep, settings)
                if score > max_risk_score:
                    max_risk_score = score
                    max_risk_level = level
                total_findings += len(rep.findings)
                any_mixer = any_mixer or rep.mixer_interaction
                any_cex = any_cex or rep.known_cex_interaction
                any_bridge = any_bridge or rep.bridge_interaction
                continue

            # Run all rules
            report = _engine.run(profile, settings)
            reports[wallet] = report

            score, level = compute_risk_score(report, settings)
            if score > max_risk_score:
                max_risk_score = score
                max_risk_level = level

            total_findings += len(report.findings)
            any_mixer = any_mixer or report.mixer_interaction
            any_cex = any_cex or report.known_cex_interaction
            any_bridge = any_bridge or report.bridge_interaction

            logger.info(
                "suspicion_detector_wallet",
                wallet=wallet,
                findings=len(report.findings),
                risk_score=score,
                risk_level=level,
            )

        logger.info(
            "suspicion_detector_complete",
            wallets=len(wallet_profiles),
            total_findings=total_findings,
            max_risk_score=max_risk_score,
            max_risk_level=max_risk_level,
        )

        return {
            "forensics_reports": reports,
            "risk_score": max_risk_score,
            "risk_level": max_risk_level,
            "total_findings": total_findings,
            "mixer_interaction": any_mixer,
            "cex_interaction": any_cex,
            "bridge_interaction": any_bridge,
        }