"""
backend/forensics/engine.py
─────────────────────────────────────────────────────────────────────────────
Orchestrates evaluation of all forensic rules against a WalletProfile.

The ForensicsEngine is the single entry point for the detector_node. It:
  1. Instantiates all 7 rule objects (stateless, reusable)
  2. Runs each rule against the profile
  3. Checks for known mixer/entity interactions
  4. Returns a ForensicsReport aggregating all findings
"""

from __future__ import annotations

import structlog
from typing import Any

from backend.blockchain.models import WalletProfile
from backend.forensics.base_rule import BaseForensicRule
from backend.forensics.models import ForensicsReport, RuleResult
from backend.forensics.rules.large_transfer import LargeTransferRule
from backend.forensics.rules.rapid_transfer import RapidTransferRule
from backend.forensics.rules.high_fanout import HighFanOutRule
from backend.forensics.rules.dormant_activation import DormantActivationRule
from backend.forensics.rules.activity_burst import ActivityBurstRule
from backend.forensics.rules.round_numbers import RoundNumbersRule
from backend.forensics.rules.new_wallet_interaction import NewWalletInteractionRule

logger = structlog.get_logger(__name__)

# All rule instances — stateless, instantiated once
_ALL_RULES: list[BaseForensicRule] = [
    LargeTransferRule(),
    RapidTransferRule(),
    HighFanOutRule(),
    DormantActivationRule(),
    ActivityBurstRule(),
    RoundNumbersRule(),
    NewWalletInteractionRule(),
]

# Known mixer entity types from known_entities.json
_MIXER_TYPES = {"mixer_suspected"}
_CEX_TYPES = {"known_cex"}
_BRIDGE_TYPES = {"bridge"}


class ForensicsEngine:
    """
    Runs all forensic rules against a wallet profile and returns aggregated
    findings as a ForensicsReport.

    Usage:
        engine = ForensicsEngine()
        report = engine.run(profile, settings)
    """

    def run(self, profile: WalletProfile, settings: Any) -> ForensicsReport:
        """
        Evaluate all 7 forensic rules against the given wallet profile.

        Args:
            profile:  Normalised WalletProfile from the blockchain layer.
            settings: Application Settings for rule thresholds.

        Returns:
            ForensicsReport with all triggered findings and summary counts.
        """
        wallet = profile.address
        results: list[RuleResult] = []

        for rule in _ALL_RULES:
            try:
                result = rule.evaluate(profile, settings)
                results.append(result)
                if result.triggered:
                    logger.info(
                        "rule_triggered",
                        rule_id=rule.RULE_ID,
                        rule_name=rule.RULE_NAME,
                        severity=result.severity,
                        wallet=wallet,
                    )
            except Exception as exc:
                logger.error(
                    "rule_evaluation_error",
                    rule_id=rule.RULE_ID,
                    wallet=wallet,
                    error=str(exc),
                )

        # Check entity interactions from transaction labels
        mixer_interaction = False
        cex_interaction = False
        bridge_interaction = False

        for tx in profile.transactions:
            for entity_type in (tx.from_entity_type, tx.to_entity_type):
                if entity_type in _MIXER_TYPES:
                    mixer_interaction = True
                elif entity_type in _CEX_TYPES:
                    cex_interaction = True
                elif entity_type in _BRIDGE_TYPES:
                    bridge_interaction = True

        report = ForensicsReport.from_results(wallet, results)

        # Rebuild with entity flags (ForensicsReport is frozen so we reconstruct)
        report = ForensicsReport(
            wallet_address=report.wallet_address,
            findings=report.findings,
            critical_count=report.critical_count,
            high_count=report.high_count,
            medium_count=report.medium_count,
            low_count=report.low_count,
            mixer_interaction=mixer_interaction,
            known_cex_interaction=cex_interaction,
            bridge_interaction=bridge_interaction,
        )

        logger.info(
            "forensics_complete",
            wallet=wallet,
            findings=len(report.findings),
            critical=report.critical_count,
            high=report.high_count,
            medium=report.medium_count,
            low=report.low_count,
            mixer=mixer_interaction,
        )

        return report