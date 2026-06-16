"""RULE-001: Large Transfer Detection."""
from __future__ import annotations

from typing import Any

from backend.blockchain.models import WalletProfile
from backend.forensics.base_rule import BaseForensicRule
from backend.forensics.models import RuleResult


class LargeTransferRule(BaseForensicRule):
    """
    RULE-001: Detects single transactions above the large-transfer threshold.

    Fires when any outgoing transaction exceeds the configured ETH threshold
    (default 10 ETH). Large single transfers are a key indicator of fund
    movement in money laundering patterns.

    Severity: HIGH if 2x threshold, CRITICAL if 10x threshold.
    """

    RULE_ID = "RULE-001"
    RULE_NAME = "Large Transfer"
    CATEGORY = "TRANSFER_PATTERN"

    def evaluate(self, profile: WalletProfile, settings: Any) -> RuleResult:
        threshold = settings.forensic_rules.RULE_001_LARGE_TRANSFER_ETH
        wallet = profile.address

        worst_tx = None
        worst_value = 0.0

        for tx in profile.transactions:
            if tx.direction == "OUTGOING" and tx.value_eth >= threshold:
                if tx.value_eth > worst_value:
                    worst_value = tx.value_eth
                    worst_tx = tx

        if worst_tx is None:
            return self._not_triggered(wallet)

        if worst_value >= threshold * 10:
            severity = "CRITICAL"
        elif worst_value >= threshold * 2:
            severity = "HIGH"
        else:
            severity = "HIGH"

        return self._triggered(
            wallet_address=wallet,
            severity=severity,
            description=(
                f"Single outgoing transfer of {worst_value:.4f} ETH detected, "
                f"exceeding the {threshold} ETH threshold."
            ),
            reasoning=(
                "Large single transfers are a key indicator of fund movement "
                "in money laundering patterns — they often represent the "
                "consolidation or initial movement of illicit proceeds before "
                "layering through multiple intermediary wallets. The larger "
                "the multiple of the threshold, the more anomalous the "
                "transfer is relative to typical retail wallet activity."
            ),
            details={
                "value_eth": worst_value,
                "threshold_eth": threshold,
                "ratio": round(worst_value / threshold, 2),
            },
            tx_hash=worst_tx.hash,
            block_number=worst_tx.block_number,
            value_eth=str(round(worst_value, 8)),
        )
