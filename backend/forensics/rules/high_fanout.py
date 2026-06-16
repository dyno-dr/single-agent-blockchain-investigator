"""RULE-003: High Fan-Out Detection."""
from __future__ import annotations
from typing import Any
from backend.blockchain.models import WalletProfile
from backend.forensics.base_rule import BaseForensicRule
from backend.forensics.models import RuleResult


class HighFanOutRule(BaseForensicRule):
    """
    RULE-003: Detects wallets sending to an unusually high number of unique
    addresses. High fan-out is a hallmark of structuring and peel-chain attacks.
    """

    RULE_ID = "RULE-003"
    RULE_NAME = "High Fan-Out"
    CATEGORY = "NETWORK"

    def evaluate(self, profile: WalletProfile, settings: Any) -> RuleResult:
        threshold = settings.forensic_rules.RULE_003_HIGH_FANOUT_UNIQUE_ADDRESSES
        wallet = profile.address

        unique_recipients = {
            tx.to_address
            for tx in profile.transactions
            if tx.direction == "OUTGOING" and tx.to_address
        }
        count = len(unique_recipients)

        if count < threshold:
            return self._not_triggered(wallet)

        severity = "CRITICAL" if count >= threshold * 3 else "HIGH"

        return self._triggered(
            wallet_address=wallet,
            severity=severity,
            description=(
                f"Wallet sent to {count} unique addresses, "
                f"exceeding the fan-out threshold of {threshold}."
            ),
            reasoning=(
                "High fan-out — sending to an unusually large number of "
                "distinct addresses — is a hallmark of structuring and "
                "peel-chain attacks, where funds are deliberately fragmented "
                "across many wallets to obscure the trail and frustrate "
                "manual or automated tracing efforts."
            ),
            details={
                "unique_recipients": count,
                "threshold": threshold,
                "ratio": round(count / threshold, 2),
            },
        )