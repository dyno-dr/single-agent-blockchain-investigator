"""RULE-004: Dormant Wallet Activation Detection."""
from __future__ import annotations
from typing import Any
from backend.blockchain.models import WalletProfile
from backend.forensics.base_rule import BaseForensicRule
from backend.forensics.models import RuleResult


class DormantActivationRule(BaseForensicRule):
    """
    RULE-004: Detects wallets that were inactive for a long period and then
    suddenly became active. Dormant-then-active patterns are common in
    long-term fund storage before laundering.
    """

    RULE_ID = "RULE-004"
    RULE_NAME = "Dormant Wallet Activation"
    CATEGORY = "LIFECYCLE"

    def evaluate(self, profile: WalletProfile, settings: Any) -> RuleResult:
        dormancy_days = settings.forensic_rules.RULE_004_DORMANCY_THRESHOLD_DAYS
        activation_hours = settings.forensic_rules.RULE_004_ACTIVATION_WINDOW_HOURS
        wallet = profile.address

        txs = sorted(profile.transactions, key=lambda t: t.timestamp)
        if len(txs) < 2:
            return self._not_triggered(wallet)

        # Look for gaps larger than dormancy_days
        worst_gap_days = 0.0
        gap_start_tx = None
        gap_end_tx = None

        for i in range(1, len(txs)):
            gap_secs = (
                txs[i].timestamp.timestamp() - txs[i - 1].timestamp.timestamp()
            )
            gap_days = gap_secs / 86400
            if gap_days > worst_gap_days:
                worst_gap_days = gap_days
                gap_start_tx = txs[i - 1]
                gap_end_tx = txs[i]

        if worst_gap_days < dormancy_days:
            return self._not_triggered(wallet)

        # Check if activity resumed within activation_hours after the gap
        if gap_end_tx is None:
            return self._not_triggered(wallet)

        resume_time = gap_end_tx.timestamp.timestamp()
        post_gap_txs = [
            tx for tx in txs
            if tx.timestamp.timestamp() >= resume_time
            and tx.timestamp.timestamp() <= resume_time + activation_hours * 3600
        ]

        severity = "CRITICAL" if worst_gap_days >= dormancy_days * 2 else "HIGH"

        return self._triggered(
            wallet_address=wallet,
            severity=severity,
            description=(
                f"Wallet was dormant for {worst_gap_days:.0f} days then resumed "
                f"activity with {len(post_gap_txs)} transaction(s) within "
                f"{activation_hours} hours."
            ),
            reasoning=(
                "Dormant-then-active patterns are common in long-term fund "
                "storage strategies preceding laundering — illicit actors "
                "often park stolen or illicit funds in a wallet for an "
                "extended period to let scrutiny fade before reactivating "
                "the wallet to move or cash out the funds."
            ),
            details={
                "dormant_days": round(worst_gap_days, 1),
                "threshold_days": dormancy_days,
                "post_activation_tx_count": len(post_gap_txs),
                "activation_window_hours": activation_hours,
                "gap_start_tx": gap_start_tx.hash if gap_start_tx else None,
                "gap_end_tx": gap_end_tx.hash if gap_end_tx else None,
            },
            tx_hash=gap_end_tx.hash,
            block_number=gap_end_tx.block_number,
        )