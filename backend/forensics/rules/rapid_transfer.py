"""RULE-002: Rapid Succession Transfer Detection."""
from __future__ import annotations

from typing import Any

from backend.blockchain.models import WalletProfile
from backend.forensics.base_rule import BaseForensicRule
from backend.forensics.models import RuleResult


class RapidTransferRule(BaseForensicRule):
    """
    RULE-002: Detects multiple outgoing transactions in a short time window.

    Fires when N or more outgoing transactions occur within a configurable
    window (default: 5 txs within 300 seconds). Rapid-fire transfers suggest
    automated splitting or layering activity.
    """

    RULE_ID = "RULE-002"
    RULE_NAME = "Rapid Succession Transfers"
    CATEGORY = "TIMING"

    def evaluate(self, profile: WalletProfile, settings: Any) -> RuleResult:
        min_count = settings.forensic_rules.RULE_002_RAPID_SUCCESSION_TX_COUNT
        window_secs = settings.forensic_rules.RULE_002_RAPID_SUCCESSION_WINDOW_SECONDS
        wallet = profile.address

        outgoing = sorted(
            [tx for tx in profile.transactions if tx.direction == "OUTGOING"],
            key=lambda t: t.timestamp,
        )

        if len(outgoing) < min_count:
            return self._not_triggered(wallet)

        max_burst = 0
        burst_txs: list = []

        for i, tx in enumerate(outgoing):
            window_end = tx.timestamp.timestamp() + window_secs
            burst = [
                t for t in outgoing[i:]
                if t.timestamp.timestamp() <= window_end
            ]
            if len(burst) > max_burst:
                max_burst = len(burst)
                burst_txs = burst

        if max_burst < min_count:
            return self._not_triggered(wallet)

        severity = "CRITICAL" if max_burst >= min_count * 3 else "HIGH"

        return self._triggered(
            wallet_address=wallet,
            severity=severity,
            description=(
                f"{max_burst} outgoing transactions detected within "
                f"{window_secs} seconds — potential layering activity."
            ),
            reasoning=(
                "Rapid-fire transfers in a short window suggest automated "
                "splitting or layering activity rather than organic human "
                "behaviour — a common technique to break a large sum into "
                "smaller transactions that individually fall below "
                "monitoring thresholds while moving funds quickly through "
                "a chain of wallets."
            ),
            details={
                "burst_count": max_burst,
                "window_seconds": window_secs,
                "threshold_count": min_count,
                "first_tx": burst_txs[0].hash if burst_txs else None,
                "last_tx": burst_txs[-1].hash if burst_txs else None,
            },
            tx_hash=burst_txs[0].hash if burst_txs else None,
        )
