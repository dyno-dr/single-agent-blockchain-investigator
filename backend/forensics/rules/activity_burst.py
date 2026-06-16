"""RULE-005: Activity Burst Detection."""
from __future__ import annotations
from collections import defaultdict
from typing import Any
from backend.blockchain.models import WalletProfile
from backend.forensics.base_rule import BaseForensicRule
from backend.forensics.models import RuleResult


class ActivityBurstRule(BaseForensicRule):
    """
    RULE-005: Detects sudden spikes in transaction volume relative to the
    wallet's historical baseline. A multiplier of 3x or more in a rolling
    30-day window vs prior activity indicates anomalous behaviour.
    """

    RULE_ID = "RULE-005"
    RULE_NAME = "Activity Burst"
    CATEGORY = "TIMING"

    def evaluate(self, profile: WalletProfile, settings: Any) -> RuleResult:
        multiplier = settings.forensic_rules.RULE_005_BURST_MULTIPLIER
        window_days = settings.forensic_rules.RULE_005_ROLLING_WINDOW_DAYS
        wallet = profile.address

        txs = sorted(profile.transactions, key=lambda t: t.timestamp)
        if len(txs) < 4:
            return self._not_triggered(wallet)

        # Group transactions by 30-day windows
        window_secs = window_days * 86400
        first_ts = txs[0].timestamp.timestamp()

        buckets: dict[int, int] = defaultdict(int)
        for tx in txs:
            bucket = int((tx.timestamp.timestamp() - first_ts) / window_secs)
            buckets[bucket] += 1

        if len(buckets) < 2:
            return self._not_triggered(wallet)

        counts = list(buckets.values())
        baseline = sum(counts[:-1]) / len(counts[:-1])
        latest = counts[-1]

        if baseline == 0 or latest < multiplier * baseline:
            return self._not_triggered(wallet)

        actual_multiplier = latest / baseline
        severity = "CRITICAL" if actual_multiplier >= multiplier * 3 else "HIGH"

        return self._triggered(
            wallet_address=wallet,
            severity=severity,
            description=(
                f"Transaction volume spiked {actual_multiplier:.1f}x above "
                f"baseline in the most recent {window_days}-day window "
                f"({latest} txs vs {baseline:.1f} avg)."
            ),
            reasoning=(
                "A sudden, large deviation from a wallet's established "
                "activity baseline is anomalous by definition and warrants "
                "scrutiny regardless of direction — sharp volume spikes "
                "often coincide with a wallet being repurposed for illicit "
                "fund movement, a compromise event, or coordinated "
                "distribution activity (e.g., airdrop farming or mixing)."
            ),
            details={
                "burst_multiplier": round(actual_multiplier, 2),
                "threshold_multiplier": multiplier,
                "latest_window_count": latest,
                "baseline_avg": round(baseline, 2),
                "window_days": window_days,
            },
        )