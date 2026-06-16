"""RULE-006: Round Number Transfer Detection."""
from __future__ import annotations
from typing import Any
from backend.blockchain.models import WalletProfile
from backend.forensics.base_rule import BaseForensicRule
from backend.forensics.models import RuleResult


class RoundNumbersRule(BaseForensicRule):
    """
    RULE-006: Detects repeated transfers of suspiciously round ETH amounts
    (e.g., 1.0, 5.0, 10.0 ETH). Legitimate users rarely transfer perfectly
    round amounts repeatedly; this pattern is common in structured layering.
    """

    RULE_ID = "RULE-006"
    RULE_NAME = "Round Number Transfers"
    CATEGORY = "TRANSFER_PATTERN"

    # Round ETH values to detect (exact or near-exact)
    _ROUND_AMOUNTS = {0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 20.0, 50.0, 100.0}
    _TOLERANCE = 0.0001  # Within 0.01% of a round number

    def evaluate(self, profile: WalletProfile, settings: Any) -> RuleResult:
        min_occurrences = settings.forensic_rules.RULE_006_ROUND_NUMBER_MIN_OCCURRENCES
        wallet = profile.address

        round_txs: list = []
        for tx in profile.transactions:
            if tx.direction != "OUTGOING" or tx.value_eth < 0.01:
                continue
            for amount in self._ROUND_AMOUNTS:
                if abs(tx.value_eth - amount) / amount < self._TOLERANCE:
                    round_txs.append((tx, amount))
                    break

        if len(round_txs) < min_occurrences:
            return self._not_triggered(wallet)

        from collections import Counter
        amount_counts = Counter(amount for _, amount in round_txs)
        most_common_amount, most_common_count = amount_counts.most_common(1)[0]

        severity = "MEDIUM" if len(round_txs) < min_occurrences * 3 else "HIGH"

        return self._triggered(
            wallet_address=wallet,
            severity=severity,
            description=(
                f"{len(round_txs)} transfers of round ETH amounts detected "
                f"(most common: {most_common_amount} ETH × {most_common_count})."
            ),
            reasoning=(
                "Legitimate human-initiated transfers rarely cluster around "
                "perfectly round ETH amounts (1.0, 5.0, 10.0, etc.) with this "
                "frequency — repeated round-number transfers are a common "
                "signature of scripted, structured layering activity, where "
                "an automated process moves funds in standardised batches "
                "rather than organic, variable-amount human transactions."
            ),
            details={
                "round_transfer_count": len(round_txs),
                "min_occurrences": min_occurrences,
                "amount_distribution": dict(amount_counts),
                "most_common_amount": most_common_amount,
            },
            tx_hash=round_txs[0][0].hash if round_txs else None,
        )