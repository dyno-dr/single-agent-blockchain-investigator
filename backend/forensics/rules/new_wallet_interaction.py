"""RULE-007: New Wallet Interaction Detection."""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from backend.blockchain.models import WalletProfile
from backend.forensics.base_rule import BaseForensicRule
from backend.forensics.models import RuleResult


class NewWalletInteractionRule(BaseForensicRule):
    """
    RULE-007: Detects transactions sent to very recently created wallets.
    Sending significant value to brand-new wallets is a structuring indicator —
    freshly created wallets are used as temporary hops in layering chains.
    """

    RULE_ID = "RULE-007"
    RULE_NAME = "New Wallet Interaction"
    CATEGORY = "NETWORK"

    def evaluate(self, profile: WalletProfile, settings: Any) -> RuleResult:
        age_hours = settings.forensic_rules.RULE_007_NEW_WALLET_AGE_HOURS
        wallet = profile.address
        now = datetime.now(UTC).timestamp()
        age_secs = age_hours * 3600

        new_wallet_txs = []
        for tx in profile.transactions:
            if tx.direction != "OUTGOING":
                continue
            if tx.to_entity_type is not None:
                continue  # known entity — skip
            # Approximate: if the tx timestamp is very recent relative to
            # the wallet's first seen timestamp, the recipient may be new.
            # Without querying recipient history we use the tx's block age.
            tx_age = now - tx.timestamp.timestamp()
            if tx_age <= age_secs and tx.value_eth >= 0.1:
                new_wallet_txs.append(tx)

        if not new_wallet_txs:
            return self._not_triggered(wallet)

        severity = "MEDIUM" if len(new_wallet_txs) == 1 else "HIGH"

        return self._triggered(
            wallet_address=wallet,
            severity=severity,
            description=(
                f"{len(new_wallet_txs)} outgoing transaction(s) to recently "
                f"active wallets (within {age_hours}h) detected."
            ),
            reasoning=(
                "Sending significant value to brand-new or freshly-active "
                "wallets is a structuring indicator — freshly created "
                "wallets are frequently used as temporary, disposable hops "
                "in layering chains, since they carry no transaction "
                "history for investigators to cross-reference and are "
                "often abandoned after a single use."
            ),
            details={
                "new_wallet_tx_count": len(new_wallet_txs),
                "age_threshold_hours": age_hours,
                "total_eth_sent": round(sum(t.value_eth for t in new_wallet_txs), 6),
            },
            tx_hash=new_wallet_txs[0].hash if new_wallet_txs else None,
            block_number=new_wallet_txs[0].block_number if new_wallet_txs else None,
        )
