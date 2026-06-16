"""
backend/forensics/base_rule.py
─────────────────────────────────────────────────────────────────────────────
Abstract base class that every forensic rule must implement.

DESIGN DECISIONS:
  1. Each rule is a stateless object. All context (transactions, settings)
     is passed into `evaluate()` — no instance state carries over between
     calls. This makes rules safe to reuse across concurrent investigations.
  2. `evaluate()` always returns a RuleResult with `triggered=False` if the
     rule did not fire. Callers never need to check for None.
  3. Rules are identified by their `rule_id` and `rule_name` class attributes.
     These map directly to the RULE-00N constants in constants.py.
  4. `_not_triggered()` is a convenience factory for the common non-firing
     case, reducing boilerplate in rule implementations.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import UTC, datetime
from typing import Any

from backend.blockchain.models import WalletProfile
from backend.forensics.models import RuleResult


class BaseForensicRule(ABC):
    """
    Abstract base for all forensic rule implementations.

    Subclasses must define:
        RULE_ID   : str  — e.g. "RULE-001"
        RULE_NAME : str  — e.g. "Large Transfer"
        CATEGORY  : str  — RuleCategory enum value

    And implement:
        evaluate(profile, settings) -> RuleResult
    """

    RULE_ID: str
    RULE_NAME: str
    CATEGORY: str

    @abstractmethod
    def evaluate(
        self,
        profile: WalletProfile,
        settings: Any,
    ) -> RuleResult:
        """
        Evaluate this rule against a wallet profile.

        Args:
            profile:  Normalised wallet data (transactions, balance, stats).
            settings: Application Settings for threshold configuration.

        Returns:
            RuleResult with triggered=True if the rule fired, False otherwise.
        """

    def _triggered(
        self,
        wallet_address: str,
        severity: str,
        description: str,
        reasoning: str = "",
        details: dict[str, Any] | None = None,
        tx_hash: str | None = None,
        block_number: int | None = None,
        value_eth: str | None = None,
    ) -> RuleResult:
        """
        Factory for a triggered RuleResult.

        Args:
            wallet_address: The wallet this finding applies to.
            severity:       LOW | MEDIUM | HIGH | CRITICAL.
            description:    Observation — what was detected, in plain language.
            reasoning:      Reasoning — why this observation is forensically
                             significant (the AML/investigative "so what").
                             Defaults to "" for rules not yet updated, but
                             every active rule in this codebase supplies one.
            details:        Evidence — concrete supporting data (counts,
                             thresholds, ratios, etc).
            tx_hash:        Evidence — primary transaction hash, if any.
            block_number:   Evidence — block number, if any.
            value_eth:      Evidence — ETH value, if any.
        """
        return RuleResult(
            rule_id=self.RULE_ID,
            rule_name=self.RULE_NAME,
            rule_category=self.CATEGORY,
            triggered=True,
            severity=severity,
            description=description,
            reasoning=reasoning,
            details=details or {},
            wallet_address=wallet_address,
            tx_hash=tx_hash,
            block_number=block_number,
            value_eth=value_eth,
            detected_at=datetime.now(UTC),
        )

    def _not_triggered(self, wallet_address: str) -> RuleResult:
        """Factory for a non-triggered RuleResult."""
        return RuleResult(
            rule_id=self.RULE_ID,
            rule_name=self.RULE_NAME,
            rule_category=self.CATEGORY,
            triggered=False,
            severity="LOW",
            description="Rule did not trigger.",
            reasoning="",
            wallet_address=wallet_address,
        )
