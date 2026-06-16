"""
backend/forensics/trace_scorer.py
─────────────────────────────────────────────────────────────────────────────
3-layer trace scoring system that ranks which wallets deserve deeper tracing.

PURPOSE:
  Not all outgoing transactions are equally suspicious. This scorer assigns
  a 0–1 priority score to each candidate wallet so the tracer expands
  the most suspicious branches first, even within the node budget.

SCORING LAYERS (weighted sum — weights from settings.trace_scoring):
  1. VALUE layer (weight: 0.3)
     Normalises the transaction value relative to the wallet's largest
     outgoing. High-value transfers (relative to wallet activity) rank higher.

  2. RECENCY layer (weight: 0.2)
     More recent transactions score higher. Suspicious activity tends to
     concentrate near the present. Uses exponential decay with a 90-day half-life.

  3. NOVELTY layer (weight: 0.3)
     Wallets that haven't been seen before in this investigation score higher.
     Re-appearing wallets may be consolidation points but add less new info.

  4. RULE layer (weight: 0.2)
     Wallets that have already triggered forensic rules score higher.
     This feeds back findings from the detector into the tracer.

DESIGN DECISIONS:
  - All layers return values in [0.0, 1.0] before weighting.
  - The final score is a weighted sum in [0.0, 1.0].
  - The weights come from settings.trace_scoring and are validated to sum to 1.
"""

from __future__ import annotations

from datetime import UTC, datetime
import math
from typing import Any

import structlog

from backend.blockchain.models import CleanTransaction

logger = structlog.get_logger(__name__)

_RECENCY_HALF_LIFE_DAYS = 90.0
_MIN_VALUE_ETH = 1e-9  # avoid division by zero


class TraceScorer:
    """
    Scores candidate wallets for multi-hop trace prioritisation.

    Usage:
        scorer = TraceScorer()
        scored = scorer.score_candidates(candidates, context)
    """

    def score(
        self,
        candidate_wallet: str,
        tx: CleanTransaction,
        max_value_eth: float,
        traced_wallets: set[str],
        rule_triggered_wallets: set[str],
        settings: Any,
    ) -> float:
        """
        Compute a priority score [0.0, 1.0] for a candidate wallet.

        Args:
            candidate_wallet:       Address being scored.
            tx:                     Transaction leading to this wallet.
            max_value_eth:          Largest outgoing value in root wallet (for normalisation).
            traced_wallets:         Wallets already traced (for novelty layer).
            rule_triggered_wallets: Wallets where a rule has fired (for rule layer).
            settings:               Application Settings for weight configuration.

        Returns:
            Priority score in [0.0, 1.0]. Higher = trace first.
        """
        weights = settings.trace_scoring
        w_value = weights.value
        w_recency = weights.recency
        w_novelty = weights.novelty
        w_rule = weights.rule

        # Layer 1: VALUE — normalised ETH amount
        value_score = _value_layer(tx.value_eth, max_value_eth)

        # Layer 2: RECENCY — exponential decay from now
        recency_score = _recency_layer(tx.timestamp)

        # Layer 3: NOVELTY — new wallet vs already-seen
        novelty_score = 0.0 if candidate_wallet in traced_wallets else 1.0

        # Layer 4: RULE — did the detector already flag this wallet?
        rule_score = 1.0 if candidate_wallet in rule_triggered_wallets else 0.0

        total = (
            w_value * value_score
            + w_recency * recency_score
            + w_novelty * novelty_score
            + w_rule * rule_score
        )

        logger.debug(
            "trace_scored",
            wallet=candidate_wallet,
            value=round(value_score, 3),
            recency=round(recency_score, 3),
            novelty=novelty_score,
            rule=rule_score,
            total=round(total, 3),
        )

        return total

    def score_and_rank(
        self,
        candidates: list[dict],
        traced_wallets: set[str],
        rule_triggered_wallets: set[str],
        settings: Any,
    ) -> list[dict]:
        """
        Score and rank a list of trace candidates.

        Each candidate dict must have:
            wallet (str), tx (CleanTransaction), max_value_eth (float)

        Returns candidates sorted by score descending (highest priority first),
        with a 'trace_score' key added to each dict.

        Args:
            candidates:             List of candidate dicts.
            traced_wallets:         Already-traced wallets.
            rule_triggered_wallets: Wallets where rules fired.
            settings:               Application settings.

        Returns:
            Sorted list with trace_score populated.
        """
        max_val = max(
            (c.get("tx").value_eth for c in candidates if c.get("tx")),
            default=1.0,
        ) or 1.0

        for c in candidates:
            tx = c.get("tx")
            if tx is None:
                c["trace_score"] = 0.0
                continue
            c["trace_score"] = self.score(
                candidate_wallet=c["wallet"],
                tx=tx,
                max_value_eth=max_val,
                traced_wallets=traced_wallets,
                rule_triggered_wallets=rule_triggered_wallets,
                settings=settings,
            )

        return sorted(candidates, key=lambda c: c.get("trace_score", 0.0), reverse=True)


# ─────────────────────────────────────────────────────────────────────────────
# Layer helpers
# ─────────────────────────────────────────────────────────────────────────────


def _value_layer(value_eth: float, max_value_eth: float) -> float:
    """Normalise ETH value to [0, 1] using log scale."""
    if value_eth <= _MIN_VALUE_ETH or max_value_eth <= _MIN_VALUE_ETH:
        return 0.0
    # Log normalisation: log(v+1) / log(max+1) caps outlier effect
    return min(1.0, math.log1p(value_eth) / math.log1p(max_value_eth))


def _recency_layer(timestamp: datetime) -> float:
    """Exponential decay: recent txs score closer to 1.0."""
    now = datetime.now(UTC)
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=UTC)
    age_days = max(0.0, (now - timestamp).total_seconds() / 86400.0)
    # half-life of 90 days: score = 2^(-age/half_life)
    return math.pow(2.0, -age_days / _RECENCY_HALF_LIFE_DAYS)
