"""
backend/forensics/risk_scorer.py
─────────────────────────────────────────────────────────────────────────────
Converts forensic rule findings into a numeric risk score (0.0–100.0) and
risk level (LOW / MEDIUM / HIGH / CRITICAL).

SCORING ALGORITHM:
  score = sum(severity_weight × count) for each severity bucket
  score = clamp(score, 0, 100)

  Weights (from settings):
    CRITICAL = 40 pts/finding
    HIGH     = 20 pts/finding
    MEDIUM   = 10 pts/finding
    LOW      =  5 pts/finding

  Mixer interaction adds a flat 30-point bonus (automatic HIGH/CRITICAL).

THRESHOLDS (from settings):
  CRITICAL  ≥ 80
  HIGH      ≥ 50
  MEDIUM    ≥ 25
  LOW       < 25
"""

from __future__ import annotations

from typing import Any

from backend.forensics.models import ForensicsReport
from backend.utils import clamp


def compute_risk_score(report: ForensicsReport, settings: Any) -> tuple[float, str]:
    """
    Compute a risk score and level from a ForensicsReport.

    Args:
        report:   Aggregated forensics output for one wallet.
        settings: Application settings (risk_scoring sub-model).

    Returns:
        Tuple of (risk_score: float, risk_level: str).
        risk_score is in [0.0, 100.0].
        risk_level is one of: LOW | MEDIUM | HIGH | CRITICAL.
    """
    rs = settings.risk_scoring

    score = (
        report.critical_count * rs.RISK_WEIGHT_CRITICAL
        + report.high_count    * rs.RISK_WEIGHT_HIGH
        + report.medium_count  * rs.RISK_WEIGHT_MEDIUM
        + report.low_count     * rs.RISK_WEIGHT_LOW
    )

    # Mixer interaction: automatic HIGH floor + bonus
    if report.mixer_interaction:
        score += 30.0

    score = clamp(score, 0.0, 100.0)

    if score >= rs.RISK_THRESHOLD_CRITICAL:
        level = "CRITICAL"
    elif score >= rs.RISK_THRESHOLD_HIGH:
        level = "HIGH"
    elif score >= rs.RISK_THRESHOLD_MEDIUM:
        level = "MEDIUM"
    else:
        level = "LOW"

    return round(score, 2), level