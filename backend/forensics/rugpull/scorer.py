"""
backend/forensics/rugpull/scorer.py
─────────────────────────────────────────────────────────────────────────────
Scoring and verdict layer for the rugpull creator triage system.

Takes a list of RugRuleResults and the RugpullProfileConfig thresholds and
produces a numeric score (0-100) and a verdict string.

SCORING MODEL:
  Each triggered rule contributes its severity's point value:
    CRITICAL  → SCORE_CRITICAL  (40 pts, reserved for future use)
    HIGH      → SCORE_HIGH      (25 pts)
    MEDIUM    → SCORE_MEDIUM    (10 pts)
    LOW       → SCORE_LOW       (5 pts)

  Score is capped at 100. Verdict is determined by score band:
    CLEAN                   0-15
    WEAK_PATTERN           16-35
    MODERATE_PATTERN       36-65
    STRONG_PATTERN         66-99
    HIGH_CONFIDENCE_RUGPULL ≥ 100 (capped)

OVERRIDE RULE:
  If RUG-NEW-B (ownership transfer) fires → verdict is elevated to at least
  MODERATE_PATTERN regardless of score. Direct ownership-chain evidence
  outweighs probabilistic per-feature scoring.

SINGLE-DEPLOY OVERRIDE:
  If RUG-NEW-A fires and no other HIGH rule fires → verdict is capped at
  INSUFFICIENT_DEPLOYMENT_HISTORY. We cannot make a strong call when F2,
  F4, and F7 are all undefined.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from backend.forensics.rugpull.rules import RugRuleResult


# ─────────────────────────────────────────────────────────────────────────────
# Verdict strings
# ─────────────────────────────────────────────────────────────────────────────

VERDICT_CLEAN = "CLEAN"
VERDICT_WEAK = "WEAK_PATTERN"
VERDICT_MODERATE = "MODERATE_PATTERN"
VERDICT_STRONG = "STRONG_PATTERN"
VERDICT_HIGH_CONFIDENCE = "HIGH_CONFIDENCE_RUGPULL"
VERDICT_INSUFFICIENT = "INSUFFICIENT_DEPLOYMENT_HISTORY"


# ─────────────────────────────────────────────────────────────────────────────
# Score result
# ─────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class RugpullScore:
    """Output of the rugpull scorer."""
    score: int                      # 0-100
    verdict: str                    # one of the VERDICT_* constants
    triggered_rule_ids: list[str]   # IDs of rules that fired
    score_breakdown: dict[str, int] # rule_id → points contributed
    override_applied: str | None    # which override fired (if any)


# ─────────────────────────────────────────────────────────────────────────────
# Scorer
# ─────────────────────────────────────────────────────────────────────────────

_SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def compute_score(results: list[RugRuleResult], cfg: Any) -> RugpullScore:
    """
    Compute a 0-100 rugpull suspicion score from a list of RugRuleResults.

    Args:
        results: All rule results (triggered + not-triggered) from evaluate_all().
        cfg:     RugpullProfileConfig from settings.

    Returns:
        RugpullScore with score, verdict, breakdown, and override info.
    """
    severity_to_points: dict[str, int] = {
        "CRITICAL": cfg.SCORE_CRITICAL,
        "HIGH":     cfg.SCORE_HIGH,
        "MEDIUM":   cfg.SCORE_MEDIUM,
        "LOW":      cfg.SCORE_LOW,
    }

    triggered = [r for r in results if r.triggered]
    breakdown: dict[str, int] = {}
    total = 0

    for r in triggered:
        pts = severity_to_points.get(r.severity, 0)
        breakdown[r.rule_id] = pts
        total += pts

    score = min(total, 100)
    triggered_ids = [r.rule_id for r in triggered]

    # ── Determine base verdict from score band ────────────────────────────────
    if score < cfg.VERDICT_WEAK_MIN:
        verdict = VERDICT_CLEAN
    elif score < cfg.VERDICT_MODERATE_MIN:
        verdict = VERDICT_WEAK
    elif score < cfg.VERDICT_STRONG_MIN:
        verdict = VERDICT_MODERATE
    elif score < cfg.VERDICT_HIGH_CONFIDENCE_MIN:
        verdict = VERDICT_STRONG
    else:
        verdict = VERDICT_HIGH_CONFIDENCE

    override: str | None = None

    # ── Override 0: RUG-FP4 (coordinated cluster) → immediate HIGH_CONFIDENCE ─
    fp4_fired = any(r.rule_id == "RUG-FP4" and r.triggered for r in results)
    if fp4_fired:
        verdict = VERDICT_HIGH_CONFIDENCE
        override = (
            "RUG-FP4 (shared upstream funders) fired — verdict immediately elevated to "
            f"{VERDICT_HIGH_CONFIDENCE}. Structural cross-wallet link is direct evidence "
            "of a coordinated rugpull factory. This overrides all other verdicts."
        )
        return RugpullScore(
            score=max(score, 80),   # Ensure score reflects seriousness
            verdict=verdict,
            triggered_rule_ids=triggered_ids,
            score_breakdown=breakdown,
            override_applied=override,
        )

    # ── Override 1: Ownership transfer → elevate to at least MODERATE ────────
    new_b_fired = any(r.rule_id == "RUG-NEW-B" and r.triggered for r in results)
    if new_b_fired and cfg.RUG_007_CROSS_MATCH_OVERRIDES_VERDICT:
        if _verdict_rank(verdict) < _verdict_rank(VERDICT_MODERATE):
            verdict = VERDICT_MODERATE
            score = max(score, cfg.VERDICT_MODERATE_MIN)
            override = (
                "RUG-NEW-B (ownership transfer) fired — verdict elevated to "
                f"{VERDICT_MODERATE}. Direct ownership-chain evidence."
            )

    # ── Override 2: Single-deploy only, no HIGH rules → INSUFFICIENT ─────────
    new_a_fired = any(r.rule_id == "RUG-NEW-A" and r.triggered for r in results)
    has_high = any(
        r.triggered and r.severity in ("HIGH", "CRITICAL")
        for r in results
        if r.rule_id != "RUG-NEW-A"
    )
    if new_a_fired and not has_high and not new_b_fired:
        verdict = VERDICT_INSUFFICIENT
        override = (
            "RUG-NEW-A fired with no HIGH-severity corroborating rules. "
            "Cannot make a strong call with only 1 deployment — "
            f"verdict set to {VERDICT_INSUFFICIENT}."
        )

    return RugpullScore(
        score=score,
        verdict=verdict,
        triggered_rule_ids=triggered_ids,
        score_breakdown=breakdown,
        override_applied=override,
    )


def _verdict_rank(verdict: str) -> int:
    """Return numeric rank for verdict comparison."""
    return {
        VERDICT_CLEAN: 0,
        VERDICT_INSUFFICIENT: 1,
        VERDICT_WEAK: 2,
        VERDICT_MODERATE: 3,
        VERDICT_STRONG: 4,
        VERDICT_HIGH_CONFIDENCE: 5,
    }.get(verdict, 0)
