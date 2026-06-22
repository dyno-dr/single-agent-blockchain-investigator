"""
backend/forensics/rugpull/rules.py
─────────────────────────────────────────────────────────────────────────────
Individual forensic rules for the rugpull creator triage system.

Each rule takes a FeatureVector and the RugpullProfileConfig thresholds and
returns a RuleResult following the same Observation / Evidence / Reasoning
contract used by the rest of the forensics engine.

RULE REGISTER:
  RUG-001  Burner Wallet (F1: warmup < 15 min)             LOW
  RUG-002  Scripted Funding CV (F2: cv < threshold)        HIGH / MEDIUM
  RUG-003  Dry-Run Activity (F3: dry_run_count ≥ 1)        HIGH / MEDIUM
  RUG-004  High Deployment Volume (F4: count > threshold)  HIGH / MEDIUM
  RUG-005  Scripted Timing (F5: entropy < threshold)       LOW (context)
  RUG-NEW-A Single Deployment Burner Pattern               MEDIUM
  RUG-NEW-B Ownership Transfer Detected (multi-hop hook)   HIGH

FEATURES INTENTIONALLY NOT TRIGGERED:
  F7 within-wallet similarity — hypothesis INVERTED by data (genuine > rugpull).
  F4 burstiness              — hypothesis INVERTED by data (genuine > rugpull).
  F5 nonce entropy           — statistically too weak (Δ = 0.09 bits).

  These are computed in the extractor for narrative reporting only.
"""

from __future__ import annotations

from typing import Any, Optional

from backend.forensics.rugpull.extractor import FeatureVector


# ─────────────────────────────────────────────────────────────────────────────
# Simple result container (avoids circular import with forensics.models)
# ─────────────────────────────────────────────────────────────────────────────

class RugRuleResult:
    """
    Lightweight result for one rugpull rule evaluation.
    Converted to the project-wide RuleResult by RugpullEngine.
    """
    __slots__ = (
        "rule_id", "rule_name", "triggered", "severity",
        "description", "reasoning", "details",
    )

    def __init__(
        self,
        rule_id: str,
        rule_name: str,
        triggered: bool,
        severity: str,
        description: str,
        reasoning: str,
        details: dict[str, Any],
    ) -> None:
        self.rule_id = rule_id
        self.rule_name = rule_name
        self.triggered = triggered
        self.severity = severity
        self.description = description
        self.reasoning = reasoning
        self.details = details

    @classmethod
    def not_triggered(cls, rule_id: str, rule_name: str) -> "RugRuleResult":
        return cls(
            rule_id=rule_id,
            rule_name=rule_name,
            triggered=False,
            severity="LOW",
            description="Rule did not trigger.",
            reasoning="",
            details={},
        )


# ─────────────────────────────────────────────────────────────────────────────
# RUG-001 — Burner Wallet (F1)
# ─────────────────────────────────────────────────────────────────────────────

RULE_ID_001 = "RUG-001"
RULE_NAME_001 = "Extreme Burner Wallet"


def rule_001_burner_wallet(fv: FeatureVector, burner_threshold_hours: float) -> RugRuleResult:
    """
    Flags wallets where the time from first on-chain activity to first
    deployment is extremely short (< 15 minutes by default).

    NOTE: The original hypothesis was that rugpullers have *low* warmup.
    Data showed the opposite (rugpull median 8.75h > genuine 2.94h).
    Only the extreme edge case (< 15 min) is retained as a minor signal
    — this captures wallets created specifically to deploy one contract
    immediately with no history at all.
    """
    if fv.f1_warmup_hours is None:
        return RugRuleResult.not_triggered(RULE_ID_001, RULE_NAME_001)

    if fv.f1_warmup_hours <= burner_threshold_hours:
        return RugRuleResult(
            rule_id=RULE_ID_001,
            rule_name=RULE_NAME_001,
            triggered=True,
            severity="LOW",
            description=(
                f"Wallet deployed a contract within "
                f"{fv.f1_warmup_hours * 60:.1f} minutes of its first on-chain activity."
            ),
            reasoning=(
                "Extremely short warmup time suggests the wallet was created "
                "specifically for this deployment with no prior legitimate history. "
                "This is consistent with a disposable burner wallet pattern, though "
                "it is a weak signal on its own — flag only when combined with others."
            ),
            details={
                "warmup_hours": round(fv.f1_warmup_hours, 4),
                "warmup_minutes": round(fv.f1_warmup_hours * 60, 1),
                "threshold_hours": burner_threshold_hours,
            },
        )

    return RugRuleResult.not_triggered(RULE_ID_001, RULE_NAME_001)


# ─────────────────────────────────────────────────────────────────────────────
# RUG-002 — Scripted Funding CV (F2)
# ─────────────────────────────────────────────────────────────────────────────

RULE_ID_002 = "RUG-002"
RULE_NAME_002 = "Scripted Funding Pattern (Low CV)"


def rule_002_scripted_funding(
    fv: FeatureVector,
    high_cv_max: float,
    medium_cv_max: float,
) -> RugRuleResult:
    """
    Flags wallets where funding arrives at a suspiciously consistent interval
    before each deployment (low Coefficient of Variation of funding lags).

    CV = std / mean. Low CV means same funder always tops up the wallet at
    the same lead time before each deployment — a hallmark of an automated
    deployment pipeline scripted by one operator.

    DATA FINDING: CONFIRMED — ~64% separation. Primary signal in this system.
    Only valid for wallets with 2+ deployments.
    """
    if fv.f2_funding_cv is None:
        return RugRuleResult.not_triggered(RULE_ID_002, RULE_NAME_002)

    if fv.f2_funding_cv <= high_cv_max:
        severity = "HIGH"
        desc = (
            f"Funding CV is {fv.f2_funding_cv:.4f} (<= HIGH threshold {high_cv_max:.4f}). "
            f"Funding arrives at nearly identical intervals before every deployment."
        )
    elif fv.f2_funding_cv <= medium_cv_max:
        severity = "MEDIUM"
        desc = (
            f"Funding CV is {fv.f2_funding_cv:.4f} (<= MEDIUM threshold {medium_cv_max:.4f}). "
            f"Funding timing shows above-average consistency across deployments."
        )
    else:
        return RugRuleResult.not_triggered(RULE_ID_002, RULE_NAME_002)

    return RugRuleResult(
        rule_id=RULE_ID_002,
        rule_name=RULE_NAME_002,
        triggered=True,
        severity=severity,
        description=desc,
        reasoning=(
            "A low Coefficient of Variation (CV) of funding-to-deployment gaps "
            "indicates that the same funder is programmatically topping up this "
            "wallet on a fixed schedule before each contract deployment. Legitimate "
            "developers fund wallets opportunistically; scripted rugpull pipelines "
            "fund wallets on a rigid, automated schedule. Empirically confirmed "
            "as the strongest single pre-deployment signal (~64% separation on "
            "50 rugpull vs 19 genuine wallets)."
        ),
        details={
            "funding_cv": round(fv.f2_funding_cv, 4),
            "high_threshold": high_cv_max,
            "medium_threshold": medium_cv_max,
            "deployment_count": fv.f4_deployment_count,
            "note": "F2 is undefined and never flagged for wallets with <2 deployments.",
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# RUG-003 — Dry-Run Activity (F3)
# ─────────────────────────────────────────────────────────────────────────────

RULE_ID_003 = "RUG-003"
RULE_NAME_003 = "Pre-Deployment Dry-Run Activity"


def rule_003_dry_run(
    fv: FeatureVector,
    high_count: int,
    medium_count: int,
) -> RugRuleResult:
    """
    Flags wallets that sent failed or bytecode-similar transactions in the
    6 hours before deployment — evidence of on-mainnet test deployments.

    v2 parameters (vs v1): similarity threshold 0.40 (was 0.70), window 6h
    (was 1h), per-deployment cap 10. Genuine group max = 0 in v2 dataset;
    rugpull group max = 62.

    NOTE: Both group medians are 0 — most wallets (both groups) test on
    testnets. This rule only fires for unsophisticated actors who test on
    mainnet with real ETH.
    """
    if fv.f3_dry_run_count < medium_count:
        return RugRuleResult.not_triggered(RULE_ID_003, RULE_NAME_003)

    severity = "HIGH" if fv.f3_dry_run_count >= high_count else "MEDIUM"

    return RugRuleResult(
        rule_id=RULE_ID_003,
        rule_name=RULE_NAME_003,
        triggered=True,
        severity=severity,
        description=(
            f"Detected {fv.f3_dry_run_count} dry-run transaction(s) across all "
            f"deployments (transactions with ≥40% bytecode similarity to the "
            f"deployment calldata, or reverted transactions, in the 6h before deploy)."
        ),
        reasoning=(
            "Dry-run transactions before a deployment indicate the operator was "
            "testing their deployment script on Ethereum mainnet rather than on a "
            "testnet or local fork. While sophisticated developers use testnets, "
            "unsophisticated rugpull operators often test directly on mainnet. "
            "The genuine wallet group had a maximum of 0 dry-run transactions "
            "under v2 parameters, making any non-zero count noteworthy."
        ),
        details={
            "dry_run_count": fv.f3_dry_run_count,
            "high_threshold": high_count,
            "medium_threshold": medium_count,
            "detection_params": {
                "jaccard_threshold": 0.40,
                "window_hours": 6,
                "per_deployment_cap": 10,
            },
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# RUG-004 — High Deployment Volume (F4)
# ─────────────────────────────────────────────────────────────────────────────

RULE_ID_004 = "RUG-004"
RULE_NAME_004 = "High Deployment Volume"


def rule_004_deployment_volume(
    fv: FeatureVector,
    high_count: int,
    medium_count: int,
) -> RugRuleResult:
    """
    Flags wallets with an unusually high number of contract deployments.

    NOTE: Burstiness was dropped as a trigger (genuine deployers are MORE
    bursty than rugpull creators). Raw deployment count is used instead as
    a proxy for sustained repeat-operator activity.

    HIGH: ≥ 20 deployments.  MEDIUM: ≥ 10 deployments.
    """
    if fv.f4_deployment_count < medium_count:
        return RugRuleResult.not_triggered(RULE_ID_004, RULE_NAME_004)

    severity = "HIGH" if fv.f4_deployment_count >= high_count else "MEDIUM"

    return RugRuleResult(
        rule_id=RULE_ID_004,
        rule_name=RULE_NAME_004,
        triggered=True,
        severity=severity,
        description=(
            f"Wallet has deployed {fv.f4_deployment_count} contracts "
            f"({'≥'+str(high_count) if fv.f4_deployment_count >= high_count else '≥'+str(medium_count)} threshold)."
        ),
        reasoning=(
            "A high deployment count from a single wallet is consistent with a "
            "sustained, repeat-operator pattern — a wallet used to systematically "
            "deploy multiple token contracts over time. While some legitimate "
            "infrastructure deployers also have high counts, combined with a low "
            "Funding CV (RUG-002) or ownership transfer events (RUG-NEW-B), high "
            "deployment volume significantly elevates suspicion. "
            "Note: burstiness was NOT used because data showed genuine professional "
            "deployers are statistically MORE bursty than rugpull creators."
        ),
        details={
            "deployment_count": fv.f4_deployment_count,
            "burstiness": fv.f4_burstiness,
            "burstiness_note": (
                "Burstiness is reported here for context only. "
                "It is NOT a severity trigger — genuine deployers score higher."
            ),
            "high_threshold": high_count,
            "medium_threshold": medium_count,
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# RUG-005 — Scripted Timing / Nonce Entropy (F5, context only)
# ─────────────────────────────────────────────────────────────────────────────

RULE_ID_005 = "RUG-005"
RULE_NAME_005 = "Highly Scripted Transaction Timing"


def rule_005_scripted_timing(
    fv: FeatureVector,
    scripted_entropy_max: float,
) -> RugRuleResult:
    """
    Flags wallets with extremely low inter-transaction timing entropy.

    DATA FINDING: Groups nearly identical (4.67 vs 4.54 median). This rule
    only fires for entropy < 3.0 (clearly below the rugpull group p25 = 3.85).
    Assigned LOW severity — narrative context only, never standalone evidence.
    """
    if fv.f5_nonce_entropy is None:
        return RugRuleResult.not_triggered(RULE_ID_005, RULE_NAME_005)

    if fv.f5_nonce_entropy >= scripted_entropy_max:
        return RugRuleResult.not_triggered(RULE_ID_005, RULE_NAME_005)

    return RugRuleResult(
        rule_id=RULE_ID_005,
        rule_name=RULE_NAME_005,
        triggered=True,
        severity="LOW",
        description=(
            f"Nonce entropy is {fv.f5_nonce_entropy:.4f} bits, below the "
            f"scripted-timing threshold of {scripted_entropy_max} bits."
        ),
        reasoning=(
            "Very low Shannon entropy of inter-transaction time gaps indicates the "
            "wallet transacts at highly regular, repetitive intervals — a hallmark "
            "of automated scripts rather than human behaviour. "
            "IMPORTANT: This is a LOW-severity context signal only. The rugpull and "
            "genuine groups have nearly identical entropy medians (4.67 vs 4.54), so "
            "this feature alone cannot discriminate between groups. Use as supporting "
            "narrative when other higher-severity rules also fire."
        ),
        details={
            "nonce_entropy_bits": round(fv.f5_nonce_entropy, 4),
            "threshold": scripted_entropy_max,
            "note": (
                "Group medians: rugpull=4.67 bits, genuine=4.54 bits (Δ=0.13). "
                "This rule only fires below the rugpull p25 (3.85 bits)."
            ),
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# RUG-NEW-A — Single Deployment Burner Pattern
# ─────────────────────────────────────────────────────────────────────────────

RULE_ID_NEW_A = "RUG-NEW-A"
RULE_NAME_NEW_A = "Single-Deployment Burner Wallet"


def rule_new_a_single_deploy(
    fv: FeatureVector,
    warmup_max_hours: float,
) -> RugRuleResult:
    """
    Flags single-deployment wallets with a short warmup time.

    54% of the rugpull group had exactly 1 deployment. For these wallets,
    F2 (Funding CV), F4 (deployment count), and F7 (template similarity)
    are all undefined. The combination of:
      - exactly 1 deployment AND
      - warmup < 2h (default)
    is a MEDIUM-severity burner-wallet indicator.
    """
    if not fv.new_a_single_deploy:
        return RugRuleResult.not_triggered(RULE_ID_NEW_A, RULE_NAME_NEW_A)

    # Single deploy alone is not enough — also need short warmup
    warmup = fv.f1_warmup_hours
    if warmup is None or warmup > warmup_max_hours:
        return RugRuleResult.not_triggered(RULE_ID_NEW_A, RULE_NAME_NEW_A)

    return RugRuleResult(
        rule_id=RULE_ID_NEW_A,
        rule_name=RULE_NAME_NEW_A,
        triggered=True,
        severity="MEDIUM",
        description=(
            f"Wallet has exactly 1 deployment and a warmup of "
            f"{warmup * 60:.0f} minutes (threshold: {warmup_max_hours * 60:.0f} minutes). "
            f"Consistent with a disposable single-use burner wallet."
        ),
        reasoning=(
            "54% of confirmed rugpull creator wallets had exactly one deployment. "
            "This 'use-once-discard' pattern makes multi-deployment features (Funding CV, "
            "template similarity) undefined — specifically by design, to avoid detection. "
            "A short warmup time on top of this further reduces the likelihood of a "
            "legitimate developer, who typically uses a wallet with a meaningful history. "
            "Verdict for single-deploy wallets: INSUFFICIENT_DEPLOYMENT_HISTORY — "
            "flag for monitoring, not conclusive evidence."
        ),
        details={
            "deployment_count": 1,
            "warmup_hours": round(warmup, 4),
            "warmup_minutes": round(warmup * 60, 1),
            "warmup_threshold_hours": warmup_max_hours,
            "f2_funding_cv": fv.f2_funding_cv,
            "note": "F2, F4, F7 are undefined for single-deployment wallets.",
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# RUG-NEW-B — Ownership Transfer Hook (multi-hop)
# ─────────────────────────────────────────────────────────────────────────────

RULE_ID_NEW_B = "RUG-NEW-B"
RULE_NAME_NEW_B = "Post-Deployment Ownership Transfer"


def rule_new_b_ownership_transfer(fv: FeatureVector) -> RugRuleResult:
    """
    Flags wallets where at least one deployment was followed by a
    transferOwnership() / setOwner() call within 48 hours.

    Rugpull operators frequently transfer contract ownership to a separate
    wallet immediately after deployment, creating a layer of indirection
    between the deployer and the actual scam operator. This breaks the
    naive "deployer = owner = scammer" assumption.

    This rule also serves as the MULTI-HOP HOOK: the engine reads
    fv.ownership_transfer_targets and queues those addresses for their
    own investigation cycle.
    """
    if fv.ownership_transfer_count == 0:
        return RugRuleResult.not_triggered(RULE_ID_NEW_B, RULE_NAME_NEW_B)

    return RugRuleResult(
        rule_id=RULE_ID_NEW_B,
        rule_name=RULE_NAME_NEW_B,
        triggered=True,
        severity="HIGH",
        description=(
            f"Detected {fv.ownership_transfer_count} ownership transfer(s) "
            f"(transferOwnership / setOwner / changeOwner) within 48h of deployment. "
            f"Target address(es): {fv.ownership_transfer_targets}"
        ),
        reasoning=(
            "Transferring contract ownership immediately after deployment is a common "
            "rugpull operator technique to create a layer of indirection. The deploying "
            "wallet (which may be linked to the operator's identity) hands off control "
            "to a fresh anonymous wallet that performs the eventual rug. "
            "In the v2 dataset, 69 ownership transfer events were detected in rugpull "
            "wallets vs 23 in genuine wallets. "
            "ACTION REQUIRED: The new owner address(es) listed in this finding should "
            "be queued for their own investigation cycle (multi-hop analysis)."
        ),
        details={
            "transfer_count": fv.ownership_transfer_count,
            "transfer_targets": fv.ownership_transfer_targets,
            "detection_selectors": [
                "0xf2fde38b (transferOwnership)",
                "0x13af4035 (setOwner)",
                "0xa6f9dae1 (changeOwner)",
            ],
            "detection_window_hours": 48,
            "multihop_action": "Queue transfer_targets for secondary investigation.",
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# Convenience: run all rules
# ─────────────────────────────────────────────────────────────────────────────

def evaluate_all(fv: FeatureVector, cfg: Any) -> list[RugRuleResult]:
    """
    Run all rugpull rules against a FeatureVector and return every result.
    Non-triggered rules are included so the caller can see the full picture.

    Args:
        fv:  Extracted feature vector for the wallet.
        cfg: RugpullProfileConfig instance from settings.

    Returns:
        List of RugRuleResult (both triggered and not-triggered).
    """
    return [
        rule_001_burner_wallet(fv, cfg.RUG_001_BURNER_THRESHOLD_HOURS),
        rule_002_scripted_funding(fv, cfg.RUG_002_HIGH_CV_MAX, cfg.RUG_002_MEDIUM_CV_MAX),
        rule_003_dry_run(fv, cfg.RUG_003_HIGH_COUNT, cfg.RUG_003_MEDIUM_COUNT),
        rule_004_deployment_volume(fv, cfg.RUG_004_HIGH_DEPLOYMENT_COUNT, cfg.RUG_004_MEDIUM_DEPLOYMENT_COUNT),
        rule_005_scripted_timing(fv, cfg.RUG_005_SCRIPTED_ENTROPY_MAX),
        rule_new_a_single_deploy(fv, cfg.RUG_NEW_A_SINGLE_DEPLOY_WARMUP_MAX_HOURS),
        rule_new_b_ownership_transfer(fv),
    ]
