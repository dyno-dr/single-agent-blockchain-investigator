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
  RUG-FP1  Mixer/Bridge First Inbound Source               HIGH
  RUG-FP2  High Hop Count from Known Source (≥ 4 hops)     HIGH
  RUG-FP3  High Fraction of Fresh Capital (≥ 50%)          HIGH / CRITICAL
  RUG-FP4  Shared Upstream Funders (coordinated cluster)   CRITICAL
  RUG-FP5  Structuring / Abnormal Seed Size                MEDIUM

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
        # Funding Provenance rules (FP1-FP5)
        rule_fp1_mixer_first_inbound(fv),
        rule_fp2_high_hop_count(fv),
        rule_fp3_fresh_capital(fv),
        rule_fp4_shared_funders(fv),
        rule_fp5_structuring(fv),
    ]


# ─────────────────────────────────────────────────────────────────────────────
# RUG-FP1 — Mixer / Bridge as First Inbound Source
# ─────────────────────────────────────────────────────────────────────────────

RULE_ID_FP1 = "RUG-FP1"
RULE_NAME_FP1 = "Mixer / Bridge First Inbound Source"


def rule_fp1_mixer_first_inbound(fv: FeatureVector) -> RugRuleResult:
    """
    Flags wallets whose very first inbound ETH came from a known mixer
    (e.g. Tornado Cash) or bridge, indicating deliberate money-trail obfuscation.

    Legitimate founders almost always receive their first ETH from a CEX
    withdrawal. Receiving from a mixer is a very strong indicator of intent
    to hide the operator's identity.
    """
    source = fv.fp_first_inbound_source_type
    suspicious_sources = {"MIXER", "FRESH_WALLET"}

    if source not in suspicious_sources:
        return RugRuleResult.not_triggered(RULE_ID_FP1, RULE_NAME_FP1)

    severity = "HIGH" if source == "MIXER" else "MEDIUM"
    return RugRuleResult(
        rule_id=RULE_ID_FP1,
        rule_name=RULE_NAME_FP1,
        triggered=True,
        severity=severity,
        description=(
            f"First inbound ETH to this wallet came from a {source}. "
            f"Legitimate founders almost always receive initial ETH from a CEX withdrawal."
        ),
        reasoning=(
            "The source of a creator wallet's seed capital is a powerful forensic signal. "
            "Centralized exchanges (CEX) perform KYC on withdrawals, creating an identity link. "
            "Receiving seed capital from a mixer (e.g. Tornado Cash) is specifically designed "
            "to sever that identity link. This is a deliberate obfuscation technique strongly "
            "associated with operators who intend to avoid post-rugpull tracing."
        ),
        details={
            "first_inbound_source_type": source,
            "suspicious_sources": list(suspicious_sources),
            "note": "CEX and BRIDGE sources are not flagged; MIXER and FRESH_WALLET are suspicious.",
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# RUG-FP2 — High Hop Count from Known Source
# ─────────────────────────────────────────────────────────────────────────────

RULE_ID_FP2 = "RUG-FP2"
RULE_NAME_FP2 = "High Hop Count from Known Source"


def rule_fp2_high_hop_count(fv: FeatureVector) -> RugRuleResult:
    """
    Flags wallets that are ≥ 4 transaction hops away from any known
    exchange, mixer, or bridge on the funding graph.

    Legitimate wallets are typically 1 hop from a CEX (CEX → creator).
    Sophisticated scammers insert multiple intermediate wallets (peel chains)
    to increase the tracing difficulty. High hop counts are a strong signal.
    """
    hops = fv.fp_min_hops_to_known_source
    if hops is None:
        return RugRuleResult.not_triggered(RULE_ID_FP2, RULE_NAME_FP2)

    _HIGH_HOPS = 4
    if hops < _HIGH_HOPS:
        return RugRuleResult.not_triggered(RULE_ID_FP2, RULE_NAME_FP2)

    severity = "CRITICAL" if hops >= 6 else "HIGH"
    return RugRuleResult(
        rule_id=RULE_ID_FP2,
        rule_name=RULE_NAME_FP2,
        triggered=True,
        severity=severity,
        description=(
            f"Creator wallet is {hops} hops away from the nearest known exchange / "
            f"mixer / bridge on the transaction graph. "
            f"(Threshold: ≥ {_HIGH_HOPS} hops = HIGH, ≥ 6 = CRITICAL)"
        ),
        reasoning=(
            "Legitimate wallets funded from a centralized exchange are 1 hop away. "
            "Sophisticated rugpull operators use 'peel chains' — a series of intermediate "
            "disposable wallets that each pass funds forward — to increase the distance "
            "between themselves and any traceable on/off-ramp. More hops = more deliberate "
            "obfuscation effort = stronger signal of malicious intent."
        ),
        details={
            "min_hops": hops,
            "high_threshold": _HIGH_HOPS,
            "critical_threshold": 6,
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# RUG-FP3 — High Fraction of Seed Capital from Fresh Wallets
# ─────────────────────────────────────────────────────────────────────────────

RULE_ID_FP3 = "RUG-FP3"
RULE_NAME_FP3 = "High Fraction of Seed Capital from Fresh Wallets"


def rule_fp3_fresh_capital(fv: FeatureVector) -> RugRuleResult:
    """
    Flags wallets where more than 50% of pre-deployment seed capital came
    from wallets that were created within the last 48 hours.

    Math (from spec):
        fraction_fresh = fresh_amount / total_seed ∈ [0, 1]
        > 0.5 → HIGH
        > 0.8 → CRITICAL

    Fresh wallets are disposable identities. High fresh-capital fraction
    is a classic money-layering technique to obscure the true funding source.
    """
    frac = fv.fp_fraction_fresh_capital
    if frac is None:
        return RugRuleResult.not_triggered(RULE_ID_FP3, RULE_NAME_FP3)

    _HIGH = 0.50
    _CRITICAL = 0.80

    if frac < _HIGH:
        return RugRuleResult.not_triggered(RULE_ID_FP3, RULE_NAME_FP3)

    severity = "CRITICAL" if frac >= _CRITICAL else "HIGH"
    return RugRuleResult(
        rule_id=RULE_ID_FP3,
        rule_name=RULE_NAME_FP3,
        triggered=True,
        severity=severity,
        description=(
            f"{frac:.1%} of this wallet's pre-deployment seed capital came from "
            f"wallets created within 48 hours of the transfer. "
            f"({'CRITICAL' if frac >= _CRITICAL else 'HIGH'} threshold: "
            f">= {_CRITICAL:.0%} or >= {_HIGH:.0%})"
        ),
        reasoning=(
            "Fresh wallets (created within 48 hours of use) are disposable digital "
            "identities. A high proportion of seed capital from fresh wallets indicates "
            "deliberate creation of throwaway addresses to layer funds and avoid "
            "tracing back to a real identity. This is a classic anti-forensics "
            "'layering' technique used in coordinated rugpull operations."
        ),
        details={
            "fraction_fresh_capital": round(frac, 4),
            "high_threshold": _HIGH,
            "critical_threshold": _CRITICAL,
            "fresh_wallet_window_hours": 48,
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# RUG-FP4 — Shared Upstream Funders (Coordinated Cluster)
# ─────────────────────────────────────────────────────────────────────────────

RULE_ID_FP4 = "RUG-FP4"
RULE_NAME_FP4 = "Shared Upstream Funders (Coordinated Cluster)"


def rule_fp4_shared_funders(fv: FeatureVector) -> RugRuleResult:
    """
    Flags wallets that share upstream funders with other known creator
    wallets in the investigation history database.

    This is the most direct evidence of a coordinated rugpull factory.
    One entity is running multiple rugpull operations using shared funding
    infrastructure. The cross-wallet link is extremely hard to explain
    innocently.

    Becomes more powerful as more wallets are investigated over time.
    """
    if not fv.fp_shared_upstream_funders:
        return RugRuleResult.not_triggered(RULE_ID_FP4, RULE_NAME_FP4)

    return RugRuleResult(
        rule_id=RULE_ID_FP4,
        rule_name=RULE_NAME_FP4,
        triggered=True,
        severity="CRITICAL",
        description=(
            "This creator wallet's upstream funders overlap with funders of "
            "other previously investigated creator wallets. This is direct "
            "structural evidence of a coordinated multi-wallet rugpull operation."
        ),
        reasoning=(
            "Legitimate founders do not share funding sources with other creators — "
            "each startup/project sources its own capital independently. "
            "When two creator wallets share an upstream funder (even several hops removed), "
            "it establishes a structural link between the operators that is extremely "
            "difficult to explain as coincidence. This is the 'fingerprint' of a "
            "rugpull factory where one operator orchestrates many separate scam deployments."
        ),
        details={
            "shared_upstream_funders": True,
            "max_funder_jaccard": fv.fp_max_funder_jaccard,
            "note": (
                "Full shared funder map is stored in the investigation_history.db. "
                "This signal becomes more powerful as more wallets are investigated."
            ),
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# RUG-FP5 — Structuring / Abnormal Seed Size
# ─────────────────────────────────────────────────────────────────────────────

RULE_ID_FP5 = "RUG-FP5"
RULE_NAME_FP5 = "Structuring / Abnormal Seed Amount"


def rule_fp5_structuring(fv: FeatureVector) -> RugRuleResult:
    """
    Flags wallets with structuring-like behaviour: many very small seed
    transactions (instead of one or two normal-sized CEX withdrawals).

    Also flags wallets where the seed amount is suspiciously close to the
    bare minimum needed to cover deployment gas costs (minimum-viable-rugpull).

    Math (from spec):
        Structuring: median_seed < 0.01 ETH AND count > 50
        Undersized:  seed_in_gas_units < 5 × 3,000,000 gas
    """
    med = fv.fp_median_seed_eth
    count = fv.fp_seed_tx_count
    gas_units = fv.fp_standardized_seed_gas_units

    _STRUCTURING_MED = 0.01
    _STRUCTURING_CNT = 50
    _DEPLOY_GAS      = 3_000_000
    _UNDERSIZED_FACTOR = 5

    structuring = (med is not None) and (med < _STRUCTURING_MED) and (count > _STRUCTURING_CNT)
    undersized  = (gas_units is not None) and (gas_units < _UNDERSIZED_FACTOR * _DEPLOY_GAS)

    if not structuring and not undersized:
        return RugRuleResult.not_triggered(RULE_ID_FP5, RULE_NAME_FP5)

    reasons = []
    if structuring:
        reasons.append(
            f"Structuring: {count} seed txs with median size {med:.6f} ETH "
            f"(threshold: < {_STRUCTURING_MED} ETH AND > {_STRUCTURING_CNT} txs)."
        )
    if undersized:
        reasons.append(
            f"Minimum-viable-rugpull: seed of {gas_units:.0f} gas units is less than "
            f"{_UNDERSIZED_FACTOR}× the typical deployment cost ({_DEPLOY_GAS:,} gas)."
        )

    return RugRuleResult(
        rule_id=RULE_ID_FP5,
        rule_name=RULE_NAME_FP5,
        triggered=True,
        severity="MEDIUM",
        description=" ".join(reasons),
        reasoning=(
            "Structuring is the practice of breaking up large fund transfers into many "
            "small ones to avoid detection thresholds — a classic money-laundering "
            "technique (inverse of RUG-002 which detects scripted regular intervals). "
            "A minimum-viable seed (just enough to cover deployment gas) indicates the "
            "operator treats each rugpull as a disposable minimum-cost operation, "
            "consistent with serial automated attackers who minimise per-run investment."
        ),
        details={
            "median_seed_eth": round(med, 8) if med is not None else None,
            "seed_tx_count": count,
            "standardized_seed_gas_units": round(gas_units, 0) if gas_units is not None else None,
            "structuring_flag": structuring,
            "undersized_flag": undersized,
            "thresholds": {
                "structuring_median_eth_max": _STRUCTURING_MED,
                "structuring_count_min": _STRUCTURING_CNT,
                "deploy_gas_units": _DEPLOY_GAS,
                "undersized_factor": _UNDERSIZED_FACTOR,
            },
        },
    )
