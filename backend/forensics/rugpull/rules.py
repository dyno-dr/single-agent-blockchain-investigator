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
  RUG-POST-1  Immediate Liquidity Drain (CP1: latency)         HIGH / CRITICAL
  RUG-POST-2  Treasury Sweep (CP2: withdrawal pattern)         MEDIUM / HIGH / CRITICAL
  RUG-POST-3  Fragmentation / Layering (CP3: outflow CV)       HIGH
  RUG-POST-4  Destination Diversity / Mule Scatter (CP4)       MEDIUM / HIGH / CRITICAL
  RUG-POST-5  Exchange / Mixer Concentration (CP5)             HIGH / CRITICAL
  RUG-POST-6  Swap-before-Cashout / LP Dump (CP6)              HIGH / CRITICAL
  RUG-POST-7  Retained Proceeds Near Zero (CP7)               HIGH / CRITICAL
  RUG-VS-1    Scripted Inbound Value Repetition                HIGH / MEDIUM
  RUG-VS-2    Round-Number Pre-Deploy Funding Pattern          HIGH / MEDIUM
  RUG-VS-3    Gas-Price Uniformity Anomaly                     HIGH / MEDIUM
  RUG-VS-4    Pre-Cashout Wallet Ping Dusting                  HIGH / MEDIUM
  RUG-VS-5    Cross-Deployment Seed Amount Consistency         HIGH / MEDIUM
  RUG-VS-6    Extreme Extraction Multiplier / LP Drain         CRITICAL / HIGH / MEDIUM
  RUG-EXIT-1  Post-Rug Silence / Wallet Abandonment           HIGH / MEDIUM
  RUG-EXIT-2  Reactivation Delay (Burner-Phone Pattern)       CRITICAL / HIGH / MEDIUM
  RUG-EXIT-4  Fresh Wallet Migration / Proxy Hopping          CRITICAL / HIGH

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
# RUG-EXIT-1 — Post-Rug Silence / Wallet Abandonment
# ─────────────────────────────────────────────────────────────────────────────

RULE_ID_EXIT1  = "RUG-EXIT-1"
RULE_NAME_EXIT1 = "Post-Rug Silence / Wallet Abandonment"


def rule_exit1_silence(fv: FeatureVector) -> RugRuleResult:
    """
    Fires when a creator wallet has been completely inactive for an extended
    period after a substantial victim inflow has been extracted.

    KEY DESIGN NOTE — Why cp7_retained_ratio instead of current_balance_wei:
    Using the current wallet balance (eth_getBalance) would require an extra
    API call per wallet and defaults to 0 if the caller forgets to provide it,
    causing is_drained=True on every wallet. cp7_retained_ratio is already
    computed by extract_cashout_features() at zero extra cost and is strictly
    more accurate: it measures deliberate extraction vs. current on-chain state.

    Trigger conditions (requires cp7_retained_ratio to be populated):
      HIGH   (+20 pts): silence > 30 days AND cp7 < 1%  AND silence_ratio > 0.5
      MEDIUM (+10 pts): silence >  7 days AND cp7 < 10%
      NO TRIGGER:       cp7 is None (no victim inflow) OR cp7 >= 10%
    """
    silence_days  = fv.exit1_silence_days
    silence_ratio = fv.exit1_silence_ratio
    cp7           = fv.cp7_retained_ratio

    # Cannot evaluate if silence was not computed or victim inflow is unknown.
    if silence_days is None or cp7 is None:
        return RugRuleResult.not_triggered(RULE_ID_EXIT1, RULE_NAME_EXIT1)

    # If the project retains >= 10% of victim funds, it is not drained.
    if cp7 >= 0.10:
        return RugRuleResult.not_triggered(RULE_ID_EXIT1, RULE_NAME_EXIT1)

    if silence_days > 30 and cp7 < 0.01 and silence_ratio is not None and silence_ratio > 0.5:
        severity = "HIGH"
        desc = (
            f"Wallet has been completely inactive for {silence_days:.0f} days "
            f"({silence_ratio:.0%} of its total lifespan). "
            f"Only {cp7:.2%} of victim inflow remains in the creator ecosystem."
        )
    elif silence_days > 7:
        severity = "MEDIUM"
        desc = (
            f"Wallet has been inactive for {silence_days:.0f} days with "
            f"only {cp7:.2%} of victim inflow remaining."
        )
    else:
        return RugRuleResult.not_triggered(RULE_ID_EXIT1, RULE_NAME_EXIT1)

    return RugRuleResult(
        rule_id=RULE_ID_EXIT1,
        rule_name=RULE_NAME_EXIT1,
        triggered=True,
        severity=severity,
        description=desc,
        reasoning=(
            "After a rugpull, scammers go completely silent to avoid being tracked "
            "and to prevent linking this wallet to their next scam. A wallet that was "
            "intensely active during the deployment and cashout window, but has since "
            "been completely dead with near-zero retained funds, is consistent "
            "exclusively with a scammer who has abandoned their crime scene. "
            "A legitimate startup always retains runway and continues paying operational "
            "costs — there is no legitimate reason for total inactivity after full extraction."
        ),
        details={
            "silence_days":           silence_days,
            "silence_ratio":          silence_ratio,
            "cp7_retained_ratio":     round(cp7, 6),
            "cp7_retained_pct":       f"{cp7:.4%}",
            "thresholds": {
                "high_silence_days":  30,
                "high_cp7_max":       0.01,
                "high_silence_ratio": 0.5,
                "medium_silence_days": 7,
                "medium_cp7_max":     0.10,
            },
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# RUG-EXIT-2 — Reactivation Delay (Burner-Phone Pattern)
# ─────────────────────────────────────────────────────────────────────────────

RULE_ID_EXIT2  = "RUG-EXIT-2"
RULE_NAME_EXIT2 = "Reactivation Delay (Burner-Phone Pattern)"


def rule_exit2_reactivation(fv: FeatureVector) -> RugRuleResult:
    """
    Fires when the wallet history shows one or more dormancy-reactivation
    cycles — periods of silence > 30 days followed by renewed activity.

    The Reactivation Context Score (RCS) distinguishes innocent long gaps
    (holiday, bear market) from criminal reactivations (first post-gap tx
    deploys a new contract or interacts with a mixer).

    Trigger conditions:
      CRITICAL (+30 pts): dormancy_events >= 2  (serial crime pattern)
      HIGH     (+20 pts): dormancy_events == 1 AND rcs >= 2 (suspicious reactivation)
      MEDIUM   (+10 pts): dormancy_events == 1 AND rcs < 2  (ambiguous gap)
      NO TRIGGER:         dormancy_events == 0
    """
    count = fv.exit2_dormancy_event_count
    rcs   = fv.exit2_reactivation_context_score
    gap   = fv.exit2_max_gap_days

    if count == 0:
        return RugRuleResult.not_triggered(RULE_ID_EXIT2, RULE_NAME_EXIT2)

    if count >= 2:
        severity = "CRITICAL"
        desc = (
            f"Wallet shows {count} distinct dormancy-reactivation cycles "
            f"(longest gap: {gap:.0f} days). Serial crime pattern detected."
        )
    elif rcs >= 2:
        severity = "HIGH"
        desc = (
            f"Wallet reactivated after {gap:.0f} days of silence and immediately "
            f"performed a suspicious action (new contract deployment or mixer interaction). "
            f"Reactivation Context Score: {rcs}."
        )
    else:
        severity = "MEDIUM"
        desc = (
            f"Wallet has one dormancy gap of {gap:.0f} days. "
            f"Reactivation appears benign (RCS={rcs}) but warrants monitoring."
        )

    return RugRuleResult(
        rule_id=RULE_ID_EXIT2,
        rule_name=RULE_NAME_EXIT2,
        triggered=True,
        severity=severity,
        description=desc,
        reasoning=(
            "Serial scammers reuse wallets across multiple rugpulls, operating in "
            "isolated bursts separated by months of dormancy to avoid pattern detection. "
            "Each reactivation is examined for WHAT the wallet did first after waking up: "
            "a legitimate developer resumes normal patterns (paying server costs, governance), "
            "while a scammer's first action is almost always a new contract deployment or "
            "routing funds through a mixer — both of which add to the Reactivation Context Score. "
            "Two or more dormancy cycles is a definitive serial-scammer signature."
        ),
        details={
            "dormancy_event_count":       count,
            "max_gap_days":               gap,
            "reactivation_context_score": rcs,
            "events_detail":              fv.exit2_events_detail,
            "dormancy_threshold_days":    30,
            "rcs_scoring": {
                "+2": "first post-gap tx deploys a new contract (to field empty)",
                "+2": "first post-gap tx interacts with a known mixer address",
            },
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# RUG-EXIT-4 — Fresh Wallet Migration / Proxy Hopping
# ─────────────────────────────────────────────────────────────────────────────

RULE_ID_EXIT4  = "RUG-EXIT-4"
RULE_NAME_EXIT4 = "Fresh Wallet Migration / Proxy Hopping"


def rule_exit4_fresh_migration(fv: FeatureVector) -> RugRuleResult:
    """
    Fires when stolen funds were bulk-transferred to a freshly created wallet.

    A "bulk transfer" is a single outgoing tx moving >= 30% of total victim inflow.
    The destination wallet's age at the time of transfer is key:

    Trigger conditions:
      CRITICAL (+40 pts): youngest destination was < 1 day old at transfer time
      HIGH     (+20 pts): youngest destination was < 7 days old at transfer time
      NO TRIGGER:         all destinations established (>= 7 days) OR
                          no bulk transfers found OR
                          destination ages unknown (cache miss)
    """
    youngest  = fv.exit4_youngest_dest_age_days
    fresh_eth = fv.exit4_total_eth_to_fresh_wallets
    count     = fv.exit4_bulk_transfer_count

    if youngest is None or fresh_eth is None:
        return RugRuleResult.not_triggered(RULE_ID_EXIT4, RULE_NAME_EXIT4)

    if youngest >= 7:
        return RugRuleResult.not_triggered(RULE_ID_EXIT4, RULE_NAME_EXIT4)

    if youngest < 1:
        severity = "CRITICAL"
        desc = (
            f"A bulk transfer ({fresh_eth:.3f} ETH) was routed to a wallet that was "
            f"less than 24 hours old ({youngest:.2f} days) at the time of transfer."
        )
    else:
        severity = "HIGH"
        desc = (
            f"A bulk transfer ({fresh_eth:.3f} ETH) was routed to a wallet that was "
            f"only {youngest:.1f} days old at the time of transfer."
        )

    return RugRuleResult(
        rule_id=RULE_ID_EXIT4,
        rule_name=RULE_NAME_EXIT4,
        triggered=True,
        severity=severity,
        description=desc,
        reasoning=(
            "Routing stolen funds through a freshly created wallet is a deliberate "
            "AML evasion technique. CEX compliance systems flag addresses with known "
            "criminal history. A brand-new wallet has zero taint history, allowing the "
            "scammer to interact with exchange deposit addresses without triggering "
            "compliance alerts. No legitimate business treasury is transferred to a "
            "wallet created hours earlier — this pattern is exclusive to money laundering."
        ),
        details={
            "youngest_dest_age_days":        youngest,
            "total_eth_to_fresh_wallets":    fresh_eth,
            "bulk_transfer_count":           count,
            "bulk_transfer_findings":        fv.exit4_bulk_transfer_findings,
            "bulk_threshold_pct_of_inflow":  "30%",
            "fresh_wallet_max_age_days":     7,
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
        # Pre-deployment behavioural rules
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
        # Post-Exploit Cash-Out rules (POST-1 through POST-7)
        rule_post1_withdrawal_latency(fv),
        rule_post2_treasury_sweep(fv),
        rule_post3_fragmentation(fv),
        rule_post4_destination_diversity(fv),
        rule_post5_exchange_concentration(fv),
        rule_post6_swap_before_cashout(fv),
        rule_post7_retained_proceeds(fv),
        # Value-Transfer Semantics rules (VS-1 through VS-6)
        rule_vs1_repeated_values(fv, cfg),
        rule_vs2_round_funding(fv, cfg),
        rule_vs3_gas_anomaly(fv, cfg),
        rule_vs4_dusting(fv, cfg),
        rule_vs5_cross_deploy_consistency(fv, cfg),
        rule_vs6_extraction_multiplier(fv, cfg),
        # Exit and Dormancy rules (RUG-EXIT-1, RUG-EXIT-2, RUG-EXIT-4)
        rule_exit1_silence(fv),
        rule_exit2_reactivation(fv),
        rule_exit4_fresh_migration(fv),
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


# ─────────────────────────────────────────────────────────────────────────────
# RUG-POST-1 — Immediate Liquidity Drain (CP1)
# ─────────────────────────────────────────────────────────────────────────────

RULE_ID_POST1 = "RUG-POST-1"
RULE_NAME_POST1 = "Immediate Liquidity Drain"


def rule_post1_withdrawal_latency(fv: FeatureVector) -> RugRuleResult:
    """
    Flags projects where the creator withdrew funds almost immediately after
    the first real user deposited.

    Thresholds:
      CRITICAL: < 3,600s  (1 hour)  — automated bot drain
      HIGH:     < 86,400s (24 hours) — same-day rugpull
    """
    latency = fv.cp1_withdrawal_latency_sec
    if latency is None:
        return RugRuleResult.not_triggered(RULE_ID_POST1, RULE_NAME_POST1)

    _CRITICAL_SEC = 3_600
    _HIGH_SEC     = 86_400

    if latency < _CRITICAL_SEC:
        severity = "CRITICAL"
        desc = (
            f"Creator withdrew funds {latency / 60:.1f} minutes after the first "
            f"victim deposit (threshold: < 1 hour = CRITICAL)."
        )
    elif latency < _HIGH_SEC:
        severity = "HIGH"
        desc = (
            f"Creator withdrew funds {latency / 3600:.2f} hours after the first "
            f"victim deposit (threshold: < 24 hours = HIGH)."
        )
    else:
        return RugRuleResult.not_triggered(RULE_ID_POST1, RULE_NAME_POST1)

    return RugRuleResult(
        rule_id=RULE_ID_POST1,
        rule_name=RULE_NAME_POST1,
        triggered=True,
        severity=severity,
        description=desc,
        reasoning=(
            "A legitimate project leaves funds in the contract for ongoing development. "
            "Withdrawing within hours of the first user deposit is exclusively consistent "
            "with a 'smash and grab' exit scam where the scammer was waiting to drain the "
            "moment victim funds arrived. Sub-1-hour latency is characteristic of fully "
            "automated bot-driven rugpulls with no human decision delay."
        ),
        details={
            "withdrawal_latency_seconds": round(latency, 1),
            "withdrawal_latency_hours":   round(latency / 3600, 4),
            "critical_threshold_sec":     _CRITICAL_SEC,
            "high_threshold_sec":         _HIGH_SEC,
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# RUG-POST-2 — Treasury Sweep (CP2)
# ─────────────────────────────────────────────────────────────────────────────

RULE_ID_POST2 = "RUG-POST-2"
RULE_NAME_POST2 = "Treasury Sweep"


def rule_post2_treasury_sweep(fv: FeatureVector) -> RugRuleResult:
    """
    Flags projects where the creator drained a large proportion of all victim
    funds in very few transactions over a short time span.

    Severity matrix (withdrawal_count, drain_ratio, withdrawal_span_hours):
      CRITICAL: count≤2 AND drain>90% AND span<24h  — smash and grab
      HIGH:     count≤2 AND drain>90% AND span≥24h  — slow sweep
      HIGH:     count≤5 AND drain>80%               — near-total drain
      MEDIUM:   drain>90% (any count)               — excessive extraction
    """
    count = fv.cp2_withdrawal_count
    drain = fv.cp2_drain_ratio
    span  = fv.cp2_withdrawal_span_hours

    if count == 0 or drain is None:
        return RugRuleResult.not_triggered(RULE_ID_POST2, RULE_NAME_POST2)

    if count <= 2 and drain > 0.90:
        if span is None or span < 24:
            severity = "CRITICAL"
            label    = "SMASH_AND_GRAB"
            desc = (
                f"Creator drained {drain:.1%} of victim funds in {count} transaction(s) "
                f"spanning {span:.1f} hours. Textbook smash-and-grab exit."
                if span is not None else
                f"Creator drained {drain:.1%} of victim funds in a single transaction."
            )
        else:
            severity = "HIGH"
            label    = "TREASURY_SWEEP"
            desc = (
                f"Creator drained {drain:.1%} of victim funds in {count} transaction(s) "
                f"spanning {span:.1f} hours."
            )
    elif count <= 5 and drain > 0.80:
        severity = "HIGH"
        label    = "NEAR_TOTAL_DRAIN"
        desc = (
            f"Creator made {count} withdrawals totalling {drain:.1%} of all victim funds."
        )
    elif drain > 0.90:
        severity = "MEDIUM"
        label    = "EXCESSIVE_EXTRACTION"
        desc = (
            f"Creator has extracted {drain:.1%} of all victim funds "
            f"across {count} withdrawals."
        )
    else:
        return RugRuleResult.not_triggered(RULE_ID_POST2, RULE_NAME_POST2)

    return RugRuleResult(
        rule_id=RULE_ID_POST2,
        rule_name=RULE_NAME_POST2,
        triggered=True,
        severity=severity,
        description=desc,
        reasoning=(
            "A legitimate project treasury shows gradual, partial withdrawals for "
            "legitimate business expenses — marketing, development, salaries. A rugpull "
            "is distinguished by draining the maximum possible amount in the fewest "
            "possible transactions as fast as possible. High drain ratio with low "
            "withdrawal count and short time span is the mathematical signature of "
            "an intentional exit scam."
        ),
        details={
            "withdrawal_count":        count,
            "drain_ratio":             round(drain, 4) if drain is not None else None,
            "withdrawal_span_hours":   round(span, 2) if span is not None else None,
            "pattern_label":           label,
            "thresholds": {
                "critical_drain_ratio":  0.90,
                "critical_max_count":    2,
                "critical_max_span_hrs": 24,
                "high_drain_ratio":      0.80,
                "high_max_count":        5,
                "medium_drain_ratio":    0.90,
            },
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# RUG-POST-3 — Fragmentation / Layering (CP3)
# ─────────────────────────────────────────────────────────────────────────────

RULE_ID_POST3 = "RUG-POST-3"
RULE_NAME_POST3 = "Withdrawal Fragmentation (Layering)"


def rule_post3_fragmentation(fv: FeatureVector) -> RugRuleResult:
    """
    Flags wallets where outgoing transaction amounts show very low variance
    (uniform amounts = scripted layering) or high round-number concentration
    (all amounts are clean multiples of 0.5 ETH).

    Both conditions indicate an AML evasion technique called structuring or
    smurfing. Requires at least 4 outgoing transactions to be statistically
    meaningful.

    Severity: HIGH for either trigger (no CRITICAL tier — this is a supporting
    signal, not standalone conclusive evidence).
    """
    cv      = fv.cp3_outflow_cv
    rr      = fv.cp3_round_number_ratio
    count   = fv.cp3_outflow_count

    if count < 4:
        return RugRuleResult.not_triggered(RULE_ID_POST3, RULE_NAME_POST3)

    _CV_HIGH  = 0.10
    _RR_HIGH  = 0.80

    uniform_layering = cv is not None and cv < _CV_HIGH
    round_layering   = rr is not None and rr > _RR_HIGH

    if not uniform_layering and not round_layering:
        return RugRuleResult.not_triggered(RULE_ID_POST3, RULE_NAME_POST3)

    reasons = []
    if uniform_layering:
        reasons.append(
            f"Outflow CV = {cv:.4f} (< {_CV_HIGH} threshold): "
            f"amounts are near-identical across {count} transactions."
        )
    if round_layering:
        reasons.append(
            f"Round-number ratio = {rr:.1%} (> {_RR_HIGH:.0%} threshold): "
            f"{rr:.1%} of outflows are clean multiples of 0.5 ETH."
        )

    return RugRuleResult(
        rule_id=RULE_ID_POST3,
        rule_name=RULE_NAME_POST3,
        triggered=True,
        severity="HIGH",
        description=" | ".join(reasons),
        reasoning=(
            "Structuring (or smurfing) is the practice of deliberately breaking up "
            "large fund transfers into many smaller, uniform chunks to evade AML "
            "detection systems at exchanges. A low Coefficient of Variation (CV near 0) "
            "proves a script is sending the exact same amount repeatedly. A high "
            "round-number ratio reveals machine-like precision — real invoices and "
            "vendor payments produce organic, irregular amounts, not clean multiples. "
            "These patterns directly follow the withdrawal of victim funds and indicate "
            "deliberate laundering activity."
        ),
        details={
            "outflow_count":       count,
            "outflow_cv":          round(cv, 4) if cv is not None else None,
            "round_number_ratio":  round(rr, 4) if rr is not None else None,
            "uniform_layering":    uniform_layering,
            "round_layering":      round_layering,
            "thresholds": {
                "cv_high_max":   _CV_HIGH,
                "rr_high_min":   _RR_HIGH,
                "min_tx_count":  4,
            },
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# RUG-POST-4 — Destination Diversity / Mule Scattering (CP4)
# ─────────────────────────────────────────────────────────────────────────────

RULE_ID_POST4 = "RUG-POST-4"
RULE_NAME_POST4 = "Destination Diversity / Mule Wallet Scattering"


def rule_post4_destination_diversity(fv: FeatureVector) -> RugRuleResult:
    """
    Flags wallets that scatter funds to many unique external destinations,
    especially when those destinations are freshly created wallets.

    Known exchanges and DEXs are excluded from the suspicious count. Fresh
    wallet ratio is computed from wallet_age_lookup built in rugpull_tool.py.

    Severity matrix:
      CRITICAL: suspicious≥10 AND fresh_ratio>60% — textbook money mule setup
      HIGH:     suspicious≥7
      MEDIUM:   suspicious≥4
    """
    suspicious = fv.cp4_suspicious_destination_count
    fresh_ratio = fv.cp4_fresh_wallet_ratio

    _CRITICAL_SUSP  = 10
    _CRITICAL_FRESH = 0.60
    _HIGH_SUSP      = 7
    _MEDIUM_SUSP    = 4

    if suspicious < _MEDIUM_SUSP:
        return RugRuleResult.not_triggered(RULE_ID_POST4, RULE_NAME_POST4)

    if suspicious >= _CRITICAL_SUSP and fresh_ratio is not None and fresh_ratio > _CRITICAL_FRESH:
        severity = "CRITICAL"
        desc = (
            f"Funds scattered to {suspicious} unknown destinations, "
            f"{fresh_ratio:.1%} of which are fresh wallets (< 7 days old). "
            f"Classic money mule scattering pattern."
        )
    elif suspicious >= _HIGH_SUSP:
        severity = "HIGH"
        desc = (
            f"Funds sent to {suspicious} unique unknown destinations. "
            f"(Fresh wallet ratio: {fresh_ratio:.1%})"
            if fresh_ratio is not None else
            f"Funds sent to {suspicious} unique unknown destinations."
        )
    else:
        severity = "MEDIUM"
        desc = (
            f"Funds dispersed to {suspicious} unique unknown destinations post-deployment."
        )

    return RugRuleResult(
        rule_id=RULE_ID_POST4,
        rule_name=RULE_NAME_POST4,
        triggered=True,
        severity=severity,
        description=desc,
        reasoning=(
            "A legitimate project sends funds to a small, predictable set of known "
            "destinations (a corporate Coinbase account, a Gnosis Safe, a known payroll "
            "address). Scattering funds to 7+ unknown wallets simultaneously is a "
            "deliberate obfuscation technique called fan-out or scattering. When a large "
            "proportion of those destinations are freshly created wallets (< 7 days old), "
            "they are almost certainly controlled by the same operator — disposable "
            "money mule wallets created specifically to receive and hold stolen funds "
            "while the trail goes cold."
        ),
        details={
            "suspicious_destination_count": suspicious,
            "fresh_wallet_ratio":           round(fresh_ratio, 4) if fresh_ratio is not None else None,
            "thresholds": {
                "critical_suspicious_min": _CRITICAL_SUSP,
                "critical_fresh_ratio":    _CRITICAL_FRESH,
                "high_suspicious_min":     _HIGH_SUSP,
                "medium_suspicious_min":   _MEDIUM_SUSP,
                "fresh_wallet_age_days":   7,
            },
            "note": "Known CEX/DEX addresses are excluded from the suspicious count.",
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# RUG-POST-5 — Exchange / Mixer Concentration (CP5)
# ─────────────────────────────────────────────────────────────────────────────

RULE_ID_POST5 = "RUG-POST-5"
RULE_NAME_POST5 = "Exchange / Mixer Concentration"


def rule_post5_exchange_concentration(fv: FeatureVector) -> RugRuleResult:
    """
    Flags wallets that route a dominant proportion of withdrawn funds directly
    to centralized exchanges (for rapid fiat liquidation) or to privacy mixers
    (to destroy the transaction trail entirely).

    Any mixer contact is CRITICAL regardless of amount.
    CEX concentration > 90% is HIGH.
    """
    conc  = fv.cp5_concentration_ratio
    mixer = fv.cp5_mixer_contact

    if not mixer and (conc is None or conc <= 0.90):
        return RugRuleResult.not_triggered(RULE_ID_POST5, RULE_NAME_POST5)

    if mixer:
        severity = "CRITICAL"
        desc = (
            "Withdrawn funds were routed to a known privacy mixer (e.g. Tornado Cash). "
            f"CEX/Mixer concentration ratio: {conc:.1%}."
            if conc is not None else
            "Withdrawn funds were routed to a known privacy mixer (e.g. Tornado Cash)."
        )
    else:
        severity = "HIGH"
        desc = (
            f"{conc:.1%} of all withdrawn funds were routed directly to centralized "
            f"exchanges. Consistent with rapid liquidation of stolen funds."
        )

    return RugRuleResult(
        rule_id=RULE_ID_POST5,
        rule_name=RULE_NAME_POST5,
        triggered=True,
        severity=severity,
        description=desc,
        reasoning=(
            "A scammer's only goal post-rugpull is to convert the stolen ETH into "
            "untraceable cash as fast as possible. This requires routing through either "
            "a centralized exchange (to sell for fiat) or a privacy mixer (to destroy "
            "the transaction graph). A legitimate project may send 30-50% of funds to "
            "a corporate exchange account for fiat expenses — but never 90%+, and never "
            "to a mixer. Any mixer contact is an absolute red flag: mixers have zero "
            "legitimate business use case in a real project treasury."
        ),
        details={
            "concentration_ratio": round(conc, 4) if conc is not None else None,
            "mixer_contact":       mixer,
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# VS Series — Value-Transfer Semantics Rules (RUG-VS-1 to RUG-VS-6)
# ─────────────────────────────────────────────────────────────────────────────
# These rules operate on VS features computed by extract_vs_features().
# All thresholds are read from RugpullProfileConfig (VS* fields in base.py).
# Thresholds are current hardcoded estimates to be refined via end-of-cycle
# comparative analysis once the full dataset (90 rugpull + 80+ genuine) is run.
# ─────────────────────────────────────────────────────────────────────────────


def rule_vs1_repeated_values(fv: FeatureVector, cfg: Any) -> RugRuleResult:
    """
    RUG-VS-1: Scripted Inbound Value Repetition

    What it checks:
        Calculates what fraction of all inbound ETH transfers share the
        same (modal) value. A human receives money in irregular amounts.
        A script sends exactly the same amount every time it runs.

    Threshold logic:
        mode_freq_ratio >= HIGH  → HIGH severity (strongly scripted)
        mode_freq_ratio >= MED   → MEDIUM severity (partially scripted)

    Data requirement: at least VS1_MIN_TX_COUNT inbound transactions.
    """
    RULE_ID   = "RUG-VS-1"
    RULE_NAME = "Scripted Inbound Value Repetition"

    mode_freq = fv.vs1_mode_freq_ratio
    count     = fv.vs1_inbound_count
    top2      = fv.vs1_top2_coverage

    # Not enough data to be meaningful
    if mode_freq is None or count < cfg.VS1_MIN_TX_COUNT:
        return RugRuleResult.not_triggered(RULE_ID, RULE_NAME)

    if mode_freq >= cfg.VS1_MODE_FREQ_HIGH:
        severity = "HIGH"
        desc = (
            f"Highly repetitive inbound funding: {mode_freq:.1%} of all "
            f"{count} inbound transfers share the same ETH amount. "
            "This is the signature of automated funding scripts."
        )
    elif mode_freq >= cfg.VS1_MODE_FREQ_MEDIUM:
        severity = "MEDIUM"
        desc = (
            f"Moderately repetitive inbound funding: {mode_freq:.1%} of "
            f"{count} inbound transfers share the same ETH amount."
        )
    else:
        return RugRuleResult.not_triggered(RULE_ID, RULE_NAME)

    return RugRuleResult(
        rule_id=RULE_ID,
        rule_name=RULE_NAME,
        triggered=True,
        severity=severity,
        description=desc,
        reasoning=(
            "Legitimate funders transfer variable amounts — payroll, investments, "
            "and personal transfers are inherently irregular in size. A funding "
            "script, on the other hand, is coded to send a fixed amount per run "
            "to make accounting simple. When > 60% of all inbound transfers share "
            "the exact same Wei value, the probability that this is organic human "
            "activity approaches zero. This is the classic signature of a "
            "scripted multi-wallet rugpull funding pipeline."
        ),
        details={
            "mode_freq_ratio":  round(mode_freq, 4),
            "top2_coverage":    round(top2, 4) if top2 is not None else None,
            "inbound_count":    count,
            "thresholds": {
                "high_min":   cfg.VS1_MODE_FREQ_HIGH,
                "medium_min": cfg.VS1_MODE_FREQ_MEDIUM,
                "min_count":  cfg.VS1_MIN_TX_COUNT,
            },
        },
    )


def rule_vs2_round_funding(fv: FeatureVector, cfg: Any) -> RugRuleResult:
    """
    RUG-VS-2: Round-Number Pre-Deploy Funding Pattern

    What it checks:
        Before a creator deploys a contract, they need ETH to cover gas
        and initial liquidity. This rule checks if those pre-deploy inflows
        are suspiciously round (multiples of 0.5 ETH). Scripts are written
        to send clean round numbers; humans send irregular amounts.

    Data requirement: at least VS2_MIN_TX_COUNT pre-deploy inbound transactions.
    """
    RULE_ID   = "RUG-VS-2"
    RULE_NAME = "Round-Number Pre-Deploy Funding Pattern"

    ratio = fv.vs2_round_funding_ratio
    count = fv.vs2_pre_deploy_funding_count

    if ratio is None or count < cfg.VS2_MIN_TX_COUNT:
        return RugRuleResult.not_triggered(RULE_ID, RULE_NAME)

    if ratio >= cfg.VS2_ROUND_RATIO_HIGH:
        severity = "HIGH"
        desc = (
            f"{ratio:.1%} of {count} pre-deployment inflows are exact multiples "
            "of 0.5 ETH. This is a strong scripted funding signature."
        )
    elif ratio >= cfg.VS2_ROUND_RATIO_MEDIUM:
        severity = "MEDIUM"
        desc = (
            f"{ratio:.1%} of {count} pre-deployment inflows are exact multiples "
            "of 0.5 ETH. Partial scripted funding pattern detected."
        )
    else:
        return RugRuleResult.not_triggered(RULE_ID, RULE_NAME)

    return RugRuleResult(
        rule_id=RULE_ID,
        rule_name=RULE_NAME,
        triggered=True,
        severity=severity,
        description=desc,
        reasoning=(
            "Human investors wire amounts based on fiat conversion rates, gas "
            "budgets, and personal preferences — these rarely land on exact "
            "0.5 ETH boundaries. Automation scripts, however, are parameterised "
            "with clean amounts (0.5, 1.0, 1.5 ETH) because the author chose a "
            "round number when writing the script. A high ratio of round-number "
            "pre-deploy inflows indicates the wallet was funded by a script "
            "rather than by organic investors or a human operator."
        ),
        details={
            "round_funding_ratio":     round(ratio, 4),
            "pre_deploy_funding_count": count,
            "thresholds": {
                "high_min":   cfg.VS2_ROUND_RATIO_HIGH,
                "medium_min": cfg.VS2_ROUND_RATIO_MEDIUM,
                "min_count":  cfg.VS2_MIN_TX_COUNT,
            },
        },
    )


def rule_vs3_gas_anomaly(fv: FeatureVector, cfg: Any) -> RugRuleResult:
    """
    RUG-VS-3: Gas-Price Uniformity Anomaly

    What it checks:
        The coefficient of variation (CV = stdev/mean) of gasPrice across
        all outgoing transactions. A script sets a hardcoded gas price —
        it will use exactly the same value (or very close to it) every time.
        A human adjusts gas manually or uses a wallet that picks from a
        live gas estimator, producing natural variation.

    Note on EIP-1559: post-London, gasPrice in Etherscan = maxFeePerGas.
    Effective gas paid varies, but maxFeePerGas is still set by the script
    config and remains uniform across scripted transactions.

    Data requirement: at least VS3_MIN_TX_COUNT outgoing transactions with
    non-zero gasPrice.
    """
    RULE_ID   = "RUG-VS-3"
    RULE_NAME = "Gas-Price Uniformity Anomaly"

    cv         = fv.vs3_cv_gas
    round_gas  = fv.vs3_round_gas_ratio
    gas_count  = fv.vs3_gas_tx_count

    if gas_count < cfg.VS3_MIN_TX_COUNT:
        return RugRuleResult.not_triggered(RULE_ID, RULE_NAME)

    triggered  = False
    severity   = "MEDIUM"
    desc_parts = []

    # CV check: extremely uniform gas price = scripted
    if cv is not None and cv < cfg.VS3_CV_GAS_HIGH:
        triggered = True
        severity  = "HIGH"
        desc_parts.append(
            f"Gas price CV = {cv:.4f} (< {cfg.VS3_CV_GAS_HIGH}) — "
            "nearly identical gasPrice across all outgoing transactions."
        )

    # Round-gas check: integer-Gwei prices are a scripting artifact
    if round_gas is not None and round_gas >= cfg.VS3_ROUND_GAS_RATIO_MEDIUM:
        triggered = True
        desc_parts.append(
            f"{round_gas:.1%} of outgoing txs use integer-Gwei gas prices "
            "(scripted gas configuration)."
        )

    if not triggered:
        return RugRuleResult.not_triggered(RULE_ID, RULE_NAME)

    return RugRuleResult(
        rule_id=RULE_ID,
        rule_name=RULE_NAME,
        triggered=True,
        severity=severity,
        description=" | ".join(desc_parts),
        reasoning=(
            "Gas prices on Ethereum fluctuate constantly. Human users either "
            "manually set gas or use wallet software that reads the current "
            "recommended fee — both produce natural variation over time. A script, "
            "however, typically hardcodes a gasPrice value (e.g., '5000000000' = 5 Gwei) "
            "and reuses it for every transaction. This produces a near-zero CV and "
            "a high ratio of integer-Gwei prices. Both signals indicate automation "
            "rather than manual wallet operation."
        ),
        details={
            "cv_gas":           round(cv, 6) if cv is not None else None,
            "round_gas_ratio":  round(round_gas, 4) if round_gas is not None else None,
            "gas_tx_count":     gas_count,
            "thresholds": {
                "cv_high_max":          cfg.VS3_CV_GAS_HIGH,
                "round_gas_medium_min": cfg.VS3_ROUND_GAS_RATIO_MEDIUM,
                "min_count":            cfg.VS3_MIN_TX_COUNT,
            },
        },
    )


def rule_vs4_dusting(fv: FeatureVector, cfg: Any) -> RugRuleResult:
    """
    RUG-VS-4: Pre-Cashout Wallet Ping Dusting

    What it checks:
        Tiny outbound ETH transfers (< 0.0001 ETH) sent from the creator
        wallet before or during the cashout phase. These 'dust' transactions
        are used to verify that mule wallets are alive and receiving before
        routing the main funds through them.

    Two trigger conditions:
        1. HIGH: >= VS4_DUST_PRE_CASHOUT_HIGH dust txs in 24h before cashout
        2. MEDIUM: >= VS4_DUST_LIFETIME_MEDIUM dust txs over wallet lifetime
    """
    RULE_ID   = "RUG-VS-4"
    RULE_NAME = "Pre-Cashout Wallet Ping Dusting"

    out_dust       = fv.vs4_outbound_dust_count
    pre_dust       = fv.vs4_pre_cashout_dust_count
    unique_targets = fv.vs4_unique_dust_destinations

    if out_dust == 0:
        return RugRuleResult.not_triggered(RULE_ID, RULE_NAME)

    if pre_dust >= cfg.VS4_DUST_PRE_CASHOUT_HIGH:
        severity = "HIGH"
        desc = (
            f"{pre_dust} outbound dust transactions detected in the 24-hour "
            f"window before the first cashout event, targeting "
            f"{unique_targets} distinct address(es). "
            "Classic pre-attack mule wallet probing pattern."
        )
    elif out_dust >= cfg.VS4_DUST_LIFETIME_MEDIUM:
        severity = "MEDIUM"
        desc = (
            f"{out_dust} total outbound dust transactions detected over wallet "
            f"lifetime, targeting {unique_targets} distinct address(es)."
        )
    else:
        return RugRuleResult.not_triggered(RULE_ID, RULE_NAME)

    return RugRuleResult(
        rule_id=RULE_ID,
        rule_name=RULE_NAME,
        triggered=True,
        severity=severity,
        description=desc,
        reasoning=(
            "Before routing stolen funds through a chain of mule wallets, "
            "sophisticated rugpullers send tiny 'ping' amounts (< 0.0001 ETH) "
            "to each mule address to confirm it is active and has not been "
            "blacklisted. This is operationally necessary — a failed transfer "
            "to a dead wallet wastes gas and creates a detectable gap in the "
            "money flow. Legitimate wallets have no operational need to send "
            "sub-dust amounts to multiple fresh wallets in the hours before a "
            "large cash withdrawal event."
        ),
        details={
            "outbound_dust_total":       out_dust,
            "pre_cashout_dust_count":    pre_dust,
            "unique_dust_destinations":  unique_targets,
            "inbound_dust_count":        fv.vs4_inbound_dust_count,
            "dust_threshold_wei":        cfg.VS4_DUST_THRESHOLD_WEI,
            "thresholds": {
                "pre_cashout_high_min":  cfg.VS4_DUST_PRE_CASHOUT_HIGH,
                "lifetime_medium_min":   cfg.VS4_DUST_LIFETIME_MEDIUM,
            },
        },
    )


def rule_vs5_cross_deploy_consistency(fv: FeatureVector, cfg: Any) -> RugRuleResult:
    """
    RUG-VS-5: Cross-Deployment Seed Amount Consistency

    What it checks:
        When a single wallet deploys multiple contracts, compares the set of
        ETH seed amounts (inflows in the 72h window before each deployment)
        across consecutive deployments using Jaccard similarity.

        High similarity = the same script funded each deployment using the
        same amount set = same operator running the same automation.

    Scope: single-wallet only (cross-wallet version requires persistent DB).
    Only fires when the wallet has >= VS5_MIN_DEPLOYMENTS deployments.
    """
    RULE_ID   = "RUG-VS-5"
    RULE_NAME = "Cross-Deployment Seed Amount Consistency"

    jaccard   = fv.vs5_avg_cross_deploy_jaccard
    dep_count = fv.vs5_deployment_count_for_vs5

    if jaccard is None or dep_count < cfg.VS5_MIN_DEPLOYMENTS:
        return RugRuleResult.not_triggered(RULE_ID, RULE_NAME)

    if jaccard >= cfg.VS5_JACCARD_HIGH:
        severity = "HIGH"
        desc = (
            f"Cross-deployment seed amount Jaccard = {jaccard:.3f} across "
            f"{dep_count} deployments. Nearly identical pre-deploy funding "
            "amounts across multiple contracts — same automation script."
        )
    elif jaccard >= cfg.VS5_JACCARD_MEDIUM:
        severity = "MEDIUM"
        desc = (
            f"Moderate cross-deployment seed consistency (Jaccard = {jaccard:.3f} "
            f"across {dep_count} deployments)."
        )
    else:
        return RugRuleResult.not_triggered(RULE_ID, RULE_NAME)

    return RugRuleResult(
        rule_id=RULE_ID,
        rule_name=RULE_NAME,
        triggered=True,
        severity=severity,
        description=desc,
        reasoning=(
            "A repeat rugpull operator running an automated workflow will fund "
            "each deployment the same way: the same seed amounts, from the same "
            "source wallets, in the same proportions. This produces a high Jaccard "
            "similarity between the pre-deployment inflow sets of consecutive "
            "deployments. A legitimate developer who deploys multiple contracts "
            "will fund them with variable amounts depending on the project's needs, "
            "team composition, and funding round — the amounts will not be "
            "mechanically identical across deployments."
        ),
        details={
            "avg_jaccard_similarity":    round(jaccard, 4),
            "deployment_count":          dep_count,
            "thresholds": {
                "high_min":         cfg.VS5_JACCARD_HIGH,
                "medium_min":       cfg.VS5_JACCARD_MEDIUM,
                "min_deployments":  cfg.VS5_MIN_DEPLOYMENTS,
            },
        },
    )


def rule_vs6_extraction_multiplier(fv: FeatureVector, cfg: Any) -> RugRuleResult:
    """
    RUG-VS-6: Extreme Extraction Multiplier + LP Drain Evidence

    What it checks:
        Three overlapping signals about the creator's financial return:

        1. Extraction multiplier: cashout_eth / (deploy_eth + self_fund_eth).
           If a creator invested 0.1 ETH and extracted 10 ETH, their multiplier
           is 100×. Legitimate projects have multipliers of 1×-3× (paying
           themselves back from revenue). Rugpullers have 10×-10000× because
           their cashout includes victim ETH, not project revenue.

        2. LP net drain: ETH removed from Uniswap LP minus ETH added.
           If positive, creator extracted more ETH from the pool than they put
           in — only possible because victims' ETH filled the pool in between.

        3. Token monopoly: creator holds > 90% of total minted token supply
           AND liquidity was added within 1 hour of minting. This is the
           structural setup for a dump-the-supply rugpull.

    Severity:
        CRITICAL: multiplier >= 50× OR (lp_net > 0 AND multiplier >= 10×)
        HIGH:     (lp_net > 0 AND multiplier >= 3×) OR token monopoly + rush
        MEDIUM:   multiplier >= 3× alone (no LP evidence)
    """
    RULE_ID   = "RUG-VS-6"
    RULE_NAME = "Extreme Extraction Multiplier / LP Drain"

    multiplier   = fv.vs6_extraction_multiplier
    lp_net       = fv.vs6_lp_net_eth
    token_frac   = fv.vs6_creator_token_fraction
    mint_lat     = fv.vs6_mint_to_lp_latency_sec

    # Need at least the extraction multiplier to proceed
    if multiplier is None:
        return RugRuleResult.not_triggered(RULE_ID, RULE_NAME)

    lp_drain_confirmed = (lp_net is not None and lp_net > cfg.VS6_MULTIPLIER_MEDIUM * 0)
    # lp_net > 0 means creator took out more than they put in from the LP
    lp_net_positive    = (lp_net is not None and lp_net > 0.0)
    token_monopoly     = (
        token_frac is not None
        and token_frac >= cfg.VS6_TOKEN_FRACTION_HIGH
        and mint_lat is not None
        and mint_lat < cfg.VS6_MINT_TO_LP_RUSH_SEC
    )

    desc_parts = []
    severity   = None

    # CRITICAL conditions
    if multiplier >= cfg.VS6_MULTIPLIER_CRITICAL:
        severity = "CRITICAL"
        desc_parts.append(
            f"Extraction multiplier = {multiplier:.1f}× "
            f"(invested {fv.vs6_v_deploy_eth or 0:.4f} ETH, "
            f"extracted {fv.vs6_v_cashout_eth or 0:.4f} ETH)."
        )
    elif lp_net_positive and multiplier >= cfg.VS6_MULTIPLIER_HIGH:
        severity = "CRITICAL"
        desc_parts.append(
            f"LP net drain = +{lp_net:.4f} ETH confirmed "
            f"(added {fv.vs6_lp_eth_added or 0:.4f} ETH, "
            f"removed {fv.vs6_lp_eth_removed or 0:.4f} ETH) "
            f"with {multiplier:.1f}× extraction multiplier."
        )

    # HIGH conditions (if not already CRITICAL)
    if severity is None:
        if lp_net_positive and multiplier >= cfg.VS6_MULTIPLIER_MEDIUM:
            severity = "HIGH"
            desc_parts.append(
                f"LP net drain = +{lp_net:.4f} ETH with {multiplier:.1f}× multiplier."
            )
        elif token_monopoly:
            severity = "HIGH"
            desc_parts.append(
                f"Token supply monopoly: creator holds {token_frac:.1%} of total "
                f"minted supply, with liquidity added {mint_lat}s after minting "
                f"(rushed deployment)."
            )

    # MEDIUM: multiplier alone, no LP confirmation
    if severity is None and multiplier >= cfg.VS6_MULTIPLIER_MEDIUM:
        severity = "MEDIUM"
        desc_parts.append(
            f"Extraction multiplier = {multiplier:.1f}× "
            f"(no LP drain data available for confirmation)."
        )

    if severity is None:
        return RugRuleResult.not_triggered(RULE_ID, RULE_NAME)

    return RugRuleResult(
        rule_id=RULE_ID,
        rule_name=RULE_NAME,
        triggered=True,
        severity=severity,
        description=" | ".join(desc_parts),
        reasoning=(
            "A legitimate project founder who invests their own ETH and later "
            "withdraws profits expects a modest return (1×-3×) proportional to "
            "the project's real revenue. A rugpuller invests a minimal 'seed' "
            "amount (to make the contract look funded) and then extracts the "
            "entire pool of victim ETH — producing multipliers of 10×-10000×. "
            "LP net drain is the most direct evidence: if the creator removed "
            "more ETH from the Uniswap pool than they added, the surplus came "
            "from victim purchases. Token supply monopoly (holding 90%+ of all "
            "minted tokens) is the structural prerequisite for a token dump — "
            "the creator can sell their tokens into any liquidity that victims "
            "provide, draining the pool completely."
        ),
        details={
            "extraction_multiplier":    round(multiplier, 4),
            "v_deploy_eth":             fv.vs6_v_deploy_eth,
            "v_self_fund_eth":          fv.vs6_v_self_fund_eth,
            "v_cashout_eth":            fv.vs6_v_cashout_eth,
            "lp_eth_added":             fv.vs6_lp_eth_added,
            "lp_eth_removed":           fv.vs6_lp_eth_removed,
            "lp_net_eth":               fv.vs6_lp_net_eth,
            "creator_token_fraction":   fv.vs6_creator_token_fraction,
            "mint_to_lp_latency_sec":   fv.vs6_mint_to_lp_latency_sec,
            "thresholds": {
                "critical_multiplier": cfg.VS6_MULTIPLIER_CRITICAL,
                "high_multiplier":     cfg.VS6_MULTIPLIER_HIGH,
                "medium_multiplier":   cfg.VS6_MULTIPLIER_MEDIUM,
                "token_fraction_high": cfg.VS6_TOKEN_FRACTION_HIGH,
                "mint_lp_rush_sec":    cfg.VS6_MINT_TO_LP_RUSH_SEC,
            },
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# RUG-POST-6 — Swap-before-Cashout / LP Dump (CP6)
# ─────────────────────────────────────────────────────────────────────────────

RULE_ID_POST6 = "RUG-POST-6"
RULE_NAME_POST6 = "Swap-before-Cashout (LP Dump)"


def rule_post6_swap_before_cashout(fv: FeatureVector) -> RugRuleResult:
    """
    Flags the specific sequence of: token withdrawal (or removeLiquidity call)
    followed immediately by a DEX swap — the mechanical fingerprint of a
    liquidity pool rugpull.

    Thresholds:
      CRITICAL: swap within 3,600s (1 hour) of withdrawal — emergency liquidation
      HIGH:     swap within 86,400s (24 hours)             — rapid dump
    """
    if not fv.cp6_swap_detected:
        return RugRuleResult.not_triggered(RULE_ID_POST6, RULE_NAME_POST6)

    latency = fv.cp6_swap_latency_sec

    _CRITICAL_SEC = 3_600
    _HIGH_SEC     = 86_400

    if latency is not None and latency < _CRITICAL_SEC:
        severity = "CRITICAL"
        desc = (
            f"Token withdrawal followed by DEX swap {latency / 60:.1f} minutes later. "
            f"Emergency liquidity pool drain detected."
        )
    else:
        severity = "HIGH"
        desc = (
            f"Token withdrawal followed by DEX swap "
            f"{latency / 3600:.1f} hours later. "
            f"Rapid liquidity dump detected."
            if latency is not None else
            "Token withdrawal followed by DEX swap detected."
        )

    return RugRuleResult(
        rule_id=RULE_ID_POST6,
        rule_name=RULE_NAME_POST6,
        triggered=True,
        severity=severity,
        description=desc,
        reasoning=(
            "DeFi rugpulls frequently involve liquidity pool drains: the scammer "
            "withdraws their own custom token (or calls removeLiquidity) and then "
            "immediately sells it on Uniswap or SushiSwap, which extracts the victims' "
            "real ETH from the liquidity pool. A legitimate project holder has no reason "
            "to market-dump their own token — doing so deliberately crashes their own "
            "token price by 99%. The tight temporal link between the withdrawal event "
            "(function selectors: removeLiquidity, ERC-20 transfer) and the subsequent "
            "DEX router interaction is the on-chain fingerprint of this specific attack."
        ),
        details={
            "swap_detected":        True,
            "swap_latency_seconds": round(latency, 1) if latency is not None else None,
            "swap_latency_hours":   round(latency / 3600, 4) if latency is not None else None,
            "thresholds": {
                "critical_max_sec": _CRITICAL_SEC,
                "high_max_sec":     _HIGH_SEC,
            },
            "detected_selectors": [
                "baa2abde (Uniswap V2 removeLiquidity)",
                "02751cec (Uniswap V2 removeLiquidityETH)",
                "af2979eb (SushiSwap removeLiquidity)",
                "ded9382a (Uniswap V3 decreaseLiquidity)",
                "a9059cbb (ERC-20 transfer)",
            ],
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# RUG-POST-7 — Retained Proceeds Near Zero (CP7)
# ─────────────────────────────────────────────────────────────────────────────

RULE_ID_POST7 = "RUG-POST-7"
RULE_NAME_POST7 = "Abandoned Treasury (Retained Proceeds Near Zero)"


def rule_post7_retained_proceeds(fv: FeatureVector) -> RugRuleResult:
    """
    Flags projects where the creator's ecosystem (project contract + creator
    wallet) retains almost none of the historical victim inflows.

    This is the mathematical proof of project abandonment: a real startup
    always retains significant runway. A rugpuller drains everything to dust.

    Thresholds:
      CRITICAL: retained < 1%
      HIGH:     retained < 10%
    """
    retained = fv.cp7_retained_ratio
    if retained is None:
        return RugRuleResult.not_triggered(RULE_ID_POST7, RULE_NAME_POST7)

    _CRITICAL = 0.01
    _HIGH     = 0.10

    if retained < _CRITICAL:
        severity = "CRITICAL"
        desc = (
            f"Only {retained:.2%} of all historical victim funds remain in the "
            f"creator's ecosystem. Treasury is effectively abandoned."
        )
    elif retained < _HIGH:
        severity = "HIGH"
        desc = (
            f"{retained:.2%} of historical victim funds remain. "
            f"Treasury is severely depleted with no operational runway."
        )
    else:
        return RugRuleResult.not_triggered(RULE_ID_POST7, RULE_NAME_POST7)

    return RugRuleResult(
        rule_id=RULE_ID_POST7,
        rule_name=RULE_NAME_POST7,
        triggered=True,
        severity=severity,
        description=desc,
        reasoning=(
            "A legitimate startup is a business with ongoing costs. Even after "
            "significant vendor payments, real projects retain 40-80% of their "
            "treasury as operational runway for future development milestones. "
            "A rugpuller has no future plans and no legitimate expenses — they drain "
            "everything they possibly can, leaving the contract holding near-zero ETH. "
            "A retained ratio under 1% is conclusive mathematical proof that the "
            "project is dead and the creator extracted all victim funds. This is the "
            "final piece of the post-exploit evidence chain."
        ),
        details={
            "retained_ratio":        round(retained, 6),
            "retained_percentage":   f"{retained:.4%}",
            "thresholds": {
                "critical_max": _CRITICAL,
                "high_max":     _HIGH,
            },
        },
    )

