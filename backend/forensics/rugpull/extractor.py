"""
backend/forensics/rugpull/extractor.py
─────────────────────────────────────────────────────────────────────────────
Feature extraction layer for the rugpull creator triage system.

Takes raw Etherscan transaction data (normal txs + internal txs) for a single
wallet and computes the 7 pre-deployment behavioural features (F1-F7) derived
empirically from the v2 threshold analysis script, PLUS the 8 new Funding
Provenance features (FP1-FP8) from the funding graph analysis.

DESIGN:
  - Pure computation: no API calls, no I/O, no side effects.
  - All algorithms are direct ports from revised_rugpull_threshold.py, so
    the feature values produced here exactly match what the threshold script
    used to derive the thresholds stored in RugpullProfileConfig.
  - FeatureVector is a frozen Pydantic model so it can be safely passed
    between LangGraph nodes and serialised to the DB.

FEATURE REFERENCE:
  F1  warmup_hours               — hours from first on-chain activity → first deployment
  F2  funding_cv                 — CV of funding-lag gaps across deployments
  F3  dry_run_count              — bytecode-similar / reverted txs before deployment
  F4  deployment_count           — total deployments from this wallet
  F4b burstiness                 — Goh-Barabási B (narrative only, not a trigger)
  F5  nonce_entropy              — Shannon entropy of inter-tx gaps (narrative only)
  F7  within_wallet_sim          — avg pairwise Levenshtein of setup sequences
  new_a_single_deploy            — wallet has exactly 1 deployment (burner flag)
  ownership_transfer_count       — deployments followed by transferOwnership() in 48h
  all_funding_sources            — unique funder addresses (for NEW-B runtime check)
  deployment_setup_sequences     — raw sequences for cross-wallet F7 DB comparison

NEW FUNDING PROVENANCE FEATURES (FP1-FP8):
  fp_first_inbound_source_type   — CEX / MIXER / BRIDGE / FRESH_WALLET / EOA
  fp_min_hops_to_known_source    — shortest path on tx graph to CEX/mixer/bridge
  fp_fraction_fresh_capital      — % of seed ETH from <48h-old wallets
  fp_funding_entropy_norm        — Shannon entropy of funding source categories
  fp_median_seed_eth             — median seed tx size (structuring detection)
  fp_seed_tx_count               — count of seed transactions
  fp_standardized_seed_gas_units — seed amount / gas_price (gas-relative)
  fp_shared_upstream_funders     — bool: shares funders with known scam wallets
  fp_max_funder_jaccard          — max Jaccard similarity with any known scammer
"""

from __future__ import annotations

import math
import statistics
from collections import Counter
from typing import Optional

from pydantic import BaseModel, Field


# ─────────────────────────────────────────────────────────────────────────────
# Constants (must match revised_rugpull_threshold.py and RugpullProfileConfig)
# ─────────────────────────────────────────────────────────────────────────────

_WINDOW_72H = 72 * 3600
_WINDOW_48H = 48 * 3600
_WINDOW_24H = 24 * 3600

# F3 revised parameters (v2) — must match RUG_003_* in RugpullProfileConfig
_F3_SIMILARITY_THRESHOLD = 0.40
_F3_WINDOW_SEC = 6 * 3600
_F3_MAX_CAP = 10

# Ownership transfer selectors (transferOwnership / setOwner / changeOwner)
_TRANSFER_OWNERSHIP_SELECTORS: frozenset[str] = frozenset({
    "0xf2fde38b",   # transferOwnership(address) — OpenZeppelin standard
    "0x13af4035",   # setOwner(address)
    "0xa6f9dae1",   # changeOwner(address)
})


# ─────────────────────────────────────────────────────────────────────────────
# Output model
# ─────────────────────────────────────────────────────────────────────────────

class FeatureVector(BaseModel):
    """
    All extracted features for one deployer wallet.

    None values indicate the feature is undefined for this wallet (e.g. F2 is
    undefined when there are fewer than 2 deployments). Rules must never flag
    a None feature.
    """

    model_config = {"frozen": True}

    wallet_address: str

    # ── F1 ────────────────────────────────────────────────────────────────────
    f1_warmup_hours: Optional[float] = None

    # ── F2 ────────────────────────────────────────────────────────────────────
    f2_funding_cv: Optional[float] = None

    # ── F3 ────────────────────────────────────────────────────────────────────
    f3_dry_run_count: int = 0

    # ── F4 ────────────────────────────────────────────────────────────────────
    f4_deployment_count: int = 0
    f4_burstiness: Optional[float] = None   # narrative only

    # ── F5 ────────────────────────────────────────────────────────────────────
    f5_nonce_entropy: Optional[float] = None   # narrative only

    # ── F7 ────────────────────────────────────────────────────────────────────
    f7_within_wallet_sim: Optional[float] = None   # narrative only

    # ── NEW-A ─────────────────────────────────────────────────────────────────
    new_a_single_deploy: bool = False

    # ── Multi-hop hook ────────────────────────────────────────────────────────
    ownership_transfer_count: int = 0
    # addresses to queue for secondary investigation (one per deployment)
    ownership_transfer_targets: list[str] = Field(default_factory=list)

    # ── NEW-B runtime data ────────────────────────────────────────────────────
    # Unique funder addresses across all deployments (checked at runtime vs DB)
    all_funding_sources: list[str] = Field(default_factory=list)

    # ── F7 cross-wallet runtime data ──────────────────────────────────────────
    # Raw selector sequences per deployment (stored in DB for cross-wallet F7)
    deployment_setup_sequences: list[list[str]] = Field(default_factory=list)

    # ── Funding Provenance Features (FP1-FP8) ────────────────────────────────
    # FP1 — First inbound source type
    fp_first_inbound_source_type: str = "UNKNOWN_EOA"

    # FP2 — Hops from nearest known exchange / mixer / bridge
    fp_min_hops_to_known_source: Optional[int] = None

    # FP3 — Fraction of seed capital from fresh wallets (<48h old)
    fp_fraction_fresh_capital: Optional[float] = None

    # FP5 — Normalised Shannon entropy of funding source categories [0, 1]
    fp_funding_entropy_norm: Optional[float] = None

    # FP6a — Median seed transaction size in ETH
    fp_median_seed_eth: Optional[float] = None

    # FP6a (count) — Number of seed transactions (for structuring detection)
    fp_seed_tx_count: int = 0

    # FP6b — Seed amount expressed in gas units (gas-relative normalisation)
    fp_standardized_seed_gas_units: Optional[float] = None

    # FP8 — Boolean: creator shares upstream funders with known scam wallets
    fp_shared_upstream_funders: bool = False

    # FP4 — Max Jaccard similarity of funder sets vs any known scam creator
    fp_max_funder_jaccard: Optional[float] = None

    # ── Post-Exploit Cash-Out Features (CP1-CP7) ─────────────────────────────
    # CP1 — Latency: seconds from first victim inflow to first creator outflow
    cp1_withdrawal_latency_sec: Optional[float] = None

    # CP2 — Staged withdrawals: count, drain ratio, time span of extraction
    cp2_withdrawal_count: int = 0
    cp2_drain_ratio: Optional[float] = None
    cp2_withdrawal_span_hours: Optional[float] = None

    # CP3 — Fragmentation: CV of outflow amounts + round-number ratio
    cp3_outflow_cv: Optional[float] = None
    cp3_round_number_ratio: Optional[float] = None
    cp3_outflow_count: int = 0

    # CP4 — Destination diversity: suspicious unique destinations + fresh ratio
    cp4_suspicious_destination_count: int = 0
    cp4_fresh_wallet_ratio: Optional[float] = None

    # CP5 — Exchange / Mixer concentration ratio
    cp5_concentration_ratio: Optional[float] = None
    cp5_mixer_contact: bool = False

    # CP6 — Swap-before-cashout: detected flag + seconds between withdraw and DEX
    cp6_swap_detected: bool = False
    cp6_swap_latency_sec: Optional[float] = None

    # CP7 — Retained proceeds: fraction of victim inflow still in creator ecosystem
    cp7_retained_ratio: Optional[float] = None

    # ── CP-AUX — Auxiliary cashout field exposed for downstream EXIT-4 use ──────
    # total_victim_wei is computed internally by extract_cashout_features().
    # Exposed here so exit_features.py can use it as a bulk-transfer threshold
    # without recomputing it or making any extra API calls.
    cp_victim_inflow_wei: Optional[int] = None

    # ── Value-Transfer Semantics Features (VS1-VS6) ───────────────────────────
    # All VS fields default to None / 0 / False so callers that do not invoke
    # extract_vs_features() continue to work without any code changes.
    # Populated by extract_vs_features() which is called separately from
    # extract_cashout_features() in the engine's run() pipeline.

    # VS1 — Repeated identical-value inbound transfers
    # Detects scripted funding: the same ETH amount repeated many times into wallet.
    # mode_freq_ratio = count(most_common_value) / total_inbound_count
    vs1_mode_freq_ratio: Optional[float] = None
    vs1_top2_coverage: Optional[float] = None    # top-2 most common values / total
    vs1_inbound_count: int = 0

    # VS2 — Round-number funding pattern (pre-deploy window only)
    # Checks if pre-deployment inflows come in clean multiples of 0.5 ETH.
    # Applied exclusively BEFORE first deployment timestamp.
    vs2_round_funding_ratio: Optional[float] = None  # fraction that are mod 0.5 ETH == 0
    vs2_pre_deploy_funding_count: int = 0

    # VS3 — Gas-price anomalies (outgoing transactions only)
    # Low CV of gasPrice across outgoing txs = script hardcoded gas = not a human.
    # Caveat: post-EIP1559 gasPrice = maxFeePerGas (approximation, signal still valid).
    vs3_cv_gas: Optional[float] = None           # stdev(gasPrice) / mean(gasPrice)
    vs3_round_gas_ratio: Optional[float] = None  # fraction with integer-Gwei gasPrice
    vs3_gas_tx_count: int = 0

    # VS4 — Dusting frequency
    # Outbound sub-threshold ETH 'pings' to test if mule wallets are alive.
    # Dust threshold: < 0.0001 ETH (10^14 Wei). Inbound dust is informational only.
    vs4_outbound_dust_count: int = 0
    vs4_pre_cashout_dust_count: int = 0      # dust sent in 24h window before cashout
    vs4_unique_dust_destinations: int = 0   # distinct addresses pinged
    vs4_inbound_dust_count: int = 0         # informational — not a score trigger

    # VS5 — Cross-deployment amount consistency (single-wallet, multi-deploy)
    # Jaccard similarity of pre-deploy funding amount sets across deployments.
    # Only computed when wallet has >= 2 deployments.
    vs5_avg_cross_deploy_jaccard: Optional[float] = None
    vs5_deployment_count_for_vs5: int = 0   # deployments included in this analysis

    # VS6 — Lifecycle allocation ratio + LP operation accounting
    # Core ETH accounting: how much the creator put in vs. extracted.
    vs6_v_deploy_eth: Optional[float] = None       # ETH attached to deployment tx(s)
    vs6_v_self_fund_eth: Optional[float] = None    # ETH creator sent into own contract
    vs6_v_cashout_eth: Optional[float] = None      # ETH extracted from contract by creator
    vs6_extraction_multiplier: Optional[float] = None  # cashout / (deploy + self_fund)
    # LP operation metrics — Uniswap selectors from normal_txs (0 extra API calls)
    vs6_lp_eth_added: Optional[float] = None       # ETH creator added to any DEX LP
    vs6_lp_eth_removed: Optional[float] = None     # ETH creator removed from any DEX LP
    vs6_lp_net_eth: Optional[float] = None         # removed − added (positive = net drain)
    # Minting metrics — from tokentx endpoint (optional, 1 extra API call)
    vs6_creator_token_fraction: Optional[float] = None  # creator's share of all minted supply
    vs6_mint_to_lp_latency_sec: Optional[int] = None    # seconds: first mint → first addLiquidity

    # ── Exit and Dormancy Features (RUG-EXIT-1, EXIT-2, EXIT-4, EXIT-META) ───────
    # Populated by extract_exit_features() called at Step 3.6 in engine.py.
    # None values mean the feature is undefined for this wallet.
    # Rules must never flag a None field.
    #
    # NOTE: No exit1_balance_usd or exit1_is_drained fields.
    # The "drained" check reads cp7_retained_ratio directly from FeatureVector.
    # cp7_retained_ratio is already computed at Step 3 (cashout extractor) with
    # zero extra API calls. Using it avoids the false-positive risk of a
    # current_balance_wei that defaults to 0 when not fetched.

    # EXIT-1 — Post-Rug Silence Duration
    exit1_silence_days: Optional[float] = None
    exit1_silence_ratio: Optional[float] = None   # silence_days / total_lifespan_days

    # EXIT-2 — Reactivation Delay
    exit2_dormancy_event_count: int = 0           # count of gaps > 30 days
    exit2_max_gap_days: Optional[float] = None    # largest single gap in history
    exit2_reactivation_context_score: int = 0     # RCS of the most suspicious event
    exit2_events_detail: list[dict] = Field(default_factory=list)

    # EXIT-4 — Fresh Wallet Migration / Proxy Hopping
    exit4_youngest_dest_age_days: Optional[float] = None
    exit4_total_eth_to_fresh_wallets: Optional[float] = None
    exit4_bulk_transfer_count: int = 0
    exit4_bulk_transfer_findings: list[dict] = Field(default_factory=list)

    # EXIT-META — Retirement Likelihood Score (metadata tag only, never a score trigger)
    exit_meta_retirement_likelihood: Optional[float] = None  # 0.0 to 0.99
    exit_meta_retirement_label: Optional[str] = None         # VERY_LIKELY_RETIRED / etc.

# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────


def _selector(input_data: str) -> Optional[str]:
    """Extract the 4-byte function selector (first 8 hex chars after 0x)."""
    s = input_data.lower()
    if s.startswith("0x"):
        s = s[2:]
    return s[:8] if len(s) >= 8 else None


def _bytecode_jaccard(a: str, b: str, k: int = 4) -> float:
    """
    k-mer Jaccard similarity between two hex strings.
    k=4 → 4-byte (8-hex-char) chunks.  Threshold: F3_SIMILARITY_THRESHOLD.
    """
    def kmers(s: str) -> set:
        s = s.lower().replace("0x", "")
        return {s[i:i + k * 2] for i in range(0, len(s) - k * 2 + 1, k * 2)}

    sa, sb = kmers(a), kmers(b)
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / len(sa | sb)


def _levenshtein_similarity(seq_a: list[str], seq_b: list[str]) -> float:
    """Normalised Levenshtein similarity for two selector sequences. [0, 1]."""
    if not seq_a and not seq_b:
        return 1.0
    if not seq_a or not seq_b:
        return 0.0
    n, m = len(seq_a), len(seq_b)
    dp = list(range(m + 1))
    for i in range(1, n + 1):
        prev = dp[:]
        dp[0] = i
        for j in range(1, m + 1):
            cost = 0 if seq_a[i - 1] == seq_b[j - 1] else 1
            dp[j] = min(dp[j] + 1, dp[j - 1] + 1, prev[j - 1] + cost)
    return 1.0 - (dp[m] / max(n, m))


def _burstiness(timestamps: list[int]) -> Optional[float]:
    """
    Goh-Barabási burstiness: B = (σ - μ) / (σ + μ) on inter-event gaps.
    Range [-1, 1]. Positive = bursty. Requires ≥ 3 events (≥ 2 gaps).
    NOTE: Narrative only — data showed genuine deployers are MORE bursty.
    """
    if len(timestamps) < 3:
        return None
    gaps = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
    mu = statistics.mean(gaps)
    if mu == 0:
        return None
    try:
        sigma = statistics.stdev(gaps)
    except statistics.StatisticsError:
        return None
    denom = sigma + mu
    return (sigma - mu) / denom if denom != 0 else None


def _nonce_entropy(intervals_sec: list[float]) -> Optional[float]:
    """
    Shannon entropy of inter-transaction time gaps, bucketed to nearest minute.
    Low entropy = robotic/scripted. Requires ≥ 3 intervals.
    NOTE: Narrative only — groups too close (4.67 vs 4.54) to use as trigger.
    """
    if len(intervals_sec) < 3:
        return None
    buckets = [round(t / 60) for t in intervals_sec]
    counts = Counter(buckets)
    total = sum(counts.values())
    return -sum((c / total) * math.log2(c / total) for c in counts.values() if c > 0)


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def extract_features(address: str, raw: dict, token_txs: list | None = None) -> FeatureVector:
    """
    Compute the full FeatureVector for one wallet from its raw Etherscan data.

    Args:
        address:    Wallet address (lowercase).
        raw:        Dict with keys "normal_txs" and "internal_txs" — the same
                    structure produced by EtherscanClient in the threshold script
                    and by the main application's blockchain layer.
        token_txs:  Optional list of ERC-20 token transfer events from the
                    Etherscan 'tokentx' endpoint. When provided, VS6 minting
                    metrics (creator_token_fraction, mint_to_lp_latency_sec)
                    are computed. When None, these fields remain None.
                    All other VS features run regardless of token_txs.

    Returns:
        FeatureVector with all fields populated (None where undefined).
    """
    addr = address.lower()
    normal_txs: list[dict] = raw.get("normal_txs", []) or []
    internal_txs: list[dict] = raw.get("internal_txs", []) or []

    # ── 0. First-seen timestamp (includes incoming txs) ──────────────────────
    all_ts: list[int] = []
    for tx in normal_txs + internal_txs:
        try:
            all_ts.append(int(tx["timeStamp"]))
        except (KeyError, ValueError):
            pass
    first_seen_ts: Optional[int] = min(all_ts) if all_ts else None

    # ── 1. Outgoing txs sorted by nonce ──────────────────────────────────────
    outgoing = sorted(
        [tx for tx in normal_txs if tx.get("from", "").lower() == addr],
        key=lambda t: int(t.get("nonce", 0)),
    )

    # ── 2. Nonce intervals for F5 ────────────────────────────────────────────
    out_ts = sorted(int(t["timeStamp"]) for t in outgoing if t.get("timeStamp"))
    nonce_intervals: list[float] = [
        float(out_ts[i + 1] - out_ts[i])
        for i in range(len(out_ts) - 1)
        if out_ts[i + 1] > out_ts[i]
    ]

    # ── 3. Deployment txs ────────────────────────────────────────────────────
    deploy_txs = sorted(
        [
            tx for tx in outgoing
            if tx.get("to") in ("", None)
            and tx.get("contractAddress") not in ("", None)
        ],
        key=lambda t: int(t.get("timeStamp", 0)),
    )

    # ── 4. All inbound ETH (for funding detection) ───────────────────────────
    all_inbound = [
        tx for tx in (normal_txs + internal_txs)
        if tx.get("to", "").lower() == addr
        and int(tx.get("value", "0")) > 0
    ]
    all_funding_sources = list({
        tx.get("from", "").lower()
        for tx in all_inbound
        if tx.get("from", "").lower() not in ("", addr)
    })

    # ─────────────────────────────────────────────────────────────────────────
    # Per-deployment extraction
    # ─────────────────────────────────────────────────────────────────────────
    warmups: list[float] = []
    funding_lags: list[float] = []
    dry_run_total: int = 0
    setup_sequences: list[list[str]] = []
    ownership_targets: list[str] = []

    for dtx in deploy_txs:
        deploy_ts = int(dtx.get("timeStamp", 0))
        deploy_calldata = dtx.get("input", "")

        # F1 — warmup for this deployment
        if first_seen_ts is not None and deploy_ts > 0:
            warmups.append(max(0.0, (deploy_ts - first_seen_ts) / 3600.0))

        # F2 — funding lag: find dominant funder in 72h window, get lag
        window_start = deploy_ts - _WINDOW_72H
        funders_window = [
            tx for tx in all_inbound
            if window_start <= int(tx.get("timeStamp", 0)) < deploy_ts
        ]
        funder_counts = Counter(
            tx.get("from", "").lower() for tx in funders_window
        )
        if funder_counts:
            dominant = funder_counts.most_common(1)[0][0]
            dom_txs = [
                tx for tx in funders_window
                if tx.get("from", "").lower() == dominant
            ]
            if dom_txs:
                latest_fund_ts = max(int(tx.get("timeStamp", 0)) for tx in dom_txs)
                lag = (deploy_ts - latest_fund_ts) / 3600.0
                if lag >= 0:
                    funding_lags.append(lag)

        # F3 — dry-run count (40% Jaccard, 6h window, cap=10)
        f3_window_start = deploy_ts - _F3_WINDOW_SEC
        pre_txs = [
            tx for tx in outgoing
            if f3_window_start <= int(tx.get("timeStamp", 0)) < deploy_ts
            and tx.get("contractAddress") in ("", None)
        ]
        dry_run_this = 0
        for candidate in pre_txs:
            if dry_run_this >= _F3_MAX_CAP:
                break
            is_reverted = candidate.get("isError", "0") == "1"
            sim = _bytecode_jaccard(candidate.get("input", ""), deploy_calldata)
            if is_reverted or sim >= _F3_SIMILARITY_THRESHOLD:
                dry_run_this += 1
        dry_run_total += dry_run_this

        # F7 setup sequence — selectors in 24h before deployment
        setup_window_start = deploy_ts - _WINDOW_24H
        setup_txs = sorted(
            [
                tx for tx in outgoing
                if setup_window_start <= int(tx.get("timeStamp", 0)) < deploy_ts
                and tx.get("contractAddress") in ("", None)
            ],
            key=lambda t: int(t.get("timeStamp", 0)),
        )
        seq = [
            "0x" + s
            for tx in setup_txs
            if (s := _selector(tx.get("input", ""))) is not None
        ]
        setup_sequences.append(seq)

        # Multi-hop — transferOwnership in 48h post-deploy
        post_end = deploy_ts + _WINDOW_48H
        for tx in outgoing:
            if deploy_ts < int(tx.get("timeStamp", 0)) <= post_end:
                sel = _selector(tx.get("input", ""))
                if sel and ("0x" + sel) in _TRANSFER_OWNERSHIP_SELECTORS:
                    raw_input = tx.get("input", "").lower().replace("0x", "")
                    if len(raw_input) >= 72:
                        new_owner = "0x" + raw_input[8 + 24: 8 + 64]
                        if new_owner != addr and len(new_owner) == 42:
                            ownership_targets.append(new_owner)
                            break

    # ─────────────────────────────────────────────────────────────────────────
    # Aggregate feature values
    # ─────────────────────────────────────────────────────────────────────────

    # F1 — minimum warmup across all deployments
    f1 = min(warmups) if warmups else None

    # F2 — CV of funding lags (undefined if < 2 lags)
    f2: Optional[float] = None
    if len(funding_lags) >= 2:
        mu = statistics.mean(funding_lags)
        try:
            sigma = statistics.stdev(funding_lags)
        except statistics.StatisticsError:
            sigma = 0.0
        f2 = (sigma / mu) if mu > 0 else None

    # F4 — deployment count + burstiness
    f4_count = len(deploy_txs)
    deploy_timestamps = sorted(int(dtx.get("timeStamp", 0)) for dtx in deploy_txs)
    f4b = _burstiness(deploy_timestamps)

    # F5 — nonce entropy
    f5 = _nonce_entropy(nonce_intervals)

    # F7 — within-wallet pairwise Levenshtein
    f7: Optional[float] = None
    active_seqs = [s for s in setup_sequences if s]
    if len(active_seqs) >= 2:
        sims = [
            _levenshtein_similarity(active_seqs[i], active_seqs[j])
            for i in range(len(active_seqs))
            for j in range(i + 1, len(active_seqs))
        ]
        f7 = statistics.mean(sims) if sims else None

    return FeatureVector(
        wallet_address=addr,
        f1_warmup_hours=f1,
        f2_funding_cv=f2,
        f3_dry_run_count=dry_run_total,
        f4_deployment_count=f4_count,
        f4_burstiness=f4b,
        f5_nonce_entropy=f5,
        f7_within_wallet_sim=f7,
        new_a_single_deploy=(f4_count == 1),
        ownership_transfer_count=len(ownership_targets),
        ownership_transfer_targets=ownership_targets,
        all_funding_sources=all_funding_sources,
        deployment_setup_sequences=setup_sequences,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Post-Exploit Cash-Out Feature Extraction
# ─────────────────────────────────────────────────────────────────────────────

# Known function selectors for token-related operations (keccak256 ABI-derived)
_REMOVE_LIQUIDITY_SELECTORS: set[str] = {
    "baa2abde",  # Uniswap V2 removeLiquidity()
    "02751cec",  # Uniswap V2 removeLiquidityETH()
    "af2979eb",  # SushiSwap removeLiquidity()
    "ded9382a",  # Uniswap V3 decreaseLiquidity()
}
_TRANSFER_TOKEN_SELECTOR = "a9059cbb"  # ERC-20 transfer(address,uint256)

_ETH = 10 ** 18  # 1 ETH in Wei


def extract_cashout_features(
    normal_txs: list[dict],
    internal_txs: list[dict],
    creator_address: str,
    wallet_age_lookup: dict[str, int | None],
    known_entities: dict[str, dict],
) -> dict:
    """
    Compute the 7 post-exploit cash-out feature fields (CP1-CP7).

    Contract address is derived INTERNALLY from deploy_txs — callers do not
    need to supply it. Returns a dict suitable for:
        fv = fv.model_copy(update=extract_cashout_features(...))

    Args:
        normal_txs:        Etherscan normal transaction list.
        internal_txs:      Etherscan internal transaction list.
        creator_address:   The creator wallet address (any case).
        wallet_age_lookup: {address: first_tx_timestamp | None} — covers
                           both upstream senders and downstream destinations.
        known_entities:    {address_lower: {type: str, ...}} from known_entities.json.
    """
    addr = creator_address.lower()

    # ── 0. Resolve the deployed contract address from the tx list ─────────────
    # Etherscan sets contractAddress on any tx where to=="" (a deployment).
    # We take the FIRST deployment if multiple exist.
    deploy_txs = sorted(
        [tx for tx in normal_txs
         if tx.get("to", "") == "" and tx.get("contractAddress")],
        key=lambda t: int(t.get("timeStamp", 0))
    )
    if not deploy_txs:
        # Not a creator wallet — all CP fields stay at their defaults (None/0/False)
        return {}
    contract_address = deploy_txs[0].get("contractAddress", "").lower()
    deploy_ts = int(deploy_txs[0].get("timeStamp", 0))

    # ── 1. Sort all transactions chronologically ───────────────────────────────
    all_txs_sorted = sorted(
        normal_txs + internal_txs,
        key=lambda t: int(t.get("timeStamp", 0))
    )

    # ── 2. Separate contract interaction streams ───────────────────────────────
    # Victim inflows: ETH sent to the project contract by anyone except creator
    # Creator outflows: ETH leaving the contract back to creator (withdrawals)
    # Creator wallet outflows: ETH sent from creator to external addresses post-deploy
    victim_inflows: list[dict] = []
    contract_to_creator: list[dict] = []   # raw withdrawal events
    creator_post_deploy_out: list[dict] = []  # creator's own outgoing txs post-deploy

    for tx in all_txs_sorted:
        from_a = tx.get("from", "").lower()
        to_a   = tx.get("to", "").lower()
        val    = int(tx.get("value", 0))
        ts     = int(tx.get("timeStamp", 0))

        # Victim inflow into contract
        if to_a == contract_address and from_a != addr and val > 0:
            victim_inflows.append(tx)

        # Withdrawal from contract to creator
        if from_a == contract_address and to_a == addr and val > 0:
            contract_to_creator.append(tx)

        # Creator outgoing (post-deploy, not deployments, not self)
        if (from_a == addr
                and to_a not in ("", None, contract_address)
                and val > 0
                and ts >= deploy_ts
                and tx.get("contractAddress") in ("", None)):
            creator_post_deploy_out.append(tx)

    # ─────────────────────────────────────────────────────────────────────────
    # CP1 — Withdrawal Latency
    # ─────────────────────────────────────────────────────────────────────────
    cp1_latency: Optional[float] = None
    if victim_inflows and contract_to_creator:
        first_inflow_ts  = int(victim_inflows[0].get("timeStamp", 0))
        first_outflow_ts = int(contract_to_creator[0].get("timeStamp", 0))
        delta = first_outflow_ts - first_inflow_ts
        if delta >= 0:
            cp1_latency = float(delta)

    # ─────────────────────────────────────────────────────────────────────────
    # CP2 — Staged Withdrawals
    # ─────────────────────────────────────────────────────────────────────────
    cp2_count     = len(contract_to_creator)
    cp2_drain     = None
    cp2_span_hrs  = None

    total_victim_wei = sum(int(t.get("value", 0)) for t in victim_inflows)
    if total_victim_wei > 0 and contract_to_creator:
        total_withdrawn = sum(int(t.get("value", 0)) for t in contract_to_creator)
        cp2_drain = total_withdrawn / total_victim_wei

        if len(contract_to_creator) >= 2:
            first_w = int(contract_to_creator[0].get("timeStamp", 0))
            last_w  = int(contract_to_creator[-1].get("timeStamp", 0))
            cp2_span_hrs = (last_w - first_w) / 3600.0

    # ─────────────────────────────────────────────────────────────────────────
    # CP3 — Fragmentation / Layering
    # ─────────────────────────────────────────────────────────────────────────
    cp3_cv       = None
    cp3_rr       = None
    cp3_count    = 0

    # Analyse amounts going OUT of creator's wallet post-deploy
    outflow_amounts_wei = [
        int(t.get("value", 0))
        for t in creator_post_deploy_out
        if int(t.get("value", 0)) > 0
    ]
    cp3_count = len(outflow_amounts_wei)

    if cp3_count >= 4:
        amounts_eth = [v / _ETH for v in outflow_amounts_wei]
        mean_eth = statistics.mean(amounts_eth)
        if mean_eth > 0:
            try:
                std_eth = statistics.stdev(amounts_eth)
            except statistics.StatisticsError:
                std_eth = 0.0
            cp3_cv = std_eth / mean_eth

        # Round number check: multiples of 0.5 ETH in ETH space
        round_count = sum(1 for v in amounts_eth if round(v % 0.5, 6) == 0)
        cp3_rr = round_count / len(amounts_eth)

    # ─────────────────────────────────────────────────────────────────────────
    # CP4 — Destination Diversity
    # ─────────────────────────────────────────────────────────────────────────
    cp4_suspicious = 0
    cp4_fresh_ratio = None

    # Unique external destinations from creator post-deploy (exclude own contract)
    unique_dests: dict[str, int] = {}
    for tx in creator_post_deploy_out:
        dest = tx.get("to", "").lower()
        if dest and dest != contract_address:
            unique_dests[dest] = unique_dests.get(dest, 0) + int(tx.get("value", 0))

    if unique_dests:
        total_dests = len(unique_dests)
        known_count = sum(1 for d in unique_dests if d in known_entities)
        cp4_suspicious = max(0, total_dests - known_count)

        # Fresh wallet detection using wallet_age_lookup (pre-populated by rugpull_tool.py)
        fresh_count = 0
        for dest_addr in unique_dests:
            if dest_addr in known_entities:
                continue
            first_ts = wallet_age_lookup.get(dest_addr)
            if first_ts is not None:
                age_days = (deploy_ts - first_ts) / 86400.0
                if age_days < 7:
                    fresh_count += 1
        cp4_fresh_ratio = fresh_count / total_dests if total_dests > 0 else 0.0

    # ─────────────────────────────────────────────────────────────────────────
    # CP5 — Exchange / Mixer Concentration
    # ─────────────────────────────────────────────────────────────────────────
    cp5_conc    = None
    cp5_mixer   = False

    total_out_wei      = sum(int(t.get("value", 0)) for t in creator_post_deploy_out)
    cex_mixer_out_wei  = 0

    for tx in creator_post_deploy_out:
        dest = tx.get("to", "").lower()
        val  = int(tx.get("value", 0))
        if val <= 0:
            continue
        entity = known_entities.get(dest)
        if entity:
            etype = entity.get("type", "")
            if etype in ("CEX", "MIXER"):
                cex_mixer_out_wei += val
            if etype == "MIXER":
                cp5_mixer = True

    if total_out_wei > 0:
        cp5_conc = cex_mixer_out_wei / total_out_wei

    # ─────────────────────────────────────────────────────────────────────────
    # CP6 — Swap-before-Cashout (Liquidity Dump)
    # ─────────────────────────────────────────────────────────────────────────
    cp6_detected   = False
    cp6_latency_s  = None

    token_withdraw_ts: Optional[int] = None

    for tx in all_txs_sorted:
        from_a     = tx.get("from", "").lower()
        to_a       = tx.get("to", "").lower()
        inp        = tx.get("input", "").lower().lstrip("0x")
        ts         = int(tx.get("timeStamp", 0))
        sel        = inp[:8] if len(inp) >= 8 else ""

        # Detect token withdrawal event from creator (removeLiquidity or ERC-20 transfer)
        if from_a == addr and ts >= deploy_ts:
            if sel in _REMOVE_LIQUIDITY_SELECTORS or sel == _TRANSFER_TOKEN_SELECTOR:
                if token_withdraw_ts is None:
                    token_withdraw_ts = ts

        # Detect subsequent DEX interaction
        if token_withdraw_ts is not None and from_a == addr:
            entity = known_entities.get(to_a)
            if entity and entity.get("type", "") in ("DEX_ROUTER", "DEX"):
                time_diff = ts - token_withdraw_ts
                if 0 <= time_diff < 86400:  # within 24h
                    cp6_detected   = True
                    cp6_latency_s  = float(time_diff)
                    break  # first occurrence is the most relevant

    # ─────────────────────────────────────────────────────────────────────────
    # CP7 — Retained Proceeds
    # ─────────────────────────────────────────────────────────────────────────
    cp7_retained = None

    if total_victim_wei > 0:
        ecosystem_balance = 0

        for tx in all_txs_sorted:
            from_a = tx.get("from", "").lower()
            to_a   = tx.get("to", "").lower()
            val    = int(tx.get("value", 0))

            # Money entering the ecosystem FROM external addresses only.
            # Internal moves (contract -> creator) must NOT be counted again
            # because the ETH was already counted when the victim deposited it.
            is_external_source = from_a not in (contract_address, addr)
            if to_a in (contract_address, addr) and is_external_source and val > 0:
                ecosystem_balance += val

            # Money leaving the ecosystem subtracts.
            # Excludes internal ecosystem moves (addr -> contract, contract -> addr).
            if (from_a in (contract_address, addr)
                    and to_a not in (contract_address, addr)
                    and val > 0):
                ecosystem_balance -= val
                # Subtract gas cost (gasUsed * gasPrice) for accuracy
                gas_used  = int(tx.get("gasUsed", 0))
                gas_price = int(tx.get("gasPrice", 0))
                ecosystem_balance -= gas_used * gas_price

        balance = max(0, ecosystem_balance)
        cp7_retained = balance / total_victim_wei

    # ─────────────────────────────────────────────────────────────────────────
    # Return as a dict for model_copy(update={...})
    # ─────────────────────────────────────────────────────────────────────────
    return {
        "cp1_withdrawal_latency_sec":      cp1_latency,
        "cp2_withdrawal_count":            cp2_count,
        "cp2_drain_ratio":                 cp2_drain,
        "cp2_withdrawal_span_hours":       cp2_span_hrs,
        "cp3_outflow_cv":                  cp3_cv,
        "cp3_round_number_ratio":          cp3_rr,
        "cp3_outflow_count":               cp3_count,
        "cp4_suspicious_destination_count": cp4_suspicious,
        "cp4_fresh_wallet_ratio":          cp4_fresh_ratio,
        "cp5_concentration_ratio":         cp5_conc,
        "cp5_mixer_contact":               cp5_mixer,
        "cp6_swap_detected":               cp6_detected,
        "cp6_swap_latency_sec":            cp6_latency_s,
        "cp7_retained_ratio":              cp7_retained,
        # Exposed for downstream EXIT-4 use (avoids double computation).
        # total_victim_wei is None-safe: if victim_inflows was empty, it is 0
        # and EXIT-4 will see cp_victim_inflow_wei == 0 and skip gracefully.
        "cp_victim_inflow_wei":            total_victim_wei if total_victim_wei > 0 else None,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Value-Transfer Semantics Feature Extraction (VS1-VS6)
# ─────────────────────────────────────────────────────────────────────────────

# Uniswap V2/V3 function selectors for liquidity operations.
# These are the first 4 bytes (8 hex chars) of the keccak256 of the ABI
# function signature. They live in the 'input' field of normal_txs.
# No extra API call needed — the data is already in the fetched normal_txs.
_ADD_LIQUIDITY_SELECTORS: frozenset[str] = frozenset({
    "f305d719",  # addLiquidityETH(address,uint,uint,uint,address,uint)
    "e8e33700",  # addLiquidity(address,address,uint,uint,uint,uint,address,uint)
    "2f2d783d",  # SushiSwap addLiquidity variant
})

# removeLiquidity selectors are already defined above (_REMOVE_LIQUIDITY_SELECTORS)
# We reuse them for VS6 LP removal detection.
_ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"
_MINIMUM_STAKE_ETH = 0.001   # floor to avoid division-by-zero for zero-investment wallets


def extract_vs_features(
    normal_txs: list[dict],
    internal_txs: list[dict],
    creator_address: str,
    token_txs: list[dict] | None = None,
    cp1_withdrawal_latency_sec: float | None = None,
) -> dict:
    """
    Compute the 6 Value-Transfer Semantics feature groups (VS1-VS6).

    Returns a dict suitable for:
        fv = fv.model_copy(update=extract_vs_features(...))

    Args:
        normal_txs:                  Etherscan normal transaction list.
        internal_txs:                Etherscan internal transaction list.
        creator_address:             The creator wallet address (any case).
        token_txs:                   Optional ERC-20 token transfer events
                                     from Etherscan tokentx endpoint.
                                     When None, minting metrics stay None.
        cp1_withdrawal_latency_sec:  First cashout timestamp reference for
                                     VS4 pre-cashout dust window calculation.
                                     Pass the value already computed by
                                     extract_cashout_features() if available.
    """
    addr = creator_address.lower()
    ETH  = _ETH   # 10^18 Wei per ETH

    # ── 0. Sort all transactions chronologically ───────────────────────────────
    all_txs = sorted(
        normal_txs + internal_txs,
        key=lambda t: int(t.get("timeStamp", 0))
    )

    # ── 0a. Find first deployment timestamp ───────────────────────────────────
    # VS2 needs this to separate pre-deploy vs post-deploy inflows.
    # VS6 needs it to separate self-funding from victim inflows.
    deploy_txs = sorted(
        [tx for tx in normal_txs
         if tx.get("from", "").lower() == addr
         and tx.get("to", "") in ("", None)
         and tx.get("contractAddress") not in ("", None)],
        key=lambda t: int(t.get("timeStamp", 0))
    )
    first_deploy_ts: int | None = (
        int(deploy_txs[0].get("timeStamp", 0)) if deploy_txs else None
    )
    contract_address: str | None = (
        deploy_txs[0].get("contractAddress", "").lower() if deploy_txs else None
    )

    # ── 0b. Partition inbound ETH transactions ────────────────────────────────
    # all_inbound: every tx where creator receives ETH (value > 0)
    # pre_deploy_inbound: only those before first deployment (VS2 scope)
    all_inbound = [
        tx for tx in all_txs
        if tx.get("to", "").lower() == addr
        and tx.get("from", "").lower() != addr
        and int(tx.get("value", 0)) > 0
    ]
    pre_deploy_inbound = (
        [tx for tx in all_inbound
         if int(tx.get("timeStamp", 0)) < first_deploy_ts]
        if first_deploy_ts is not None
        else all_inbound
    )

    # ── 0c. Outgoing normal transactions ──────────────────────────────────────
    outgoing = [
        tx for tx in normal_txs
        if tx.get("from", "").lower() == addr
    ]

    # =========================================================================
    # VS1 — Repeated Identical-Value Transfers
    # =========================================================================
    # We look at ALL inbound transactions (not just pre-deploy) because
    # scripted funding can happen at any point.
    vs1_mode_freq: Optional[float] = None
    vs1_top2: Optional[float] = None
    vs1_count = 0

    if all_inbound:
        inbound_values = [int(tx.get("value", 0)) for tx in all_inbound]
        vs1_count = len(inbound_values)

        if vs1_count >= 2:                      # need at least 2 to have a pattern
            counter = Counter(inbound_values)
            total = vs1_count

            # Mode frequency ratio: how dominant is the single most common value?
            most_common_val, mode_count = counter.most_common(1)[0]
            vs1_mode_freq = mode_count / total

            # Top-2 coverage: are the two most common values dominating?
            top2_pairs = counter.most_common(2)
            top2_sum = sum(c for _, c in top2_pairs)
            vs1_top2 = top2_sum / total

    # =========================================================================
    # VS2 — Round-Number Funding Pattern (pre-deploy inflows only)
    # =========================================================================
    # Check: how many pre-deploy inflows are exact multiples of 0.5 ETH?
    # CRITICAL: modulo must be done in ETH space, not Wei.
    vs2_round_ratio: Optional[float] = None
    vs2_pre_count = len(pre_deploy_inbound)

    if vs2_pre_count >= 2:
        amounts_eth = [int(tx.get("value", 0)) / ETH for tx in pre_deploy_inbound]
        # round(..., 6) prevents floating-point noise from mis-classifying
        # values like 0.4999999999 which should be 0.5 ETH.
        round_count = sum(
            1 for v in amounts_eth
            if round(v % 0.5, 6) == 0.0
        )
        vs2_round_ratio = round_count / vs2_pre_count

    # =========================================================================
    # VS3 — Gas-Price Anomalies (outgoing transactions)
    # =========================================================================
    # Low CV of gasPrice = script hardcoded the value = not a human.
    GWEI = 10 ** 9
    vs3_cv: Optional[float] = None
    vs3_round_gas: Optional[float] = None
    vs3_gas_count = 0

    gas_prices_gwei: list[float] = []
    for tx in outgoing:
        gp = int(tx.get("gasPrice", 0))
        if gp > 0:
            gas_prices_gwei.append(gp / GWEI)

    vs3_gas_count = len(gas_prices_gwei)

    if vs3_gas_count >= 2:
        mean_gas = statistics.mean(gas_prices_gwei)
        if mean_gas > 0:
            try:
                std_gas = statistics.stdev(gas_prices_gwei)
            except statistics.StatisticsError:
                std_gas = 0.0
            vs3_cv = std_gas / mean_gas

        # Integer-Gwei check: gas price is "round" if it's an exact whole Gwei
        # round(..., 4) prevents noise from floating point conversion
        round_gas_count = sum(
            1 for g in gas_prices_gwei
            if round(g % 1.0, 4) == 0.0
        )
        vs3_round_gas = round_gas_count / vs3_gas_count

    # =========================================================================
    # VS4 — Dusting Frequency
    # =========================================================================
    # Dust = outbound transfer where value < 0.0001 ETH (10^14 Wei).
    # These are "alive pings" sent to mule wallets before the main cashout.
    DUST_WEI = 100_000_000_000_000   # 10^14 Wei = 0.0001 ETH

    vs4_out_dust = 0
    vs4_pre_cashout_dust = 0
    vs4_inbound_dust = 0
    dust_dest_set: set[str] = set()

    # Compute the cashout event timestamp for the pre-cashout window.
    # If cp1_withdrawal_latency_sec is available, we need the ABSOLUTE timestamp
    # of the first cashout. We approximate it from victim_inflow + latency.
    # More simply: we look for the first contract-to-creator internal tx.
    first_cashout_ts: int | None = None
    if contract_address:
        for tx in all_txs:
            if (tx.get("from", "").lower() == contract_address
                    and tx.get("to", "").lower() == addr
                    and int(tx.get("value", 0)) > 0):
                first_cashout_ts = int(tx.get("timeStamp", 0))
                break

    for tx in all_txs:
        val = int(tx.get("value", 0))
        from_a = tx.get("from", "").lower()
        to_a = tx.get("to", "").lower()
        ts = int(tx.get("timeStamp", 0))

        if 0 < val < DUST_WEI:
            # Outbound dust from creator
            if from_a == addr:
                vs4_out_dust += 1
                dust_dest_set.add(to_a)
                # Pre-cashout dust: within 24h window before first cashout event
                if first_cashout_ts is not None:
                    window_start = first_cashout_ts - 86400  # 24h
                    if window_start <= ts <= first_cashout_ts:
                        vs4_pre_cashout_dust += 1
            # Inbound dust to creator (informational, not scored)
            if to_a == addr:
                vs4_inbound_dust += 1

    # =========================================================================
    # VS5 — Cross-Deployment Amount Consistency (single wallet, multi-deploy)
    # =========================================================================
    # For each deployment, find the set of unique seed amounts (pre-deploy
    # inflows in 72h window). Then compute Jaccard between consecutive deploys.
    vs5_jaccard: Optional[float] = None
    vs5_dep_count = len(deploy_txs)

    if len(deploy_txs) >= 2:
        per_deploy_seed_sets: list[set[float]] = []

        for dtx in deploy_txs:
            d_ts = int(dtx.get("timeStamp", 0))
            window_start = d_ts - (72 * 3600)

            seed_amounts = {
                round(int(tx.get("value", 0)) / ETH, 2)
                for tx in normal_txs + internal_txs
                if tx.get("to", "").lower() == addr
                and tx.get("from", "").lower() != addr
                and window_start <= int(tx.get("timeStamp", 0)) < d_ts
                and int(tx.get("value", 0)) > 0
            }
            per_deploy_seed_sets.append(seed_amounts)

        # Jaccard between each pair of consecutive deployment seed sets.
        jaccard_scores: list[float] = []
        for i in range(len(per_deploy_seed_sets) - 1):
            a = per_deploy_seed_sets[i]
            b = per_deploy_seed_sets[i + 1]
            union = a | b
            if union:
                jaccard_scores.append(len(a & b) / len(union))

        if jaccard_scores:
            vs5_jaccard = statistics.mean(jaccard_scores)

    # =========================================================================
    # VS6 — Lifecycle Allocation Ratio + LP Operation Accounting
    # =========================================================================
    vs6_deploy_eth: Optional[float] = None
    vs6_self_fund_eth: Optional[float] = None
    vs6_cashout_eth: Optional[float] = None
    vs6_multiplier: Optional[float] = None
    vs6_lp_added: Optional[float] = None
    vs6_lp_removed: Optional[float] = None
    vs6_lp_net: Optional[float] = None
    vs6_token_frac: Optional[float] = None
    vs6_mint_lp_lat: Optional[int] = None

    if deploy_txs and contract_address:
        deploy_ts = int(deploy_txs[0].get("timeStamp", 0))

        # Step 1: ETH attached to the deployment transaction(s)
        # Most deployments send 0 ETH, but some seed the contract inline.
        v_deploy_wei = sum(
            int(tx.get("value", 0)) for tx in deploy_txs
        )
        vs6_deploy_eth = v_deploy_wei / ETH

        # Step 2: ETH the creator sent INTO their own contract post-deploy.
        # These are self-funding transactions (providing initial liquidity seed).
        v_self_fund_wei = 0
        for tx in all_txs:
            if (tx.get("from", "").lower() == addr
                    and tx.get("to", "").lower() == contract_address
                    and int(tx.get("value", 0)) > 0
                    and int(tx.get("timeStamp", 0)) >= deploy_ts):
                v_self_fund_wei += int(tx.get("value", 0))
        vs6_self_fund_eth = v_self_fund_wei / ETH

        # Step 3: ETH the creator extracted FROM the contract.
        # Internal txs cover contract → creator (withdraw/removeLiquidity payouts).
        v_cashout_wei = 0
        for tx in all_txs:
            if (tx.get("from", "").lower() == contract_address
                    and tx.get("to", "").lower() == addr
                    and int(tx.get("value", 0)) > 0):
                v_cashout_wei += int(tx.get("value", 0))
        vs6_cashout_eth = v_cashout_wei / ETH

        # Step 4: Extraction multiplier = cashout / creator's own stake.
        # Floor at MINIMUM_STAKE_ETH to avoid division-by-zero.
        total_invested = max(vs6_deploy_eth + vs6_self_fund_eth, _MINIMUM_STAKE_ETH)
        vs6_multiplier = vs6_cashout_eth / total_invested

        # Step 5: LP operation accounting from Uniswap function selectors.
        # The ETH value attached to addLiquidityETH internal calls gives the
        # amount actually locked. For removeLiquidity, the ETH returned comes
        # via internal transactions to the creator.
        lp_added_wei = 0
        lp_removed_wei = 0
        first_add_liquidity_ts: int | None = None

        for tx in all_txs:
            from_a = tx.get("from", "").lower()
            to_a = tx.get("to", "").lower()
            inp = tx.get("input", "").lower().lstrip("0x")
            sel = inp[:8] if len(inp) >= 8 else ""
            val = int(tx.get("value", 0))
            ts  = int(tx.get("timeStamp", 0))

            # addLiquidity or addLiquidityETH — creator adds ETH to a DEX pool
            if from_a == addr and sel in _ADD_LIQUIDITY_SELECTORS and val > 0:
                lp_added_wei += val
                if first_add_liquidity_ts is None:
                    first_add_liquidity_ts = ts

            # removeLiquidity — ETH returned to creator from the pool
            # These arrive as internal transactions from the DEX router
            if to_a == addr and sel in _REMOVE_LIQUIDITY_SELECTORS and val > 0:
                lp_removed_wei += val

        if lp_added_wei > 0 or lp_removed_wei > 0:
            vs6_lp_added   = lp_added_wei / ETH
            vs6_lp_removed = lp_removed_wei / ETH
            vs6_lp_net     = vs6_lp_removed - vs6_lp_added

        # Step 6: Minting metrics from ERC-20 token transfer events (optional).
        # Mint events: transfers where from == zero address.
        # Only runs if caller provided token_txs (1 extra API call).
        if token_txs:
            total_minted = 0      # sum of ALL token units minted (any recipient)
            creator_minted = 0    # token units minted directly to creator wallet
            first_mint_ts: int | None = None

            for ttx in token_txs:
                from_addr = ttx.get("from", "").lower()
                to_addr   = ttx.get("to", "").lower()
                # Token amounts in the tokentx response are stored in the
                # 'value' field as integer strings (token smallest units).
                try:
                    amount = int(ttx.get("value", 0))
                except (ValueError, TypeError):
                    amount = 0

                if from_addr == _ZERO_ADDRESS and amount > 0:
                    # This is a mint event
                    total_minted += amount
                    if to_addr == addr:
                        creator_minted += amount
                    ts = int(ttx.get("timeStamp", 0))
                    if first_mint_ts is None:
                        first_mint_ts = ts

            # Creator's fraction of total minted supply
            if total_minted > 0:
                vs6_token_frac = creator_minted / total_minted

            # Mint-to-addLiquidity latency (seconds)
            # Measures how quickly creator deployed the trap after minting.
            if first_mint_ts is not None and first_add_liquidity_ts is not None:
                if first_add_liquidity_ts >= first_mint_ts:
                    vs6_mint_lp_lat = first_add_liquidity_ts - first_mint_ts

    # =========================================================================
    # Return as a dict for model_copy(update={...})
    # =========================================================================
    return {
        "vs1_mode_freq_ratio":         vs1_mode_freq,
        "vs1_top2_coverage":           vs1_top2,
        "vs1_inbound_count":           vs1_count,
        "vs2_round_funding_ratio":     vs2_round_ratio,
        "vs2_pre_deploy_funding_count": vs2_pre_count,
        "vs3_cv_gas":                  vs3_cv,
        "vs3_round_gas_ratio":         vs3_round_gas,
        "vs3_gas_tx_count":            vs3_gas_count,
        "vs4_outbound_dust_count":     vs4_out_dust,
        "vs4_pre_cashout_dust_count":  vs4_pre_cashout_dust,
        "vs4_unique_dust_destinations": len(dust_dest_set),
        "vs4_inbound_dust_count":      vs4_inbound_dust,
        "vs5_avg_cross_deploy_jaccard": vs5_jaccard,
        "vs5_deployment_count_for_vs5": vs5_dep_count,
        "vs6_v_deploy_eth":            vs6_deploy_eth,
        "vs6_v_self_fund_eth":         vs6_self_fund_eth,
        "vs6_v_cashout_eth":           vs6_cashout_eth,
        "vs6_extraction_multiplier":   vs6_multiplier,
        "vs6_lp_eth_added":            vs6_lp_added,
        "vs6_lp_eth_removed":          vs6_lp_removed,
        "vs6_lp_net_eth":              vs6_lp_net,
        "vs6_creator_token_fraction":  vs6_token_frac,
        "vs6_mint_to_lp_latency_sec":  vs6_mint_lp_lat,
    }
