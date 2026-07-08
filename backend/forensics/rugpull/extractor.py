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

def extract_features(address: str, raw: dict) -> FeatureVector:
    """
    Compute the full FeatureVector for one wallet from its raw Etherscan data.

    Args:
        address: Wallet address (lowercase).
        raw:     Dict with keys "normal_txs" and "internal_txs" — the same
                 structure produced by EtherscanClient in the threshold script
                 and by the main application's blockchain layer.

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
    }
