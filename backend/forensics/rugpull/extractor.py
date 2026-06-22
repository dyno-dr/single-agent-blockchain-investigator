"""
backend/forensics/rugpull/extractor.py
─────────────────────────────────────────────────────────────────────────────
Feature extraction layer for the rugpull creator triage system.

Takes raw Etherscan transaction data (normal txs + internal txs) for a single
wallet and computes the 7 pre-deployment behavioural features (F1-F7) derived
empirically from the v2 threshold analysis script.

DESIGN:
  - Pure computation: no API calls, no I/O, no side effects.
  - All algorithms are direct ports from revised_rugpull_threshold.py, so
    the feature values produced here exactly match what the threshold script
    used to derive the thresholds stored in RugpullProfileConfig.
  - FeatureVector is a frozen Pydantic model so it can be safely passed
    between LangGraph nodes and serialised to the DB.

FEATURE REFERENCE:
  F1  warmup_hours            — hours from first on-chain activity → first deployment
  F2  funding_cv              — CV of funding-lag gaps across deployments
  F3  dry_run_count           — bytecode-similar / reverted txs before deployment
  F4  deployment_count        — total deployments from this wallet
  F4b burstiness              — Goh-Barabási B (narrative only, not a trigger)
  F5  nonce_entropy           — Shannon entropy of inter-tx gaps (narrative only)
  F7  within_wallet_sim       — avg pairwise Levenshtein of setup sequences
  new_a_single_deploy         — wallet has exactly 1 deployment (burner flag)
  ownership_transfer_count    — deployments followed by transferOwnership() in 48h
  all_funding_sources         — unique funder addresses (for NEW-B runtime check)
  deployment_setup_sequences  — raw sequences for cross-wallet F7 DB comparison
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
