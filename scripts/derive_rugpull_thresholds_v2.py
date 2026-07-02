"""
derive_rugpull_thresholds_v2.py
================================
REVISED threshold derivation script for the rugpull creator flagging system.

This script runs offline against a set of known rugpull creator addresses and
a genuine deployer control group. It computes all 7 pre-deployment features
(F1–F7, minus F6 which requires gas data not fetched here), derives data-driven
thresholds, and produces a ready-to-paste RugpullProfileConfig block for
settings/base.py.

CRITICAL CHANGES FROM V1:
  - F3: similarity threshold lowered to 0.40 (was 0.70), window extended to 6h,
         cap added at 10 to suppress batch-deploy false positives
  - F4: burstiness dropped as primary signal; replaced by raw deployment-count
         thresholds because data showed genuine high-volume deployers are MORE
         bursty than rugpull wallets
  - F5: nonce entropy kept only as narrative detail; groups too close (4.67 vs 4.54)
         to use as a severity trigger
  - F7: within-wallet template similarity dropped as trigger; genuine professional
         deployers score HIGHER (0.28) than rugpull wallets (0.19). Cross-wallet
         comparison kept and handled at rule-engine runtime (not in this script).
  - NEW-A: single-deployment burner-wallet flag added (54% of rugpull group)
  - NEW-B: cross-wallet funding-source flag registered at analysis time (needs DB)
  - Multi-hop ownership transfer detection: detect transferOwnership() call within
         48h of each deployment and record new_owner_address for downstream analysis.
         This script does NOT recursively analyze owner wallets — it surfaces the
         address so the rule engine can queue it.

MULTI-HOP DECISION (read this before asking "do we need it here?"):
  Multi-hop investigation is NOT done in this threshold script. Reason:
  This script is a one-time offline statistics runner. Multi-hop (following
  transferOwnership recipients, following funding sources) is a runtime decision
  made by the agent/rule engine per investigation. What this script does do is:
    1. Detect and record transferOwnership events in each deployment profile
       (so the rule engine has the data to act on at runtime).
    2. Record all unique funding source addresses per wallet
       (so the cross-wallet funding rule has data to compare against).
  The actual branching logic ("now analyze 0xBBB too") lives in rugpull_engine.py,
  not here. This is the correct architectural separation.

USAGE:
  python scripts/derive_rugpull_thresholds_v2.py \
    --rugpull-addresses rugpull_addresses.txt \
    --genuine-addresses genuine_addresses.txt \
    --api-key YOUR_ETHERSCAN_KEY \
    --cache-file raw_wallet_data_v2.json \
    --output threshold_results_v2.json

  If --cache-file exists and contains data, no new API calls are made.
  This lets you re-run with tweaked parameters for free.

REQUIRED FILES:
  rugpull_addresses.txt  — one address per line, 50 known rugpull creators
  genuine_addresses.txt  — one address per line, 20-30 legitimate deployers

OUTPUT:
  threshold_results_v2.json   — full per-wallet feature values + threshold stats
  Console output              — paste-ready RugpullProfileConfig block
"""

import argparse
import json
import math
import os
import statistics
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from typing import Optional
import urllib.request
import urllib.parse


# ─────────────────────────────────────────────────────────────────────────────
# DATA STRUCTURES
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class DeploymentRecord:
    """One contract deployment by the wallet under analysis."""
    contract_address: str
    deployed_at: int                        # unix timestamp
    method: str                             # "direct" | "via_factory"
    factory_address: Optional[str]
    setup_sequence: list[str]               # ordered 4-byte selectors pre-deployment
    dry_run_count: int
    warmup_hours: Optional[float]           # hours from wallet first seen to THIS deployment
    funding_sources: list[str]              # funder addresses in 72h window before deploy
    funding_lag_hours: Optional[float]      # hours: dominant funder → deployment
    owner_transfer_to: Optional[str]        # address from transferOwnership() within 48h post-deploy
    # ^ This is the multi-hop hook: if not None, the rule engine should queue this address


@dataclass
class WalletProfile:
    """All extracted data for one wallet address."""
    address: str
    label: str                              # "rugpull" | "genuine"
    first_seen_ts: Optional[int]            # unix ts of earliest tx (including incoming)
    deployments: list[DeploymentRecord] = field(default_factory=list)
    all_nonce_intervals_sec: list[float] = field(default_factory=list)
    all_funding_sources: list[str] = field(default_factory=list)
    # Computed features (filled by compute_features())
    f1_warmup_hours: Optional[float] = None
    f2_funding_cv: Optional[float] = None
    f3_dry_run_count: int = 0
    f4_burstiness: Optional[float] = None
    f4_deployment_count: int = 0
    f5_nonce_entropy: Optional[float] = None
    f7_within_wallet_similarity: Optional[float] = None
    new_a_single_deploy: bool = False


# ─────────────────────────────────────────────────────────────────────────────
# ETHERSCAN API CLIENT  (minimal, no external deps)
# ─────────────────────────────────────────────────────────────────────────────

class EtherscanClient:
    BASE = "https://api.etherscan.io/v2/api"

    def __init__(self, api_key: str, rate_limit_delay: float = 0.22):
        self.api_key = api_key
        self.delay = rate_limit_delay          # stay within 5 req/s free tier

    def _get(self, params: dict) -> dict:
        params["apikey"] = self.api_key
        url = self.BASE + "?" + urllib.parse.urlencode(params)
        time.sleep(self.delay)
        with urllib.request.urlopen(url, timeout=20) as resp:
            data = json.loads(resp.read())
        if data.get("status") == "0" and data.get("message") not in ("No transactions found", "No records found"):
            raise RuntimeError(f"Etherscan error: {data.get('result')}")
        return data

    def get_normal_txs(self, address: str) -> list[dict]:
        """All outgoing + incoming normal transactions for an address."""
        r = self._get({
            "module": "account", "action": "txlist",
            "address": address, "startblock": 0, "endblock": 99999999,
            "sort": "asc", "offset": 10000, "page": 1
        })
        return r.get("result", []) or []

    def get_internal_txs(self, address: str) -> list[dict]:
        """Internal transactions (ETH transfers via contract calls)."""
        r = self._get({
            "module": "account", "action": "txlistinternal",
            "address": address, "startblock": 0, "endblock": 99999999,
            "sort": "asc", "offset": 10000, "page": 1
        })
        return r.get("result", []) or []

    def get_tx_receipt(self, tx_hash: str) -> Optional[dict]:
        """Transaction receipt to confirm contract creation."""
        r = self._get({
            "module": "proxy", "action": "eth_getTransactionReceipt",
            "txhash": tx_hash
        })
        return r.get("result")


# ─────────────────────────────────────────────────────────────────────────────
# FETCH + CACHE LAYER
# ─────────────────────────────────────────────────────────────────────────────

def fetch_wallet_raw(address: str, client: EtherscanClient) -> dict:
    """
    Pull all raw on-chain data for one address. Returns a dict that is
    immediately JSON-serialisable (for the cache file).
    """
    addr = address.lower()
    print(f"  Fetching normal txs for {addr}...")
    normal = client.get_normal_txs(addr)
    print(f"  Fetching internal txs for {addr}...")
    internal = client.get_internal_txs(addr)
    return {"address": addr, "normal_txs": normal, "internal_txs": internal}


def load_or_fetch_all(
    addresses: list[tuple[str, str]],     # (address, label) pairs
    client: EtherscanClient,
    cache_file: str
) -> dict[str, dict]:
    """
    Returns {address: raw_data}. Uses cache_file if present, otherwise
    fetches from Etherscan and writes the cache.
    """
    if os.path.exists(cache_file):
        print(f"[CACHE] Loading raw data from {cache_file} (no API calls).")
        with open(cache_file) as f:
            cached = json.load(f)
        # Validate all addresses are in cache; fetch missing ones
        missing = [(a, l) for a, l in addresses if a.lower() not in cached]
        if missing:
            print(f"[CACHE] {len(missing)} addresses not in cache, fetching...")
            for addr, label in missing:
                try:
                    cached[addr.lower()] = fetch_wallet_raw(addr, client)
                except Exception as e:
                    print(f"  ERROR fetching {addr}: {e}")
            with open(cache_file, "w") as f:
                json.dump(cached, f, indent=2)
        return cached
    else:
        print(f"[FETCH] Cache not found. Fetching {len(addresses)} addresses from Etherscan...")
        raw: dict[str, dict] = {}
        for addr, label in addresses:
            try:
                raw[addr.lower()] = fetch_wallet_raw(addr, client)
            except Exception as e:
                print(f"  ERROR fetching {addr}: {e}")
        with open(cache_file, "w") as f:
            json.dump(raw, f, indent=2)
        print(f"[CACHE] Raw data saved to {cache_file}")
        return raw


# ─────────────────────────────────────────────────────────────────────────────
# FEATURE EXTRACTION
# ─────────────────────────────────────────────────────────────────────────────

TRANSFER_OWNERSHIP_SELECTORS = {
    "0xf2fde38b",   # transferOwnership(address) — OpenZeppelin standard
    "0x13af4035",   # setOwner(address)
    "0xa6f9dae1",   # changeOwner(address)
}

WINDOW_72H_SEC = 72 * 3600
WINDOW_24H_SEC = 24 * 3600
WINDOW_48H_SEC = 48 * 3600

# F3 revised parameters (v2)
F3_SIMILARITY_THRESHOLD = 0.40    # was 0.70 — too strict, lowered
F3_WINDOW_SEC = 6 * 3600          # was 1h — extended to 6h
F3_MAX_CAP = 10                   # cap per deployment to suppress batch-deploy FPs


def _selector(input_data: str) -> Optional[str]:
    """Extract first 4 bytes (function selector) from hex calldata."""
    s = input_data.lower()
    if s.startswith("0x"):
        s = s[2:]
    if len(s) >= 8:
        return s[:8]
    return None


def _bytecode_jaccard(a: str, b: str, k: int = 4) -> float:
    """
    k-mer Jaccard similarity between two hex strings (treated as byte sequences).
    k=4 means 4-byte (8-hex-char) chunks. Used for dry-run detection.
    Lower k → more permissive (catches partial matches). 
    At k=4 with threshold=0.40 this is the revised F3 detection criterion.
    """
    def kmers(s: str) -> set:
        s = s.lower().replace("0x", "")
        return {s[i:i+k*2] for i in range(0, len(s) - k*2 + 1, k*2)}
    sa, sb = kmers(a), kmers(b)
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / len(sa | sb)


def _levenshtein_similarity(seq_a: list, seq_b: list) -> float:
    """
    Normalised Levenshtein similarity for two selector sequences.
    Returns float in [0,1]. 1.0 = identical. Used for F7.
    """
    if not seq_a and not seq_b:
        return 1.0
    if not seq_a or not seq_b:
        return 0.0
    n, m = len(seq_a), len(seq_b)
    # DP table
    dp = list(range(m + 1))
    for i in range(1, n + 1):
        prev = dp[:]
        dp[0] = i
        for j in range(1, m + 1):
            cost = 0 if seq_a[i-1] == seq_b[j-1] else 1
            dp[j] = min(dp[j] + 1, dp[j-1] + 1, prev[j-1] + cost)
    edit_dist = dp[m]
    max_len = max(n, m)
    return 1.0 - (edit_dist / max_len)


def _nonce_entropy(intervals_sec: list[float]) -> Optional[float]:
    """
    Shannon entropy of inter-transaction time gaps, bucketed to nearest minute.
    Low entropy = robotic/scripted; high entropy = human variation.
    Unit: bits.
    """
    if len(intervals_sec) < 3:
        return None
    buckets = [round(t / 60) for t in intervals_sec]   # round to nearest minute
    counts = Counter(buckets)
    total = sum(counts.values())
    entropy = -sum((c / total) * math.log2(c / total) for c in counts.values() if c > 0)
    return entropy


def _burstiness(timestamps: list[int]) -> Optional[float]:
    """
    Goh & Barabási burstiness parameter B = (σ - μ) / (σ + μ) on inter-event gaps.
    Range: [-1, 1]. Positive = bursty (clustered). 0 = Poisson random.
    Requires ≥ 3 timestamps (i.e. ≥ 2 intervals).
    """
    if len(timestamps) < 3:
        return None
    gaps = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
    mu = statistics.mean(gaps)
    if mu == 0:
        return None
    try:
        sigma = statistics.stdev(gaps)
    except statistics.StatisticsError:
        return None
    denom = sigma + mu
    if denom == 0:
        return None
    return (sigma - mu) / denom


def build_wallet_profile(
    address: str,
    label: str,
    raw: dict
) -> WalletProfile:
    """
    Build a WalletProfile from raw Etherscan data.
    This is pure computation — no API calls. Works entirely on the cached dict.
    """
    addr = address.lower()
    normal_txs: list[dict] = raw.get("normal_txs", [])
    internal_txs: list[dict] = raw.get("internal_txs", [])

    # ── 0. Establish first_seen timestamp ────────────────────────────────────
    # Include incoming txs (wallet gets funded before it sends anything)
    all_timestamps = []
    for tx in normal_txs:
        try:
            all_timestamps.append(int(tx["timeStamp"]))
        except (KeyError, ValueError):
            pass
    for tx in internal_txs:
        try:
            all_timestamps.append(int(tx["timeStamp"]))
        except (KeyError, ValueError):
            pass

    first_seen_ts = min(all_timestamps) if all_timestamps else None

    profile = WalletProfile(address=addr, label=label, first_seen_ts=first_seen_ts)

    # ── 1. Identify outgoing txs from this wallet ────────────────────────────
    outgoing = [tx for tx in normal_txs if tx.get("from", "").lower() == addr]
    # Sort by block/nonce to ensure correct ordering
    outgoing_sorted = sorted(outgoing, key=lambda t: int(t.get("nonce", 0)))

    # ── 2. Nonce intervals (for F5) ──────────────────────────────────────────
    outgoing_ts = sorted(int(t["timeStamp"]) for t in outgoing if t.get("timeStamp"))
    if len(outgoing_ts) >= 2:
        profile.all_nonce_intervals_sec = [
            float(outgoing_ts[i+1] - outgoing_ts[i])
            for i in range(len(outgoing_ts)-1)
            if outgoing_ts[i+1] > outgoing_ts[i]
        ]

    # ── 3. Identify deployments ──────────────────────────────────────────────
    # A deployment is an outgoing tx where "to" is empty/null and
    # contractAddress is populated in the receipt. Etherscan includes
    # contractAddress directly in the normal tx list for deployments.
    deploy_txs = [
        tx for tx in outgoing
        if (tx.get("to") == "" or tx.get("to") is None)
        and tx.get("contractAddress") not in ("", None)
    ]
    deploy_txs_sorted = sorted(deploy_txs, key=lambda t: int(t.get("timeStamp", 0)))

    # ── 4. All inbound ETH transfers (for funding source detection) ──────────
    inbound_normal = [
        tx for tx in normal_txs
        if tx.get("to", "").lower() == addr
        and int(tx.get("value", "0")) > 0
    ]
    inbound_internal = [
        tx for tx in internal_txs
        if tx.get("to", "").lower() == addr
        and int(tx.get("value", "0")) > 0
    ]
    all_inbound = inbound_normal + inbound_internal

    # Collect all unique funding sources across the whole wallet
    profile.all_funding_sources = list({
        tx.get("from", "").lower()
        for tx in all_inbound
        if tx.get("from", "").lower() not in ("", addr)
    })

    # ── 5. Build one DeploymentRecord per deployment ─────────────────────────
    funding_lags: list[float] = []   # accumulated for F2 CV calculation

    for dtx in deploy_txs_sorted:
        deploy_ts = int(dtx.get("timeStamp", 0))
        contract_addr = dtx.get("contractAddress", "").lower()

        # Determine if factory-deployed (to address != null means factory call)
        # If Etherscan lists contractAddress but "to" has a value, it's a factory
        method = "direct"
        factory_address = None
        if dtx.get("to") not in ("", None):
            method = "via_factory"
            factory_address = dtx.get("to", "").lower()

        # ── F1: warmup hours for this deployment ────────────────────────────
        warmup_hours = None
        if first_seen_ts is not None and deploy_ts > 0:
            warmup_hours = (deploy_ts - first_seen_ts) / 3600.0
            warmup_hours = max(0.0, warmup_hours)

        # ── F2: funding sources in 72h window before this deployment ─────────
        window_start = deploy_ts - WINDOW_72H_SEC
        funders_this_deploy = [
            tx for tx in all_inbound
            if window_start <= int(tx.get("timeStamp", 0)) < deploy_ts
        ]
        funder_addresses = list({
            tx.get("from", "").lower()
            for tx in funders_this_deploy
            if tx.get("from", "").lower() not in ("", addr)
        })

        # Dominant funder = the one that funded the most transactions in window
        funder_counts = Counter(
            tx.get("from", "").lower()
            for tx in funders_this_deploy
        )
        dominant_funder = funder_counts.most_common(1)[0][0] if funder_counts else None

        # Funding lag: time from most recent dominant-funder tx to this deployment
        funding_lag_hours = None
        if dominant_funder:
            dominant_txs = [
                tx for tx in funders_this_deploy
                if tx.get("from", "").lower() == dominant_funder
            ]
            if dominant_txs:
                latest_fund_ts = max(int(tx.get("timeStamp", 0)) for tx in dominant_txs)
                funding_lag_hours = (deploy_ts - latest_fund_ts) / 3600.0
                if funding_lag_hours >= 0:
                    funding_lags.append(funding_lag_hours)

        # ── F3: dry-run detection (REVISED: threshold=0.40, window=6h, cap=10) ──
        window_start_f3 = deploy_ts - F3_WINDOW_SEC
        deploy_calldata = dtx.get("input", "")
        dry_run_count = 0

        pre_deploy_txs = [
            tx for tx in outgoing
            if window_start_f3 <= int(tx.get("timeStamp", 0)) < deploy_ts
            and tx.get("contractAddress") in ("", None)   # not itself a deployment
        ]
        for candidate in pre_deploy_txs:
            if dry_run_count >= F3_MAX_CAP:
                break
            # Condition 1: reverted transaction
            is_reverted = candidate.get("isError", "0") == "1"
            # Condition 2: bytecode similarity to deployment calldata
            candidate_input = candidate.get("input", "")
            similarity = _bytecode_jaccard(candidate_input, deploy_calldata)
            is_similar = similarity >= F3_SIMILARITY_THRESHOLD

            if is_reverted or is_similar:
                dry_run_count += 1

        # ── F7 setup sequence: selectors in 24h window before deployment ──────
        setup_window_start = deploy_ts - WINDOW_24H_SEC
        setup_txs = sorted(
            [
                tx for tx in outgoing
                if setup_window_start <= int(tx.get("timeStamp", 0)) < deploy_ts
                and tx.get("contractAddress") in ("", None)
            ],
            key=lambda t: int(t.get("timeStamp", 0))
        )
        setup_sequence = [
            "0x" + s
            for tx in setup_txs
            if (s := _selector(tx.get("input", ""))) is not None
        ]

        # ── Multi-hop hook: detect transferOwnership() within 48h post-deploy ──
        # This is NOT recursive analysis — just recording the new owner address
        # so that rugpull_engine.py can decide to queue it for investigation.
        owner_transfer_to = None
        post_window_end = deploy_ts + WINDOW_48H_SEC
        post_deploy_txs = [
            tx for tx in outgoing
            if deploy_ts < int(tx.get("timeStamp", 0)) <= post_window_end
        ]
        for tx in post_deploy_txs:
            sel = _selector(tx.get("input", ""))
            if sel and ("0x" + sel) in TRANSFER_OWNERSHIP_SELECTORS:
                # Extract target address from calldata: bytes 4..23 after selector
                raw_input = tx.get("input", "").lower().replace("0x", "")
                if len(raw_input) >= 72:   # 8 (selector) + 64 (padded address)
                    new_owner = "0x" + raw_input[8+24:8+64]   # strip 12-byte padding
                    if new_owner != addr and len(new_owner) == 42:
                        owner_transfer_to = new_owner
                        break   # first transferOwnership wins

        profile.deployments.append(DeploymentRecord(
            contract_address=contract_addr,
            deployed_at=deploy_ts,
            method=method,
            factory_address=factory_address,
            setup_sequence=setup_sequence,
            dry_run_count=dry_run_count,
            warmup_hours=warmup_hours,
            funding_sources=funder_addresses,
            funding_lag_hours=funding_lag_hours,
            owner_transfer_to=owner_transfer_to,
        ))

    return profile


def compute_features(profile: WalletProfile) -> WalletProfile:
    """
    Populate all scalar feature fields on the profile.
    Call this after build_wallet_profile().
    """
    deps = profile.deployments

    # ── F1: use first deployment's warmup_hours ───────────────────────────────
    warmups = [d.warmup_hours for d in deps if d.warmup_hours is not None]
    profile.f1_warmup_hours = min(warmups) if warmups else None

    # ── F2: Coefficient of Variation of funding lags across all deployments ───
    # CV = std / mean. Low CV → consistent/scripted. Only for 2+ deployments.
    all_lags = [d.funding_lag_hours for d in deps if d.funding_lag_hours is not None]
    if len(all_lags) >= 2:
        mu = statistics.mean(all_lags)
        try:
            sigma = statistics.stdev(all_lags)
        except statistics.StatisticsError:
            sigma = 0.0
        profile.f2_funding_cv = (sigma / mu) if mu > 0 else None
    else:
        profile.f2_funding_cv = None    # undefined for single-deployment wallets

    # ── F3: sum of dry-run counts across all deployments, capped per deploy ───
    # The per-deployment cap is already applied in build_wallet_profile().
    profile.f3_dry_run_count = sum(d.dry_run_count for d in deps)

    # ── F4: deployment count (replaces burstiness as primary signal) ──────────
    # Burstiness is still computed but NOT used as a severity trigger — see notes.
    profile.f4_deployment_count = len(deps)
    deploy_timestamps = sorted(d.deployed_at for d in deps)
    profile.f4_burstiness = _burstiness(deploy_timestamps)

    # ── F5: nonce entropy (contextual only, no severity trigger) ──────────────
    profile.f5_nonce_entropy = _nonce_entropy(profile.all_nonce_intervals_sec)

    # ── F7: within-wallet template similarity ─────────────────────────────────
    # Compare every pair of setup_sequences using normalised Levenshtein.
    # NOTE: data showed genuine deployers score HIGHER on this than rugpulls.
    # We compute it here for completeness/reporting, but it is NOT used as a
    # severity trigger in the rule engine — only cross-wallet comparison matters.
    sequences = [d.setup_sequence for d in deps if d.setup_sequence]
    if len(sequences) >= 2:
        sims = []
        for i in range(len(sequences)):
            for j in range(i+1, len(sequences)):
                sims.append(_levenshtein_similarity(sequences[i], sequences[j]))
        profile.f7_within_wallet_similarity = statistics.mean(sims) if sims else None
    else:
        profile.f7_within_wallet_similarity = None

    # ── NEW-A: single deployment flag ─────────────────────────────────────────
    # 54% of rugpull group had exactly 1 deployment. This is the burner-wallet pattern.
    profile.new_a_single_deploy = (len(deps) == 1)

    return profile


# ─────────────────────────────────────────────────────────────────────────────
# THRESHOLD DERIVATION
# ─────────────────────────────────────────────────────────────────────────────

def _percentile(data: list[float], p: float) -> float:
    """Compute the p-th percentile of a sorted list (linear interpolation)."""
    if not data:
        return float("nan")
    sorted_data = sorted(data)
    n = len(sorted_data)
    idx = (p / 100) * (n - 1)
    lo = int(idx)
    hi = lo + 1
    if hi >= n:
        return sorted_data[-1]
    frac = idx - lo
    return sorted_data[lo] + frac * (sorted_data[hi] - sorted_data[lo])


def derive_thresholds(profiles: list[WalletProfile]) -> dict:
    """
    For each feature, split into rugpull/genuine groups, compute statistics,
    and determine threshold values with separation quality notes.
    Returns a nested dict of results ready for JSON output.
    """
    rug = [p for p in profiles if p.label == "rugpull"]
    gen = [p for p in profiles if p.label == "genuine"]

    results = {}

    # ── Helper: assess separation quality ────────────────────────────────────
    def separation_quality(rug_vals, gen_vals, threshold, rug_direction="below"):
        """
        Count how many genuine wallets fall on the 'suspicious' side of the threshold.
        rug_direction: "below" means values BELOW threshold are suspicious.
        """
        if not gen_vals:
            return "UNKNOWN (no genuine data)", 0, 0
        if rug_direction == "below":
            false_pos = sum(1 for v in gen_vals if v <= threshold)
        else:
            false_pos = sum(1 for v in gen_vals if v >= threshold)
        pct = false_pos / len(gen_vals) * 100
        quality = "GOOD" if pct < 20 else "FAIR" if pct < 40 else "WEAK"
        return f"{quality} ({false_pos}/{len(gen_vals)} genuine wallets on suspicious side)", false_pos, len(gen_vals)

    # ─────────────────────────────────────────────────────────────────────────
    # F1 — Warmup Hours
    # Hypothesis: rugpull wallets have LOW warmup (burner wallets).
    # Data finding: HYPOTHESIS WRONG. Rugpull median (8.75h) > genuine (2.61h).
    # Decision: only flag < 0.25h (15 min) as a very minor supporting signal.
    # ─────────────────────────────────────────────────────────────────────────
    f1_rug = [p.f1_warmup_hours for p in rug if p.f1_warmup_hours is not None]
    f1_gen = [p.f1_warmup_hours for p in gen if p.f1_warmup_hours is not None]
    f1_rug_p25  = _percentile(f1_rug, 25)
    f1_rug_med  = _percentile(f1_rug, 50)
    f1_rug_p75  = _percentile(f1_rug, 75)
    f1_gen_p25  = _percentile(f1_gen, 25)
    f1_gen_med  = _percentile(f1_gen, 50)
    sq, _, _ = separation_quality(f1_rug, f1_gen, f1_rug_med, "below")

    results["F1_warmup_hours"] = {
        "rugpull": {"n": len(f1_rug), "p25": f1_rug_p25, "median": f1_rug_med, "p75": f1_rug_p75,
                    "min": min(f1_rug) if f1_rug else None, "max": max(f1_rug) if f1_rug else None},
        "genuine": {"n": len(f1_gen), "p25": f1_gen_p25, "median": f1_gen_med,
                    "min": min(f1_gen) if f1_gen else None, "max": max(f1_gen) if f1_gen else None},
        "separation_quality": sq,
        "HYPOTHESIS_STATUS": "WRONG — rugpull median HIGHER than genuine. Original direction inverted by data.",
        "thresholds": {
            # Only retain extreme burner case (under 15 min)
            "BURNER_FLAG_hours": 0.25,
            "NOTE": "Full warmup threshold dropped. Original hypothesis not supported by data."
        }
    }

    # ─────────────────────────────────────────────────────────────────────────
    # F2 — Funding CV (Coefficient of Variation of funding lag)
    # Hypothesis: scripted funding → low CV (always funded at same lead time).
    # Data finding: CONFIRMED with 64% separation. Best-performing feature.
    # Only computable for wallets with 2+ deployments.
    # ─────────────────────────────────────────────────────────────────────────
    f2_rug = [p.f2_funding_cv for p in rug if p.f2_funding_cv is not None]
    f2_gen = [p.f2_funding_cv for p in gen if p.f2_funding_cv is not None]
    f2_rug_med  = _percentile(f2_rug, 50)
    f2_rug_p75  = _percentile(f2_rug, 75)
    f2_gen_p25  = _percentile(f2_gen, 25)
    sq2, _, _ = separation_quality(f2_rug, f2_gen, f2_rug_med, "below")

    results["F2_funding_cv"] = {
        "rugpull": {"n": len(f2_rug), "p25": _percentile(f2_rug, 25), "median": f2_rug_med, "p75": f2_rug_p75,
                    "min": min(f2_rug) if f2_rug else None, "max": max(f2_rug) if f2_rug else None},
        "genuine": {"n": len(f2_gen), "p25": f2_gen_p25, "median": _percentile(f2_gen, 50),
                    "min": min(f2_gen) if f2_gen else None, "max": max(f2_gen) if f2_gen else None},
        "separation_quality": sq2,
        "HYPOTHESIS_STATUS": "CONFIRMED — 64% separation. Primary signal. Low CV = scripted automated funding.",
        "thresholds": {
            "HIGH_severity_cv_below": f2_rug_med,       # bottom 50% of rugpull group
            "MEDIUM_severity_cv_below": f2_rug_p75,     # bottom 75% of rugpull group
            "CLEAN_FLOOR_cv_above": f2_gen_p25,         # genuine group p25 — rarely suspicious
            "NOTE_single_deploy": "Undefined for wallets with < 2 deployments. Return None, do not flag."
        }
    }

    # ─────────────────────────────────────────────────────────────────────────
    # F3 — Dry-Run Count (REVISED PARAMETERS)
    # Hypothesis: rugpull operators test-deploy before real deployment.
    # Data finding v1: BROKEN (median=0 both groups, threshold 70% too strict).
    # Data finding v2: REDESIGNED with 40% threshold, 6h window, cap=10.
    # These are enforced in build_wallet_profile() above, not tunable here.
    # ─────────────────────────────────────────────────────────────────────────
    f3_rug = [p.f3_dry_run_count for p in rug]
    f3_gen = [p.f3_dry_run_count for p in gen]
    f3_rug_med  = _percentile(f3_rug, 50)
    f3_rug_p75  = _percentile(f3_rug, 75)
    sq3, _, _ = separation_quality(f3_rug, f3_gen, 1, "below")   # threshold of 1+ dry runs

    results["F3_dry_run_count"] = {
        "rugpull": {"n": len(f3_rug), "median": f3_rug_med, "p75": f3_rug_p75,
                    "min": min(f3_rug) if f3_rug else None, "max": max(f3_rug) if f3_rug else None},
        "genuine": {"n": len(f3_gen), "median": _percentile(f3_gen, 50),
                    "min": min(f3_gen) if f3_gen else None, "max": max(f3_gen) if f3_gen else None},
        "parameters_used": {
            "similarity_threshold": F3_SIMILARITY_THRESHOLD,
            "window_hours": F3_WINDOW_SEC / 3600,
            "max_cap_per_deployment": F3_MAX_CAP
        },
        "HYPOTHESIS_STATUS": "REDESIGNED — v1 broke due to 70% threshold being too strict. v2 uses 40%/6h/cap=10.",
        "thresholds": {
            "HIGH_severity_count_above": 3,     # 3+ dry-runs across deployments
            "MEDIUM_severity_count_above": 1,   # 1-2 dry-runs
        }
    }

    # ─────────────────────────────────────────────────────────────────────────
    # F4 — Burstiness + Deployment Count
    # Hypothesis: rugpull wallets MORE bursty than genuine.
    # Data finding: INVERTED. Genuine pro-deployers are MORE bursty (0.17 vs 0.06).
    # Decision: drop burstiness as trigger. Use total deployment count instead.
    # HIGH: 10+ deployments (sustained repeat operator)
    # ─────────────────────────────────────────────────────────────────────────
    f4b_rug = [p.f4_burstiness for p in rug if p.f4_burstiness is not None]
    f4b_gen = [p.f4_burstiness for p in gen if p.f4_burstiness is not None]
    f4c_rug = [p.f4_deployment_count for p in rug]
    f4c_gen = [p.f4_deployment_count for p in gen]

    results["F4_burstiness_and_count"] = {
        "burstiness": {
            "rugpull": {"n": len(f4b_rug), "median": _percentile(f4b_rug, 50)},
            "genuine": {"n": len(f4b_gen), "median": _percentile(f4b_gen, 50)},
            "HYPOTHESIS_STATUS": "INVERTED — genuine deployers are more bursty. DO NOT use as trigger.",
        },
        "deployment_count": {
            "rugpull": {"n": len(f4c_rug), "median": _percentile(f4c_rug, 50),
                        "p75": _percentile(f4c_rug, 75), "max": max(f4c_rug) if f4c_rug else None},
            "genuine": {"n": len(f4c_gen), "median": _percentile(f4c_gen, 50)},
        },
        "thresholds": {
            "HIGH_severity_deploy_count_above": 20,    # 20+ deployments worth flagging
            "MEDIUM_severity_deploy_count_above": 10,  # 10+ deployments
            "NOTE": "Burstiness reported in output as context only. Not a severity trigger."
        }
    }

    # ─────────────────────────────────────────────────────────────────────────
    # F5 — Nonce Entropy
    # Hypothesis: scripted wallets have low entropy (robotic timing).
    # Data finding: TOO WEAK. Medians nearly identical (4.67 vs 4.54).
    # Decision: compute for narrative, never trigger severity from it alone.
    # Only flag if entropy < 3.0 (clearly automated, below rugpull p25=3.85).
    # ─────────────────────────────────────────────────────────────────────────
    f5_rug = [p.f5_nonce_entropy for p in rug if p.f5_nonce_entropy is not None]
    f5_gen = [p.f5_nonce_entropy for p in gen if p.f5_nonce_entropy is not None]
    sq5, _, _ = separation_quality(f5_rug, f5_gen, _percentile(f5_rug, 50), "below")

    results["F5_nonce_entropy"] = {
        "rugpull": {"n": len(f5_rug), "p25": _percentile(f5_rug, 25), "median": _percentile(f5_rug, 50)},
        "genuine": {"n": len(f5_gen), "median": _percentile(f5_gen, 50)},
        "separation_quality": sq5,
        "HYPOTHESIS_STATUS": "TOO WEAK — groups nearly identical. Contextual narrative only.",
        "thresholds": {
            "CLEARLY_AUTOMATED_entropy_below": 3.0,    # below rugpull p25, not a severity trigger
            "NOTE": "Only report this as context. Do not assign MEDIUM/HIGH from this alone."
        }
    }

    # ─────────────────────────────────────────────────────────────────────────
    # F7 — Template Similarity (within-wallet)
    # Hypothesis: rugpull wallets reuse the same setup sequence across deployments.
    # Data finding: INVERTED. Genuine pro-deployers score HIGHER (0.28 vs 0.19).
    # Decision: within-wallet similarity NOT a trigger. Cross-wallet comparison
    #           IS kept, handled at rule-engine runtime, not here.
    # ─────────────────────────────────────────────────────────────────────────
    f7_rug = [p.f7_within_wallet_similarity for p in rug if p.f7_within_wallet_similarity is not None]
    f7_gen = [p.f7_within_wallet_similarity for p in gen if p.f7_within_wallet_similarity is not None]

    results["F7_template_similarity"] = {
        "within_wallet": {
            "rugpull": {"n": len(f7_rug), "median": _percentile(f7_rug, 50)},
            "genuine": {"n": len(f7_gen), "median": _percentile(f7_gen, 50)},
            "HYPOTHESIS_STATUS": "INVERTED — genuine wallets score higher. Within-wallet NOT a trigger.",
        },
        "thresholds": {
            "CROSS_WALLET_match_min_similarity": 0.75,   # flag if matches another wallet in DB
            "NOTE": "Cross-wallet comparison happens at rule-engine runtime via creator_templates DB table."
        }
    }

    # ─────────────────────────────────────────────────────────────────────────
    # NEW-A — Single Deployment (Burner Wallet)
    # Finding: 54% of rugpull group deployed exactly 1 contract.
    # Multi-deployment features (F2, F4, F7) undefined for these wallets.
    # Flag when: 1 deployment AND warmup < 2h, OR 1 deployment AND known funder.
    # ─────────────────────────────────────────────────────────────────────────
    single_rug = sum(1 for p in rug if p.new_a_single_deploy)
    single_gen = sum(1 for p in gen if p.new_a_single_deploy)

    results["NEW_A_single_deployment"] = {
        "rugpull_single_deploy_count": single_rug,
        "rugpull_single_deploy_pct": round(single_rug / len(rug) * 100, 1) if rug else 0,
        "genuine_single_deploy_count": single_gen,
        "genuine_single_deploy_pct": round(single_gen / len(gen) * 100, 1) if gen else 0,
        "thresholds": {
            "MEDIUM_when_single_deploy_AND_warmup_below_hours": 2.0,
            "HIGH_when_single_deploy_AND_known_funder": "Checked at runtime via creator_funding_sources DB table.",
            "VERDICT_OVERRIDE_when_single_deploy": "INSUFFICIENT_DEPLOYMENT_HISTORY — flag for monitoring, not conclusive."
        }
    }

    # ─────────────────────────────────────────────────────────────────────────
    # NEW-B — Cross-wallet funding source (runtime only, not derived here)
    # ─────────────────────────────────────────────────────────────────────────
    results["NEW_B_cross_wallet_funding"] = {
        "NOTE": "Not derived from threshold script. Populated at runtime from creator_funding_sources DB table.",
        "thresholds": {
            "HIGH_when_funder_has_funded_N_or_more_known_wallets": 3
        }
    }

    # ─────────────────────────────────────────────────────────────────────────
    # OWNERSHIP TRANSFER DETECTION (multi-hop hook)
    # ─────────────────────────────────────────────────────────────────────────
    transfer_rug = sum(1 for p in rug for d in p.deployments if d.owner_transfer_to)
    transfer_gen = sum(1 for p in gen for d in p.deployments if d.owner_transfer_to)

    results["MULTI_HOP_ownership_transfer"] = {
        "rugpull_wallets_with_transfer": transfer_rug,
        "genuine_wallets_with_transfer": transfer_gen,
        "description": (
            "Detected by scanning outgoing txs 48h post-deployment for transferOwnership() "
            "or setOwner() calls (selectors: 0xf2fde38b, 0x13af4035, 0xa6f9dae1). "
            "Recorded as owner_transfer_to in each DeploymentRecord. "
            "The rule engine (rugpull_engine.py) should queue this address for "
            "secondary analysis — this script does NOT perform that hop."
        ),
        "why_not_multihop_here": (
            "This threshold script is a one-time offline statistics runner. "
            "Multi-hop branching is a runtime decision made per-investigation by the agent. "
            "Separation of concerns: statistics here, investigation logic in the engine."
        )
    }

    return results


# ─────────────────────────────────────────────────────────────────────────────
# SETTINGS BLOCK GENERATOR
# ─────────────────────────────────────────────────────────────────────────────

def generate_settings_block(results: dict) -> str:
    """
    Produce a paste-ready Python class block for settings/base.py.
    Values come from the derived thresholds in the results dict.
    """
    f2 = results["F2_funding_cv"]["thresholds"]
    f3 = results["F3_dry_run_count"]["thresholds"]
    f4 = results["F4_burstiness_and_count"]["thresholds"]
    f5 = results["F5_nonce_entropy"]["thresholds"]
    f7 = results["F7_template_similarity"]["thresholds"]
    na = results["NEW_A_single_deployment"]["thresholds"]
    nb = results["NEW_B_cross_wallet_funding"]["thresholds"]

    block = f'''
# ════════════════════════════════════════════════════════════════════
# PASTE THIS INTO: settings/base.py
# Generated by: scripts/derive_rugpull_thresholds_v2.py
# Dataset: 50 rugpull wallets + 20 genuine deployer wallets
# IMPORTANT: Re-run this script when your address set changes.
# ════════════════════════════════════════════════════════════════════

class RugpullProfileConfig(BaseModel):
    """
    Thresholds derived empirically from 50 confirmed rugpull creator
    addresses and 20 genuine deployer addresses. Each threshold comment
    includes the data finding that justifies it.

    F6 (gas-window timing) is excluded — requires block-level gas data.
    """

    # ── F1: Warmup Hours ─────────────────────────────────────────────────
    # DATA FINDING: hypothesis WRONG. Rugpull median (8.75h) > genuine (2.61h).
    # Only flag extreme burner-wallet case (< 15 min). Minor supporting signal.
    RUG_001_BURNER_THRESHOLD_HOURS: float = 0.25   # under 15 minutes only

    # ── F2: Funding CV ───────────────────────────────────────────────────
    # DATA FINDING: CONFIRMED — 64% separation. Best single feature.
    # Low CV = scripted/automated funding pipeline (same funder, same timing).
    # UNDEFINED for wallets with < 2 deployments — return None, do NOT flag.
    RUG_002_HIGH_CV_MAX: float = {f2["HIGH_severity_cv_below"]:.4f}   # rugpull median
    RUG_002_MEDIUM_CV_MAX: float = {f2["MEDIUM_severity_cv_below"]:.4f}  # rugpull p75
    RUG_002_CLEAN_FLOOR_CV_MIN: float = {f2["CLEAN_FLOOR_cv_above"]:.4f} # genuine p25

    # ── F3: Dry-Run Count ────────────────────────────────────────────────
    # DATA FINDING: REDESIGNED in v2. v1 70% threshold was too strict.
    # v2 uses: similarity_threshold=0.40, window=6h, cap=10 per deployment.
    # These parameters are in the feature extractor (rugpull_features.py).
    RUG_003_HIGH_COUNT: int = {f3["HIGH_severity_count_above"]}    # 3+ dry-runs = HIGH
    RUG_003_MEDIUM_COUNT: int = {f3["MEDIUM_severity_count_above"]} # 1-2 dry-runs = MEDIUM
    # Internal extractor params (also set in rugpull_features.py):
    RUG_003_SIMILARITY_THRESHOLD: float = 0.40
    RUG_003_WINDOW_HOURS: int = 6
    RUG_003_MAX_COUNT_CAP: int = 10

    # ── F4: Deployment Count ─────────────────────────────────────────────
    # DATA FINDING: burstiness INVERTED (genuine more bursty). Dropped as trigger.
    # Using raw deployment count as proxy for sustained repeat operator activity.
    RUG_004_HIGH_DEPLOYMENT_COUNT: int = {f4["HIGH_severity_deploy_count_above"]}   # 20+ deployments
    RUG_004_MEDIUM_DEPLOYMENT_COUNT: int = {f4["MEDIUM_severity_deploy_count_above"]} # 10+ deployments
    # Burstiness is computed and printed in the report as context only.

    # ── F5: Nonce Entropy ────────────────────────────────────────────────
    # DATA FINDING: TOO WEAK — groups nearly identical (4.67 vs 4.54 median).
    # Only report as narrative context. No severity trigger.
    # Below 3.0 = clearly automated (below rugpull p25), but still only context.
    RUG_005_SCRIPTED_ENTROPY_MAX: float = {f5["CLEARLY_AUTOMATED_entropy_below"]:.1f}

    # ── F7: Template Similarity ──────────────────────────────────────────
    # DATA FINDING: within-wallet similarity INVERTED (genuine = 0.28, rugpull = 0.19).
    # Within-wallet similarity: compute + report, no severity trigger.
    # Cross-wallet similarity: checked at runtime against creator_templates DB table.
    RUG_007_CROSS_WALLET_SIMILARITY_MIN: float = {f7["CROSS_WALLET_match_min_similarity"]:.2f}

    # ── NEW-A: Single Deployment (Burner Wallet) ──────────────────────────
    # DATA FINDING: 54% of rugpull group had exactly 1 deployment.
    # F2, F4, F7 are undefined for these wallets.
    # Trigger MEDIUM when: 1 deployment AND warmup < 2h.
    # Trigger HIGH when: 1 deployment AND funder is a known bad actor (runtime).
    RUG_NEW_A_SINGLE_DEPLOY_WARMUP_MAX_HOURS: float = {na["MEDIUM_when_single_deploy_AND_warmup_below_hours"]:.1f}

    # ── NEW-B: Cross-wallet Funding Source ───────────────────────────────
    # Flag HIGH if the funding source wallet has funded N+ known rugpull wallets.
    # Checked at runtime from creator_funding_sources DB table.
    RUG_NEW_B_FUNDER_MIN_KNOWN_WALLETS: int = {nb["HIGH_when_funder_has_funded_N_or_more_known_wallets"]}

    # ── Scoring weights ───────────────────────────────────────────────────
    # Used in rugpull_scorer.py
    SCORE_CRITICAL: int = 40
    SCORE_HIGH: int = 25
    SCORE_MEDIUM: int = 10
    SCORE_LOW: int = 5

    # ── Verdict bands ─────────────────────────────────────────────────────
    VERDICT_WEAK_MIN: int = 16
    VERDICT_MODERATE_MIN: int = 36
    VERDICT_STRONG_MIN: int = 66
    VERDICT_HIGH_CONFIDENCE_MIN: int = 100

    # ── Override rule ─────────────────────────────────────────────────────
    # If RUG-007 cross-wallet match fires → verdict = at least STRONG_PATTERN
    # regardless of score. Direct linkage evidence outweighs probabilistic score.
    RUG_007_CROSS_MATCH_OVERRIDES_VERDICT: bool = True

    # ── Multi-hop ownership transfer ──────────────────────────────────────
    # When a deployment has owner_transfer_to set, queue that address for analysis.
    # The rule engine handles this — these constants control the detection window.
    OWNERSHIP_TRANSFER_WINDOW_HOURS: int = 48   # scan this many hours post-deployment
    OWNERSHIP_TRANSFER_SELECTORS: list = [
        "0xf2fde38b",   # transferOwnership(address) — OpenZeppelin
        "0x13af4035",   # setOwner(address)
        "0xa6f9dae1",   # changeOwner(address)
    ]
'''
    return block


# ─────────────────────────────────────────────────────────────────────────────
# PRINT REPORT
# ─────────────────────────────────────────────────────────────────────────────

def print_report(profiles: list[WalletProfile], results: dict, settings_block: str):
    LINE = "─" * 70
    DLINE = "═" * 70

    print(f"\n{DLINE}")
    print("RUGPULL THRESHOLD DERIVATION v2 — RESULTS")
    print(DLINE)

    rug = [p for p in profiles if p.label == "rugpull"]
    gen = [p for p in profiles if p.label == "genuine"]
    print(f"\nDataset: {len(rug)} rugpull wallets, {len(gen)} genuine wallets")
    print(f"(wallets with 0 deployments contribute to F5 only)\n")

    for feature_key, data in results.items():
        if feature_key in ("NEW_B_cross_wallet_funding", "MULTI_HOP_ownership_transfer"):
            continue
        print(LINE)
        print(f" {feature_key}")
        print(LINE)
        # Print group stats
        for group_key in ("rugpull", "genuine", "within_wallet", "deployment_count", "burstiness"):
            if group_key in data:
                gd = data[group_key]
                if isinstance(gd, dict) and "median" in gd:
                    n = gd.get("n", "?")
                    med = gd.get("median", "N/A")
                    p25 = gd.get("p25", "N/A")
                    p75 = gd.get("p75", "N/A")
                    mn = gd.get("min", "")
                    mx = gd.get("max", "")
                    print(f"  [{group_key:10s}] n={n:>4}  min={mn}  p25={p25}  median={med}  p75={p75}  max={mx}")
        if "separation_quality" in data:
            print(f"  Separation: {data['separation_quality']}")
        if "HYPOTHESIS_STATUS" in data:
            print(f"  Status: {data['HYPOTHESIS_STATUS']}")
        if "thresholds" in data:
            print(f"  Thresholds: {data['thresholds']}")
        if "parameters_used" in data:
            print(f"  Params: {data['parameters_used']}")
        print()

    print(LINE)
    print(" MULTI-HOP OWNERSHIP TRANSFER")
    print(LINE)
    mh = results["MULTI_HOP_ownership_transfer"]
    print(f"  Rugpull wallets with transferOwnership detected: {mh['rugpull_wallets_with_transfer']}")
    print(f"  Genuine wallets with transferOwnership detected: {mh['genuine_wallets_with_transfer']}")
    print(f"  {mh['description'][:120]}...")
    print()

    print(LINE)
    print(" SINGLE DEPLOYMENT STATS (NEW-A)")
    print(LINE)
    na = results["NEW_A_single_deployment"]
    print(f"  Rugpull: {na['rugpull_single_deploy_count']} wallets ({na['rugpull_single_deploy_pct']}%) have exactly 1 deployment")
    print(f"  Genuine: {na['genuine_single_deploy_count']} wallets ({na['genuine_single_deploy_pct']}%) have exactly 1 deployment")
    print()

    print(DLINE)
    print(" PASTE THIS BLOCK INTO: settings/base.py")
    print(DLINE)
    print(settings_block)
    print(DLINE)
    print("[DONE] Re-run after adding more labeled addresses to refine thresholds.")
    print(DLINE)


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def load_addresses(filepath: str, label: str) -> list[tuple[str, str]]:
    """Load addresses from a text file (one per line). Returns (address, label) pairs."""
    if not os.path.exists(filepath):
        print(f"WARNING: {filepath} not found. Returning empty list.")
        return []
    with open(filepath) as f:
        lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    return [(line.lower(), label) for line in lines if line.startswith("0x")]


def main():
    parser = argparse.ArgumentParser(
        description="Derive rugpull flagging thresholds from labeled wallet sets."
    )
    parser.add_argument("--rugpull-addresses", default="rugpull_addresses.txt",
                        help="Text file with known rugpull creator addresses (one per line)")
    parser.add_argument("--genuine-addresses", default="genuine_addresses.txt",
                        help="Text file with genuine deployer addresses (one per line)")
    parser.add_argument("--api-key", default=os.environ.get("ETHERSCAN_API_KEY", ""),
                        help="Etherscan API key (or set ETHERSCAN_API_KEY env var)")
    parser.add_argument("--cache-file", default="raw_wallet_data_v2.json",
                        help="JSON file to cache raw Etherscan responses")
    parser.add_argument("--output", default="threshold_results_v2.json",
                        help="JSON file for full threshold results")
    args = parser.parse_args()

    if not args.api_key:
        print("ERROR: No Etherscan API key. Set --api-key or ETHERSCAN_API_KEY env var.")
        return

    # Load address lists
    rugpull_addrs = load_addresses(args.rugpull_addresses, "rugpull")
    genuine_addrs = load_addresses(args.genuine_addresses, "genuine")
    all_addrs = rugpull_addrs + genuine_addrs

    if not all_addrs:
        print("ERROR: No addresses loaded. Check your input files.")
        return

    print(f"[INFO] Loaded {len(rugpull_addrs)} rugpull + {len(genuine_addrs)} genuine addresses.")

    # Fetch / load from cache
    client = EtherscanClient(api_key=args.api_key)
    raw_data = load_or_fetch_all(all_addrs, client, args.cache_file)

    # Build profiles
    print("\n[INFO] Building wallet profiles...")
    profiles: list[WalletProfile] = []
    for addr, label in all_addrs:
        if addr not in raw_data:
            print(f"  SKIP {addr} — no raw data")
            continue
        profile = build_wallet_profile(addr, label, raw_data[addr])
        profile = compute_features(profile)
        dep_count = len(profile.deployments)
        warmup = f"{profile.f1_warmup_hours:.4f}h" if profile.f1_warmup_hours is not None else "None"
        burst = f"{profile.f4_burstiness:.4f}" if profile.f4_burstiness is not None else "None"
        entr = f"{profile.f5_nonce_entropy:.4f}" if profile.f5_nonce_entropy is not None else "None"
        cv = f"{profile.f2_funding_cv:.4f}" if profile.f2_funding_cv is not None else "None"
        ownership_hops = sum(1 for d in profile.deployments if d.owner_transfer_to)
        print(
            f"  {addr[:12]}... [{label:8s}] "
            f"deploys={dep_count:3d}  warmup={warmup:>12}  "
            f"burst={burst:>8}  entropy={entr:>8}  CV={cv:>8}  "
            f"ownership_hops={ownership_hops}"
        )
        profiles.append(profile)

    # Derive thresholds
    print("\n[INFO] Deriving thresholds...")
    results = derive_thresholds(profiles)

    # Generate settings block
    settings_block = generate_settings_block(results)

    # Save full results
    # Convert profiles to dict for JSON serialization
    profiles_json = []
    for p in profiles:
        pd = asdict(p)
        profiles_json.append(pd)

    output_data = {
        "thresholds": results,
        "profiles": profiles_json,
        "parameters": {
            "f3_similarity_threshold": F3_SIMILARITY_THRESHOLD,
            "f3_window_hours": F3_WINDOW_SEC / 3600,
            "f3_max_cap_per_deployment": F3_MAX_CAP,
            "ownership_transfer_selectors": list(TRANSFER_OWNERSHIP_SELECTORS),
        }
    }
    with open(args.output, "w") as f:
        json.dump(output_data, f, indent=2, default=str)
    print(f"\n[INFO] Full results saved to {args.output}")

    # Print report to console
    print_report(profiles, results, settings_block)


if __name__ == "__main__":
    main()