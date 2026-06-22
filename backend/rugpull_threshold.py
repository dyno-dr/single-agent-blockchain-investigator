"""
derive_rugpull_thresholds.py
────────────────────────────────────────────────────────────────────────────
Fetches on-chain data for all 70 addresses (20 genuine + 50 rugpull),
computes 6 features per wallet, and prints the threshold values to use
in RugpullProfileConfig in settings/base.py.

HOW TO RUN:
  1. Put your Etherscan API key in a file called .env in the same folder:
       ETHERSCAN_API_KEY=your_key_here

  2. Run:
       python derive_rugpull_thresholds.py

  3. It saves raw data to:  raw_wallet_data.json   (so you don't re-fetch)
     It saves results to:   threshold_results.json
     It prints a summary to the terminal.

  4. Copy the printed threshold values into your settings/base.py

FEATURES COMPUTED:
  F1 - Warmup time      : hours from first activity to first deployment
  F2 - Funding CV       : consistency of funding lead-time before deployments
  F3 - Dry run count    : failed/similar transactions before deployment
  F4 - Burstiness       : how clumped deployments are in time
  F5 - Nonce entropy    : how scripted the transaction timing looks
  F7 - Template sim     : how similar setup sequences are across deployments
       (F6 gas feature skipped - pending data availability)
"""

import json
from typing import Any
import math
import os
import time
import statistics
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import requests
from dotenv import load_dotenv

load_dotenv()

# ─────────────────────────────────────────────────────────────────────────────
# ADDRESS LISTS
# ─────────────────────────────────────────────────────────────────────────────

GENUINE_ADDRESSES = [
    "0xaba7161a7fb69c88e16ed9f455ce62b791ee4d03",
    "0xd45058bf25bbd8f586124c479d384c8c708ce23a",
    "0x7a59205733a593a184156f91085dc64ed050408f",
    "0xcaff2ff35295b803b33f3cf652224532cfc64301",
    "0xe9da256a28630efdc637bfd4c65f0887be1aeda8",
    "0xce8d642cdd81d805b9b770da9af3790e7e3dfb05",
    "0x2aa5ebd85ba9fbdc87a774c29cdad806d7892820",
    "0xc9b6321dc216d91e626e9baa61b06b0e4d55bdb1",
    "0x4265de963cdd60629d03fee2cd3285e6d5ff6015",
    "0xcc9b1fa104d13639c287bd77555e90d4558282fe",
    "0x0bdfd4ad937ff179985276b7f5be7ae3de0229e6",
    "0xfd16f84e1f9bb5ec33b52d0133d61f7d20699658",
    "0xc352b534e8b987e036a93539fd6897f53488e56a",
    "0x9056d15c49b19df52ffad1e6c11627f035c0c960",
    "0x1354d8cef0b3459e2677db6321c25639d2b658bd",
    "0x3ab208d3ce512f2ac0aa821eecf2b816a96799b0",
    "0x5ef6e3570a32ea63c7bfb69bbb72fe0cd37dfa42",
    "0x7ea79bad324579fac7a7645c62fe8c60a8b73055",
]

RUGPULL_ADDRESSES = [
    "0x00859b3baac525143bb8a3ee3e19ddf9daf2408c",
    "0x00df4e8d293d57718aac0b18cbfbe128c5d484ef",
    "0x021ac107832f1c10400e3190281d3ffed4f38bc6",
    "0x03f15ecc984669237aac41392b5dd6cf3132ff35",
    "0x0659724a5293127789660734d64c18254e7dbd18",
    "0x07cb37ed2198fc7a2a1671ac94311738a548b877",
    "0x0e04ba718d3c7ac4d7c8fa357ab73abdd45d89dc",
    "0x0ea10e39a2923a7fc7354f40daac938764b71ca8",
    "0x0eb1849c92eda5b346bdc13116f12127fc75c3b3",
    "0x10850762bac0dc6660630c1effe188a7cbfddc88",
    "0x1123aaf2d3aa6e075c9e7e232895818387826026",
    "0x154827328a10e1c5c2878acba12bc6a4ed3c6b2a",
    "0x17a45f80efd20594afe2c59d7e1ae7ab0c6954cc",
    "0x19cc350a22eb342e91a2199abacc8c5bbd87c7a5",
    "0x19fde224c03249bd0ef503815dcad200c57c2adc",
    "0x1a1427a73b7cb0f4ea3f71c6c8090c4366c8ebe1",
    "0x1b2ef9d5db72ea1103fc24eedd2226477409383a",
    "0x1d524a067f1828665273a0f85bd58cbb1cd18c3f",
    "0x2108007b64b3968b4a1c21fa1af0ea8e7b2d3912",
    "0x212da8c9dad7e9b6a71422665c58bf9a7ecae6d0",
    "0x2272ecf43a7481088fa2d4ba9109804ed5a31901",
    "0x25d295635e747ec6ff3f0c1e19e30a335de66ed5",
    "0x266db4743755109a5926d6fded5ed6f6a284ab98",
    "0x2b3ab8e7bb14988616359b78709538b10900ab7d",
    "0x32220f07dbcd18149f619f28cd09fd911cc0372d",
    "0x3450265c76c0fb04b4a6b5195aebe00314040c6f",
    "0x34b365c3a98d0ec12a680047fe299aff2a032554",
    "0x3549d95f144c0cc9eb5fc29fc8b6881a84d51536",
    "0x39f922521855738ea802ca26da385e0bddf98600",
    "0x3a0bef9700474a00b10a1063b59685de6e690c08",
    "0x3e18eda374aa344f4a6f0d3ff73f10e6ced8ad21",
    "0x3fbfac2397902ba762d6da683b567dc5bbb1fce0",
    "0x42fab76321440273044ef6a157e86a9777b5809b",
    "0x44343df908f0fb88326d03ad828524c08f61e4bc",
    "0x457d955ef9b1e942ae3d7185e69a3ecfbcdd625d",
    "0x460fd5059e7301680fa53e63bbbf7272e643e89c",
    "0x476f3a6b93951f081b1ec119530defaacaa9a330",
    "0x47a511b96f180d378f00f6cd64f9ab3393c6c8d7",
    "0x47d150897c96b99a09d3796b67de8487d1f0063e",
    "0x48dcfd6fe331348600a377dfeb0ab3db0a415f88",
    "0x494b33439f5790168640d55f8b7ac96e6d3bf4f9",
    "0x49fd6b8ad6aa667d03716f4632157538be1159d4",
    "0x4a4c729448091355d4f82b2b57dbcc946092b670",
    "0x4b76837f8d8ad0a28590d06e53dcd44b6b7d4554",
    "0x4b841c0019475c4bac90764f947db202fce44678",
    "0x4fe4e666be5752f1fdd210f4ab5de2cc26e3e0e8",
    "0x5295b474f3a0bb39418456c96d6fcf13901a4aa1",
    "0x53e83e786444d603c87036487036cd43a3e91704",
    "0x585faacf6cfc7c379414334c30e1097a26c7cba6",
    "0x58efa9aae017589b9fadbea3ed6f09730635efaf",
]

# ─────────────────────────────────────────────────────────────────────────────
# ETHERSCAN FETCHER
# ─────────────────────────────────────────────────────────────────────────────

ETHERSCAN_BASE = "https://api.etherscan.io/v2/api"
API_KEY = os.getenv("ETHERSCAN_API_KEY", "")

if not API_KEY:
    raise SystemExit(
        "\n[ERROR] No Etherscan API key found.\n"
        "Create a .env file in this folder with:\n"
        "  ETHERSCAN_API_KEY=your_key_here\n"
        "Get a free key at: https://etherscan.io/apis\n"
    )


def etherscan_get(params: dict, retries: int = 3) -> dict:
    """Call Etherscan V2 API with retry logic and rate limiting."""
    params["apikey"] = API_KEY
    params.setdefault("chainid", 1)  # Ethereum mainnet (V2 requirement)
    for attempt in range(retries):
        try:
            resp = requests.get(ETHERSCAN_BASE, params=params, timeout=15)
            resp.raise_for_status()
            data = resp.json()
            result = data.get("result", [])
            # Detect deprecated-endpoint / NOTOK error returned as a string
            if isinstance(result, str):
                msg = result.lower()
                if "rate limit" in msg:
                    print("    [rate limit hit - waiting 6s]")
                    time.sleep(6)
                    continue
                # Any other string result means the API returned an error
                raise RuntimeError(f"Etherscan API error: {result}")
            return data
        except RuntimeError:
            raise  # surface immediately — don't retry API errors
        except Exception as e:
            print(f"    [attempt {attempt+1} failed: {e}]")
            time.sleep(3)
    return {"status": "0", "result": []}


def fetch_normal_txs(address: str) -> list:
    """Fetch all normal outgoing + incoming transactions for a wallet."""
    all_txs = []
    page = 1
    while True:
        data = etherscan_get({
            "module": "account",
            "action": "txlist",
            "address": address,
            "startblock": 0,
            "endblock": 99999999,
            "page": page,
            "offset": 1000,
            "sort": "asc",
        })
        result = data.get("result", [])
        if not isinstance(result, list) or len(result) == 0:
            break
        all_txs.extend(result)
        if len(result) < 1000:
            break
        page += 1
        time.sleep(0.25)  # stay under free tier rate limit
    return all_txs


def fetch_internal_txs(address: str) -> list:
    """Fetch internal transactions - catches factory-based deployments."""
    data = etherscan_get({
        "module": "account",
        "action": "txlistinternal",
        "address": address,
        "startblock": 0,
        "endblock": 99999999,
        "page": 1,
        "offset": 1000,
        "sort": "asc",
    })
    result = data.get("result", [])
    return result if isinstance(result, list) else []


def fetch_wallet_data(address: str) -> dict:
    """
    Fetch all data needed for feature computation for one wallet.
    Returns a dict with normal_txs and internal_txs.
    """
    print(f"  Fetching normal txs for {address[:10]}...")
    normal = fetch_normal_txs(address)
    time.sleep(0.3)

    print(f"  Fetching internal txs for {address[:10]}...")
    internal = fetch_internal_txs(address)
    time.sleep(0.3)

    return {
        "address": address,
        "normal_txs": normal,
        "internal_txs": internal,
    }


# ─────────────────────────────────────────────────────────────────────────────
# DEPLOYMENT DETECTION
# ─────────────────────────────────────────────────────────────────────────────

def find_deployments(wallet_data: dict) -> list:
    """
    Find all contract deployments from this wallet.
    Checks both:
      - Direct deployments: normal tx where 'to' is empty/null
      - Factory deployments: internal tx where 'type' is 'create'

    Returns list of dicts: {timestamp, contract_address, tx_hash,
                             input_data, method, gas_price}
    """
    address = wallet_data["address"].lower()
    deployments = []
    seen_contracts = set()

    # Direct deployments - 'to' field is empty means contract creation
    for tx in wallet_data["normal_txs"]:
        from_addr = tx.get("from", "").lower()
        to_addr = tx.get("to", "").lower()
        contract_addr = tx.get("contractAddress", "").lower()

        if from_addr == address and to_addr == "" and contract_addr:
            if contract_addr not in seen_contracts:
                seen_contracts.add(contract_addr)
                deployments.append({
                    "timestamp": int(tx.get("timeStamp", 0)),
                    "contract_address": contract_addr,
                    "tx_hash": tx.get("hash", ""),
                    "input_data": tx.get("input", ""),
                    "method": "direct",
                    "gas_price": int(tx.get("gasPrice", 0)),
                    "is_error": tx.get("isError", "0") == "1",
                    "nonce": int(tx.get("nonce", 0)),
                })

    # Factory deployments - internal tx of type 'create'
    for tx in wallet_data["internal_txs"]:
        from_addr = tx.get("from", "").lower()
        tx_type = tx.get("type", "").lower()
        contract_addr = tx.get("contractAddress", "").lower()

        if from_addr == address and tx_type == "create" and contract_addr:
            if contract_addr not in seen_contracts:
                seen_contracts.add(contract_addr)
                deployments.append({
                    "timestamp": int(tx.get("timeStamp", 0)),
                    "contract_address": contract_addr,
                    "tx_hash": tx.get("hash", ""),
                    "input_data": "",  # internal txs don't carry full input
                    "method": "factory",
                    "gas_price": 0,
                    "is_error": tx.get("isError", "0") == "1",
                    "nonce": -1,
                })

    # Sort by timestamp ascending
    deployments.sort(key=lambda d: d["timestamp"])
    return deployments


# ─────────────────────────────────────────────────────────────────────────────
# FEATURE COMPUTATIONS
# ─────────────────────────────────────────────────────────────────────────────

def compute_f1_warmup_hours(wallet_data: dict, deployments: list) -> float | None:
    """
    F1: Hours from wallet's very first on-chain activity to first deployment.

    First activity = earliest timestamp across ALL transactions
                     (incoming or outgoing - wallet existed when it first
                     received or sent anything).
    First deployment = earliest deployment timestamp.

    Returns None if no deployments found.
    """
    if not deployments:
        return None

    all_txs = wallet_data["normal_txs"] + wallet_data["internal_txs"]
    if not all_txs:
        return None

    timestamps = [int(t.get("timeStamp", 0)) for t in all_txs if t.get("timeStamp")]
    if not timestamps:
        return None

    first_activity = min(timestamps)
    first_deploy = deployments[0]["timestamp"]

    diff_seconds = first_deploy - first_activity
    # Can be 0 or slightly negative (data quirk) - floor at 0
    diff_hours = max(0.0, diff_seconds / 3600.0)
    return round(diff_hours, 4)


def compute_f2_funding_cv(wallet_data: dict, deployments: list) -> float | None:
    """
    F2: Consistency of funding lead-time before deployments.

    For each deployment, find the most recent INCOMING transaction
    before it (within 72 hours). Record the gap in hours.
    Compute the coefficient of variation (CV) of those gaps.

    CV = std_dev / mean
    Low CV (< 0.2) means funding always arrives at the same time before
    deployment = scripted/automated pattern.

    Returns None if fewer than 2 deployments with funding found.
    """
    address = wallet_data["address"].lower()
    WINDOW_SECONDS = 72 * 3600  # 72 hour look-back window

    # Get all incoming transactions
    incoming = [
        tx for tx in wallet_data["normal_txs"]
        if tx.get("to", "").lower() == address
        and tx.get("isError", "0") == "0"
    ]

    if not incoming:
        return None

    funding_gaps = []

    for dep in deployments:
        dep_time = dep["timestamp"]
        window_start = dep_time - WINDOW_SECONDS

        # Find the most recent incoming tx before this deployment
        candidates = [
            tx for tx in incoming
            if window_start <= int(tx.get("timeStamp", 0)) < dep_time
        ]

        if not candidates:
            continue

        # Closest one to the deployment (most recent before it)
        closest = max(candidates, key=lambda t: int(t.get("timeStamp", 0)))
        gap_hours = (dep_time - int(closest["timeStamp"])) / 3600.0
        funding_gaps.append(gap_hours)

    if len(funding_gaps) < 2:
        return None

    mean_gap = statistics.mean(funding_gaps)
    if mean_gap == 0:
        return 0.0

    std_gap = statistics.stdev(funding_gaps)
    cv = std_gap / mean_gap
    return round(cv, 4)


def bytecode_similarity(a: str, b: str, k: int = 4) -> float:
    """
    Compute Jaccard similarity between two hex strings using k-byte chunks.
    Used to detect dry-run (test) transactions before deployment.

    Jaccard = size of intersection / size of union of chunk sets.
    Returns 0.0 to 1.0 (1.0 = identical).
    """
    if not a or not b:
        return 0.0
    # Remove 0x prefix if present
    a = a.lower().replace("0x", "")
    b = b.lower().replace("0x", "")
    if len(a) < k * 2 or len(b) < k * 2:
        return 0.0

    # Build sets of k-byte chunks (each byte = 2 hex chars)
    step = k * 2
    set_a = set(a[i:i+step] for i in range(0, len(a) - step + 1, step))
    set_b = set(b[i:i+step] for i in range(0, len(b) - step + 1, step))

    if not set_a or not set_b:
        return 0.0

    intersection = len(set_a & set_b)
    union = len(set_a | set_b)
    return round(intersection / union, 4) if union > 0 else 0.0


def compute_f3_dryrun_count(wallet_data: dict, deployments: list) -> int:
    """
    F3: Total dry-run transactions detected across all deployments.

    A dry-run is a transaction sent FROM this wallet BEFORE a deployment
    within a 1-hour window that either:
      (a) Failed/reverted (isError = '1'), OR
      (b) Has input data with >= 70% bytecode similarity to the deployment

    Returns total count of dry-run transactions.
    """
    address = wallet_data["address"].lower()
    WINDOW_SECONDS = 3600  # 1 hour before deployment
    SIMILARITY_THRESHOLD = 0.70

    # Outgoing transactions
    outgoing = [
        tx for tx in wallet_data["normal_txs"]
        if tx.get("from", "").lower() == address
    ]

    total_dryruns = 0

    for dep in deployments:
        dep_time = dep["timestamp"]
        dep_input = dep.get("input_data", "")
        window_start = dep_time - WINDOW_SECONDS

        for tx in outgoing:
            tx_time = int(tx.get("timeStamp", 0))
            if not (window_start <= tx_time < dep_time):
                continue

            tx_hash = tx.get("hash", "")
            if tx_hash == dep.get("tx_hash", ""):
                continue  # skip the deployment itself

            is_failed = tx.get("isError", "0") == "1"
            tx_input = tx.get("input", "")

            if is_failed:
                total_dryruns += 1
            elif dep_input and tx_input and len(tx_input) > 10:
                sim = bytecode_similarity(tx_input, dep_input)
                if sim >= SIMILARITY_THRESHOLD:
                    total_dryruns += 1

    return total_dryruns


def compute_f4_burstiness(deployments: list) -> float | None:
    """
    F4: Burstiness of deployment timeline.

    Uses the Goh-Barabasi burstiness parameter:
      B = (std - mean) / (std + mean)   where values are inter-deployment gaps

    Range: -1 (perfectly regular) to +1 (extremely bursty/clumped)
    Returns None if fewer than 2 deployments.
    """
    if len(deployments) < 2:
        return None

    timestamps = [d["timestamp"] for d in deployments]
    timestamps.sort()

    gaps = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]

    if len(gaps) == 1:
        # Only one gap - can't compute meaningful burstiness
        # Return 0 as neutral (single gap tells us nothing about clustering)
        return 0.0

    mean_gap = statistics.mean(gaps)
    std_gap = statistics.stdev(gaps)

    if mean_gap + std_gap == 0:
        return 0.0

    b = (std_gap - mean_gap) / (std_gap + mean_gap)
    return round(b, 4)


def compute_f5_nonce_entropy(wallet_data: dict) -> float | None:
    """
    F5: Entropy of inter-transaction time gaps (nonce regularity).

    Steps:
      1. Get all OUTGOING transactions sorted by nonce/timestamp
      2. Compute time gaps between consecutive transactions
      3. Round each gap to nearest minute (groups similar waiting times)
      4. Count frequency of each rounded gap value
      5. Compute Shannon entropy: H = -sum(p * log2(p))

    Low entropy = wallet always waits the same amount of time = scripted
    High entropy = irregular timing = more human-like

    Returns None if fewer than 3 outgoing transactions.
    """
    address = wallet_data["address"].lower()

    outgoing = sorted(
        [
            tx for tx in wallet_data["normal_txs"]
            if tx.get("from", "").lower() == address
            and tx.get("isError", "0") == "0"
        ],
        key=lambda t: (int(t.get("nonce", 0)), int(t.get("timeStamp", 0)))
    )

    if len(outgoing) < 3:
        return None

    timestamps = [int(tx["timeStamp"]) for tx in outgoing]
    gaps_seconds = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]

    # Filter out negative or zero gaps (data artifacts)
    gaps_seconds = [g for g in gaps_seconds if g > 0]

    if len(gaps_seconds) < 2:
        return None

    # Round to nearest minute for binning
    gaps_minutes = [round(g / 60) for g in gaps_seconds]
    gaps_minutes = [g for g in gaps_minutes if g >= 0]

    if not gaps_minutes:
        return None

    # Frequency count
    counts = Counter(gaps_minutes)
    total = sum(counts.values())

    # Shannon entropy
    entropy = 0.0
    for count in counts.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)

    return round(entropy, 4)


def selector_sequence(input_data: str) -> str:
    """
    Extract the 4-byte function selector from transaction input data.
    Returns '0x' + first 8 hex chars, or 'transfer' for plain ETH transfers.
    """
    if not input_data or input_data == "0x" or len(input_data) < 10:
        return "ETH_TRANSFER"
    return input_data[:10].lower()  # '0x' + 8 hex chars


def compute_f7_template_similarity(wallet_data: dict, deployments: list) -> float | None:
    """
    F7: How similar are the setup sequences across this wallet's deployments?

    For each deployment, extract the sequence of function selectors called
    in the 24 hours before it. Compare every pair of sequences using
    normalised edit distance (Levenshtein similarity).

    Returns the AVERAGE pairwise similarity across all deployment pairs.
    Returns None if fewer than 2 deployments.
    Returns 0.0 if only 1 deployment (no pairs to compare).
    """
    if len(deployments) < 2:
        return None

    address = wallet_data["address"].lower()
    WINDOW_SECONDS = 24 * 3600  # 24 hours before deployment

    outgoing = sorted(
        [
            tx for tx in wallet_data["normal_txs"]
            if tx.get("from", "").lower() == address
        ],
        key=lambda t: int(t.get("timeStamp", 0))
    )

    # Build setup sequence for each deployment
    sequences = []
    for dep in deployments:
        dep_time = dep["timestamp"]
        window_start = dep_time - WINDOW_SECONDS

        seq = []
        for tx in outgoing:
            tx_time = int(tx.get("timeStamp", 0))
            if window_start <= tx_time < dep_time:
                sel = selector_sequence(tx.get("input", ""))
                seq.append(sel)
        sequences.append(seq)

    if len(sequences) < 2:
        return None

    # Compute pairwise Levenshtein similarity
    def levenshtein(s1: list, s2: list) -> int:
        """Standard dynamic programming edit distance."""
        m, n = len(s1), len(s2)
        if m == 0:
            return n
        if n == 0:
            return m
        dp = list(range(n + 1))
        for i in range(1, m + 1):
            prev = dp[:]
            dp[0] = i
            for j in range(1, n + 1):
                if s1[i-1] == s2[j-1]:
                    dp[j] = prev[j-1]
                else:
                    dp[j] = 1 + min(prev[j-1], prev[j], dp[j-1])
        return dp[n]

    similarities = []
    for i in range(len(sequences)):
        for j in range(i + 1, len(sequences)):
            s1, s2 = sequences[i], sequences[j]
            max_len = max(len(s1), len(s2))
            if max_len == 0:
                similarities.append(1.0)
                continue
            ed = levenshtein(s1, s2)
            sim = 1.0 - (ed / max_len)
            similarities.append(max(0.0, sim))

    if not similarities:
        return 0.0

    return round(statistics.mean(similarities), 4)


# ─────────────────────────────────────────────────────────────────────────────
# MAIN PIPELINE
# ─────────────────────────────────────────────────────────────────────────────

def compute_all_features(wallet_data: dict) -> dict:
    """Compute all 6 features for one wallet. Returns feature dict."""
    deployments = find_deployments(wallet_data)
    n_deployments = len(deployments)

    f1 = compute_f1_warmup_hours(wallet_data, deployments)
    f2 = compute_f2_funding_cv(wallet_data, deployments)
    f3 = compute_f3_dryrun_count(wallet_data, deployments)
    f4 = compute_f4_burstiness(deployments)
    f5 = compute_f5_nonce_entropy(wallet_data)
    f7 = compute_f7_template_similarity(wallet_data, deployments)

    return {
        "address": wallet_data["address"],
        "n_deployments": n_deployments,
        "n_normal_txs": len(wallet_data["normal_txs"]),
        "f1_warmup_hours": f1,
        "f2_funding_cv": f2,
        "f3_dryrun_count": f3,
        "f4_burstiness": f4,
        "f5_nonce_entropy": f5,
        "f7_template_similarity": f7,
    }


def percentile(data: list, p: float) -> float:
    """Compute p-th percentile of a list (0-100 scale)."""
    if not data:
        return 0.0
    sorted_data = sorted(data)
    n = len(sorted_data)
    idx = (p / 100) * (n - 1)
    lower = int(idx)
    upper = min(lower + 1, n - 1)
    frac = idx - lower
    return round(sorted_data[lower] + frac * (sorted_data[upper] - sorted_data[lower]), 4)


def compute_thresholds(rug_values: list, gen_values: list, feature_name: str,
                       higher_is_worse: bool = True) -> dict:
    """
    Compute threshold values from both groups for one feature.

    higher_is_worse=True  means high values → suspicious (e.g. burstiness)
    higher_is_worse=False means low values  → suspicious (e.g. warmup hours)

    Returns dict with all threshold values and separation quality score.
    """
    rug_clean = [v for v in rug_values if v is not None]
    gen_clean = [v for v in gen_values if v is not None]

    if not rug_clean:
        return {"error": "no rugpull data", "feature": feature_name}

    result: dict[str, Any] = {
        "feature": feature_name,
        "higher_is_worse": higher_is_worse,
        "rugpull": {
            "n": len(rug_clean),
            "p25": percentile(rug_clean, 25),
            "median": percentile(rug_clean, 50),
            "p75": percentile(rug_clean, 75),
            "min": min(rug_clean),
            "max": max(rug_clean),
        },
    }

    if gen_clean:
        result["genuine"] = {
            "n": len(gen_clean),
            "p25": percentile(gen_clean, 25),
            "median": percentile(gen_clean, 50),
            "p75": percentile(gen_clean, 75),
            "min": min(gen_clean),
            "max": max(gen_clean),
        }

        # Separation score: what fraction of genuine fall on the "safe" side
        # of the rugpull median threshold?
        rug_median = result["rugpull"]["median"]
        if higher_is_worse:
            # Genuine that are BELOW the rugpull median (good — they look different)
            gen_safe = sum(1 for v in gen_clean if v < rug_median)
        else:
            # Genuine that are ABOVE the rugpull median (good — they look different)
            gen_safe = sum(1 for v in gen_clean if v > rug_median)

        result["separation_score"] = round(gen_safe / len(gen_clean), 2)
        result["separation_note"] = (
            f"{gen_safe}/{len(gen_clean)} genuine wallets fall on the "
            f"'safe' side of the rugpull median threshold"
        )
    else:
        result["genuine"] = {"n": 0, "note": "no genuine data available"}
        result["separation_score"] = None

    # Derive recommended thresholds
    if higher_is_worse:
        result["recommended_thresholds"] = {
            "HIGH_severity_above":   result["rugpull"]["median"],
            "MEDIUM_severity_above": result["rugpull"]["p25"],
            "CLEAN_FLOOR_below":     result["genuine"]["p25"] if gen_clean else None,
            "explanation": (
                "Values ABOVE HIGH threshold match bottom 50% of rugpull group. "
                "Values BELOW CLEAN_FLOOR rarely appear in genuine creators."
            )
        }
    else:
        result["recommended_thresholds"] = {
            "HIGH_severity_below":   result["rugpull"]["median"],
            "MEDIUM_severity_below": result["rugpull"]["p75"],
            "CLEAN_FLOOR_above":     result["genuine"]["p25"] if gen_clean else None,
            "explanation": (
                "Values BELOW HIGH threshold match top 50% of rugpull group. "
                "Values ABOVE CLEAN_FLOOR rarely appear in genuine creators."
            )
        }

    return result


def print_summary(all_thresholds: list, rug_features: list, gen_features: list):
    """Print a clean summary of thresholds to paste into settings/base.py"""

    print("\n")
    print("=" * 70)
    print("  THRESHOLD DERIVATION RESULTS")
    print("=" * 70)

    print(f"\n  Dataset: {len(rug_features)} rugpull wallets, "
          f"{len(gen_features)} genuine wallets\n")

    # Per-feature summary
    for t in all_thresholds:
        if "error" in t:
            print(f"\n  {t['feature']}: SKIPPED — {t['error']}")
            continue

        print(f"\n  {'─'*66}")
        print(f"  {t['feature']}")
        print(f"  {'─'*66}")

        r = t.get("rugpull", {})
        g = t.get("genuine", {})

        print(f"  Rugpull group (n={r.get('n',0)}):")
        print(f"    min={r.get('min','?')}  p25={r.get('p25','?')}  "
              f"median={r.get('median','?')}  p75={r.get('p75','?')}  "
              f"max={r.get('max','?')}")

        if g.get("n", 0) > 0:
            print(f"  Genuine group (n={g.get('n',0)}):")
            print(f"    min={g.get('min','?')}  p25={g.get('p25','?')}  "
                  f"median={g.get('median','?')}  p75={g.get('p75','?')}  "
                  f"max={g.get('max','?')}")
            sep = t.get("separation_score")
            note = t.get("separation_note", "")
            quality = "GOOD" if sep and sep >= 0.7 else ("FAIR" if sep and sep >= 0.5 else "WEAK")
            print(f"  Separation quality: {quality} ({note})")
        else:
            print(f"  Genuine group: no data")

        thresh = t.get("recommended_thresholds", {})
        print(f"  Recommended thresholds:")
        for k, v in thresh.items():
            if k != "explanation":
                print(f"    {k}: {v}")
        print(f"  Note: {thresh.get('explanation', '')}")

    # Settings block to copy-paste
    print("\n")
    print("=" * 70)
    print("  COPY THIS INTO YOUR settings/base.py → RugpullProfileConfig")
    print("=" * 70)
    print()

    settings_lines = []
    feature_map = {
        "F1 Warmup Hours":        ("RUG_001", False),
        "F2 Funding CV":          ("RUG_002", False),
        "F3 Dry-Run Count":       ("RUG_003", True),
        "F4 Burstiness":          ("RUG_004", True),
        "F5 Nonce Entropy":       ("RUG_005", False),
        "F7 Template Similarity": ("RUG_007", True),
    }

    for t in all_thresholds:
        if "error" in t:
            continue
        fname = t["feature"]
        if fname not in feature_map:
            continue

        prefix, higher_is_worse = feature_map[fname]
        thresh = t.get("recommended_thresholds", {})
        r = t.get("rugpull", {})
        g = t.get("genuine", {})

        if higher_is_worse:
            high_val = thresh.get("HIGH_severity_above", "# TODO")
            med_val  = thresh.get("MEDIUM_severity_above", "# TODO")
            floor    = thresh.get("CLEAN_FLOOR_below", "# TODO")
            settings_lines.append(
                f"    # {fname}: rugpull median={r.get('median')}, "
                f"genuine median={g.get('median', 'N/A')}"
            )
            settings_lines.append(
                f"    {prefix}_WARMUP_HIGH: float = {high_val}  # noqa"
                if "WARMUP" in prefix else
                f"    {prefix}_HIGH: float = {high_val}"
            )
            settings_lines.append(f"    {prefix}_MEDIUM: float = {med_val}")
            settings_lines.append(f"    {prefix}_CLEAN_FLOOR: float = {floor}")
        else:
            high_val = thresh.get("HIGH_severity_below", "# TODO")
            med_val  = thresh.get("MEDIUM_severity_below", "# TODO")
            floor    = thresh.get("CLEAN_FLOOR_above", "# TODO")
            settings_lines.append(
                f"    # {fname}: rugpull median={r.get('median')}, "
                f"genuine median={g.get('median', 'N/A')}"
            )
            settings_lines.append(f"    {prefix}_HIGH: float = {high_val}")
            settings_lines.append(f"    {prefix}_MEDIUM: float = {med_val}")
            settings_lines.append(f"    {prefix}_CLEAN_FLOOR: float = {floor}")

        settings_lines.append("")

    print("  class RugpullProfileConfig(BaseModel):")
    for line in settings_lines:
        print(f"  {line}")


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def main():
    raw_cache_file = Path("raw_wallet_data.json")
    results_file   = Path("threshold_results.json")

    # ── Step 1: Fetch or load raw data ──────────────────────────────────────
    if raw_cache_file.exists():
        print(f"\n[INFO] Loading cached raw data from {raw_cache_file}")
        print("       (Delete this file to force a fresh Etherscan fetch)\n")
        with open(raw_cache_file) as f:
            raw_data = json.load(f)
    else:
        raw_data = {}

        all_addresses = (
            [("genuine", a) for a in GENUINE_ADDRESSES] +
            [("rugpull", a) for a in RUGPULL_ADDRESSES]
        )

        total = len(all_addresses)
        print(f"\n[INFO] Fetching data for {total} addresses from Etherscan...")
        print("       This will take ~10-15 minutes due to API rate limits.\n")

        for i, (label, addr) in enumerate(all_addresses, 1):
            print(f"[{i:3d}/{total}] {label.upper()} {addr}")
            wallet_data = fetch_wallet_data(addr)
            raw_data[addr] = {"label": label, **wallet_data}
            time.sleep(0.5)  # stay within free tier limits

        with open(raw_cache_file, "w") as f:
            json.dump(raw_data, f, indent=2)
        print(f"\n[INFO] Raw data saved to {raw_cache_file}\n")

    # ── Step 2: Compute features ─────────────────────────────────────────────
    print("[INFO] Computing features for all wallets...\n")

    rug_features = []
    gen_features = []

    for addr, data in raw_data.items():
        label = data.get("label", "unknown")
        features = compute_all_features(data)
        features["label"] = label

        n_dep = features["n_deployments"]
        f1    = features["f1_warmup_hours"]
        f4    = features["f4_burstiness"]
        f5    = features["f5_nonce_entropy"]

        print(f"  {addr[:12]}... [{label:7s}] "
              f"deployments={n_dep:3d}  "
              f"warmup={str(f1)+'h':>10}  "
              f"burst={str(f4):>7}  "
              f"entropy={str(f5):>7}")

        if label == "rugpull":
            rug_features.append(features)
        else:
            gen_features.append(features)

    # ── Step 3: Compute thresholds ───────────────────────────────────────────
    print("\n[INFO] Computing thresholds...\n")

    def get_values(feat_list: list, key: str) -> list:
        return [f[key] for f in feat_list]

    all_thresholds = [
        compute_thresholds(
            get_values(rug_features, "f1_warmup_hours"),
            get_values(gen_features, "f1_warmup_hours"),
            "F1 Warmup Hours",
            higher_is_worse=False,  # LOW warmup hours = suspicious
        ),
        compute_thresholds(
            get_values(rug_features, "f2_funding_cv"),
            get_values(gen_features, "f2_funding_cv"),
            "F2 Funding CV",
            higher_is_worse=False,  # LOW CV = consistent = scripted = suspicious
        ),
        compute_thresholds(
            get_values(rug_features, "f3_dryrun_count"),
            get_values(gen_features, "f3_dryrun_count"),
            "F3 Dry-Run Count",
            higher_is_worse=True,   # MORE dry-runs = suspicious
        ),
        compute_thresholds(
            get_values(rug_features, "f4_burstiness"),
            get_values(gen_features, "f4_burstiness"),
            "F4 Burstiness",
            higher_is_worse=True,   # MORE bursty = suspicious
        ),
        compute_thresholds(
            get_values(rug_features, "f5_nonce_entropy"),
            get_values(gen_features, "f5_nonce_entropy"),
            "F5 Nonce Entropy",
            higher_is_worse=False,  # LOW entropy = scripted = suspicious
        ),
        compute_thresholds(
            get_values(rug_features, "f7_template_similarity"),
            get_values(gen_features, "f7_template_similarity"),
            "F7 Template Similarity",
            higher_is_worse=True,   # HIGH similarity = templated = suspicious
        ),
    ]

    # ── Step 4: Save and print ────────────────────────────────────────────────
    output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "rugpull_count": len(rug_features),
        "genuine_count": len(gen_features),
        "thresholds": all_thresholds,
        "rugpull_features": rug_features,
        "genuine_features": gen_features,
    }

    with open(results_file, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\n[INFO] Full results saved to {results_file}")

    print_summary(all_thresholds, rug_features, gen_features)

    print("\n[DONE] Copy the settings block above into your settings/base.py\n")


if __name__ == "__main__":
    main()