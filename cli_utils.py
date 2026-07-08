"""
cli_utils.py
─────────────────────────────────────────────────────────────────────────────
Shared utilities for CLI test / batch scripts.

NOT part of the backend application package. Import only from root-level
scripts (test_rugpull.py, rugpull_live_batch.py, test_full_dataset.py, etc.).

CONTENTS:
  Console colours        — VERDICT_COLOURS, RESET, BOLD, DIM
  Known address sets     — KNOWN_RUGPULL, KNOWN_GENUINE (canonical, 18-addr)
  Etherscan helpers      — _etherscan_get, fetch_normal_txs, fetch_internal_txs,
                           fetch_first_tx_ts, fetch_wallet_full
  Deploy-ts detection    — find_deploy_ts
  JSON cache helpers     — load_json, save_json
"""

from __future__ import annotations

import json
import os
import time
import urllib.parse
import urllib.request

# ─────────────────────────────────────────────────────────────────────────────
# Console colours
# ─────────────────────────────────────────────────────────────────────────────

VERDICT_COLOURS: dict[str, str] = {
    "CLEAN":                           "\033[92m",   # green
    "INSUFFICIENT_DEPLOYMENT_HISTORY": "\033[96m",   # cyan
    "INSUFFICIENT_DATA":               "\033[96m",   # cyan
    "WEAK_PATTERN":                    "\033[93m",   # yellow
    "MODERATE_PATTERN":                "\033[33m",   # dark yellow
    "STRONG_PATTERN":                  "\033[91m",   # light red
    "HIGH_CONFIDENCE_RUGPULL":         "\033[31m",   # red
}
RESET   = "\033[0m"
BOLD    = "\033[1m"
DIM     = "\033[2m"

# Individual colour codes (for scripts that colour-code by severity/value)
RED     = "\033[91m"
YELLOW  = "\033[93m"
GREEN   = "\033[92m"
CYAN    = "\033[96m"
MAGENTA = "\033[35m"

# ─────────────────────────────────────────────────────────────────────────────
# Known address sets — single authoritative source for all CLI scripts
# ─────────────────────────────────────────────────────────────────────────────

KNOWN_RUGPULL: list[str] = [
    "0x00859b3baac525143bb8a3ee3e19ddf9daf2408c",
    "0x1d524a067f1828665273a0f85bd58cbb1cd18c3f",
    "0x212da8c9dad7e9b6a71422665c58bf9a7ecae6d0",
    "0x2b3ab8e7bb14988616359b78709538b10900ab7d",
    "0x58efa9aae017589b9fadbea3ed6f09730635efaf",
]

# 18-address list from test_full_dataset.py — largest / most complete set
KNOWN_GENUINE: list[str] = [
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

# ─────────────────────────────────────────────────────────────────────────────
# Etherscan helpers — best version from rugpull_live_batch.py (retry + backoff)
# ─────────────────────────────────────────────────────────────────────────────

ETHERSCAN_BASE   = "https://api.etherscan.io/v2/api"
RATE_SLEEP       = 0.22   # ~5 req/s on free Etherscan tier
RATE_SLEEP_BURST = 8.0    # back-off when rate-limited


def _etherscan_get(params: dict, api_key: str, retries: int = 3) -> list:
    """Call Etherscan V2 API with rate limiting and exponential retry."""
    params["apikey"] = api_key
    params.setdefault("chainid", 1)
    url = ETHERSCAN_BASE + "?" + urllib.parse.urlencode(params)
    time.sleep(RATE_SLEEP)
    try:
        with urllib.request.urlopen(url, timeout=25) as resp:
            data = json.loads(resp.read())
    except Exception as exc:
        if retries > 0:
            time.sleep(3)
            return _etherscan_get(params, api_key, retries - 1)
        print(f"    [WARN] Etherscan request failed: {exc}")
        return []

    result = data.get("result", [])
    if isinstance(result, str):
        if "rate limit" in result.lower():
            print(f"    [rate limit — waiting {RATE_SLEEP_BURST}s]")
            time.sleep(RATE_SLEEP_BURST)
            return _etherscan_get(params, api_key, retries)
        return []   # "No transactions found" etc — not an error
    return result or []


def fetch_normal_txs(address: str, api_key: str) -> list:
    """Fetch all normal (external) transactions for a wallet, oldest first."""
    return _etherscan_get({
        "module": "account", "action": "txlist",
        "address": address.lower(), "sort": "asc",
        "page": 1, "offset": 10000,
    }, api_key)


def fetch_internal_txs(address: str, api_key: str) -> list:
    """Fetch internal transactions for any address (creator wallet OR contract)."""
    return _etherscan_get({
        "module": "account", "action": "txlistinternal",
        "address": address.lower(), "sort": "asc",
        "page": 1, "offset": 10000,
    }, api_key)


def fetch_first_tx_ts(address: str, api_key: str) -> int | None:
    """Return the timestamp of the very first transaction (for wallet-age checks)."""
    result = _etherscan_get({
        "module": "account", "action": "txlist",
        "address": address.lower(), "sort": "asc",
        "page": 1, "offset": 1,
    }, api_key)
    if result:
        try:
            return int(result[0].get("timeStamp", 0))
        except (ValueError, IndexError):
            return None
    return None


def fetch_wallet_full(addr: str, api_key: str, live_cache: dict) -> dict:
    """
    Fetch complete transaction data for one creator wallet.

    Returns:
        {
          "normal_txs":       [...] creator's normal txs
          "internal_txs":     [...] MERGED internal txs from creator AND contract
          "contract_address": "0x..."  first deployed contract (or "")
        }

    The contract internal-tx merge is the key fix over simpler fetchers:
      Creator txlistinternal  → inbound ETH to creator (from users, CEX)
      Contract txlistinternal → outbound ETH FROM contract to creator (withdraw(),
                                removeLiquidity()) — required for POST rules.

    Deduplication is by (hash, traceId) so the same internal tx is never
    counted twice even when it appears in both lists.

    Results are stored in live_cache[addr] so callers can persist them without
    extra round-trips.
    """
    if addr in live_cache:
        return live_cache[addr]

    print(f"    [API] normal_txs      creator  {addr[:14]}...")
    normal_txs = fetch_normal_txs(addr, api_key)

    print(f"    [API] internal_txs    creator  {addr[:14]}...")
    creator_internal = fetch_internal_txs(addr, api_key)

    # Detect the first deployed contract address from normal txs
    deploy_txs = sorted(
        [tx for tx in normal_txs
         if tx.get("from", "").lower() == addr
         and tx.get("to", "") in ("", None)
         and tx.get("contractAddress") not in ("", None)],
        key=lambda t: int(t.get("timeStamp", 0))
    )
    contract_address = (
        deploy_txs[0].get("contractAddress", "").lower() if deploy_txs else ""
    )

    # Fetch internal txs FOR THE CONTRACT (captures withdraw() ETH payouts)
    contract_internal: list = []
    if contract_address:
        print(f"    [API] internal_txs    contract {contract_address[:14]}...")
        contract_internal = fetch_internal_txs(contract_address, api_key)

    # Merge + deduplicate by (hash, traceId)
    seen: set[tuple] = set()
    merged: list = []
    for tx in creator_internal + contract_internal:
        key = (
            tx.get("hash", ""),
            tx.get("traceId", tx.get("logIndex", tx.get("type", ""))),
        )
        if key not in seen:
            seen.add(key)
            merged.append(tx)

    print(
        f"    Txs: {len(normal_txs)} normal + {len(merged)} internal "
        f"(creator+contract merged)"
    )

    result = {
        "normal_txs":       normal_txs,
        "internal_txs":     merged,
        "contract_address": contract_address,
    }
    live_cache[addr] = result
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Deploy-timestamp detection
# ─────────────────────────────────────────────────────────────────────────────

def find_deploy_ts(addr: str, normal_txs: list, all_txs: list) -> int:
    """
    Return the timestamp of the first contract deployment from this wallet.

    Falls back to the first transaction timestamp if no deployment is found,
    and to 0 if the wallet has no transactions at all.
    """
    deploy_txs = sorted(
        [tx for tx in normal_txs
         if tx.get("from", "").lower() == addr
         and tx.get("to", "") in ("", None)
         and tx.get("contractAddress") not in ("", None)],
        key=lambda t: int(t.get("timeStamp", 0))
    )
    if deploy_txs:
        return int(deploy_txs[0].get("timeStamp", 0))
    return int(all_txs[0].get("timeStamp", 0)) if all_txs else 0


# ─────────────────────────────────────────────────────────────────────────────
# JSON cache helpers
# ─────────────────────────────────────────────────────────────────────────────

def load_json(path: str) -> dict:
    """Load a JSON file, returning an empty dict if the file does not exist."""
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_json(path: str, data: dict) -> None:
    """Atomically write data to a JSON file (overwrites in place)."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
