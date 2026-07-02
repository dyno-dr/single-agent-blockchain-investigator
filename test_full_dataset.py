"""
test_full_dataset.py
─────────────────────────────────────────────────────────────────────────────
Runs the RugpullEngine (including Funding Provenance) against the full dataset
of 92 known rugpull EOAs and 20 genuine EOAs.

Uses caching heavily to avoid Etherscan rate limits.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

# Allow running from project root
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from backend.forensics.rugpull.engine import RugpullEngine, RugpullReport
from backend.forensics.rugpull.funding_graph import extract_funding_provenance, FunderGraph

# ─────────────────────────────────────────────────────────────────────────────
# Config & Paths
# ─────────────────────────────────────────────────────────────────────────────

ETHERSCAN_BASE = "https://api.etherscan.io/v2/api"
DATASET_CACHE_FILE = "raw_wallet_data_v2.json"
AGE_CACHE_FILE = "wallet_age_cache.json"
KNOWN_ENTITIES_PATH = Path(__file__).parent / "backend" / "blockchain" / "known_entities.json"
DB_PATH = Path(__file__).parent / "investigation_history.db"

KNOWN_GENUINE = [
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
    "0x7ea79bad324579fac7a7645c62fe8c60a8b73055"
]

VERDICT_COLOURS = {
    "CLEAN":                        "\033[92m",   # green
    "INSUFFICIENT_DEPLOYMENT_HISTORY": "\033[96m",# cyan
    "WEAK_PATTERN":                 "\033[93m",   # yellow
    "MODERATE_PATTERN":             "\033[33m",   # dark yellow
    "STRONG_PATTERN":               "\033[91m",   # light red
    "HIGH_CONFIDENCE_RUGPULL":      "\033[31m",   # red
}
RESET = "\033[0m"

# ─────────────────────────────────────────────────────────────────────────────
# Etherscan Fetchers with Caching
# ─────────────────────────────────────────────────────────────────────────────

def _etherscan_get(params: dict, api_key: str, retries: int = 3) -> list:
    params["apikey"] = api_key
    params.setdefault("chainid", 1)
    url = ETHERSCAN_BASE + "?" + urllib.parse.urlencode(params)
    time.sleep(0.22)
    try:
        with urllib.request.urlopen(url, timeout=20) as resp:
            data = json.loads(resp.read())
    except Exception as e:
        if retries > 0:
            time.sleep(3)
            return _etherscan_get(params, api_key, retries - 1)
        raise e

    result = data.get("result", [])
    if isinstance(result, str):
        if "rate limit" in result.lower():
            print("  [rate limit — waiting 8s]")
            time.sleep(8)
            return _etherscan_get(params, api_key)
        return []
    return result or []

def fetch_wallet_live(address: str, api_key: str) -> dict:
    addr = address.lower()
    normal = _etherscan_get({
        "module": "account", "action": "txlist",
        "address": addr, "sort": "asc", "page": 1, "offset": 10000,
    }, api_key)
    internal = _etherscan_get({
        "module": "account", "action": "txlistinternal",
        "address": addr, "sort": "asc", "page": 1, "offset": 10000,
    }, api_key)
    return {"address": addr, "normal_txs": normal, "internal_txs": internal}

def fetch_first_tx_ts_live(address: str, api_key: str) -> int | None:
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

def load_json_cache(path: str) -> dict:
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return {}

def save_json_cache(path: str, data: dict):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

# ─────────────────────────────────────────────────────────────────────────────
# Main Routine
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fetch", action="store_true", help="Allow live API calls (requires ETHERSCAN_API_KEY)")
    args = parser.parse_args()

    api_key = os.environ.get("ETHERSCAN_API_KEY", "")
    if args.fetch and not api_key:
        print("ERROR: --fetch requires ETHERSCAN_API_KEY in .env")
        sys.exit(1)

    # Load EOA addresses
    if not os.path.exists("eoa_addresses.txt"):
        print("ERROR: eoa_addresses.txt not found. Run separate_addresses.py first.")
        sys.exit(1)
    
    with open("eoa_addresses.txt") as f:
        KNOWN_RUGPULL = [line.strip().lower() for line in f if line.strip()]

    # Load Known Entities
    known_entities: dict = {}
    if KNOWN_ENTITIES_PATH.exists():
        with open(KNOWN_ENTITIES_PATH) as f:
            raw_entities = json.load(f)
        for cat, entries in raw_entities.items():
            if not cat.startswith("_") and isinstance(entries, dict):
                for k, v in entries.items():
                    known_entities[k.lower()] = v

    dataset_cache = load_json_cache(DATASET_CACHE_FILE)
    age_cache = load_json_cache(AGE_CACHE_FILE)
    engine = RugpullEngine()
    funder_db = FunderGraph(DB_PATH)

    results: list[tuple[str, str, RugpullReport]] = []

    def evaluate_dataset(addresses: list[str], label: str):
        for idx, addr in enumerate(addresses):
            print(f"[{idx+1}/{len(addresses)}] Evaluating {label} {addr[:12]}...")
            
            # Get Raw Data
            if addr in dataset_cache:
                raw = dataset_cache[addr]
            elif args.fetch:
                raw = fetch_wallet_live(addr, api_key)
                dataset_cache[addr] = raw
                save_json_cache(DATASET_CACHE_FILE, dataset_cache)
            else:
                print(f"  SKIP: {addr} not in cache")
                continue

            all_txs = raw.get("normal_txs", []) + raw.get("internal_txs", [])
            if not all_txs:
                print("  SKIP: No transactions")
                continue

            # Find deploy_ts
            deploy_txs = sorted(
                [tx for tx in raw.get("normal_txs", [])
                 if tx.get("from", "").lower() == addr
                 and tx.get("to") in ("", None)
                 and tx.get("contractAddress") not in ("", None)],
                key=lambda t: int(t.get("timeStamp", 0))
            )
            deploy_ts = int(deploy_txs[0].get("timeStamp", 0)) if deploy_txs else int(all_txs[0].get("timeStamp", 0))

            # Fetch sender ages
            senders = {
                tx.get("from", "").lower() for tx in all_txs
                if tx.get("to", "").lower() == addr and int(tx.get("value", "0")) > 0
                and tx.get("from", "").lower() != addr
            }
            
            wallet_age_lookup = {}
            for s in senders:
                if s in known_entities:
                    wallet_age_lookup[s] = None
                elif s in age_cache:
                    wallet_age_lookup[s] = age_cache[s]
                elif args.fetch:
                    ts = fetch_first_tx_ts_live(s, api_key)
                    age_cache[s] = ts
                    wallet_age_lookup[s] = ts
                else:
                    wallet_age_lookup[s] = None # Treat as unknown age if offline

            if args.fetch:
                save_json_cache(AGE_CACHE_FILE, age_cache)

            # Compute Provenance
            fp_result = extract_funding_provenance(
                wallet_address=addr,
                txs=all_txs,
                deploy_timestamp=deploy_ts,
                known_entities=known_entities,
                wallet_age_lookup=wallet_age_lookup,
                funder_graph_db=funder_db,
            )

            # Run Engine
            report = engine.run(addr, raw, fp_result=fp_result)
            results.append((addr, label, report))

    evaluate_dataset(KNOWN_RUGPULL, "RUGPULL")
    evaluate_dataset(KNOWN_GENUINE, "GENUINE")

    # Summary Output
    print(f"\n{'-'*90}")
    print(f"{'WALLET':>44}  {'LABEL':>8}  {'VERDICT':>28}  {'SCORE':>5}  RULES")
    print("-" * 90)
    for addr, label, r in results:
        col = VERDICT_COLOURS.get(r.verdict, "")
        rule_ids = " ".join(rule["rule_id"] for rule in r.triggered_rules) or "-"
        verdict_short = r.verdict.replace("_", " ")[:26]
        print(f"  {addr}  {label:>8}  {col}{verdict_short:<26}{RESET}  {r.score:>5}  {rule_ids}")
    print("-" * 90)

    # Metrics
    if results:
        rugpulls = [r for r in results if r[1] == "RUGPULL"]
        genuines = [r for r in results if r[1] == "GENUINE"]

        tp = sum(1 for r in rugpulls if r[2].score >= 25)
        tn = sum(1 for r in genuines if r[2].score < 25)
        
        print(f"\n  Rugpull Accuracy : {tp}/{len(rugpulls)} ({tp/len(rugpulls)*100 if rugpulls else 0:.1f}%) detected (score >= 25)")
        print(f"  Genuine Accuracy : {tn}/{len(genuines)} ({tn/len(genuines)*100 if genuines else 0:.1f}%) clean (score < 25)")

if __name__ == "__main__":
    main()
