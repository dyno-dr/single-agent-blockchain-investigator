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
from pathlib import Path

# Allow running from project root
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from cli_utils import (
    VERDICT_COLOURS, RESET,
    KNOWN_GENUINE,
    _etherscan_get, fetch_first_tx_ts,
    find_deploy_ts, load_json, save_json,
)

from backend.forensics.rugpull.engine import RugpullEngine, RugpullReport
from backend.forensics.rugpull.funding_graph import extract_funding_provenance, FunderGraph

# ─────────────────────────────────────────────────────────────────────────────
# Config & Paths
# ─────────────────────────────────────────────────────────────────────────────

DATASET_CACHE_FILE  = "raw_wallet_data_v2.json"
AGE_CACHE_FILE      = "wallet_age_cache.json"
KNOWN_ENTITIES_PATH = Path(__file__).parent / "backend" / "blockchain" / "known_entities.json"
DB_PATH             = Path(__file__).parent / "investigation_history.db"

# ETHERSCAN_BASE, KNOWN_GENUINE, VERDICT_COLOURS, RESET
# imported from cli_utils (see top of file).

# ─────────────────────────────────────────────────────────────────────────────
# _etherscan_get, fetch_first_tx_ts, load_json/save_json imported from cli_utils.
# fetch_wallet_live below is intentionally slimmer (no contract-internal merge)
# because test_full_dataset.py uses raw_wallet_data_v2.json cache (pre-merged).
# ─────────────────────────────────────────────────────────────────────────────

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


def fetch_first_tx_ts(address: str, api_key: str) -> int | None:
    return fetch_first_tx_ts(address, api_key)


def load_json_cache(path: str) -> dict:
    return load_json(path)


def save_json_cache(path: str, data: dict):
    save_json(path, data)

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
            deploy_ts = find_deploy_ts(addr, raw.get("normal_txs", []), all_txs)

            # Fetch sender ages
            senders = {
                tx.get("from", "").lower() for tx in all_txs
                if tx.get("to", "").lower() == addr and int(tx.get("value", "0")) > 0
                and tx.get("from", "").lower() != addr
            }

            # Collect post-deploy outbound destinations for CP4 wallet-age lookup
            destinations = {
                tx.get("to", "").lower() for tx in all_txs
                if tx.get("from", "").lower() == addr
                and tx.get("to", "") not in ("", None)
                and int(tx.get("value", "0")) > 0
                and tx.get("contractAddress") in ("", None)
                and int(tx.get("timeStamp", 0)) >= deploy_ts
            }

            wallet_age_lookup = {}
            all_to_fetch = (senders | destinations) - set(known_entities.keys())
            for s in all_to_fetch:
                if s in age_cache:
                    wallet_age_lookup[s] = age_cache[s]
                elif args.fetch:
                    ts = fetch_first_tx_ts_live(s, api_key)
                    age_cache[s] = ts
                    wallet_age_lookup[s] = ts
                else:
                    wallet_age_lookup[s] = None  # Treat as unknown age if offline

            # Mark known entities as non-fresh (age = 0 = very old)
            for s in senders | destinations:
                if s in known_entities and s not in wallet_age_lookup:
                    wallet_age_lookup[s] = None

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

            # Run Engine — now passes wallet_age_lookup + known_entities for CP features
            report = engine.run(
                addr, raw,
                fp_result=fp_result,
                wallet_age_lookup=wallet_age_lookup,
                known_entities=known_entities,
            )
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

        # -- POST-rule breakdown ----------------------------------------------------
        post_rule_ids = [
            "RUG-POST-1", "RUG-POST-2", "RUG-POST-3",
            "RUG-POST-4", "RUG-POST-5", "RUG-POST-6", "RUG-POST-7",
        ]
        print(f"\n  POST-Rule Breakdown (rugpull group):")
        for rid in post_rule_ids:
            hit_count = sum(
                1 for _, lbl, r in rugpulls
                if any(rule["rule_id"] == rid for rule in r.triggered_rules)
            )
            severity_map = {}
            for _, _, r in rugpulls:
                for rule in r.triggered_rules:
                    if rule["rule_id"] == rid:
                        sev = rule.get("severity", "?")
                        severity_map[sev] = severity_map.get(sev, 0) + 1
            sev_str = "  ".join(f"{s}:{n}" for s, n in sorted(severity_map.items()))
            print(f"    {rid:<14}  {hit_count:>3} wallets  {sev_str}")

        # ── Verdict upgrade analysis ─────────────────────────────────────────
        upgraded = []
        for addr, lbl, r in rugpulls:
            post_fired = [rule["rule_id"] for rule in r.triggered_rules if rule["rule_id"].startswith("RUG-POST")]
            if post_fired and r.verdict in ("STRONG_PATTERN", "HIGH_CONFIDENCE_RUGPULL"):
                upgraded.append((addr, r.verdict, r.score, post_fired))
        print(f"\n  Wallets where POST rules contributed to STRONG/HIGH_CONFIDENCE verdict: {len(upgraded)}")
        for addr, verdict, score, fired in upgraded[:15]:  # cap at 15 for readability
            print(f"    {addr}  {verdict}  score={score}  post={fired}")

if __name__ == "__main__":
    main()

