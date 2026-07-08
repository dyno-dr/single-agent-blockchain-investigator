"""
rugpull_live_batch.py
─────────────────────────────────────────────────────────────────────────────
Live batch runner for all 90 rugpull wallets from eoa_addresses.txt.

KEY FIX vs test_full_dataset.py:
  The old script only fetched txlistinternal for the CREATOR wallet.
  Some CONTRACT→CREATOR internal ETH flows (withdraw(), removeLiquidity()
  payouts) may not appear in the creator's paginated internal tx list.

  This script additionally fetches txlistinternal for the DEPLOYED
  CONTRACT ADDRESS and merges + deduplicates both lists. That gives:

    RUG-POST-1 (Withdrawal Latency)  — sees CONTRACT→CREATOR first payout
    RUG-POST-2 (Treasury Sweep)       — sees full creator withdrawal volume
    RUG-POST-7 (Retained Proceeds)    — sees true ecosystem balance

Results are saved in rugpull_live_cache.json so re-runs skip the API.
Age lookups are merged into wallet_age_cache.json (shared with old script).

Usage:
    venv\\Scripts\\python.exe rugpull_live_batch.py
    (Requires ETHERSCAN_API_KEY in .env)

    To re-fetch a specific wallet even if cached, delete its entry from
    rugpull_live_cache.json before running.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from cli_utils import (
    VERDICT_COLOURS, RESET,
    _etherscan_get, fetch_normal_txs, fetch_internal_txs,
    fetch_first_tx_ts, fetch_wallet_full,
    find_deploy_ts, load_json, save_json,
)

from backend.forensics.rugpull.engine import RugpullEngine, RugpullReport
from backend.forensics.rugpull.funding_graph import extract_funding_provenance, FunderGraph

# ─────────────────────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────────────────────

LIVE_CACHE_FILE     = "rugpull_live_cache.json"
AGE_CACHE_FILE      = "wallet_age_cache.json"
KNOWN_ENTITIES_PATH = Path(__file__).parent / "backend" / "blockchain" / "known_entities.json"
DB_PATH             = Path(__file__).parent / "investigation_history.db"
EOA_FILE            = "eoa_addresses.txt"

POST_RULE_IDS = [
    "RUG-POST-1", "RUG-POST-2", "RUG-POST-3",
    "RUG-POST-4", "RUG-POST-5", "RUG-POST-6", "RUG-POST-7",
]

# VERDICT_COLOURS, RESET, ETHERSCAN_BASE, RATE_SLEEP, RATE_SLEEP_BURST
# imported from cli_utils (see top of file).


# _etherscan_get, fetch_normal_txs, fetch_internal_txs, fetch_first_tx_ts,
# fetch_wallet_full, load_json, save_json imported from cli_utils.


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    api_key = os.environ.get("ETHERSCAN_API_KEY", "")
    if not api_key:
        print("ERROR: ETHERSCAN_API_KEY not set in environment / .env")
        sys.exit(1)

    if not os.path.exists(EOA_FILE):
        print(f"ERROR: {EOA_FILE} not found")
        sys.exit(1)
    with open(EOA_FILE) as f:
        addresses = [line.strip().lower() for line in f if line.strip()]
    print(f"Loaded {len(addresses)} rugpull addresses from {EOA_FILE}")

    known_entities: dict = {}
    if KNOWN_ENTITIES_PATH.exists():
        with open(KNOWN_ENTITIES_PATH) as f:
            raw_ents = json.load(f)
        for cat, entries in raw_ents.items():
            if not cat.startswith("_") and isinstance(entries, dict):
                for k, v in entries.items():
                    known_entities[k.lower()] = v
    print(f"Loaded {len(known_entities)} known entities")

    live_cache = load_json(LIVE_CACHE_FILE)
    age_cache  = load_json(AGE_CACHE_FILE)
    engine     = RugpullEngine()
    funder_db  = FunderGraph(DB_PATH)

    results: list[tuple[str, RugpullReport]] = []

    for idx, addr in enumerate(addresses):
        print(f"\n[{idx+1}/{len(addresses)}] {addr}")

        # 1. Fetch all tx data (with contract internal txs merged)
        raw = fetch_wallet_full(addr, api_key, live_cache)
        save_json(LIVE_CACHE_FILE, live_cache)

        normal_txs   = raw.get("normal_txs",   [])
        internal_txs = raw.get("internal_txs", [])
        all_txs      = normal_txs + internal_txs

        if not all_txs:
            print("    SKIP: no transactions found")
            continue

        print(f"    Txs: {len(normal_txs)} normal + {len(internal_txs)} internal (merged)")

        # 2. Find deploy_ts
        deploy_ts = find_deploy_ts(addr, normal_txs, all_txs)

        # 3. Build wallet_age_lookup (senders + post-deploy destinations)
        senders = {
            tx.get("from", "").lower() for tx in all_txs
            if tx.get("to", "").lower() == addr
            and int(tx.get("value", "0")) > 0
            and tx.get("from", "").lower() != addr
        }
        destinations = {
            tx.get("to", "").lower() for tx in all_txs
            if tx.get("from", "").lower() == addr
            and tx.get("to", "") not in ("", None)
            and int(tx.get("value", "0")) > 0
            and tx.get("contractAddress") in ("", None)
            and int(tx.get("timeStamp", 0)) >= deploy_ts
        }

        wallet_age_lookup: dict[str, int | None] = {}
        age_fetches = 0
        for s in (senders | destinations) - set(known_entities.keys()):
            if s in age_cache:
                wallet_age_lookup[s] = age_cache[s]
            else:
                ts = fetch_first_tx_ts(s, api_key)
                age_cache[s] = ts
                wallet_age_lookup[s] = ts
                age_fetches += 1

        for s in senders | destinations:
            if s in known_entities:
                wallet_age_lookup[s] = None

        if age_fetches:
            save_json(AGE_CACHE_FILE, age_cache)
            print(f"    Age lookups: {age_fetches} new wallets fetched")

        # 4. Funding provenance
        fp_result = extract_funding_provenance(
            wallet_address=addr,
            txs=all_txs,
            deploy_timestamp=deploy_ts,
            known_entities=known_entities,
            wallet_age_lookup=wallet_age_lookup,
            funder_graph_db=funder_db,
        )

        # 5. Full engine run
        report = engine.run(
            addr, raw,
            fp_result=fp_result,
            wallet_age_lookup=wallet_age_lookup,
            known_entities=known_entities,
        )
        results.append((addr, report))

        # Inline per-wallet summary
        col        = VERDICT_COLOURS.get(report.verdict, "")
        all_fired  = [r["rule_id"] for r in report.triggered_rules]
        post_fired = [rid for rid in all_fired if rid.startswith("RUG-POST")]
        print(f"    Score={report.score}  {col}{report.verdict}{RESET}")
        print(f"    Rules : {' '.join(all_fired) or '-'}")
        if post_fired:
            print(f"    POST  : {' '.join(post_fired)}")

    # ─────────────────────────────────────────────────────────────────────────
    # Final report table
    # ─────────────────────────────────────────────────────────────────────────
    sep = "-" * 100
    print(f"\n{'='*100}")
    print(f"  FINAL RESULTS  ({len(results)} rugpull wallets evaluated)")
    print(f"{'='*100}")
    print(f"  {'WALLET':<44}  {'VERDICT':<30}  {'SCORE':>5}  RULES FIRED")
    print(f"  {sep}")
    for addr, r in results:
        col      = VERDICT_COLOURS.get(r.verdict, "")
        rule_ids = " ".join(rule["rule_id"] for rule in r.triggered_rules) or "-"
        print(f"  {addr}  {col}{r.verdict:<30}{RESET}  {r.score:>5}  {rule_ids}")

    print(f"\n{'='*100}")

    # Accuracy
    detected = sum(1 for _, r in results if r.score >= 25)
    print(f"\n  Detection rate : {detected}/{len(results)} ({detected/len(results)*100:.1f}%) at score >= 25")

    # POST-rule breakdown
    print(f"\n  POST-Rule Breakdown:")
    print(f"  {'-'*65}")
    for rid in POST_RULE_IDS:
        hits    = [(a, r) for a, r in results
                   if any(rule["rule_id"] == rid for rule in r.triggered_rules)]
        sev_map: dict[str, int] = {}
        for _, r in results:
            for rule in r.triggered_rules:
                if rule["rule_id"] == rid:
                    sev = rule.get("severity", "?")
                    sev_map[sev] = sev_map.get(sev, 0) + 1
        sev_str = "  ".join(f"{s}:{n}" for s, n in sorted(sev_map.items()))
        print(f"    {rid:<14}  {len(hits):>3} wallets  {sev_str}")

    # Verdict distribution
    print(f"\n  Verdict Distribution:")
    from collections import Counter
    dist = Counter(r.verdict for _, r in results)
    for verdict, count in sorted(dist.items(), key=lambda x: -x[1]):
        col = VERDICT_COLOURS.get(verdict, "")
        print(f"    {col}{verdict:<32}{RESET}  {count:>3}")

    # Wallets where POST is primary/only signal
    print(f"\n  Wallets where POST rules are the primary/only evidence:")
    primary_count = 0
    for addr, r in results:
        all_fired  = [rule["rule_id"] for rule in r.triggered_rules]
        post_fired = [rid for rid in all_fired if rid.startswith("RUG-POST")]
        other      = [rid for rid in all_fired if not rid.startswith("RUG-POST")]
        if post_fired and len(other) < 2:
            primary_count += 1
            print(f"    {addr}  score={r.score}  verdict={r.verdict}")
            print(f"      post={post_fired}  other={other}")
    if primary_count == 0:
        print("    (none — all POST-rule wallets also had pre-deploy rule signals)")

    print()


if __name__ == "__main__":
    main()
