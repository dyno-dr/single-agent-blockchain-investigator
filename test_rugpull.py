"""
test_rugpull.py
─────────────────────────────────────────────────────────────────────────────
Manual test harness for the rugpull creator triage system.

USAGE:
    # Test a single address (live Etherscan fetch)
    python test_rugpull.py 0xABC...

    # Test against the cached dataset (no API calls needed)
    python test_rugpull.py 0xABC... --cache

    # Test ALL addresses in the v2 cache and show a summary table
    python test_rugpull.py --all

    # Test a list of known rugpull + genuine addresses built into the script
    python test_rugpull.py --known

HOW IT WORKS:
    1. Loads raw Etherscan data (from cache or live API)
    2. Runs RugpullEngine.run() — the same pipeline that will run in production
    3. Prints a formatted report with score, verdict, triggered rules, features

REQUIRES:
    - ETHERSCAN_API_KEY in .env (only needed for live fetch, not --cache/--all/--known)
"""

import argparse
import json
import os
import sys
from pathlib import Path

# Fix Windows console encoding for characters like ≥
if sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')

# ─── allow running from project root ──────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from cli_utils import (
    VERDICT_COLOURS, RESET, BOLD, DIM,
    KNOWN_RUGPULL, KNOWN_GENUINE,
    _etherscan_get, fetch_first_tx_ts, fetch_wallet_full,
    find_deploy_ts, load_json, save_json,
)

from backend.forensics.rugpull import RugpullEngine, RugpullReport
from backend.forensics.rugpull.funding_graph import extract_funding_provenance, FunderGraph

KNOWN_ENTITIES_PATH = Path(__file__).parent / "backend" / "blockchain" / "known_entities.json"
DB_PATH             = Path(__file__).parent / "investigation_history.db"
AGE_CACHE_FILE      = "wallet_age_cache.json"

# ─────────────────────────────────────────────────────────────────────────────
# Known address sets — imported from cli_utils (canonical 18-address source)
# ─────────────────────────────────────────────────────────────────────────────

if os.path.exists("rugpull_live_cache.json"):
    DEFAULT_CACHE_FILE = "rugpull_live_cache.json"
else:
    DEFAULT_CACHE_FILE = "raw_wallet_data_v2.json"

# _etherscan_get, fetch_first_tx_ts, and fetch_wallet_full
# are imported from cli_utils (see top of file).


def load_raw(address: str, cache_file: str, api_key: str, use_cache: bool) -> dict | None:
    """Return raw data from cache or live fetch."""
    addr = address.lower()
    cache = load_json(cache_file)

    if addr in cache and use_cache:
        print(f"  [cache hit] Loaded {addr[:12]}... from {cache_file}")
        return cache[addr]

    if use_cache:
        print(f"  [MISS] {addr} not in cache — run without --cache to fetch live")
        return None

    if not api_key:
        print("ERROR: No Etherscan API key. Set ETHERSCAN_API_KEY in .env or use --cache")
        return None

    raw = fetch_wallet_full(addr, api_key, cache)
    save_json(cache_file, cache)
    print(f"  [saved] Raw data cached to {cache_file}")
    return raw


# ─────────────────────────────────────────────────────────────────────────────
# Report printer
# ─────────────────────────────────────────────────────────────────────────────

# VERDICT_COLOURS, RESET, BOLD, DIM imported from cli_utils (see top of file).


def _colour(verdict: str, text: str) -> str:
    c = VERDICT_COLOURS.get(verdict, "")
    return f"{c}{BOLD}{text}{RESET}"


def print_report(report: RugpullReport, label: str = "") -> None:
    sep = "=" * 68
    thin = "-" * 68

    label_str = f"  [{label}]" if label else ""
    print(f"\n{sep}")
    print(f"  RUGPULL TRIAGE REPORT{label_str}")
    print(f"  Wallet : {report.wallet_address}")
    print(f"  Time   : {report.analyzed_at.strftime('%Y-%m-%d %H:%M UTC')}")
    print(sep)

    # Verdict banner
    verdict_col = _colour(report.verdict, f"  {report.verdict}  (score: {report.score}/100)")
    print(verdict_col)
    if report.override_applied:
        print(f"  {DIM}Override: {report.override_applied}{RESET}")

    print(thin)
    print("  FEATURES")
    print(thin)

    fv = report.features
    def _fmt(v, unit=""):
        if v is None:
            return f"{DIM}None (undefined){RESET}"
        return f"{v:.4f}{unit}"

    print(f"  F1  Warmup hours          : {_fmt(fv.f1_warmup_hours, 'h')}")
    print(f"  F2  Funding CV             : {_fmt(fv.f2_funding_cv)}")
    print(f"  F3  Dry-run count          : {fv.f3_dry_run_count}")
    print(f"  F4  Deployment count       : {fv.f4_deployment_count}")
    print(f"  F4b Burstiness             : {_fmt(fv.f4_burstiness)} {DIM}(narrative){RESET}")
    print(f"  F5  Nonce entropy          : {_fmt(fv.f5_nonce_entropy, ' bits')} {DIM}(narrative){RESET}")
    print(f"  F7  Within-wallet sim      : {_fmt(fv.f7_within_wallet_sim)} {DIM}(narrative){RESET}")
    print(f"  NEW-A Single deploy        : {fv.new_a_single_deploy}")
    print(f"  Funding sources            : {len(fv.all_funding_sources)} unique addresses")

    # Funding Provenance
    print()
    print(f"  {DIM}--- Funding Provenance (FP) ---{RESET}")
    print(f"  FP1 First inbound source   : {fv.fp_first_inbound_source_type}")
    print(f"  FP2 Min hops to known src  : {fv.fp_min_hops_to_known_source}")
    print(f"  FP3 Fresh capital fraction : {_fmt(fv.fp_fraction_fresh_capital)}")
    print(f"  FP4 Shared funders flag    : {fv.fp_shared_upstream_funders}")
    print(f"  FP4 Max funder Jaccard     : {_fmt(fv.fp_max_funder_jaccard)}")
    print(f"  FP5 Funding entropy (norm) : {_fmt(fv.fp_funding_entropy_norm)}")
    print(f"  FP5 Median seed ETH        : {_fmt(fv.fp_median_seed_eth, ' ETH')}")
    print(f"  FP5 Seed tx count          : {fv.fp_seed_tx_count}")

    # Post-Exploit Cash-Out
    print()
    print(f"  {DIM}--- Post-Exploit Cash-Out (CP) ---{RESET}")
    print(f"  CP1 Withdrawal latency     : {_fmt(fv.cp1_withdrawal_latency_sec, 's')}")
    print(f"  CP2 Withdrawal count       : {fv.cp2_withdrawal_count}")
    print(f"  CP2 Drain ratio            : {_fmt(fv.cp2_drain_ratio)}")
    print(f"  CP2 Withdrawal span        : {_fmt(fv.cp2_withdrawal_span_hours, 'h')}")
    print(f"  CP3 Outflow CV             : {_fmt(fv.cp3_outflow_cv)}")
    print(f"  CP3 Round number ratio     : {_fmt(fv.cp3_round_number_ratio)}")
    print(f"  CP3 Outflow count          : {fv.cp3_outflow_count}")
    print(f"  CP4 Suspicious dests       : {fv.cp4_suspicious_destination_count}")
    print(f"  CP4 Fresh wallet ratio     : {_fmt(fv.cp4_fresh_wallet_ratio)}")
    print(f"  CP5 CEX/Mixer conc. ratio  : {_fmt(fv.cp5_concentration_ratio)}")
    print(f"  CP5 Mixer contact          : {fv.cp5_mixer_contact}")
    print(f"  CP6 Swap detected          : {fv.cp6_swap_detected}")
    print(f"  CP6 Swap latency           : {_fmt(fv.cp6_swap_latency_sec, 's')}")
    print(f"  CP7 Retained ratio         : {_fmt(fv.cp7_retained_ratio)}")

    print(thin)
    print("  TRIGGERED RULES")
    print(thin)

    if not report.triggered_rules:
        print(f"  {DIM}No rules triggered.{RESET}")
    else:
        for r in report.triggered_rules:
            sev = r["severity"]
            sev_col = {
                "CRITICAL": "\033[31m", "HIGH": "\033[91m",
                "MEDIUM":   "\033[93m", "LOW":  "\033[96m",
            }.get(sev, "")
            print(f"  {sev_col}{BOLD}[{sev}]{RESET}  {r['rule_id']} — {r['rule_name']}")
            print(f"         Observation : {r['description']}")
            print(f"         Reasoning   : {r['reasoning'][:160]}")
            pts = report.score_breakdown.get(r['rule_id'], 0)
            print(f"         {DIM}Score points: +{pts}{RESET}")
            print()

    # Multi-hop targets
    if report.multihop_addresses:
        print(thin)
        print(f"  {BOLD}[!] MULTI-HOP TARGETS — Queue for secondary investigation:{RESET}")
        for addr in set(report.multihop_addresses):
            print(f"     -> {addr}")

    print(sep)


def print_summary_table(results: list[tuple[str, str, RugpullReport]]) -> None:
    """Print a compact table for --all or --known mode."""
    sep = "-" * 90
    print(f"\n{'WALLET':>44}  {'LABEL':>8}  {'VERDICT':>28}  {'SCORE':>5}  RULES")
    print(sep)
    for addr, label, report in results:
        col = VERDICT_COLOURS.get(report.verdict, "")
        rule_ids = " ".join(r["rule_id"] for r in report.triggered_rules) or "-"
        verdict_short = report.verdict.replace("_", " ")[:26]
        print(
            f"  {addr}  {label:>8}  "
            f"{col}{verdict_short:<26}{RESET}  {report.score:>5}  {rule_ids}"
        )
    print(sep)

    # Count correct calls
    high_on_rugpull = sum(1 for _, lbl, r in results if lbl == "RUGPULL" and r.score >= 25)
    clean_on_genuine = sum(1 for _, lbl, r in results if lbl == "GENUINE" and r.score < 25)
    rugpull_total = sum(1 for _, lbl, _ in results if lbl == "RUGPULL")
    genuine_total = sum(1 for _, lbl, _ in results if lbl == "GENUINE")
    print(f"\n  Rugpull wallets with score >= 25 : {high_on_rugpull}/{rugpull_total}")
    print(f"  Genuine wallets  with score < 25 : {clean_on_genuine}/{genuine_total}")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Manual test harness for the rugpull creator triage system."
    )
    parser.add_argument(
        "address", nargs="?", default=None,
        help="Single Ethereum wallet address to test"
    )
    parser.add_argument(
        "--cache", action="store_true",
        help="Only use cached data — no live Etherscan calls"
    )
    parser.add_argument(
        "--cache-file", default=DEFAULT_CACHE_FILE,
        help=f"Path to raw wallet data cache (default: {DEFAULT_CACHE_FILE})"
    )
    parser.add_argument(
        "--all", action="store_true",
        help="Run against ALL addresses in the cache file and print a summary table"
    )
    parser.add_argument(
        "--known", action="store_true",
        help="Run against the hardcoded known rugpull + genuine address sets"
    )
    args = parser.parse_args()

    api_key = os.environ.get("ETHERSCAN_API_KEY", "")
    engine = RugpullEngine()

    # ── --all mode ────────────────────────────────────────────────────────────
    if args.all:
        if not os.path.exists(args.cache_file):
            print(f"ERROR: Cache file not found: {args.cache_file}")
            sys.exit(1)
        with open(args.cache_file) as f:
            cache = json.load(f)
        print(f"Running against all {len(cache)} addresses in {args.cache_file}...")
        results = []
        for addr, raw in cache.items():
            report = engine.run(addr, raw)
            results.append((addr, "?", report))
        print_summary_table(results)
        return

    # ── --known mode ──────────────────────────────────────────────────────────
    if args.known:
        results = []
        for addr in KNOWN_RUGPULL:
            raw = load_raw(addr, args.cache_file, api_key, use_cache=True)
            if raw:
                report = engine.run(addr, raw)
                results.append((addr, "RUGPULL", report))
            else:
                print(f"  SKIP {addr} — not in cache (run without --cache to fetch)")
        for addr in KNOWN_GENUINE:
            raw = load_raw(addr, args.cache_file, api_key, use_cache=True)
            if raw:
                report = engine.run(addr, raw)
                results.append((addr, "GENUINE", report))
        if results:
            print_summary_table(results)
        return

    # ── Single address mode ───────────────────────────────────────────────────
    if not args.address:
        parser.print_help()
        print("\nExamples:")
        print("  python test_rugpull.py 0xABC123...              # live fetch")
        print("  python test_rugpull.py 0xABC123... --cache      # cache only")
        print("  python test_rugpull.py --known                  # known address set")
        print("  python test_rugpull.py --all                    # entire cache")
        sys.exit(0)

    addr = args.address.lower().strip()
    if not addr.startswith("0x") or len(addr) != 42:
        print(f"ERROR: '{addr}' does not look like a valid Ethereum address.")
        sys.exit(1)

    print(f"\nLoading data for {addr}...")
    raw = load_raw(addr, args.cache_file, api_key, use_cache=args.cache)
    if raw is None:
        sys.exit(1)

    # Load known entities
    known_entities: dict = {}
    if KNOWN_ENTITIES_PATH.exists():
        with open(KNOWN_ENTITIES_PATH) as f:
            raw_ents = json.load(f)
        for cat, entries in raw_ents.items():
            if not cat.startswith("_") and isinstance(entries, dict):
                for k, v in entries.items():
                    known_entities[k.lower()] = v

    normal_txs   = raw.get("normal_txs",   [])
    internal_txs = raw.get("internal_txs", [])
    all_txs      = normal_txs + internal_txs

    # Find deploy_ts
    deploy_ts = find_deploy_ts(addr, normal_txs, all_txs)

    # Build wallet_age_lookup
    age_cache_data: dict = {}
    if os.path.exists(AGE_CACHE_FILE):
        with open(AGE_CACHE_FILE) as f:
            age_cache_data = json.load(f)

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

    wallet_age_lookup: dict = {}
    new_ages = 0
    for s in (senders | destinations) - set(known_entities.keys()):
        if s in age_cache_data:
            wallet_age_lookup[s] = age_cache_data[s]
        elif api_key and not args.cache:
            ts = fetch_first_tx_ts(s, api_key)
            age_cache_data[s] = ts
            wallet_age_lookup[s] = ts
            new_ages += 1
        else:
            wallet_age_lookup[s] = None
    for s in senders | destinations:
        if s in known_entities:
            wallet_age_lookup[s] = None

    if new_ages:
        with open(AGE_CACHE_FILE, "w") as f:
            json.dump(age_cache_data, f, indent=2)
        print(f"  Fetched wallet ages for {new_ages} new addresses")

    # Funding provenance
    funder_db = FunderGraph(DB_PATH)
    fp_result = extract_funding_provenance(
        wallet_address=addr,
        txs=all_txs,
        deploy_timestamp=deploy_ts,
        known_entities=known_entities,
        wallet_age_lookup=wallet_age_lookup,
        funder_graph_db=funder_db,
    )

    print("Running full rugpull triage pipeline (all rule layers)...")
    report = engine.run(
        addr, raw,
        fp_result=fp_result,
        wallet_age_lookup=wallet_age_lookup,
        known_entities=known_entities,
    )
    print_report(report)

    # Hint for multihop
    if report.multihop_addresses:
        print("\nTip: Test the multi-hop targets above:")
        for target in set(report.multihop_addresses):
            print(f"  python test_rugpull.py {target} --cache")


if __name__ == "__main__":
    main()
