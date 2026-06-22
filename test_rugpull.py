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
import time
import urllib.parse
import urllib.request

# ─── allow running from project root ──────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from backend.forensics.rugpull import RugpullEngine, RugpullReport

# ─────────────────────────────────────────────────────────────────────────────
# Known address sets for --known mode
# ─────────────────────────────────────────────────────────────────────────────

KNOWN_RUGPULL = [
    "0x00859b3baac525143bb8a3ee3e19ddf9daf2408c",
    "0x1d524a067f1828665273a0f85bd58cbb1cd18c3f",
    "0x212da8c9dad7e9b6a71422665c58bf9a7ecae6d0",
    "0x2b3ab8e7bb14988616359b78709538b10900ab7d",
    "0x58efa9aae017589b9fadbea3ed6f09730635efaf",
]

KNOWN_GENUINE = [
    "0xaba7161a7fb69c88e16ed9f455ce62b791ee4d03",
    "0xd45058bf25bbd8f586124c479d384c8c708ce23a",
    "0xce8d642cdd81d805b9b770da9af3790e7e3dfb05",
    "0xb5191de5e9ed5ce94176b7917430a8512e5ad517",
]

DEFAULT_CACHE_FILE = "raw_wallet_data_v2.json"

# ─────────────────────────────────────────────────────────────────────────────
# Etherscan minimal fetcher (no external deps, same as threshold script)
# ─────────────────────────────────────────────────────────────────────────────

ETHERSCAN_BASE = "https://api.etherscan.io/v2/api"


def _etherscan_get(params: dict, api_key: str) -> list:
    params["apikey"] = api_key
    params.setdefault("chainid", 1)
    url = ETHERSCAN_BASE + "?" + urllib.parse.urlencode(params)
    time.sleep(0.25)  # stay under 5 req/s free tier
    with urllib.request.urlopen(url, timeout=20) as resp:
        data = json.loads(resp.read())
    result = data.get("result", [])
    if isinstance(result, str):
        if "rate limit" in result.lower():
            print("  [rate limit — waiting 6s]")
            time.sleep(6)
            return _etherscan_get(params, api_key)
        raise RuntimeError(f"Etherscan error: {result}")
    return result or []


def fetch_live(address: str, api_key: str) -> dict:
    """Fetch normal + internal txs from Etherscan live."""
    addr = address.lower()
    print(f"  Fetching normal txs for {addr[:12]}...")
    normal = _etherscan_get({
        "module": "account", "action": "txlist",
        "address": addr, "startblock": 0, "endblock": 99999999,
        "sort": "asc", "page": 1, "offset": 10000,
    }, api_key)

    print(f"  Fetching internal txs for {addr[:12]}...")
    internal = _etherscan_get({
        "module": "account", "action": "txlistinternal",
        "address": addr, "startblock": 0, "endblock": 99999999,
        "sort": "asc", "page": 1, "offset": 10000,
    }, api_key)

    return {"address": addr, "normal_txs": normal, "internal_txs": internal}


def load_raw(address: str, cache_file: str, api_key: str, use_cache: bool) -> dict | None:
    """Return raw data from cache or live fetch."""
    addr = address.lower()

    if os.path.exists(cache_file):
        with open(cache_file) as f:
            cache = json.load(f)
        if addr in cache:
            if use_cache:
                print(f"  [cache hit] Loaded {addr[:12]}... from {cache_file}")
            return cache[addr]

    if use_cache:
        print(f"  [MISS] {addr} not in cache — run without --cache to fetch live")
        return None

    if not api_key:
        print("ERROR: No Etherscan API key. Set ETHERSCAN_API_KEY in .env or use --cache")
        return None

    raw = fetch_live(addr, api_key)

    # Save to cache for future runs
    cache = {}
    if os.path.exists(cache_file):
        with open(cache_file) as f:
            cache = json.load(f)
    cache[addr] = raw
    with open(cache_file, "w") as f:
        json.dump(cache, f, indent=2)
    print(f"  [saved] Raw data cached to {cache_file}")

    return raw


# ─────────────────────────────────────────────────────────────────────────────
# Report printer
# ─────────────────────────────────────────────────────────────────────────────

VERDICT_COLOURS = {
    "CLEAN":                        "\033[92m",   # green
    "INSUFFICIENT_DEPLOYMENT_HISTORY": "\033[96m",# cyan
    "WEAK_PATTERN":                 "\033[93m",   # yellow
    "MODERATE_PATTERN":             "\033[33m",   # dark yellow
    "STRONG_PATTERN":               "\033[91m",   # light red
    "HIGH_CONFIDENCE_RUGPULL":      "\033[31m",   # red
}
RESET = "\033[0m"
BOLD  = "\033[1m"
DIM   = "\033[2m"


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

    print(f"  F1  Warmup hours      : {_fmt(fv.f1_warmup_hours, 'h')}")
    print(f"  F2  Funding CV        : {_fmt(fv.f2_funding_cv)}")
    print(f"  F3  Dry-run count     : {fv.f3_dry_run_count}")
    print(f"  F4  Deployment count  : {fv.f4_deployment_count}")
    print(f"  F4b Burstiness        : {_fmt(fv.f4_burstiness)} {DIM}(narrative only){RESET}")
    print(f"  F5  Nonce entropy     : {_fmt(fv.f5_nonce_entropy, ' bits')} {DIM}(narrative only){RESET}")
    print(f"  F7  Within-wallet sim : {_fmt(fv.f7_within_wallet_sim)} {DIM}(narrative only){RESET}")
    print(f"  NEW-A Single deploy   : {fv.new_a_single_deploy}")
    print(f"  Funding sources       : {len(fv.all_funding_sources)} unique addresses")

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
            print(f"         {r['description']}")
            pts = report.score_breakdown.get(r['rule_id'], 0)
            print(f"         {DIM}Points: +{pts}  |  Reasoning: {r['reasoning'][:100]}...{RESET}")
            print()

    # Multi-hop targets
    if report.multihop_addresses:
        print(thin)
        print(f"  {BOLD}[!] MULTI-HOP TARGETS - Queue for secondary investigation:{RESET}")
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

    print("Running rugpull triage engine...")
    report = engine.run(addr, raw)
    print_report(report)

    # Hint for multihop
    if report.multihop_addresses:
        print("\nTip: Test the multi-hop targets above:")
        for target in set(report.multihop_addresses):
            print(f"  python test_rugpull.py {target} --cache")


if __name__ == "__main__":
    main()
