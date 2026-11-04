"""
test_vs_features.py
─────────────────────────────────────────────────────────────────────────────
Standalone per-feature evaluation script for the VS1-VS6 Value-Transfer
Semantics features.

PURPOSE:
  This is the comparative analysis tool. It evaluates each VS feature
  INDIVIDUALLY against the full wallet dataset and produces:

  1. A raw value matrix CSV — one row per wallet, one column per VS metric,
     with the wallet's class label (rugpull / genuine). This is the primary
     input for threshold optimisation and intersection wallet study.

  2. A per-feature performance table — trigger rate, FP rate, precision
     for each VS rule at the current hardcoded thresholds.

  Features are evaluated WITHOUT running the full RugpullEngine, so each
  VS signal can be studied in isolation without confounding effects from
  other rules.

USAGE:
  # Run all 6 VS features against the full dataset
  python test_vs_features.py --all

  # Run a single feature
  python test_vs_features.py --feature vs1
  python test_vs_features.py --feature vs6

  # Also fetch token_txs for VS6 minting metrics (1 extra API call per wallet)
  python test_vs_features.py --all --fetch-tokens

  # Use a specific API key (overrides .env)
  python test_vs_features.py --all --api-key YOUR_KEY

OUTPUTS:
  vs_raw_values.csv           — per-wallet per-feature raw value matrix
  vs_feature_report.txt       — human-readable per-feature performance table
  token_txs_cache.json        — cached token transfer data (VS6 minting only)
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
from typing import Any, Optional

# Force UTF-8 output on Windows CMD to prevent UnicodeEncodeError crashes
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")

# ── Path setup: allow running from project root without installing the package
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cli_utils import (
    KNOWN_RUGPULL,
    KNOWN_GENUINE,
    RESET, BOLD, DIM,
    RED, YELLOW, GREEN, CYAN, MAGENTA,
    fetch_token_txs,
    load_json,
    save_json,
)
from backend.forensics.rugpull.extractor import extract_vs_features
from backend.forensics.rugpull.rules import (
    rule_vs1_repeated_values,
    rule_vs2_round_funding,
    rule_vs3_gas_anomaly,
    rule_vs4_dusting,
    rule_vs5_cross_deploy_consistency,
    rule_vs6_extraction_multiplier,
    FeatureVector,
)
from backend.settings.base import get_settings

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

DATASET_CACHE   = "raw_wallet_data_v2.json"
TOKEN_CACHE     = "token_txs_cache.json"
RAW_VALUES_CSV  = "vs_raw_values.csv"
REPORT_TXT      = "vs_feature_report.txt"

# VS metric field names as they appear in the FeatureVector — used for CSV columns
VS_FIELD_NAMES = [
    "vs1_mode_freq_ratio",
    "vs1_top2_coverage",
    "vs1_inbound_count",
    "vs2_round_funding_ratio",
    "vs2_pre_deploy_funding_count",
    "vs3_cv_gas",
    "vs3_round_gas_ratio",
    "vs3_gas_tx_count",
    "vs4_outbound_dust_count",
    "vs4_pre_cashout_dust_count",
    "vs4_unique_dust_destinations",
    "vs4_inbound_dust_count",
    "vs5_avg_cross_deploy_jaccard",
    "vs5_deployment_count_for_vs5",
    "vs6_v_deploy_eth",
    "vs6_v_self_fund_eth",
    "vs6_v_cashout_eth",
    "vs6_extraction_multiplier",
    "vs6_lp_eth_added",
    "vs6_lp_eth_removed",
    "vs6_lp_net_eth",
    "vs6_creator_token_fraction",
    "vs6_mint_to_lp_latency_sec",
]

# Map short name to (rule_function, display_name)
VS_RULES = {
    "vs1": (rule_vs1_repeated_values,       "RUG-VS-1  Scripted Inbound Value Repetition"),
    "vs2": (rule_vs2_round_funding,          "RUG-VS-2  Round-Number Pre-Deploy Funding"),
    "vs3": (rule_vs3_gas_anomaly,            "RUG-VS-3  Gas-Price Uniformity Anomaly"),
    "vs4": (rule_vs4_dusting,                "RUG-VS-4  Pre-Cashout Wallet Ping Dusting"),
    "vs5": (rule_vs5_cross_deploy_consistency,"RUG-VS-5  Cross-Deployment Seed Consistency"),
    "vs6": (rule_vs6_extraction_multiplier,  "RUG-VS-6  Extreme Extraction Multiplier / LP Drain"),
}


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _load_dataset(cache_path: str) -> dict[str, dict]:
    """
    Load the existing wallet cache from test_full_dataset.py.
    Returns {address: {"normal_txs": [...], "internal_txs": [...]}}.
    Exits with an error message if the file does not exist — no live fetching.
    """
    if not os.path.exists(cache_path):
        print(f"{RED}[ERROR]{RESET} Cache file not found: {cache_path}")
        print(
            "Run test_full_dataset.py first to populate the cache, then "
            "re-run this script."
        )
        sys.exit(1)

    print(f"{DIM}Loading wallet cache from {cache_path}...{RESET}")
    data = load_json(cache_path)
    print(f"  Loaded {len(data)} cached wallet records.")
    return data


def _load_token_cache(path: str) -> dict[str, list]:
    """Load the token_txs cache, returning empty dict if not present."""
    if os.path.exists(path):
        data = load_json(path)
        print(f"{DIM}Token cache loaded: {len(data)} wallets have token_txs data.{RESET}")
        return data
    return {}


def _fetch_missing_token_txs(
    addresses: list[str],
    token_cache: dict[str, list],
    api_key: str,
) -> dict[str, list]:
    """
    Fetch token_txs for any address not already in the token cache.
    Saves the updated cache to TOKEN_CACHE after every successful fetch.
    """
    missing = [a for a in addresses if a not in token_cache]
    if not missing:
        print(f"{GREEN}All token_txs already cached — skipping fetch.{RESET}")
        return token_cache

    print(f"\n{CYAN}Fetching token_txs for {len(missing)} wallets...{RESET}")
    for i, addr in enumerate(missing, 1):
        print(f"  [{i}/{len(missing)}] {addr[:16]}...", end="", flush=True)
        txs = fetch_token_txs(addr, api_key)
        token_cache[addr] = txs
        print(f" -> {len(txs)} token transfers")
        # Save after every wallet so progress is not lost on interruption
        save_json(TOKEN_CACHE, token_cache)
        time.sleep(0.22)  # Rate limit: 5 req/s on free tier

    return token_cache


def _build_feature_vector(
    addr: str,
    wallet_data: dict,
    token_cache: dict[str, list],
    cfg: Any,
) -> FeatureVector:
    """
    Compute a FeatureVector with VS fields populated for one wallet.
    Starts from a minimal FeatureVector (no F/CP fields needed for VS rules).
    """
    normal_txs   = wallet_data.get("normal_txs",   [])
    internal_txs = wallet_data.get("internal_txs", [])
    token_txs    = token_cache.get(addr)            # None if not fetched

    vs_fields = extract_vs_features(
        normal_txs=normal_txs,
        internal_txs=internal_txs,
        creator_address=addr,
        token_txs=token_txs,
    )

    # Build a minimal FeatureVector and populate VS fields
    fv = FeatureVector(wallet_address=addr)
    fv = fv.model_copy(update=vs_fields)
    return fv


# ─────────────────────────────────────────────────────────────────────────────
# Per-feature evaluation
# ─────────────────────────────────────────────────────────────────────────────

class WalletResult:
    """Holds VS feature values + rule trigger results for one wallet."""
    def __init__(self, address: str, label: str, fv: FeatureVector):
        self.address = address
        self.label   = label   # "rugpull" or "genuine"
        self.fv      = fv


def _evaluate_feature(
    feature_key: str,
    results: list[WalletResult],
    cfg: Any,
) -> dict:
    """
    Run one VS rule against all wallets and collect metrics.
    Returns a summary dict with trigger counts and per-wallet details.
    """
    rule_fn, display_name = VS_RULES[feature_key]

    rugpull_total    = 0
    rugpull_trigger  = 0
    genuine_total    = 0
    genuine_trigger  = 0
    triggered_rugpull_details = []
    triggered_genuine_details = []

    for wr in results:
        result = rule_fn(wr.fv, cfg)

        if wr.label == "rugpull":
            rugpull_total += 1
            if result.triggered:
                rugpull_trigger += 1
                triggered_rugpull_details.append({
                    "address":  wr.address,
                    "severity": result.severity,
                    "details":  result.details,
                })
        else:
            genuine_total += 1
            if result.triggered:
                genuine_trigger += 1
                triggered_genuine_details.append({
                    "address":  wr.address,
                    "severity": result.severity,
                    "details":  result.details,
                })

    # Precision: out of all triggered, what fraction is actually rugpull?
    total_triggered = rugpull_trigger + genuine_trigger
    precision = (rugpull_trigger / total_triggered) if total_triggered > 0 else None
    tp_rate   = (rugpull_trigger / rugpull_total) if rugpull_total > 0 else None
    fp_rate   = (genuine_trigger / genuine_total) if genuine_total > 0 else None

    return {
        "feature_key":   feature_key,
        "display_name":  display_name,
        "rugpull_total": rugpull_total,
        "rugpull_trigger": rugpull_trigger,
        "genuine_total": genuine_total,
        "genuine_trigger": genuine_trigger,
        "tp_rate":    tp_rate,
        "fp_rate":    fp_rate,
        "precision":  precision,
        "triggered_rugpull": triggered_rugpull_details,
        "triggered_genuine": triggered_genuine_details,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Raw value CSV writer
# ─────────────────────────────────────────────────────────────────────────────

def _write_raw_csv(results: list[WalletResult]) -> None:
    """
    Write the per-wallet per-feature raw value matrix to CSV.
    This is the primary input for the end-of-cycle threshold analysis.
    Thresholds are NOT embedded in this file — raw values only.
    """
    rows = []
    for wr in results:
        fv = wr.fv
        row = {
            "address": wr.address,
            "label":   wr.label,
        }
        for field in VS_FIELD_NAMES:
            row[field] = getattr(fv, field, None)
        rows.append(row)

    fieldnames = ["address", "label"] + VS_FIELD_NAMES
    with open(RAW_VALUES_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"\n{GREEN}Raw value matrix written -> {RAW_VALUES_CSV}{RESET}")
    print(
        f"  {len(rows)} wallets × {len(VS_FIELD_NAMES)} VS metrics. "
        "Use this for threshold analysis and intersection wallet study."
    )


# ─────────────────────────────────────────────────────────────────────────────
# Report printer
# ─────────────────────────────────────────────────────────────────────────────

def _print_feature_report(summaries: list[dict]) -> None:
    """Print and save the per-feature performance table."""

    sep = "━" * 68
    lines = []

    def p(s: str = "") -> None:
        print(s)
        lines.append(s)

    p(f"\n{BOLD}{sep}{RESET}")
    p(f"{BOLD}  VS Feature Performance Report (Rugpulls Only){RESET}")
    p(f"{BOLD}  Thresholds: hardcoded estimates (pending end-of-cycle calibration){RESET}")
    p(f"{BOLD}{sep}{RESET}")

    for s in summaries:
        rp_trig  = s["rugpull_trigger"]
        rp_total = s["rugpull_total"]
        tp       = s["tp_rate"]

        tp_str   = f"{tp:.1%}" if tp   is not None else "N/A"
        tp_col   = GREEN  if tp   is not None and tp   >= 0.30 else YELLOW

        p(f"\n  {BOLD}{s['display_name']}{RESET}")
        p(f"  {'─' * 60}")
        p(f"  Rugpulls Triggered: {rp_trig:3d} / {rp_total:3d}  ({tp_col}{tp_str}{RESET} trigger rate)")

        if s["triggered_rugpull"]:
            p(f"\n  {CYAN}Triggered Rugpull Wallets:{RESET}")
            for item in s["triggered_rugpull"]:
                p(f"     {item['address']}  [{item['severity']}]")
        else:
            p(f"\n  {DIM}No rugpull wallets triggered this feature.{RESET}")

    # Summary table
    p(f"\n{BOLD}{sep}{RESET}")
    p(f"{BOLD}  Summary Table{RESET}")
    p(f"{BOLD}{sep}{RESET}")
    p(f"  {'Rule':<10} {'Trigger Rate':>12}")
    p(f"  {'─'*10} {'─'*12}")
    for s in summaries:
        tp_str   = f"{s['tp_rate']:.1%}" if s['tp_rate'] is not None else "N/A"
        key      = s["feature_key"].upper()
        p(f"  {key:<10} {tp_str:>12}")

    p(f"{BOLD}{sep}{RESET}")
    p(f"\n  {DIM}Note: Thresholds are hardcoded estimates. Do NOT treat these numbers{RESET}")
    p(f"  {DIM}as final. Use vs_raw_values.csv for threshold optimisation.{RESET}\n")

    # Save report to file as well (strip ANSI codes for the file)
    import re
    ansi_escape = re.compile(r"\033\[[0-9;]*m")
    clean_lines = [ansi_escape.sub("", line) for line in lines]
    with open(REPORT_TXT, "w", encoding="utf-8") as f:
        f.write("\n".join(clean_lines))
    print(f"{GREEN}Report saved -> {REPORT_TXT}{RESET}")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Evaluate VS1-VS6 features individually against the full wallet dataset.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--all", action="store_true",
        help="Run all 6 VS features (default if --feature not specified).",
    )
    parser.add_argument(
        "--feature", choices=list(VS_RULES.keys()), metavar="FEATURE",
        help="Run a single feature: vs1 | vs2 | vs3 | vs4 | vs5 | vs6",
    )
    parser.add_argument(
        "--fetch-tokens", action="store_true",
        help=(
            "Fetch ERC-20 token transfer data via tokentx endpoint "
            "(needed for VS6 minting metrics). Cached after first run."
        ),
    )
    parser.add_argument(
        "--api-key", default=None,
        help="Etherscan API key. Falls back to .env ETHERSCAN_API_KEY.",
    )
    parser.add_argument(
        "--cache", default=DATASET_CACHE,
        help=f"Path to wallet data cache (default: {DATASET_CACHE}).",
    )
    args = parser.parse_args()

    if not args.all and not args.feature:
        # Default to --all if nothing specified
        args.all = True

    # ── API key
    api_key = args.api_key
    if not api_key:
        try:
            api_key = get_settings().etherscan.api_key
        except Exception:
            api_key = os.environ.get("ETHERSCAN_API_KEY", "")
    if not api_key or api_key == "not-configured":
        print(f"{RED}[ERROR]{RESET} No Etherscan API key configured.")
        print("Set ETHERSCAN_API_KEY in .env or use --api-key.")
        sys.exit(1)

    # ── Config (thresholds)
    cfg = get_settings().rugpull

    # ── Load wallet dataset cache
    wallet_data = _load_dataset(args.cache)

    # ── Build address list with labels
    # Use the addresses that are actually present in the cache
    all_addresses: list[tuple[str, str]] = []  # (address, label)

    rugpull_set = {a.lower() for a in KNOWN_RUGPULL}
    genuine_set = {a.lower() for a in KNOWN_GENUINE}

    for addr_lower in wallet_data:
        if addr_lower in rugpull_set:
            all_addresses.append((addr_lower, "rugpull"))
        else:
            # Skip genuine or unclassified wallets completely as requested
            continue

    rugpull_count = sum(1 for _, lbl in all_addresses if lbl == "rugpull")
    print(
        f"\n{BOLD}Dataset:{RESET} {len(all_addresses)} wallets  "
        f"({CYAN}{rugpull_count} rugpulls only{RESET})"
    )

    # ── Fetch token_txs if requested (for VS6 minting)
    token_cache: dict[str, list] = {}
    if args.fetch_tokens or (args.feature == "vs6") or args.all:
        token_cache = _load_token_cache(TOKEN_CACHE)
        if args.fetch_tokens:
            addresses_needed = [a for a, _ in all_addresses]
            token_cache = _fetch_missing_token_txs(
                addresses=addresses_needed,
                token_cache=token_cache,
                api_key=api_key,
            )

    # ── Build FeatureVectors for all wallets
    print(f"\n{CYAN}Computing VS features for {len(all_addresses)} wallets...{RESET}")
    wallet_results: list[WalletResult] = []

    for i, (addr, label) in enumerate(all_addresses, 1):
        data = wallet_data.get(addr, {})
        if not data:
            continue

        fv = _build_feature_vector(addr, data, token_cache, cfg)
        wallet_results.append(WalletResult(addr, label, fv))

        if i % 20 == 0 or i == len(all_addresses):
            print(f"  {i}/{len(all_addresses)} wallets processed...", end="\r")

    print(f"  {len(wallet_results)} wallets ready.                    ")

    # ── Write raw value CSV (always — this is the primary analysis artifact)
    _write_raw_csv(wallet_results)

    # ── Determine which features to evaluate
    features_to_run: list[str] = []
    if args.feature:
        features_to_run = [args.feature]
    else:
        features_to_run = list(VS_RULES.keys())

    # ── Evaluate each selected feature
    summaries: list[dict] = []
    for fkey in features_to_run:
        _, display_name = VS_RULES[fkey]
        print(f"\n{CYAN}Evaluating {display_name}...{RESET}")
        summary = _evaluate_feature(fkey, wallet_results, cfg)
        summaries.append(summary)

    # ── Print and save report
    _print_feature_report(summaries)


if __name__ == "__main__":
    main()
