"""
extract_all_features_csv.py
─────────────────────────────────────────────────────────────────────────────
Runs the complete rugpull feature extraction pipeline against all wallets
(90 confirmed rugpull + 18 genuine deployers) and writes a raw feature
matrix CSV.

OUTPUT: full_feature_matrix.csv
  - One row per wallet.
  - First two columns: address, label (rugpull / genuine).
  - Every subsequent column is a raw FeatureVector field — the actual
    measured figure for that wallet (float, int, bool, or str).
  - No severity labels, no scores, no verdicts anywhere in the file.

FEATURE GROUPS COVERED (63 raw fields):
  Group 1 — Baseline Pre-Deployment (F1-F7):    9 fields
  Group 2 — Funding Provenance (FP1-FP8):        9 fields
  Group 3 — Post-Exploit Cash-Out (CP1-CP7):    15 fields (incl. cp_victim_inflow_wei)
  Group 4 — Value-Transfer Semantics (VS1-VS6): 21 fields
  Group 5 — Exit and Dormancy (EXIT-1,2,4,META):  9 fields

DESIGN:
  - Uses engine.run() as the single entry point so all merge/ordering
    invariants (CP before EXIT, CP fields feed EXIT-4, scoring feeds
    EXIT-META) are guaranteed identical to production.
  - FundingProvenance is computed separately and passed as fp_result,
    exactly as test_full_dataset.py does.
  - wallet_age_lookup is built from the age cache for both senders (FP3)
    and post-deploy destinations (CP4).
  - Runs entirely from cached data — no live API calls unless --fetch is
    passed.

USAGE:
  # Offline (uses raw_wallet_data_v2.json + wallet_age_cache.json)
  .\\venv\\Scripts\\python.exe extract_all_features_csv.py

  # With live API fallback for wallets/addresses not in cache
  .\\venv\\Scripts\\python.exe extract_all_features_csv.py --fetch
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import traceback
from pathlib import Path

# ── Force UTF-8 on Windows CMD ────────────────────────────────────────────────
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")

# ── Path setup ────────────────────────────────────────────────────────────────
ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from cli_utils import (
    KNOWN_RUGPULL,
    KNOWN_GENUINE,
    find_deploy_ts,
    load_json,
    save_json,
    fetch_first_tx_ts,
)
from backend.forensics.rugpull.engine import RugpullEngine, RugpullReport
from backend.forensics.rugpull.extractor import FeatureVector
from backend.forensics.rugpull.funding_graph import extract_funding_provenance, FunderGraph

# ─────────────────────────────────────────────────────────────────────────────
# Paths
# ─────────────────────────────────────────────────────────────────────────────
DATASET_CACHE_FILE  = ROOT / "raw_wallet_data_v2.json"
AGE_CACHE_FILE      = ROOT / "wallet_age_cache.json"
KNOWN_ENTITIES_PATH = ROOT / "backend" / "blockchain" / "known_entities.json"
DB_PATH             = ROOT / "investigation_history.db"
OUTPUT_CSV          = ROOT / "full_feature_matrix.csv"

# ─────────────────────────────────────────────────────────────────────────────
# Column specification
# Each tuple: (csv_column_name, FeatureVector_attribute_name)
# The two names are identical here — kept as pairs for explicit clarity.
# ─────────────────────────────────────────────────────────────────────────────
COLUMNS: list[tuple[str, str]] = [
    # ── Group 1: Baseline Pre-Deployment (F1-F7) ──────────────────────────────
    ("f1_warmup_hours",              "f1_warmup_hours"),
    ("f2_funding_cv",                "f2_funding_cv"),
    ("f3_dry_run_count",             "f3_dry_run_count"),
    ("f4_deployment_count",          "f4_deployment_count"),
    ("f4_burstiness",                "f4_burstiness"),
    ("f5_nonce_entropy",             "f5_nonce_entropy"),
    ("f7_within_wallet_sim",         "f7_within_wallet_sim"),
    ("new_a_single_deploy",          "new_a_single_deploy"),
    ("ownership_transfer_count",     "ownership_transfer_count"),

    # ── Group 2: Funding Provenance (FP1-FP8) ─────────────────────────────────
    ("fp_first_inbound_source_type",    "fp_first_inbound_source_type"),
    ("fp_min_hops_to_known_source",     "fp_min_hops_to_known_source"),
    ("fp_fraction_fresh_capital",       "fp_fraction_fresh_capital"),
    ("fp_funding_entropy_norm",         "fp_funding_entropy_norm"),
    ("fp_median_seed_eth",              "fp_median_seed_eth"),
    ("fp_seed_tx_count",                "fp_seed_tx_count"),
    ("fp_standardized_seed_gas_units",  "fp_standardized_seed_gas_units"),
    ("fp_shared_upstream_funders",      "fp_shared_upstream_funders"),
    ("fp_max_funder_jaccard",           "fp_max_funder_jaccard"),

    # ── Group 3: Post-Exploit Cash-Out (CP1-CP7) ──────────────────────────────
    ("cp1_withdrawal_latency_sec",          "cp1_withdrawal_latency_sec"),
    ("cp2_withdrawal_count",                "cp2_withdrawal_count"),
    ("cp2_drain_ratio",                     "cp2_drain_ratio"),
    ("cp2_withdrawal_span_hours",           "cp2_withdrawal_span_hours"),
    ("cp3_outflow_cv",                      "cp3_outflow_cv"),
    ("cp3_round_number_ratio",              "cp3_round_number_ratio"),
    ("cp3_outflow_count",                   "cp3_outflow_count"),
    ("cp4_suspicious_destination_count",    "cp4_suspicious_destination_count"),
    ("cp4_fresh_wallet_ratio",              "cp4_fresh_wallet_ratio"),
    ("cp5_concentration_ratio",             "cp5_concentration_ratio"),
    ("cp5_mixer_contact",                   "cp5_mixer_contact"),
    ("cp6_swap_detected",                   "cp6_swap_detected"),
    ("cp6_swap_latency_sec",                "cp6_swap_latency_sec"),
    ("cp7_retained_ratio",                  "cp7_retained_ratio"),
    ("cp_victim_inflow_wei",                "cp_victim_inflow_wei"),

    # ── Group 4: Value-Transfer Semantics (VS1-VS6) ───────────────────────────
    ("vs1_mode_freq_ratio",              "vs1_mode_freq_ratio"),
    ("vs1_top2_coverage",                "vs1_top2_coverage"),
    ("vs1_inbound_count",                "vs1_inbound_count"),
    ("vs2_round_funding_ratio",          "vs2_round_funding_ratio"),
    ("vs2_pre_deploy_funding_count",     "vs2_pre_deploy_funding_count"),
    ("vs3_cv_gas",                       "vs3_cv_gas"),
    ("vs3_round_gas_ratio",              "vs3_round_gas_ratio"),
    ("vs3_gas_tx_count",                 "vs3_gas_tx_count"),
    ("vs4_outbound_dust_count",          "vs4_outbound_dust_count"),
    ("vs4_pre_cashout_dust_count",       "vs4_pre_cashout_dust_count"),
    ("vs4_unique_dust_destinations",     "vs4_unique_dust_destinations"),
    ("vs4_inbound_dust_count",           "vs4_inbound_dust_count"),
    ("vs5_avg_cross_deploy_jaccard",     "vs5_avg_cross_deploy_jaccard"),
    ("vs5_deployment_count_for_vs5",     "vs5_deployment_count_for_vs5"),
    ("vs6_v_deploy_eth",                 "vs6_v_deploy_eth"),
    ("vs6_v_self_fund_eth",              "vs6_v_self_fund_eth"),
    ("vs6_v_cashout_eth",                "vs6_v_cashout_eth"),
    ("vs6_extraction_multiplier",        "vs6_extraction_multiplier"),
    ("vs6_lp_eth_added",                 "vs6_lp_eth_added"),
    ("vs6_lp_eth_removed",               "vs6_lp_eth_removed"),
    ("vs6_lp_net_eth",                   "vs6_lp_net_eth"),
    ("vs6_creator_token_fraction",       "vs6_creator_token_fraction"),
    ("vs6_mint_to_lp_latency_sec",       "vs6_mint_to_lp_latency_sec"),

    # ── Group 5: Exit and Dormancy (EXIT-1, EXIT-2, EXIT-4, EXIT-META) ─────────
    ("exit1_silence_days",               "exit1_silence_days"),
    ("exit1_silence_ratio",              "exit1_silence_ratio"),
    ("exit2_dormancy_event_count",       "exit2_dormancy_event_count"),
    ("exit2_max_gap_days",               "exit2_max_gap_days"),
    ("exit2_reactivation_context_score", "exit2_reactivation_context_score"),
    ("exit4_youngest_dest_age_days",     "exit4_youngest_dest_age_days"),
    ("exit4_total_eth_to_fresh_wallets", "exit4_total_eth_to_fresh_wallets"),
    ("exit4_bulk_transfer_count",        "exit4_bulk_transfer_count"),
    ("exit_meta_retirement_likelihood",  "exit_meta_retirement_likelihood"),
    ("exit_meta_retirement_label",       "exit_meta_retirement_label"),
]

CSV_HEADER = ["address", "label"] + [col for col, _ in COLUMNS]


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _fmt(v, decimals: int = 6):
    """
    Format a value for a CSV cell.
    - float   → rounded to `decimals` places
    - None    → empty string  (blank cell, not the word 'None')
    - bool    → True / False  (Python capitalised booleans)
    - int/str → unchanged
    """
    if v is None:
        return ""
    if isinstance(v, float):
        return round(v, decimals)
    return v


def _fv_to_row(address: str, label: str, fv: FeatureVector) -> list:
    """Extract every target field from a FeatureVector into a flat list."""
    row = [address, label]
    for _, attr in COLUMNS:
        row.append(_fmt(getattr(fv, attr, None)))
    return row


def _build_wallet_age_lookup(
    addr: str,
    raw: dict,
    deploy_ts: int,
    known_entities: dict,
    age_cache: dict,
    api_key: str,
    allow_fetch: bool,
) -> dict[str, int | None]:
    """
    Build {address: first_tx_timestamp | None} covering all senders and
    post-deploy destinations that the extractors need for age checks.

    FP3 needs sender ages (fresh capital fraction).
    CP4 needs destination ages (fresh mule wallet ratio).
    """
    normal_txs   = raw.get("normal_txs", [])
    internal_txs = raw.get("internal_txs", [])
    all_txs      = normal_txs + internal_txs

    # All unique addresses that sent ETH to the creator
    senders: set[str] = {
        tx.get("from", "").lower()
        for tx in all_txs
        if tx.get("to", "").lower() == addr
        and int(tx.get("value", "0")) > 0
        and tx.get("from", "").lower() not in ("", addr)
    }

    # First contract deployed by this wallet (to exclude from destinations)
    contract_addr = next(
        (
            tx.get("contractAddress", "").lower()
            for tx in sorted(normal_txs, key=lambda t: int(t.get("timeStamp", 0)))
            if tx.get("from", "").lower() == addr
            and tx.get("to", "") in ("", None)
            and tx.get("contractAddress") not in ("", None)
        ),
        "",
    )

    # Post-deploy destinations the creator sent ETH to
    destinations: set[str] = {
        tx.get("to", "").lower()
        for tx in all_txs
        if tx.get("from", "").lower() == addr
        and tx.get("to", "") not in ("", None, contract_addr)
        and int(tx.get("value", "0")) > 0
        and tx.get("contractAddress") in ("", None)
        and int(tx.get("timeStamp", 0)) >= deploy_ts
    }

    lookup: dict[str, int | None] = {}
    for target in (senders | destinations) - {""}:
        # Known entities (CEX, mixer, DEX) are marked as non-fresh via None
        if target in known_entities:
            lookup[target] = None
            continue
        if target in age_cache:
            lookup[target] = age_cache[target]
        elif allow_fetch and api_key:
            ts = fetch_first_tx_ts(target, api_key)
            age_cache[target] = ts
            lookup[target] = ts
        else:
            # Unknown age when offline → treated conservatively (not fresh)
            lookup[target] = None

    return lookup


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Extract raw feature matrix for all wallets → full_feature_matrix.csv\n"
            "All 6 feature groups, 63 raw FeatureVector fields. No scores, no severity."
        )
    )
    parser.add_argument(
        "--fetch",
        action="store_true",
        help="Allow live Etherscan API calls for wallets or addresses not in cache.",
    )
    args = parser.parse_args()

    api_key = os.environ.get("ETHERSCAN_API_KEY", "")
    if args.fetch and not api_key:
        print("[ERROR] --fetch requires ETHERSCAN_API_KEY in .env")
        sys.exit(1)

    # ── Load caches ───────────────────────────────────────────────────────────
    print(f"Loading dataset cache  : {DATASET_CACHE_FILE}")
    dataset_cache: dict = load_json(str(DATASET_CACHE_FILE))
    print(f"  → {len(dataset_cache)} wallet records in cache")

    print(f"Loading wallet age cache: {AGE_CACHE_FILE}")
    age_cache: dict = load_json(str(AGE_CACHE_FILE))
    print(f"  → {len(age_cache)} address ages in cache")

    known_entities: dict = {}
    if KNOWN_ENTITIES_PATH.exists():
        with open(KNOWN_ENTITIES_PATH, encoding="utf-8") as f:
            raw_ent = json.load(f)
        for cat, entries in raw_ent.items():
            if not cat.startswith("_") and isinstance(entries, dict):
                for k, v in entries.items():
                    known_entities[k.lower()] = v
        print(f"Loaded {len(known_entities)} known entities (CEX/mixer/DEX/bridge)")
    else:
        print("[WARN] known_entities.json not found — FP/CP entity lookups will be empty")

    print()

    engine    = RugpullEngine()
    funder_db = FunderGraph(DB_PATH)

    # Dataset: rugpull wallets, then genuine wallets
    all_wallets: list[tuple[str, str]] = (
        [(addr.lower(), "rugpull") for addr in KNOWN_RUGPULL]
        + [(addr.lower(), "genuine") for addr in KNOWN_GENUINE]
    )
    total = len(all_wallets)

    print(f"Dataset: {len(KNOWN_RUGPULL)} rugpull + {len(KNOWN_GENUINE)} genuine = {total} wallets")
    print("=" * 80)

    rows:    list[list]          = []
    skipped: list[str]           = []
    errors:  list[tuple[str, str]] = []

    for idx, (addr, label) in enumerate(all_wallets, start=1):
        tag = f"[{idx:>3}/{total}] {label:>8}  {addr}"
        print(tag, end="  ")

        # ── Get raw data from cache (or live if --fetch) ──────────────────────
        raw = dataset_cache.get(addr) or dataset_cache.get(addr.lower())
        if raw is None:
            if args.fetch:
                from cli_utils import fetch_wallet_full
                live_tmp: dict = {}
                try:
                    raw = fetch_wallet_full(addr, api_key, live_tmp)
                    dataset_cache[addr] = raw
                    save_json(str(DATASET_CACHE_FILE), dataset_cache)
                except Exception as exc:
                    print(f"→ FETCH ERROR: {exc}")
                    skipped.append(addr)
                    continue
            else:
                print("→ SKIP (not in cache — run with --fetch)")
                skipped.append(addr)
                continue

        normal_txs   = raw.get("normal_txs", [])
        internal_txs = raw.get("internal_txs", [])
        all_txs      = normal_txs + internal_txs

        if not all_txs:
            print("→ SKIP (no transactions)")
            skipped.append(addr)
            continue

        # ── Build wallet_age_lookup ───────────────────────────────────────────
        deploy_ts = find_deploy_ts(addr, normal_txs, all_txs)
        wallet_age_lookup = _build_wallet_age_lookup(
            addr=addr,
            raw=raw,
            deploy_ts=deploy_ts,
            known_entities=known_entities,
            age_cache=age_cache,
            api_key=api_key,
            allow_fetch=args.fetch,
        )

        # Save any freshly fetched ages back to disk
        if args.fetch:
            age_cache.update({k: v for k, v in wallet_age_lookup.items()})
            save_json(str(AGE_CACHE_FILE), age_cache)

        # ── Funding provenance (FP1-FP8) ──────────────────────────────────────
        fp_result = None
        try:
            fp_result = extract_funding_provenance(
                wallet_address=addr,
                txs=all_txs,
                deploy_timestamp=deploy_ts,
                known_entities=known_entities,
                wallet_age_lookup=wallet_age_lookup,
                funder_graph_db=funder_db,
            )
        except Exception as exc:
            # FP failure is non-fatal — FP fields stay at defaults (UNKNOWN_EOA etc.)
            print(f"\n    [WARN] FP extraction failed for {addr[:14]}: {exc}", end="")

        # ── Full engine run (Steps 1-6.5) ─────────────────────────────────────
        try:
            report: RugpullReport = engine.run(
                address=addr,
                raw_data=raw,
                fp_result=fp_result,
                wallet_age_lookup=wallet_age_lookup,
                known_entities=known_entities,
            )
        except Exception as exc:
            err_msg = f"{type(exc).__name__}: {exc}"
            print(f"\n    [ERROR] engine.run() failed: {err_msg}")
            traceback.print_exc()
            errors.append((addr, err_msg))
            continue

        # ── Collect raw FeatureVector values into a CSV row ───────────────────
        fv: FeatureVector = report.features
        row = _fv_to_row(addr, label, fv)
        rows.append(row)

        # Status line: score + number of rules fired (not written to CSV)
        n_fired = len(report.triggered_rules)
        print(f"→ score={report.score:>3}  fired={n_fired:>2}  verdict={report.verdict}")

    # ── Write CSV ─────────────────────────────────────────────────────────────
    print("\n" + "=" * 80)
    print(f"Writing CSV → {OUTPUT_CSV}")

    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(CSV_HEADER)
        writer.writerows(rows)

    # ── Final summary ─────────────────────────────────────────────────────────
    print(f"\n  Rows written : {len(rows)}")
    print(f"  Skipped      : {len(skipped)}")
    print(f"  Errors       : {len(errors)}")
    print(f"  CSV columns  : {len(CSV_HEADER)}  (address + label + {len(COLUMNS)} raw feature fields)")
    print(f"  Output file  : {OUTPUT_CSV}")
    print("=" * 80)

    if skipped:
        print("\nSkipped (not in cache or empty):")
        for a in skipped:
            print(f"  {a}")

    if errors:
        print("\nEngine errors:")
        for a, msg in errors:
            print(f"  {a}  →  {msg}")

    # ── Quick spot-check: print a slice of the first 4 rows ───────────────────
    if rows:
        spot_fields = [
            "address", "label",
            "f1_warmup_hours", "f4_deployment_count",
            "cp1_withdrawal_latency_sec", "cp2_drain_ratio",
            "vs1_mode_freq_ratio", "vs6_extraction_multiplier",
            "exit1_silence_days", "exit2_dormancy_event_count",
            "exit_meta_retirement_likelihood",
        ]
        idx_map = {name: CSV_HEADER.index(name) for name in spot_fields if name in CSV_HEADER}

        print("\nSpot-check (first 4 rows, selected columns):\n")
        # Header
        print("  " + "  ".join(f"{n[:20]:>20}" for n in spot_fields))
        print("  " + "-" * (22 * len(spot_fields)))
        for row in rows[:4]:
            vals = [str(row[idx_map[n]])[:20] if n in idx_map else "" for n in spot_fields]
            print("  " + "  ".join(f"{v:>20}" for v in vals))
        print()


if __name__ == "__main__":
    main()
