"""
test_funding_provenance.py
─────────────────────────────────────────────────────────────────────────────
Quick test harness for the new Funding Provenance features (FP1-FP8).

Fetches live Etherscan data for one address, runs ALL rugpull rules
(both old F1-F7 and new FP1-FP8), and prints the full enriched report.

USAGE:
    python test_funding_provenance.py 0xABC...

The new FP fields need extra data beyond what the old engine fetches:
  - The first-tx timestamp of each SENDER (for fresh-wallet detection)
  - The known_entities.json lookup table

For now, we load known_entities.json from the data/ folder.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from cli_utils import (
    BOLD, DIM, RESET, GREEN, RED, CYAN, YELLOW, MAGENTA,
    _etherscan_get, fetch_first_tx_ts,
    find_deploy_ts,
)

from backend.forensics.rugpull.extractor import extract_features, FeatureVector
from backend.forensics.rugpull.rules import evaluate_all
from backend.forensics.rugpull.scorer import compute_score
from backend.forensics.rugpull.funding_graph import (
    extract_funding_provenance,
    FunderGraph,
)
from backend.settings.base import get_settings

KNOWN_ENTITIES_PATH = Path(__file__).parent / "backend" / "blockchain" / "known_entities.json"
DB_PATH             = Path(__file__).parent / "investigation_history.db"

# BOLD, DIM, RESET, RED, YELLOW, GREEN, CYAN, MAGENTA imported from cli_utils.
# ETHERSCAN_BASE removed — now in cli_utils.

# Severity colours unique to this script
SEV_COLOUR = {
    "CRITICAL": "\033[31m",
    "HIGH":     "\033[91m",
    "MEDIUM":   "\033[93m",
    "LOW":      "\033[96m",
}


# ─────────────────────────────────────────────────────────────────────────────
# _etherscan_get and fetch_first_tx_ts imported from cli_utils.
# fetch_wallet below is intentionally kept local (unique print format).
# ─────────────────────────────────────────────────────────────────────────────

def fetch_wallet(address: str, api_key: str) -> dict:
    addr = address.lower()
    print(f"  -> Fetching normal txs   for {addr[:14]}...")
    normal = _etherscan_get({
        "module": "account", "action": "txlist",
        "address": addr, "sort": "asc", "page": 1, "offset": 10000,
    }, api_key)
    print(f"  -> Fetching internal txs for {addr[:14]}...")
    internal = _etherscan_get({
        "module": "account", "action": "txlistinternal",
        "address": addr, "sort": "asc", "page": 1, "offset": 10000,
    }, api_key)
    return {"address": addr, "normal_txs": normal, "internal_txs": internal}


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("Usage: python test_funding_provenance.py <wallet_address>")
        sys.exit(1)

    addr = sys.argv[1].strip().lower()
    if not addr.startswith("0x") or len(addr) != 42:
        print(f"ERROR: '{addr}' is not a valid Ethereum address.")
        sys.exit(1)

    api_key = os.environ.get("ETHERSCAN_API_KEY", "")
    if not api_key:
        print("ERROR: ETHERSCAN_API_KEY not found in .env")
        sys.exit(1)

    # ── Load known_entities.json (flatten nested categories into flat dict) ──────
    known_entities: dict = {}
    if KNOWN_ENTITIES_PATH.exists():
        with open(KNOWN_ENTITIES_PATH) as f:
            raw_entities = json.load(f)
        # File is structured as {category: {address: {label, type, ...}}}
        # Flatten to {address: {label, type, ...}} for O(1) lookup
        for category, entries in raw_entities.items():
            if category.startswith("_"):
                continue  # skip _comment etc
            if isinstance(entries, dict):
                for addr_key, info in entries.items():
                    known_entities[addr_key.lower()] = info
        print(f"  Loaded {len(known_entities)} known entities from {KNOWN_ENTITIES_PATH.name}")
    else:
        print(f"  [WARN] {KNOWN_ENTITIES_PATH} not found -- FP1 source type will be UNKNOWN_EOA")

    # ── Fetch main wallet data ────────────────────────────────────────────────
    print(f"\n{BOLD}[1/3] Fetching transaction data for {addr}{RESET}")
    raw = fetch_wallet(addr, api_key)
    all_txs = raw.get("normal_txs", []) + raw.get("internal_txs", [])

    if not all_txs:
        print("  [WARN] No transactions found for this address.")

    # ── Find deploy timestamp ─────────────────────────────────────────────────
    deploy_ts = find_deploy_ts(addr, raw.get("normal_txs", []), all_txs)
    print(f"  Found {len([tx for tx in raw.get('normal_txs', []) if tx.get('to') in ('', None) and tx.get('contractAddress') not in ('', None)])} deployment(s). Using deploy_ts = {deploy_ts}")

    # ── Fetch sender wallet ages (for fresh-wallet detection) ─────────────────
    print(f"\n{BOLD}[2/3] Fetching sender wallet ages (for fresh-wallet detection){RESET}")
    unique_senders = {
        tx.get("from", "").lower()
        for tx in all_txs
        if tx.get("to", "").lower() == addr
        and int(tx.get("value", "0")) > 0
        and tx.get("from", "").lower() != addr
    }
    print(f"  Found {len(unique_senders)} unique sender(s) to check...")

    wallet_age_lookup: dict[str, int | None] = {}
    for i, sender in enumerate(unique_senders):
        if sender in known_entities:
            wallet_age_lookup[sender] = None  # known entity, skip age check
            continue
        ts = fetch_first_tx_ts(sender, api_key)
        wallet_age_lookup[sender] = ts
        if (i + 1) % 5 == 0:
            print(f"    Checked {i+1}/{len(unique_senders)} senders...")

    print(f"  Done. Age data for {len(wallet_age_lookup)} senders collected.")

    # ── Run old features ──────────────────────────────────────────────────────
    print(f"\n{BOLD}[3/3] Running Rugpull Engine{RESET}")
    base_fv = extract_features(addr, raw)

    # ── Run new Funding Provenance features ───────────────────────────────────
    funder_db = FunderGraph(DB_PATH)
    fp_result = extract_funding_provenance(
        wallet_address    = addr,
        txs               = all_txs,
        deploy_timestamp  = deploy_ts,
        known_entities    = known_entities,
        wallet_age_lookup = wallet_age_lookup,
        funder_graph_db   = funder_db,
    )

    # ── Merge FP fields into FeatureVector ────────────────────────────────────
    # FeatureVector is frozen, so we rebuild with the FP fields populated
    fv = base_fv.model_copy(update={
        "fp_first_inbound_source_type":   fp_result.first_inbound_source_type,
        "fp_min_hops_to_known_source":    fp_result.min_hops_to_known_source,
        "fp_fraction_fresh_capital":      fp_result.fraction_fresh_capital,
        "fp_funding_entropy_norm":        fp_result.funding_entropy_norm,
        "fp_median_seed_eth":             fp_result.median_seed_eth,
        "fp_seed_tx_count":               fp_result.seed_tx_count,
        "fp_standardized_seed_gas_units": fp_result.standardized_seed_gas_units,
        "fp_shared_upstream_funders":     fp_result.shared_upstream_funders_flag,
        "fp_max_funder_jaccard":          fp_result.max_funder_jaccard,
    })

    # ── Run ALL rules (old + new) ─────────────────────────────────────────────
    cfg = get_settings().rugpull
    rule_results = evaluate_all(fv, cfg)
    scored = compute_score(rule_results, cfg)

    # ── Print full report ─────────────────────────────────────────────────────
    sep  = "=" * 70
    thin = "-" * 70

    verdict_colours = {
        "CLEAN":                           GREEN,
        "INSUFFICIENT_DEPLOYMENT_HISTORY": CYAN,
        "WEAK_PATTERN":                    YELLOW,
        "MODERATE_PATTERN":                YELLOW,
        "STRONG_PATTERN":                  RED,
        "HIGH_CONFIDENCE_RUGPULL":         RED,
    }
    vc = verdict_colours.get(scored.verdict, "")

    print(f"\n{sep}")
    print(f"  {BOLD}RUGPULL TRIAGE REPORT (+ Funding Provenance){RESET}")
    print(f"  Wallet : {addr}")
    print(sep)
    print(f"  {vc}{BOLD}{scored.verdict}  (score: {scored.score}/100){RESET}")
    if scored.override_applied:
        print(f"  {DIM}Override: {scored.override_applied[:100]}...{RESET}")

    print(f"\n{thin}")
    print(f"  {BOLD}ORIGINAL BEHAVIOURAL FEATURES (F1-F7){RESET}")
    print(thin)

    def _f(v, unit=""):
        return f"{DIM}None{RESET}" if v is None else f"{v:.4f}{unit}"

    print(f"  F1  Warmup hours      : {_f(fv.f1_warmup_hours, 'h')}")
    print(f"  F2  Funding CV        : {_f(fv.f2_funding_cv)}")
    print(f"  F3  Dry-run count     : {fv.f3_dry_run_count}")
    print(f"  F4  Deployment count  : {fv.f4_deployment_count}")
    print(f"  F5  Nonce entropy     : {_f(fv.f5_nonce_entropy, ' bits')}  {DIM}(narrative){RESET}")
    print(f"  NEW-A Single deploy   : {fv.new_a_single_deploy}")
    print(f"  Funding sources       : {len(fv.all_funding_sources)} unique addr(s)")

    print(f"\n{thin}")
    print(f"  {BOLD}NEW FUNDING PROVENANCE FEATURES (FP1-FP8){RESET}")
    print(thin)

    src = fv.fp_first_inbound_source_type
    src_col = RED if src in ("MIXER", "FRESH_WALLET") else GREEN
    print(f"  FP1  First inbound source    : {src_col}{BOLD}{src}{RESET}")

    hops = fv.fp_min_hops_to_known_source
    hop_col = RED if (hops is not None and hops >= 4) else GREEN
    print(f"  FP2  Min hops to known src   : {hop_col}{hops if hops is not None else 'N/A'}{RESET}  {DIM}(>= 4 = suspicious){RESET}")

    frac = fv.fp_fraction_fresh_capital
    frac_col = RED if (frac is not None and frac >= 0.5) else GREEN
    frac_str = f"{frac:.1%}" if frac is not None else "N/A"
    print(f"  FP3  Fresh capital fraction  : {frac_col}{frac_str}{RESET}  {DIM}(>= 50% = HIGH){RESET}")

    ent = fv.fp_funding_entropy_norm
    print(f"  FP5  Funding entropy (norm)  : {_f(ent)}  {DIM}(0=obfuscation, 1=smurfing){RESET}")

    med = fv.fp_median_seed_eth
    cnt = fv.fp_seed_tx_count
    med_col = RED if (med is not None and med < 0.01 and cnt > 50) else GREEN
    print(f"  FP6a Median seed amount      : {med_col}{f'{med:.6f} ETH' if med is not None else 'N/A'}{RESET}  {DIM}({cnt} seed txs){RESET}")

    gu = fv.fp_standardized_seed_gas_units
    gu_col = RED if (gu is not None and gu < 15_000_000) else GREEN
    print(f"  FP6b Seed in gas units       : {gu_col}{f'{gu:,.0f}' if gu is not None else 'N/A'}{RESET}  {DIM}(< 15M = undersized){RESET}")

    shared_col = RED if fv.fp_shared_upstream_funders else GREEN
    shared_str = f"{BOLD}YES — COORDINATED ATTACK SIGNAL{RESET}" if fv.fp_shared_upstream_funders else "No"
    print(f"  FP8  Shared upstream funders : {shared_col}{shared_str}")

    jac = fv.fp_max_funder_jaccard
    print(f"  FP4  Max funder Jaccard sim  : {_f(jac)}  {DIM}(> 0.3 = cluster signal){RESET}")

    print(f"\n{thin}")
    print(f"  {BOLD}TRIGGERED RULES{RESET}")
    print(thin)

    triggered = [r for r in rule_results if r.triggered]
    if not triggered:
        print(f"  {DIM}No rules triggered.{RESET}")
    else:
        for r in triggered:
            col = SEV_COLOUR.get(r.severity, "")
            pts = scored.score_breakdown.get(r.rule_id, 0)
            print(f"  {col}{BOLD}[{r.severity}]{RESET}  {r.rule_id} — {r.rule_name}  {DIM}(+{pts} pts){RESET}")
            print(f"         {r.description}")
            print()

    if fp_result.shared_funder_map:
        print(thin)
        print(f"  {RED}{BOLD}[!] SHARED FUNDER MAP — Evidence of coordinated operation:{RESET}")
        for funder, linked_wallets in list(fp_result.shared_funder_map.items())[:5]:
            print(f"     Funder {funder[:14]}... also funded: {list(linked_wallets)[:3]}")

    print(f"\n{sep}\n")


if __name__ == "__main__":
    main()
