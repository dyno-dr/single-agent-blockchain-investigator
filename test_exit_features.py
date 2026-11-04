"""
test_exit_features.py
─────────────────────────────────────────────────────────────────────────────
Test harness for RUG-EXIT-1, RUG-EXIT-2, RUG-EXIT-4 on the 90-wallet rugpull dataset.

Loads cached transaction data (raw_wallet_data_v2.json) and runs the exit
features extraction + rules.  Produces a per-wallet summary and trigger-rate table.

Usage:
    .\\venv\\Scripts\\python.exe test_exit_features.py
"""

import json
import os
import sys
import pathlib

# Force UTF-8 output on Windows to prevent UnicodeEncodeError crashes
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")

# ── path setup ───────────────────────────────────────────────────────────────
ROOT = pathlib.Path(__file__).parent
sys.path.insert(0, str(ROOT))

from cli_utils import KNOWN_RUGPULL as RUGPULL_ADDRESSES, load_json
from backend.forensics.rugpull.extractor import FeatureVector
from backend.forensics.rugpull.exit_features import (
    extract_exit_features,
    compute_retirement_likelihood,
)
from backend.forensics.rugpull.rules import (
    rule_exit1_silence,
    rule_exit2_reactivation,
    rule_exit4_fresh_migration,
)

# ── load caches ───────────────────────────────────────────────────────────────
DATASET_CACHE = ROOT / "raw_wallet_data_v2.json"
AGE_CACHE     = ROOT / "wallet_age_cache.json"

if not DATASET_CACHE.exists():
    print(f"[ERROR] Cache file not found: {DATASET_CACHE}")
    print("Run test_full_dataset.py first to populate the cache, then re-run.")
    sys.exit(1)

print(f"Loading wallet cache from {DATASET_CACHE}...")
all_wallet_data: dict = load_json(str(DATASET_CACHE))
print(f"  Loaded {len(all_wallet_data)} cached wallet records.")

wallet_age_lookup: dict = {}
if AGE_CACHE.exists():
    with open(AGE_CACHE, encoding="utf-8") as f:
        wallet_age_lookup = json.load(f)

# ── run analysis ──────────────────────────────────────────────────────────────
print("\n" + "━" * 72)
print("  EXIT Feature Analysis — 90 Rugpull Wallets")
print("━" * 72)

results = []
skipped = 0

for addr in RUGPULL_ADDRESSES:
    wallet_entry = all_wallet_data.get(addr) or all_wallet_data.get(addr.lower())
    if wallet_entry is None:
        skipped += 1
        continue

    # Simulate the cp_victim_inflow_wei by summing inbound value to any
    # contract deployed by this address. In the full engine this is computed
    # by extract_cashout_features() and stored on FeatureVector.
    creator = addr.lower()
    normal_txs   = wallet_entry.get("normal_txs", [])
    internal_txs = wallet_entry.get("internal_txs", [])

    # Find first deployed contract address
    deploy_txs = sorted(
        [t for t in normal_txs if t.get("to", "") == "" and t.get("contractAddress")],
        key=lambda t: int(t.get("timeStamp", 0))
    )
    contract_addr = deploy_txs[0]["contractAddress"].lower() if deploy_txs else None

    victim_inflow_wei = 0
    if contract_addr:
        for tx in normal_txs + internal_txs:
            if (tx.get("to", "").lower() == contract_addr
                    and tx.get("from", "").lower() != creator
                    and int(tx.get("value", 0)) > 0):
                victim_inflow_wei += int(tx.get("value", 0))

    # cp7_retained_ratio approximation
    cp7_retained = None
    if victim_inflow_wei > 0:
        ecosystem_balance = 0
        all_sorted = sorted(normal_txs + internal_txs, key=lambda t: int(t.get("timeStamp", 0)))
        for tx in all_sorted:
            fa = tx.get("from", "").lower()
            ta = tx.get("to", "").lower()
            val = int(tx.get("value", 0))
            if contract_addr and ta in (contract_addr, creator) and fa not in (contract_addr, creator) and val > 0:
                ecosystem_balance += val
            if contract_addr and fa in (contract_addr, creator) and ta not in (contract_addr, creator) and val > 0:
                ecosystem_balance -= val
        cp7_retained = max(0, ecosystem_balance) / victim_inflow_wei

    # Extract EXIT features
    exit_fields = extract_exit_features(
        normal_txs=normal_txs,
        internal_txs=internal_txs,
        creator_address=addr,
        cp_victim_inflow_wei=victim_inflow_wei if victim_inflow_wei > 0 else None,
        wallet_age_lookup=wallet_age_lookup,
    )

    # Build minimal FeatureVector with EXIT fields + cp7_retained_ratio
    fv = FeatureVector(
        wallet_address=creator,
        cp7_retained_ratio=cp7_retained,
        **{k: v for k, v in exit_fields.items()},
    )

    # Evaluate rules
    r1 = rule_exit1_silence(fv)
    r2 = rule_exit2_reactivation(fv)
    r4 = rule_exit4_fresh_migration(fv)

    # Retirement likelihood (treat as flagged if any exit rule triggered)
    is_flagged = r1.triggered or r2.triggered or r4.triggered
    ret = compute_retirement_likelihood(
        silence_days=fv.exit1_silence_days,
        dormancy_events=fv.exit2_dormancy_event_count,
        is_already_flagged=is_flagged,
    )

    results.append({
        "addr":              addr,
        "silence_days":      fv.exit1_silence_days,
        "silence_ratio":     fv.exit1_silence_ratio,
        "cp7":               round(cp7_retained, 4) if cp7_retained is not None else None,
        "exit1_triggered":   r1.triggered,
        "exit1_severity":    r1.severity if r1.triggered else "-",
        "dormancy_events":   fv.exit2_dormancy_event_count,
        "max_gap_days":      fv.exit2_max_gap_days,
        "exit2_triggered":   r2.triggered,
        "exit2_severity":    r2.severity if r2.triggered else "-",
        "bulk_count":        fv.exit4_bulk_transfer_count,
        "youngest_age":      fv.exit4_youngest_dest_age_days,
        "exit4_triggered":   r4.triggered,
        "exit4_severity":    r4.severity if r4.triggered else "-",
        "retirement":        ret.get("exit_meta_retirement_likelihood"),
        "retirement_label":  ret.get("exit_meta_retirement_label", "-"),
    })

# ── print per-wallet table ────────────────────────────────────────────────────
print(f"\n  Wallets loaded: {len(results)}   Skipped (no cache): {skipped}\n")

print(f"{'Address':>44}  {'Sil(d)':>6}  {'SilR':>5}  {'CP7%':>6}  "
      f"{'E1':>4}  {'Evts':>4}  {'E2':>4}  {'BulkCnt':>7}  {'E4':>4}  {'Retire':>6}")
print("  " + "-" * 100)

for r in sorted(results, key=lambda x: (not x["exit1_triggered"], not x["exit2_triggered"])):
    e1 = r["exit1_severity"][0] if r["exit1_triggered"] else "."
    e2 = r["exit2_severity"][0] if r["exit2_triggered"] else "."
    e4 = r["exit4_severity"][0] if r["exit4_triggered"] else "."
    sil  = f"{r['silence_days']:.0f}" if r["silence_days"] is not None else "n/a"
    silr = f"{r['silence_ratio']:.2f}" if r["silence_ratio"] is not None else "n/a"
    cp7  = f"{r['cp7']:.3f}" if r["cp7"] is not None else "n/a"
    ret  = f"{r['retirement']:.2f}" if r["retirement"] is not None else "-"
    print(f"  {r['addr']:>44}  {sil:>6}  {silr:>5}  {cp7:>6}  "
          f"{e1:>4}  {r['dormancy_events']:>4}  {e2:>4}  {r['bulk_count']:>7}  {e4:>4}  {ret:>6}")

# ── summary table ─────────────────────────────────────────────────────────────
total = len(results)
if total == 0:
    print("[ERROR] No wallets were loaded from the cache. Check raw_wallet_data_v2.json.")
    sys.exit(1)

e1_total = sum(1 for r in results if r["exit1_triggered"])
e2_total = sum(1 for r in results if r["exit2_triggered"])
e4_total = sum(1 for r in results if r["exit4_triggered"])
ret_total = sum(1 for r in results if r["retirement"] is not None)

e1_h = sum(1 for r in results if r["exit1_severity"] == "HIGH")
e1_m = sum(1 for r in results if r["exit1_severity"] == "MEDIUM")
e2_c = sum(1 for r in results if r["exit2_severity"] == "CRITICAL")
e2_h = sum(1 for r in results if r["exit2_severity"] == "HIGH")
e2_m = sum(1 for r in results if r["exit2_severity"] == "MEDIUM")
e4_c = sum(1 for r in results if r["exit4_severity"] == "CRITICAL")
e4_h = sum(1 for r in results if r["exit4_severity"] == "HIGH")

print("\n" + "━" * 72)
print("  Summary Table")
print("━" * 72)
print(f"  {'Rule':<12}  {'Triggered':>9}  {'Rate':>6}  {'Breakdown'}")
print(f"  {'-'*12}  {'-'*9}  {'-'*6}  {'-'*30}")
print(f"  {'EXIT-1':<12}  {e1_total:>9}  {e1_total/total:>5.1%}  HIGH={e1_h}  MEDIUM={e1_m}")
print(f"  {'EXIT-2':<12}  {e2_total:>9}  {e2_total/total:>5.1%}  CRITICAL={e2_c}  HIGH={e2_h}  MEDIUM={e2_m}")
print(f"  {'EXIT-4':<12}  {e4_total:>9}  {e4_total/total:>5.1%}  CRITICAL={e4_c}  HIGH={e4_h}")
print(f"  {'EXIT-META':<12}  {ret_total:>9}  {ret_total/total:>5.1%}  (computed for any triggered wallet)")
print("━" * 72)
print("\n  Legend: H=HIGH  M=MEDIUM  C=CRITICAL  .=not triggered  n/a=insufficient data")
print()
