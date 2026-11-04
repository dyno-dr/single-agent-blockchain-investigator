"""
backend/forensics/rugpull/exit_features.py
─────────────────────────────────────────────────────────────────────────────
Exit and Dormancy feature extraction for the rugpull creator triage system.

Implements:
  EXIT-1  Post-Rug Silence Duration
  EXIT-2  Reactivation Delay (Burner-Phone Pattern)
  EXIT-4  Fresh Wallet Migration / Proxy Hopping
  EXIT-META Retirement Likelihood Score (heuristic, metadata-only)

DESIGN CONTRACT (matches all existing extractor modules):
  - Pure computation only.  No API calls.  No file I/O.  No side effects.
  - Returns a dict suitable for:
        fv = fv.model_copy(update=extract_exit_features(...))
  - Every output key corresponds exactly to a field on FeatureVector.
  - If a feature cannot be computed (insufficient data), its key is simply
    omitted from the returned dict. The FeatureVector field stays at its
    default (None or 0 or False) — the rule sees None and does not trigger.

KEY DESIGN DECISION — EXIT-1 "drained" check:
  We do NOT accept current_balance_wei as a parameter. Getting it requires
  an extra eth_getBalance API call and defaults to 0 if the caller forgets,
  which causes is_drained = True on every wallet regardless of actual balance.
  Instead, EXIT-1 reads fv.cp7_retained_ratio inside rule_exit1_silence()
  in rules.py.  cp7_retained_ratio is already computed by Step 3 of the
  engine pipeline (extract_cashout_features) with zero extra API calls.
  See rules.py for the trigger logic.

KEY DESIGN DECISION — EXIT-4 victim inflow threshold:
  extract_exit_features() receives cp_victim_inflow_wei from the caller
  (engine.py passes fv.cp_victim_inflow_wei, which was populated by
  extract_cashout_features() and exposed as a named FeatureVector field).
  This avoids double computation of victim inflow across two modules.
"""

from __future__ import annotations

import time
from typing import Optional

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

_ETH = 10 ** 18

# DeFi function selectors that represent a significant outgoing action.
# An outgoing tx qualifies as "significant" if its value > 0.001 ETH OR if
# its input data starts with one of these selectors.
# This prevents gaming the silence clock via trivial 0.0001 ETH pings.
_SIGNIFICANT_SELECTORS: frozenset[str] = frozenset({
    "0xa9059cbb",  # ERC-20 transfer(address,uint256)
    "0xbaa2abde",  # removeLiquidity(address,address,uint,uint,uint,address,uint)
    "0x02751cec",  # removeLiquidityETH(address,uint,uint,uint,address,uint)
    "0x7ff36ab5",  # swapExactETHForTokens(uint,address[],address,uint)
    "0x18cbafe5",  # swapExactTokensForETH(uint,uint,address[],address,uint)
    "0x791ac947",  # swapExactTokensForETHSupportingFeeOnTransferTokens
    "0xfb3bdb41",  # swapETHForExactTokens
})

# Known mixer contract addresses (lowercase).
# Used in EXIT-2 Reactivation Context Score to flag post-gap mixer interactions.
_KNOWN_MIXER_ADDRESSES: frozenset[str] = frozenset({
    "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b",  # Tornado Cash 0.1 ETH
    "0x9ad122c22b14202b4490edaf288fdb3c7cb3ff5e",  # Tornado Cash 1 ETH
    "0x910cbd523d972eb0a6f4cae4618ad62622b39dbf",  # Tornado Cash 10 ETH
    "0xa160cdab225685da1d56aa342ad8841c3b53f291",  # Tornado Cash 100 ETH
    "0x722122df12d4e14e13ac3b6895a86e84145b6967",  # Tornado Cash proxy router
    "0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936", # Tornado Cash (variant)
    "0x8589427373d6d84e98730d7795d8f6f8731fda16",  # ChipMixer
})

# A gap in outgoing tx history longer than this is classified as a Dormancy Event.
# Threshold raised from the original 14 days to 30 days.
# Rationale: a developer holiday or bear-market pause of 2-4 weeks is normal
# legitimate behaviour. Only gaps exceeding a full month are suspicious.
_DORMANCY_THRESHOLD_DAYS: float = 30.0

# A bulk transfer must move at least this fraction of victim inflow to qualify
# for EXIT-4 analysis.  Relative threshold avoids the "10 ETH absolute" flaw
# that would miss scammers who stole less than 10 ETH.
_BULK_TRANSFER_RATIO: float = 0.30


# ─────────────────────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────────────────────

def extract_exit_features(
    normal_txs: list[dict],
    internal_txs: list[dict],
    creator_address: str,
    cp_victim_inflow_wei: Optional[int],
    wallet_age_lookup: dict[str, int | None],
) -> dict:
    """
    Compute Exit and Dormancy features (EXIT-1, EXIT-2, EXIT-4).

    The EXIT-META retirement likelihood is computed separately in engine.py
    Step 6.5 (after scoring), because it needs the final rugpull score as a
    guard condition.  It is NOT computed here.

    Args:
        normal_txs:           Etherscan normal transaction list.
        internal_txs:         Etherscan internal transaction list.
        creator_address:      The creator wallet address (any case).
        cp_victim_inflow_wei: Total ETH (in Wei) deposited by victims into the
                              project contract.  Populated by extract_cashout_features()
                              and passed from fv.cp_victim_inflow_wei by engine.py.
                              If None, EXIT-4 is skipped gracefully.
        wallet_age_lookup:    {address_lower: first_tx_unix_timestamp | None}
                              covering destination wallets.  Pre-loaded from
                              wallet_age_cache.json by the caller.  Addresses
                              absent from this dict cause EXIT-4 to skip that
                              destination (no API call, no false positive).

    Returns:
        dict of field_name → value, ready for fv.model_copy(update=...).
        Missing keys mean "insufficient data" — FeatureVector defaults apply.
    """
    creator = creator_address.lower()
    result: dict = {}

    # EXIT-1: Post-Rug Silence Duration
    exit1 = _extract_exit1(normal_txs, internal_txs, creator)
    result.update(exit1)

    # EXIT-2: Reactivation Delay
    exit2 = _extract_exit2(normal_txs, creator)
    result.update(exit2)

    # EXIT-4: Fresh Wallet Migration / Proxy Hopping
    exit4 = _extract_exit4(normal_txs, creator, cp_victim_inflow_wei, wallet_age_lookup)
    result.update(exit4)

    return result


# ─────────────────────────────────────────────────────────────────────────────
# EXIT-1 — Post-Rug Silence Duration
# ─────────────────────────────────────────────────────────────────────────────

def _extract_exit1(
    normal_txs: list[dict],
    internal_txs: list[dict],
    creator: str,
) -> dict:
    """
    Measure how long the creator wallet has been completely silent since its
    last significant outgoing action.

    Returns dict with keys: exit1_silence_days, exit1_silence_ratio.
    Returns empty dict if fewer than 2 significant outgoing txs exist.

    NOTE: The "is_drained" condition is NOT evaluated here.
    rule_exit1_silence() reads cp7_retained_ratio directly from FeatureVector,
    which is the corrected design — see rules.py for details.
    """
    # Combine normal and internal txs; sort oldest → newest.
    # Internal txs must be included because Uniswap removeLiquidity calls
    # generate internal txs, not normal txs. Ignoring internals would miss
    # the single most common rugpull exit pattern.
    all_txs = sorted(
        normal_txs + internal_txs,
        key=lambda t: int(t.get("timeStamp", 0))
    )

    significant_out: list[dict] = []
    for tx in all_txs:
        if tx.get("from", "").lower() != creator:
            continue
        value = int(tx.get("value", 0))
        selector = tx.get("input", "")[:10].lower()
        is_valuable = value > int(0.001 * _ETH)
        is_defi_exit = selector in _SIGNIFICANT_SELECTORS
        if is_valuable or is_defi_exit:
            significant_out.append(tx)

    if len(significant_out) < 2:
        # Cannot compute a meaningful silence period with a single data point.
        return {}

    last_ts  = int(significant_out[-1].get("timeStamp", 0))
    first_ts = int(significant_out[0].get("timeStamp", 0))
    now      = int(time.time())

    silence_days  = (now - last_ts)  / 86400
    lifespan_days = (now - first_ts) / 86400

    # Silence ratio: what fraction of the wallet's entire existence is silence?
    # A ratio > 0.5 means the wallet has been dead for MORE than half its life.
    # Raw silence days alone are misleading — contextualising against lifespan
    # is critical (7 days of silence on a 9-day-old wallet is very different
    # from 7 days on a 3-year-old wallet).
    silence_ratio = (
        silence_days / lifespan_days
        if lifespan_days > 0
        else 0.0
    )

    return {
        "exit1_silence_days":  round(silence_days,  1),
        "exit1_silence_ratio": round(silence_ratio,  3),
    }


# ─────────────────────────────────────────────────────────────────────────────
# EXIT-2 — Reactivation Delay (Burner-Phone Pattern)
# ─────────────────────────────────────────────────────────────────────────────

def _extract_exit2(normal_txs: list[dict], creator: str) -> dict:
    """
    Detect historical dormancy-reactivation cycles in the wallet's outgoing
    transaction history.

    A Dormancy Event is any gap between consecutive outgoing txs that exceeds
    30 days. For each such event, we compute a Reactivation Context Score (RCS)
    based on WHAT the wallet did immediately after waking up:
      +2 if first post-gap tx deploys a new contract (to field is empty)
      +2 if first post-gap tx interacts with a known mixer address

    Returns dict with: exit2_dormancy_event_count, exit2_max_gap_days,
                       exit2_reactivation_context_score, exit2_events_detail.
    Returns dict with exit2_dormancy_event_count=0 if insufficient data.
    """
    outgoing_txs = sorted(
        [tx for tx in normal_txs if tx.get("from", "").lower() == creator],
        key=lambda t: int(t.get("timeStamp", 0))
    )

    if len(outgoing_txs) < 2:
        # No gap analysis possible with a single outgoing tx.
        return {"exit2_dormancy_event_count": 0}

    dormancy_events: list[dict] = []

    for i in range(1, len(outgoing_txs)):
        prev_ts  = int(outgoing_txs[i - 1].get("timeStamp", 0))
        curr_ts  = int(outgoing_txs[i].get("timeStamp", 0))
        gap_days = (curr_ts - prev_ts) / 86400

        if gap_days <= _DORMANCY_THRESHOLD_DAYS:
            continue

        # This is a Dormancy Event. Evaluate the first 3 post-gap txs for context.
        rcs = 0
        for post_tx in outgoing_txs[i: i + 3]:
            to_addr = post_tx.get("to", "").lower()
            # Empty "to" field means this tx deployed a new contract.
            if not to_addr or to_addr == "":
                rcs += 2
            # Interaction with a known money mixer.
            if to_addr in _KNOWN_MIXER_ADDRESSES:
                rcs += 2

        dormancy_events.append({
            "gap_days": round(gap_days, 1),
            "rcs":      rcs,
        })

    if not dormancy_events:
        return {"exit2_dormancy_event_count": 0}

    max_gap = max(e["gap_days"] for e in dormancy_events)
    max_rcs = max(e["rcs"]      for e in dormancy_events)

    return {
        "exit2_dormancy_event_count":       len(dormancy_events),
        "exit2_max_gap_days":               round(max_gap, 1),
        "exit2_reactivation_context_score": max_rcs,
        "exit2_events_detail":              dormancy_events,
    }


# ─────────────────────────────────────────────────────────────────────────────
# EXIT-4 — Fresh Wallet Migration / Proxy Hopping
# ─────────────────────────────────────────────────────────────────────────────

def _extract_exit4(
    normal_txs: list[dict],
    creator: str,
    cp_victim_inflow_wei: Optional[int],
    wallet_age_lookup: dict[str, int | None],
) -> dict:
    """
    Detect bulk transfers to freshly created destination wallets.

    A "bulk transfer" is any single outgoing tx that moves >= 30% of the total
    victim inflow in one shot. This relative threshold replaces the old absolute
    10 ETH threshold, which would silently miss any rugpull that stole < 10 ETH.

    For each bulk transfer, we look up the destination's age at the time of
    transfer using wallet_age_lookup (pre-loaded from wallet_age_cache.json).
    If the destination is NOT in the cache, we skip it silently — we do not make
    any API calls, and we do not produce a false positive.

    Returns dict with: exit4_youngest_dest_age_days, exit4_total_eth_to_fresh_wallets,
                       exit4_bulk_transfer_count, exit4_bulk_transfer_findings.
    Returns dict with exit4_bulk_transfer_count=0 if no bulk transfers found,
    or empty dict if victim inflow is unknown (cp_victim_inflow_wei is None).
    """
    if not cp_victim_inflow_wei or cp_victim_inflow_wei <= 0:
        # No victim inflow data: cannot compute a relative bulk threshold.
        # Return empty dict — EXIT-4 fields stay at defaults (no false positive).
        return {}

    bulk_threshold_wei = int(cp_victim_inflow_wei * _BULK_TRANSFER_RATIO)

    bulk_transfers = [
        tx for tx in normal_txs
        if tx.get("from", "").lower() == creator
        and int(tx.get("value", 0)) > bulk_threshold_wei
        and tx.get("to", "")  # exclude contract deployments (to == "")
    ]

    if not bulk_transfers:
        return {"exit4_bulk_transfer_count": 0}

    findings: list[dict] = []

    for tx in bulk_transfers:
        dest_addr     = tx.get("to", "").lower()
        transfer_time = int(tx.get("timeStamp", 0))
        value_eth     = int(tx.get("value", 0)) / _ETH

        # Look up destination age from cache.
        # None means "address not in cache" — we skip to avoid false positives.
        dest_first_tx = wallet_age_lookup.get(dest_addr)
        if dest_first_tx is None:
            continue

        age_at_transfer_days = (transfer_time - dest_first_tx) / 86400

        # Negative age means the cache has a later tx than our transfer timestamp.
        # This is a data integrity issue — skip this finding.
        if age_at_transfer_days < 0:
            continue

        findings.append({
            "destination":               dest_addr,
            "value_eth":                 round(value_eth, 4),
            "dest_age_at_transfer_days": round(age_at_transfer_days, 2),
        })

    if not findings:
        # All bulk transfers had unknown destination ages (cache misses).
        return {"exit4_bulk_transfer_count": len(bulk_transfers)}

    youngest  = min(f["dest_age_at_transfer_days"] for f in findings)
    fresh_eth = sum(
        f["value_eth"] for f in findings
        if f["dest_age_at_transfer_days"] < 7
    )

    return {
        "exit4_youngest_dest_age_days":     round(youngest, 2),
        "exit4_total_eth_to_fresh_wallets": round(fresh_eth, 4),
        "exit4_bulk_transfer_count":        len(bulk_transfers),
        "exit4_bulk_transfer_findings":     findings,
    }


# ─────────────────────────────────────────────────────────────────────────────
# EXIT-META — Retirement Likelihood Score (heuristic)
# ─────────────────────────────────────────────────────────────────────────────

def compute_retirement_likelihood(
    silence_days: Optional[float],
    dormancy_events: int,
    is_already_flagged: bool,
) -> dict:
    """
    Compute a heuristic retirement likelihood score for a wallet already
    identified as a rugpull.

    THIS IS NOT A STATISTICAL PROBABILITY. The base scores and time modifiers
    are behavioural heuristics, not empirically calibrated values.
    All consumers of this output must surface the "HEURISTIC ESTIMATE" warning.

    Called from engine.py Step 6.5 AFTER compute_score() runs, so that
    is_already_flagged can use the real final score rather than a placeholder.

    Args:
        silence_days:       From fv.exit1_silence_days.
        dormancy_events:    From fv.exit2_dormancy_event_count.
        is_already_flagged: True if scored.score >= 36 (MODERATE_PATTERN threshold).

    Returns:
        Dict with exit_meta_retirement_likelihood and exit_meta_retirement_label,
        or empty dict if not applicable (wallet not flagged or silence unknown).
    """
    if not is_already_flagged or silence_days is None:
        # Only meaningful after another rule has already confirmed this is a rugpull.
        return {}

    # Base score from number of historical dormancy cycles.
    # More cycles = more confident the wallet pattern is criminal and permanent.
    if dormancy_events == 0:
        base = 0.50   # First-time scammer — likely retired but uncertain
    elif dormancy_events == 1:
        base = 0.70   # Two-time scammer — pattern of abandonment established
    else:
        base = 0.88   # Serial scammer — high confidence in permanent retirement

    # Time modifier: longer current silence = higher confidence wallet is dead.
    if silence_days > 180:
        time_mod = 0.10
    elif silence_days > 60:
        time_mod = 0.07
    elif silence_days > 30:
        time_mod = 0.04
    else:
        time_mod = 0.00

    # Cap at 0.99. We can never be 100% certain a wallet is permanently retired.
    final_score = min(0.99, base + time_mod)

    if final_score >= 0.90:
        label = "VERY_LIKELY_RETIRED"
    elif final_score >= 0.70:
        label = "PROBABLY_RETIRED"
    else:
        label = "UNCERTAIN_MONITOR_ACTIVE"

    return {
        "exit_meta_retirement_likelihood": round(final_score, 2),
        "exit_meta_retirement_label":      label,
    }
