"""
backend/forensics/rugpull/funding_graph.py
─────────────────────────────────────────────────────────────────────────────
Funding Provenance Engine — the core implementation of the 8 new funding
graph heuristics for the rugpull creator triage system.

FEATURES IMPLEMENTED:
  F1  first_inbound_source_type       — CEX / MIXER / BRIDGE / FRESH / EOA
  F2  min_hops_to_known_source        — BFS shortest path on tx graph
  F3  fraction_fresh_capital          — % of seed ETH from brand-new wallets
  F4  funder_recurrence / jaccard     — Shared funders across creator wallets
  F5  funding_entropy_norm            — Shannon entropy of funding source types
  F6a median_seed_eth                 — Structuring detection
  F6b standardized_seed_gas_units     — Seed relative to gas conditions
  F8  shared_upstream_funders_flag    — Boolean: coordinated attack indicator

DESIGN:
  - Pure computation functions receive pre-fetched tx lists (no API calls).
  - A single `FundingProvenanceExtractor` class orchestrates all features.
  - SQLite persistence for the cross-wallet funder graph (F4 / F8).
  - All math is a direct port of the user's mathematical specification.

DEPENDENCIES:
  - networkx  (BFS / shortest path)
  - sqlite3   (standard library — investigation history DB)
  - math, statistics (standard library)
"""

from __future__ import annotations

import math
import sqlite3
import statistics
from collections import defaultdict, deque
from pathlib import Path
from typing import Optional

try:
    import networkx as nx
    _HAS_NETWORKX = True
except ImportError:
    _HAS_NETWORKX = False


# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

# Source type labels (must be kept in sync with known_entities.json labels)
SOURCE_CEX          = "CEX"
SOURCE_MIXER        = "MIXER"
SOURCE_BRIDGE       = "BRIDGE"
SOURCE_DEX          = "DEX"
SOURCE_FRESH_WALLET = "FRESH_WALLET"
SOURCE_KNOWN_EOA    = "KNOWN_EOA"
SOURCE_UNKNOWN_EOA  = "UNKNOWN_EOA"

# Shannon entropy categories (N=7 → H_max = log2(7) ≈ 2.807 bits)
ALL_CATEGORIES = [
    SOURCE_CEX, SOURCE_MIXER, SOURCE_BRIDGE, SOURCE_DEX,
    SOURCE_FRESH_WALLET, SOURCE_KNOWN_EOA, SOURCE_UNKNOWN_EOA,
]
_H_MAX = math.log2(len(ALL_CATEGORIES))   # ≈ 2.807 bits

# BFS limits
MAX_BFS_DEPTH     = 5     # Cap for hop-counting (Feature 2)
MAX_CLUSTER_DEPTH = 3     # Cap for Jaccard / shared-funders BFS (Feature 4/8)

# Detection thresholds (from the user's mathematical specification)
FRESH_WALLET_FRESH_WINDOW_HOURS = 48    # wallet age ≤ 48h → FRESH
FRACTION_FRESH_HIGH    = 0.50
FRACTION_FRESH_CRITICAL = 0.80
HOP_HIGH_THRESHOLD     = 4             # min_hops ≥ 4 → HIGH severity
STRUCTURING_MEDIAN_MAX = 0.01          # ETH
STRUCTURING_COUNT_MIN  = 50            # tx count
DEPLOY_GAS_UNITS       = 3_000_000     # typical deployment gas cost
SEED_UNDERSIZED_FACTOR = 5             # seed_in_gas_units < 5× deploy_gas → flag

WEI_PER_ETH = 1e18

# High-traffic contracts that appear in nearly every DeFi wallet's history.
# Treating them as "funders" would create spurious shared-funder links (false positives).
# These are EXCLUDED from the BFS funder graph traversal.
NOISE_ADDRESSES: frozenset[str] = frozenset({
    # WETH — wrapping/unwrapping creates ETH flows to/from virtually everyone
    "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
    # ETH2 Deposit Contract — anyone staking goes through here
    "0x00000000219ab540356cbb839cbe05303d7705fa",
    # Ethereum burn / zero address
    "0x0000000000000000000000000000000000000000",
    "0x000000000000000000000000000000000000dead",
    # Flashbots / MEV relayer
    "0x00000000003b3cc22af3ae1eac0440bcee416b40",
    # Uniswap V2 / V3 universal router (not a funder — a router)
    "0x7a250d5630b4cf539739df2c5dacb4c659f2488d",
    "0xe592427a0aece92de3edee1f18e0157c05861564",
    "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45",
    # Coinbase: Ethereum Name Service registrar (sends dust to many)
    "0x283af0b28c62c092c9727f1ee09c02ca627eb7f5",
})


# ─────────────────────────────────────────────────────────────────────────────
# Feature 1 — First Inbound Source Type
# ─────────────────────────────────────────────────────────────────────────────

def classify_first_inbound(
    wallet_address: str,
    txs: list[dict],
    known_entities: dict[str, dict],
    wallet_age_lookup: dict[str, Optional[int]],
    current_ts: Optional[int] = None,
) -> str:
    """
    Classify the entity that sent the very first ETH into the wallet.

    Args:
        wallet_address:    The creator wallet being investigated.
        txs:               Combined normal + internal tx list from Etherscan.
        known_entities:    Dict of {address: {"type": "CEX" | "MIXER" | ...}}.
        wallet_age_lookup: Dict of {sender_addr: first_tx_timestamp | None}.
        current_ts:        Deployment timestamp (for FRESH_WALLET age check).

    Returns:
        One of: "CEX", "MIXER", "BRIDGE", "DEX", "FRESH_WALLET",
                "KNOWN_EOA", "UNKNOWN_EOA"
    """
    addr = wallet_address.lower()
    inbound = [
        tx for tx in txs
        if tx.get("to", "").lower() == addr
        and int(tx.get("value", "0")) > 0
    ]
    if not inbound:
        return SOURCE_UNKNOWN_EOA

    first_tx = min(inbound, key=lambda t: int(t.get("timeStamp", 0)))
    sender = first_tx.get("from", "").lower()

    # Check known entities first
    entry = known_entities.get(sender, {})
    if entry:
        return entry.get("type", SOURCE_KNOWN_EOA)

    # Check if sender is a fresh wallet
    sender_first_ts = wallet_age_lookup.get(sender)
    if sender_first_ts is not None and current_ts is not None:
        age_hours = (current_ts - sender_first_ts) / 3600.0
        if age_hours <= FRESH_WALLET_FRESH_WINDOW_HOURS:
            return SOURCE_FRESH_WALLET

    return SOURCE_UNKNOWN_EOA


# ─────────────────────────────────────────────────────────────────────────────
# Feature 2 — Min Hops from Known Source (BFS / NetworkX)
# ─────────────────────────────────────────────────────────────────────────────

def build_funding_graph(txs: list[dict]) -> "nx.DiGraph":
    """
    Build a directed transaction graph from a list of transactions.
    Edge direction: sender → receiver (money flows forward).
    Only includes transactions with value > 0.
    """
    if not _HAS_NETWORKX:
        raise ImportError("networkx is required for hop-counting. Install with: pip install networkx")

    G = nx.DiGraph()
    for tx in txs:
        sender   = tx.get("from", "").lower()
        receiver = tx.get("to",   "").lower()
        value    = int(tx.get("value", "0"))
        if sender and receiver and value > 0:
            G.add_edge(sender, receiver, value=value, ts=int(tx.get("timeStamp", 0)))
    return G


def min_hops_to_known_source(
    creator_wallet: str,
    G: "nx.DiGraph",
    known_sources: set[str],
    max_depth: int = MAX_BFS_DEPTH,
) -> Optional[int]:
    """
    Shortest path (in hops) from any known source to the creator wallet.

    Implements the user's specification:
        min_hops = min( nx.shortest_path_length(G, s, creator_wallet)
                        for s in known_sources if nx.has_path(G, s, creator_wallet) )

    Args:
        creator_wallet: The creator wallet address.
        G:              Directed transaction graph (sender → receiver).
        known_sources:  Set of known CEX / MIXER / BRIDGE addresses.
        max_depth:      BFS depth cap (default 5).

    Returns:
        Minimum hop count, or None if no path found within max_depth.
    """
    if not _HAS_NETWORKX:
        return None

    wallet = creator_wallet.lower()
    min_hops: Optional[int] = None

    for source in known_sources:
        if source not in G or wallet not in G:
            continue
        try:
            length = nx.shortest_path_length(G, source, wallet)
            if length <= max_depth:
                if min_hops is None or length < min_hops:
                    min_hops = length
        except nx.NetworkXNoPath:
            continue
        except nx.NodeNotFound:
            continue

    return min_hops


# ─────────────────────────────────────────────────────────────────────────────
# Feature 3 — Fraction of Seed Capital from Fresh Wallets
# ─────────────────────────────────────────────────────────────────────────────

def fraction_fresh_capital(
    wallet_address: str,
    txs: list[dict],
    deploy_timestamp: int,
    wallet_age_lookup: dict[str, Optional[int]],
    fresh_window_hours: float = FRESH_WALLET_FRESH_WINDOW_HOURS,
) -> Optional[float]:
    """
    Fraction of total seed ETH (before deploy) that came from fresh wallets.

    Math (from spec):
        fresh_amount = sum(tx.value  for seed_txs  if wallet_age(tx.from) < 48h)
        fraction_fresh = fresh_amount / total_seed ∈ [0, 1]

    Returns None if there were no seed transactions.
    """
    addr = wallet_address.lower()
    seed_txs = [
        tx for tx in txs
        if tx.get("to", "").lower() == addr
        and int(tx.get("value", "0")) > 0
        and int(tx.get("timeStamp", 0)) < deploy_timestamp
    ]
    if not seed_txs:
        return None

    total_seed_wei = sum(int(tx.get("value", "0")) for tx in seed_txs)
    if total_seed_wei == 0:
        return None

    fresh_wei = 0
    for tx in seed_txs:
        sender     = tx.get("from", "").lower()
        sender_first_ts = wallet_age_lookup.get(sender)
        if sender_first_ts is not None:
            tx_ts = int(tx.get("timeStamp", 0))
            age_hours = (tx_ts - sender_first_ts) / 3600.0
            if age_hours <= fresh_window_hours:
                fresh_wei += int(tx.get("value", "0"))

    return fresh_wei / total_seed_wei


# ─────────────────────────────────────────────────────────────────────────────
# Feature 5 — Shannon Entropy of Funding Sources
# ─────────────────────────────────────────────────────────────────────────────

def funding_entropy_norm(
    wallet_address: str,
    txs: list[dict],
    deploy_timestamp: int,
    known_entities: dict[str, dict],
    wallet_age_lookup: dict[str, Optional[int]],
) -> Optional[float]:
    """
    Normalised Shannon entropy of the funding source type distribution.

    Math (from spec):
        H = -Σ p_i × log2(p_i)     (for all i where p_i > 0)
        H_norm = H / H_max          where H_max = log2(N), N=7 categories

    H_norm ≈ 0 → everything from one source (suspicious if mixer)
    H_norm ≈ 1 → perfectly spread (suspicious if artificially diversified)

    Returns normalised entropy ∈ [0, 1], or None if no seed txs.
    """
    addr = wallet_address.lower()
    seed_txs = [
        tx for tx in txs
        if tx.get("to", "").lower() == addr
        and int(tx.get("value", "0")) > 0
        and int(tx.get("timeStamp", 0)) < deploy_timestamp
    ]
    if not seed_txs:
        return None

    total_wei = sum(int(tx.get("value", "0")) for tx in seed_txs)
    if total_wei == 0:
        return None

    # Tally value by category
    category_totals: dict[str, int] = defaultdict(int)
    for tx in seed_txs:
        sender  = tx.get("from", "").lower()
        value   = int(tx.get("value", "0"))
        tx_ts   = int(tx.get("timeStamp", 0))

        entry = known_entities.get(sender, {})
        if entry:
            cat = entry.get("type", SOURCE_KNOWN_EOA)
        else:
            sender_first_ts = wallet_age_lookup.get(sender)
            if sender_first_ts is not None:
                age_hours = (tx_ts - sender_first_ts) / 3600.0
                cat = SOURCE_FRESH_WALLET if age_hours <= FRESH_WALLET_FRESH_WINDOW_HOURS else SOURCE_UNKNOWN_EOA
            else:
                cat = SOURCE_UNKNOWN_EOA
        category_totals[cat] += value

    # Shannon entropy
    h = 0.0
    for val in category_totals.values():
        p = val / total_wei
        if p > 0:
            h -= p * math.log2(p)

    return h / _H_MAX if _H_MAX > 0 else 0.0


# ─────────────────────────────────────────────────────────────────────────────
# Feature 6a — Median Seed Amount (Structuring Detection)
# ─────────────────────────────────────────────────────────────────────────────

def median_seed_eth(
    wallet_address: str,
    txs: list[dict],
    deploy_timestamp: int,
) -> Optional[tuple[float, int]]:
    """
    Compute the median seed transaction size and count of seed transactions.

    Returns:
        (median_eth, tx_count) or None if no seed transactions.

    Flag condition (from spec):
        median_seed < 0.01 ETH AND count > 50 → STRUCTURING
    """
    addr = wallet_address.lower()
    seed_values_wei = [
        int(tx.get("value", "0"))
        for tx in txs
        if tx.get("to", "").lower() == addr
        and int(tx.get("value", "0")) > 0
        and int(tx.get("timeStamp", 0)) < deploy_timestamp
    ]
    if not seed_values_wei:
        return None

    med_eth = statistics.median(seed_values_wei) / WEI_PER_ETH
    return (med_eth, len(seed_values_wei))


# ─────────────────────────────────────────────────────────────────────────────
# Feature 6b — Standardised Seed Amount (Gas-Relative)
# ─────────────────────────────────────────────────────────────────────────────

def standardized_seed_gas_units(
    wallet_address: str,
    txs: list[dict],
    deploy_timestamp: int,
) -> Optional[float]:
    """
    Express seed amount in "gas units" using the gas price from the seed tx.

    Math (from spec):
        seed_in_gas_units = seed_amount_wei / gas_price_wei

    A typical deployment costs ~3,000,000 gas.
    If seed_in_gas_units < 5 × DEPLOY_GAS_UNITS → minimum-viable-rugpull.

    Returns the seed_in_gas_units ratio, or None if data is unavailable.
    """
    addr = wallet_address.lower()
    seed_txs = [
        tx for tx in txs
        if tx.get("to", "").lower() == addr
        and int(tx.get("value", "0")) > 0
        and int(tx.get("timeStamp", 0)) < deploy_timestamp
        and int(tx.get("gasPrice", "0")) > 0
    ]
    if not seed_txs:
        return None

    # Use the largest seed transaction (most likely the primary funding tx)
    primary = max(seed_txs, key=lambda t: int(t.get("value", "0")))
    seed_wei      = int(primary.get("value", "0"))
    gas_price_wei = int(primary.get("gasPrice", "1"))

    if gas_price_wei == 0:
        return None

    return seed_wei / gas_price_wei


# ─────────────────────────────────────────────────────────────────────────────
# Feature 4 + 8 — Cross-Wallet Funder Graph (SQLite)
# ─────────────────────────────────────────────────────────────────────────────

class FunderGraph:
    """
    Persistent, SQLite-backed store for the cross-wallet funder graph.

    Maps:  funder_address  →  {creator_wallets_it_funded}

    Used for:
        F4 — Jaccard similarity between two creator wallets' funder sets.
        F8 — Boolean: does this creator share funders with any known scammer?
    """

    def __init__(self, db_path: str | Path = "investigation_history.db") -> None:
        self.db_path = str(db_path)
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as con:
            con.execute("""
                CREATE TABLE IF NOT EXISTS funder_links (
                    funder_address  TEXT NOT NULL,
                    creator_wallet  TEXT NOT NULL,
                    hop_depth       INTEGER DEFAULT 0,
                    PRIMARY KEY (funder_address, creator_wallet)
                )
            """)
            con.execute("CREATE INDEX IF NOT EXISTS idx_funder ON funder_links(funder_address)")
            con.execute("CREATE INDEX IF NOT EXISTS idx_creator ON funder_links(creator_wallet)")
            con.commit()

    def record_funders(self, creator_wallet: str, funders: set[str], depth: int = 0) -> None:
        """Save the upstream funders for a creator wallet."""
        wallet = creator_wallet.lower()
        with sqlite3.connect(self.db_path) as con:
            con.executemany(
                "INSERT OR IGNORE INTO funder_links (funder_address, creator_wallet, hop_depth) VALUES (?, ?, ?)",
                [(f.lower(), wallet, depth) for f in funders],
            )
            con.commit()

    def get_funders(self, creator_wallet: str) -> set[str]:
        """Retrieve all recorded funders for a creator wallet."""
        wallet = creator_wallet.lower()
        with sqlite3.connect(self.db_path) as con:
            rows = con.execute(
                "SELECT funder_address FROM funder_links WHERE creator_wallet = ?", (wallet,)
            ).fetchall()
        return {row[0] for row in rows}

    def get_wallets_by_funder(self, funder: str) -> set[str]:
        """Get all creator wallets funded by this address."""
        f = funder.lower()
        with sqlite3.connect(self.db_path) as con:
            rows = con.execute(
                "SELECT creator_wallet FROM funder_links WHERE funder_address = ?", (f,)
            ).fetchall()
        return {row[0] for row in rows}

    def shared_upstream_funders_flag(
        self,
        creator_wallet: str,
        funders: set[str],
    ) -> tuple[bool, dict[str, set[str]]]:
        """
        Feature 8: Does this creator share upstream funders with any other
        known creator wallet in the database?

        Returns:
            (flag: bool, shared_map: dict[funder → set of other creator wallets])
        """
        wallet = creator_wallet.lower()
        shared_map: dict[str, set[str]] = {}

        for funder in funders:
            linked_wallets = self.get_wallets_by_funder(funder)
            others = linked_wallets - {wallet}
            if others:
                shared_map[funder] = others

        return (len(shared_map) > 0, shared_map)

    def jaccard_similarity(self, wallet_a: str, wallet_b: str) -> float:
        """
        Feature 4: Jaccard similarity between two creator wallets' funder sets.

        Math (from spec):
            overlap(W1, W2) = |F(W1) ∩ F(W2)| / |F(W1) ∪ F(W2)|
        """
        fa = self.get_funders(wallet_a)
        fb = self.get_funders(wallet_b)
        if not fa and not fb:
            return 0.0
        intersection = fa & fb
        union = fa | fb
        return len(intersection) / len(union) if union else 0.0


# ─────────────────────────────────────────────────────────────────────────────
# BFS upstream traversal (for populating FunderGraph)
# ─────────────────────────────────────────────────────────────────────────────

def get_upstream_funders_bfs(
    creator_wallet: str,
    tx_graph: dict[str, list[str]],
    known_entities: dict[str, dict],
    depth: int = MAX_CLUSTER_DEPTH,
) -> set[str]:
    """
    BFS backwards through the tx graph to find all upstream funders
    up to `depth` hops from the creator wallet.

    Args:
        creator_wallet: Starting wallet address.
        tx_graph:       Dict mapping receiver → [list of sender addresses].
        depth:          Max BFS depth (default 3, per spec).

    Returns:
        Set of unique upstream funder addresses.
    """
    visited: set[str] = set()
    queue: deque[tuple[str, int]] = deque([(creator_wallet.lower(), 0)])
    wallet = creator_wallet.lower()

    while queue:
        node, current_depth = queue.popleft()
        if current_depth >= depth:
            continue
        senders = tx_graph.get(node, [])
        for sender in senders:
            s = sender.lower()
            # Skip noise addresses (WETH, burn addr, routers) — they link everyone
            if s in NOISE_ADDRESSES:
                continue
            # Skip known public infrastructure (CEX, Bridge, Mixer, DEX)
            entry = known_entities.get(s, {})
            if entry.get("type") in ("CEX", "BRIDGE", "MIXER", "DEX"):
                continue
            if s not in visited and s != wallet:
                visited.add(s)
                queue.append((s, current_depth + 1))

    return visited


def build_reverse_tx_graph(txs: list[dict]) -> dict[str, list[str]]:
    """
    Build a reverse adjacency list: receiver → [senders].
    Used by get_upstream_funders_bfs().
    """
    graph: dict[str, list[str]] = defaultdict(list)
    # Ignore any transfer less than 0.005 ETH to prevent dust/airdrop links
    MIN_FUNDING_WEI = 5_000_000_000_000_000  
    for tx in txs:
        sender   = tx.get("from", "").lower()
        receiver = tx.get("to",   "").lower()
        value    = int(tx.get("value", "0"))
        if sender and receiver and value >= MIN_FUNDING_WEI:
            graph[receiver].append(sender)
    return dict(graph)


# ─────────────────────────────────────────────────────────────────────────────
# High-level result container
# ─────────────────────────────────────────────────────────────────────────────

class FundingProvenanceResult:
    """
    Container for all 8 funding provenance feature values.
    Passed directly into the FeatureVector.
    """
    __slots__ = (
        "first_inbound_source_type",
        "min_hops_to_known_source",
        "fraction_fresh_capital",
        "funding_entropy_norm",
        "median_seed_eth",
        "seed_tx_count",
        "standardized_seed_gas_units",
        "shared_upstream_funders_flag",
        "shared_funder_map",
        "max_funder_jaccard",
    )

    def __init__(self) -> None:
        self.first_inbound_source_type:   str            = SOURCE_UNKNOWN_EOA
        self.min_hops_to_known_source:    Optional[int]  = None
        self.fraction_fresh_capital:      Optional[float] = None
        self.funding_entropy_norm:        Optional[float] = None
        self.median_seed_eth:             Optional[float] = None
        self.seed_tx_count:               int             = 0
        self.standardized_seed_gas_units: Optional[float] = None
        self.shared_upstream_funders_flag: bool            = False
        self.shared_funder_map:           dict            = {}
        self.max_funder_jaccard:          Optional[float] = None


def extract_funding_provenance(
    wallet_address: str,
    txs: list[dict],
    deploy_timestamp: int,
    known_entities: dict[str, dict],
    wallet_age_lookup: dict[str, Optional[int]],
    funder_graph_db: Optional[FunderGraph] = None,
) -> FundingProvenanceResult:
    """
    Orchestrate all 8 funding provenance feature computations.

    Args:
        wallet_address:   The creator wallet being investigated.
        txs:              Combined normal + internal tx list.
        deploy_timestamp: Unix timestamp of the first deployment.
        known_entities:   {address: {"type": ...}} dict from known_entities.json.
        wallet_age_lookup:{sender: first_tx_timestamp} for fresh-wallet checks.
        funder_graph_db:  Optional FunderGraph for cross-wallet checks (F4/F8).

    Returns:
        FundingProvenanceResult with all features populated.
    """
    result = FundingProvenanceResult()

    # F1 — First Inbound Source Type
    result.first_inbound_source_type = classify_first_inbound(
        wallet_address, txs, known_entities, wallet_age_lookup, deploy_timestamp
    )

    # F2 — Min Hops (requires NetworkX)
    if _HAS_NETWORKX:
        G = build_funding_graph(txs)
        known_addrs = {addr for addr, info in known_entities.items()}
        result.min_hops_to_known_source = min_hops_to_known_source(
            wallet_address, G, known_addrs, max_depth=MAX_BFS_DEPTH
        )

    # F3 — Fraction Fresh Capital
    result.fraction_fresh_capital = fraction_fresh_capital(
        wallet_address, txs, deploy_timestamp, wallet_age_lookup
    )

    # F5 — Funding Entropy
    result.funding_entropy_norm = funding_entropy_norm(
        wallet_address, txs, deploy_timestamp, known_entities, wallet_age_lookup
    )

    # F6a — Median Seed Amount
    seed_result = median_seed_eth(wallet_address, txs, deploy_timestamp)
    if seed_result is not None:
        result.median_seed_eth, result.seed_tx_count = seed_result

    # F6b — Standardised Seed Amount
    result.standardized_seed_gas_units = standardized_seed_gas_units(
        wallet_address, txs, deploy_timestamp
    )

    # F4 + F8 — Cross-wallet funder graph (requires DB)
    if funder_graph_db is not None:
        reverse_graph = build_reverse_tx_graph(txs)
        upstream = get_upstream_funders_bfs(wallet_address, reverse_graph, known_entities)
        funder_graph_db.record_funders(wallet_address, upstream, depth=MAX_CLUSTER_DEPTH)

        flag, shared_map = funder_graph_db.shared_upstream_funders_flag(
            wallet_address, upstream
        )
        result.shared_upstream_funders_flag = flag
        result.shared_funder_map            = shared_map

    return result
