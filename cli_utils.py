"""
cli_utils.py
─────────────────────────────────────────────────────────────────────────────
Shared utilities for CLI test / batch scripts.

NOT part of the backend application package. Import only from root-level
scripts (test_rugpull.py, rugpull_live_batch.py, test_full_dataset.py, etc.).

CONTENTS:
  Console colours        — VERDICT_COLOURS, RESET, BOLD, DIM
  Known address sets     — KNOWN_RUGPULL, KNOWN_GENUINE (canonical, 18-addr)
  Etherscan helpers      — _etherscan_get, fetch_normal_txs, fetch_internal_txs,
                           fetch_first_tx_ts, fetch_token_txs, fetch_wallet_full
  Deploy-ts detection    — find_deploy_ts
  JSON cache helpers     — load_json, save_json
"""

from __future__ import annotations

import json
import os
import time
import urllib.parse
import urllib.request

# ─────────────────────────────────────────────────────────────────────────────
# Console colours
# ─────────────────────────────────────────────────────────────────────────────

VERDICT_COLOURS: dict[str, str] = {
    "CLEAN":                           "\033[92m",   # green
    "INSUFFICIENT_DEPLOYMENT_HISTORY": "\033[96m",   # cyan
    "INSUFFICIENT_DATA":               "\033[96m",   # cyan
    "WEAK_PATTERN":                    "\033[93m",   # yellow
    "MODERATE_PATTERN":                "\033[33m",   # dark yellow
    "STRONG_PATTERN":                  "\033[91m",   # light red
    "HIGH_CONFIDENCE_RUGPULL":         "\033[31m",   # red
}
RESET   = "\033[0m"
BOLD    = "\033[1m"
DIM     = "\033[2m"

# Individual colour codes (for scripts that colour-code by severity/value)
RED     = "\033[91m"
YELLOW  = "\033[93m"
GREEN   = "\033[92m"
CYAN    = "\033[96m"
MAGENTA = "\033[35m"

# ─────────────────────────────────────────────────────────────────────────────
# Known address sets — single authoritative source for all CLI scripts
# ─────────────────────────────────────────────────────────────────────────────

KNOWN_RUGPULL: list[str] = [
    "0x00df4e8d293d57718aac0b18cbfbe128c5d484ef",
    "0x021ac107832f1c10400e3190281d3ffed4f38bc6",
    "0x03f15ecc984669237aac41392b5dd6cf3132ff35",
    "0x0659724a5293127789660734d64c18254e7dbd18",
    "0x07cb37ed2198fc7a2a1671ac94311738a548b877",
    "0x0e04ba718d3c7ac4d7c8fa357ab73abdd45d89dc",
    "0x0ea10e39a2923a7fc7354f40daac938764b71ca8",
    "0x0eb1849c92eda5b346bdc13116f12127fc75c3b3",
    "0x10850762bac0dc6660630c1effe188a7cbfddc88",
    "0x1123aaf2d3aa6e075c9e7e232895818387826026",
    "0x154827328a10e1c5c2878acba12bc6a4ed3c6b2a",
    "0x17a45f80efd20594afe2c59d7e1ae7ab0c6954cc",
    "0x19cc350a22eb342e91a2199abacc8c5bbd87c7a5",
    "0x19fde224c03249bd0ef503815dcad200c57c2adc",
    "0x1a1427a73b7cb0f4ea3f71c6c8090c4366c8ebe1",
    "0x1d524a067f1828665273a0f85bd58cbb1cd18c3f",
    "0x2108007b64b3968b4a1c21fa1af0ea8e7b2d3912",
    "0x212da8c9dad7e9b6a71422665c58bf9a7ecae6d0",
    "0x2272ecf43a7481088fa2d4ba9109804ed5a31901",
    "0x25d295635e747ec6ff3f0c1e19e30a335de66ed5",
    "0x266db4743755109a5926d6fded5ed6f6a284ab98",
    "0x2b3ab8e7bb14988616359b78709538b10900ab7d",
    "0x32220f07dbcd18149f619f28cd09fd911cc0372d",
    "0x3450265c76c0fb04b4a6b5195aebe00314040c6f",
    "0x34b365c3a98d0ec12a680047fe299aff2a032554",
    "0x3549d95f144c0cc9eb5fc29fc8b6881a84d51536",
    "0x39f922521855738ea802ca26da385e0bddf98600",
    "0x3a0bef9700474a00b10a1063b59685de6e690c08",
    "0x3e18eda374aa344f4a6f0d3ff73f10e6ced8ad21",
    "0x3fbfac2397902ba762d6da683b567dc5bbb1fce0",
    "0x42fab76321440273044ef6a157e86a9777b5809b",
    "0x44343df908f0fb88326d03ad828524c08f61e4bc",
    "0x457d955ef9b1e942ae3d7185e69a3ecfbcdd625d",
    "0x476f3a6b93951f081b1ec119530defaacaa9a330",
    "0x47a511b96f180d378f00f6cd64f9ab3393c6c8d7",
    "0x47d150897c96b99a09d3796b67de8487d1f0063e",
    "0x48dcfd6fe331348600a377dfeb0ab3db0a415f88",
    "0x494b33439f5790168640d55f8b7ac96e6d3bf4f9",
    "0x49fd6b8ad6aa667d03716f4632157538be1159d4",
    "0x4a4c729448091355d4f82b2b57dbcc946092b670",
    "0x4b76837f8d8ad0a28590d06e53dcd44b6b7d4554",
    "0x4b841c0019475c4bac90764f947db202fce44678",
    "0x4fe4e666be5752f1fdd210f4ab5de2cc26e3e0e8",
    "0x5295b474f3a0bb39418456c96d6fcf13901a4aa1",
    "0x53e83e786444d603c87036487036cd43a3e91704",
    "0x585faacf6cfc7c379414334c30e1097a26c7cba6",
    "0x58efa9aae017589b9fadbea3ed6f09730635efaf",
    "0xdd01e9be0f8ac1be72f57a29e2e960777ef2d152",
    "0x7be0f7cdaf17fbb4f5cdcfdb625c7c608472a094",
    "0xa57cbab4bf1e1fb14cd375c5c374198df6d69db2",
    "0xf07cf50d68992ac6dea462c739d65cc311e76480",
    "0x992228c6903caa66f0e79b1129d36be780eaf6ac",
    "0x82eeed190ff3e197645240a2ad190e1b8801a020",
    "0x7a984c84f0fafadaab7d0395e6abe560e26ff370",
    "0x77730563f9014cf782cfcf8ae2a0fed111cb7419",
    "0x843a97185de92a8fd214efa8e14bf67e97892342",
    "0xc008c0f712c1289a571e2f9336b237bded5132e0",
    "0xc268eaf1c21cae0b5f7b819cae37eccd206a8e36",
    "0x6b913b6f2562570cd8f8e746b44439162f0c3798",
    "0xbfc4664c36ff3cc632fdac143d8e546c4dd7e4d5",
    "0x81d3ec77438b4e99aa99ba25b1dbc3fea317fe3b",
    "0xe51c910738a91ed6c966f6d0d6c25289d4292613",
    "0x99b9c2b49ff03dd1f4d6e537c4d94d73a75e7c4f",
    "0xa2b0ddb3dde52675d1b3c23c082bd7b4eec9460e",
    "0xd53a37f9eb79288589f05daf586c49574506f6f2",
    "0xfb82cdc0c8aea92da1d02883d466eb6eb9073e90",
    "0x86331216b8fcf873ea91a20757a43f4b718ca324",
    "0xdba015a0a174461a56644f3743a39adff4307e10",
    "0xdb9ea2b61f7d2a7a903b21920e0fc746d53691e6",
    "0x8aa51a7cfb4a7f27ca299a8460b618b3a234da2a",
    "0xe0293e633002682911814624548548f90f244478",
    "0x7e7b814d0771170c1345749a0506b35802056bac",
    "0xe28f847bc1bc35d7ba1334c379cec11e7bbed273",
    "0x91a625b8df39b14acde602401bef2ed8695cf3ea",
    "0x9c6a79a0c922ae123fd3378f13be9f5f421702c3",
    "0xa3bbcd67e63812f8adcc39e3d0de72bb1b77f621",
    "0xbc713c6fd2ad5e965a2e3f8db40f13448527545e",
    "0x8303881cd4cfb33422efc89705c2030dbc502995",
    "0xd5017ce378720f890ab00f774c7ab553bbbbea50",
    "0xb4a8d9a37a9f7ab8b464e288fa022e2ef53fe9e6",
    "0xde5eff16da045fde0c0438fa3cce330d9ae643ff",
    "0x8fc99f13d3fed6bb25ea4061e01fe925b1019a42",
    "0x629a23c89fa389cc3633db70547f436af2692e59",
    "0x9d080bc9e24a5a8446d4d864414b4a7a03ccc377",
    "0x9110730b731a8e8b3492f2e27fbe401d01067050",
    "0xf0fe0b903331348e9ae28a94dd548c8c66cb46a6",
    "0xcdd69ba6300bbc239e1de3cee86088f3688a7160",
    "0x91f02f52e9251fe69a17337faadc344944fade15",
    "0xf20f4c3692377d426119a7649b27cf99b10dd720",
    "0x9b17de91387b00d9cf910ec0cb236221e45669c9",
]

# 18-address list from test_full_dataset.py — largest / most complete set
KNOWN_GENUINE: list[str] = [
    "0xaba7161a7fb69c88e16ed9f455ce62b791ee4d03",
    "0xd45058bf25bbd8f586124c479d384c8c708ce23a",
    "0x7a59205733a593a184156f91085dc64ed050408f",
    "0xcaff2ff35295b803b33f3cf652224532cfc64301",
    "0xe9da256a28630efdc637bfd4c65f0887be1aeda8",
    "0xce8d642cdd81d805b9b770da9af3790e7e3dfb05",
    "0x2aa5ebd85ba9fbdc87a774c29cdad806d7892820",
    "0xc9b6321dc216d91e626e9baa61b06b0e4d55bdb1",
    "0x4265de963cdd60629d03fee2cd3285e6d5ff6015",
    "0xcc9b1fa104d13639c287bd77555e90d4558282fe",
    "0x0bdfd4ad937ff179985276b7f5be7ae3de0229e6",
    "0xfd16f84e1f9bb5ec33b52d0133d61f7d20699658",
    "0xc352b534e8b987e036a93539fd6897f53488e56a",
    "0x9056d15c49b19df52ffad1e6c11627f035c0c960",
    "0x1354d8cef0b3459e2677db6321c25639d2b658bd",
    "0x3ab208d3ce512f2ac0aa821eecf2b816a96799b0",
    "0x5ef6e3570a32ea63c7bfb69bbb72fe0cd37dfa42",
    "0x7ea79bad324579fac7a7645c62fe8c60a8b73055",
]

# ─────────────────────────────────────────────────────────────────────────────
# Etherscan helpers — best version from rugpull_live_batch.py (retry + backoff)
# ─────────────────────────────────────────────────────────────────────────────

ETHERSCAN_BASE   = "https://api.etherscan.io/v2/api"
RATE_SLEEP       = 0.22   # ~5 req/s on free Etherscan tier
RATE_SLEEP_BURST = 8.0    # back-off when rate-limited


def _etherscan_get(params: dict, api_key: str, retries: int = 3) -> list:
    """Call Etherscan V2 API with rate limiting and exponential retry."""
    params["apikey"] = api_key
    params.setdefault("chainid", 1)
    url = ETHERSCAN_BASE + "?" + urllib.parse.urlencode(params)
    time.sleep(RATE_SLEEP)
    try:
        with urllib.request.urlopen(url, timeout=25) as resp:
            data = json.loads(resp.read())
    except Exception as exc:
        if retries > 0:
            time.sleep(3)
            return _etherscan_get(params, api_key, retries - 1)
        print(f"    [WARN] Etherscan request failed: {exc}")
        return []

    result = data.get("result", [])
    if isinstance(result, str):
        if "rate limit" in result.lower():
            print(f"    [rate limit — waiting {RATE_SLEEP_BURST}s]")
            time.sleep(RATE_SLEEP_BURST)
            return _etherscan_get(params, api_key, retries)
        return []   # "No transactions found" etc — not an error
    return result or []


def fetch_normal_txs(address: str, api_key: str) -> list:
    """Fetch all normal (external) transactions for a wallet, oldest first."""
    return _etherscan_get({
        "module": "account", "action": "txlist",
        "address": address.lower(), "sort": "asc",
        "page": 1, "offset": 10000,
    }, api_key)


def fetch_internal_txs(address: str, api_key: str) -> list:
    """Fetch internal transactions for any address (creator wallet OR contract)."""
    return _etherscan_get({
        "module": "account", "action": "txlistinternal",
        "address": address.lower(), "sort": "asc",
        "page": 1, "offset": 10000,
    }, api_key)


def fetch_first_tx_ts(address: str, api_key: str) -> int | None:
    """Return the timestamp of the very first transaction (for wallet-age checks)."""
    result = _etherscan_get({
        "module": "account", "action": "txlist",
        "address": address.lower(), "sort": "asc",
        "page": 1, "offset": 1,
    }, api_key)
    if result:
        try:
            return int(result[0].get("timeStamp", 0))
        except (ValueError, IndexError):
            return None
    return None


def fetch_token_txs(address: str, api_key: str) -> list:
    """
    Fetch ERC-20 token transfer events for a wallet address, oldest-first.

    Used exclusively for VS6 Value-Transfer Semantics analysis:
      - Mint events: records where from == "0x0000000000000000000000000000000000000000"
        (the zero address). When a token contract mints new supply, Etherscan
        records a transfer FROM the zero address TO the recipient.
      - Provides token amounts (in token units, NOT ETH) and timestamps.

    Note: The 'value' field here is in token units (with the token's own
    decimal precision), NOT in Wei or ETH. Do not compare across different
    tokens without normalising by the token's decimal count.

    Rate-limited and retried using the same _etherscan_get helper as all
    other fetch functions.
    """
    return _etherscan_get({
        "module": "account",
        "action": "tokentx",
        "address": address.lower(),
        "sort": "asc",
        "page": 1,
        "offset": 10000,
    }, api_key)


def fetch_wallet_full(addr: str, api_key: str, live_cache: dict) -> dict:
    """
    Fetch complete transaction data for one creator wallet.

    Returns:
        {
          "normal_txs":       [...] creator's normal txs
          "internal_txs":     [...] MERGED internal txs from creator AND contract
          "contract_address": "0x..."  first deployed contract (or "")
        }

    The contract internal-tx merge is the key fix over simpler fetchers:
      Creator txlistinternal  → inbound ETH to creator (from users, CEX)
      Contract txlistinternal → outbound ETH FROM contract to creator (withdraw(),
                                removeLiquidity()) — required for POST rules.

    Deduplication is by (hash, traceId) so the same internal tx is never
    counted twice even when it appears in both lists.

    Results are stored in live_cache[addr] so callers can persist them without
    extra round-trips.
    """
    if addr in live_cache:
        return live_cache[addr]

    print(f"    [API] normal_txs      creator  {addr[:14]}...")
    normal_txs = fetch_normal_txs(addr, api_key)

    print(f"    [API] internal_txs    creator  {addr[:14]}...")
    creator_internal = fetch_internal_txs(addr, api_key)

    # Detect the first deployed contract address from normal txs
    deploy_txs = sorted(
        [tx for tx in normal_txs
         if tx.get("from", "").lower() == addr
         and tx.get("to", "") in ("", None)
         and tx.get("contractAddress") not in ("", None)],
        key=lambda t: int(t.get("timeStamp", 0))
    )
    contract_address = (
        deploy_txs[0].get("contractAddress", "").lower() if deploy_txs else ""
    )

    # Fetch internal txs FOR THE CONTRACT (captures withdraw() ETH payouts)
    contract_internal: list = []
    if contract_address:
        print(f"    [API] internal_txs    contract {contract_address[:14]}...")
        contract_internal = fetch_internal_txs(contract_address, api_key)

    # Merge + deduplicate by (hash, traceId)
    seen: set[tuple] = set()
    merged: list = []
    for tx in creator_internal + contract_internal:
        key = (
            tx.get("hash", ""),
            tx.get("traceId", tx.get("logIndex", tx.get("type", ""))),
        )
        if key not in seen:
            seen.add(key)
            merged.append(tx)

    print(
        f"    Txs: {len(normal_txs)} normal + {len(merged)} internal "
        f"(creator+contract merged)"
    )

    result = {
        "normal_txs":       normal_txs,
        "internal_txs":     merged,
        "contract_address": contract_address,
    }
    live_cache[addr] = result
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Deploy-timestamp detection
# ─────────────────────────────────────────────────────────────────────────────

def find_deploy_ts(addr: str, normal_txs: list, all_txs: list) -> int:
    """
    Return the timestamp of the first contract deployment from this wallet.

    Falls back to the first transaction timestamp if no deployment is found,
    and to 0 if the wallet has no transactions at all.
    """
    deploy_txs = sorted(
        [tx for tx in normal_txs
         if tx.get("from", "").lower() == addr
         and tx.get("to", "") in ("", None)
         and tx.get("contractAddress") not in ("", None)],
        key=lambda t: int(t.get("timeStamp", 0))
    )
    if deploy_txs:
        return int(deploy_txs[0].get("timeStamp", 0))
    return int(all_txs[0].get("timeStamp", 0)) if all_txs else 0


# ─────────────────────────────────────────────────────────────────────────────
# JSON cache helpers
# ─────────────────────────────────────────────────────────────────────────────

def load_json(path: str) -> dict:
    """Load a JSON file, returning an empty dict if the file does not exist."""
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_json(path: str, data: dict) -> None:
    """Atomically write data to a JSON file (overwrites in place)."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
