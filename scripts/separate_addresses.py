"""
separate_addresses.py
─────────────────────────────────────────────────────────────────────────────
Script to separate a list of Ethereum addresses into EOAs (creator wallets)
and Smart Contracts by checking their on-chain bytecode via Etherscan.

If an address has bytecode (eth_getCode != '0x'), it's a contract.
Otherwise, it's an EOA.
"""

import json
import os
import time
import requests
import urllib.parse
import urllib.request
from typing import List

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# We use a Session to keep the TCP connection alive. This prevents the OS 
# from running out of DNS sockets (which causes "getaddrinfo failed").
session = requests.Session()
session.headers.update({'Content-Type': 'application/json'})

# The raw list of addresses provided by the user
RAW_ADDRESSES = [
    "0x00859b3baac525143bb8a3ee3e19ddf9daf2408c",
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
    "0x1b2ef9d5db72ea1103fc24eedd2226477409383a",
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
    "0x460fd5059e7301680fa53e63bbbf7272e643e89c",
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
    "0xDd01e9Be0f8aC1be72f57a29e2e960777eF2d152",
    "0x19Fde224C03249bd0EF503815DCad200C57C2aDc",
    "0x7Be0f7Cdaf17FBb4F5cDCFdB625c7c608472a094",
    "0x19Fde224C03249bd0EF503815DCad200C57C2aDc",
    "0x19Fde224C03249bd0EF503815DCad200C57C2aDc",
    "0x3549d95f144c0CC9EB5fC29fC8b6881A84d51536",
    "0xa57cbAb4BF1e1fb14CD375C5c374198df6D69Db2",
    "0x3fbfAc2397902bA762D6Da683b567dC5BBb1fcE0",
    "0x212Da8c9Dad7e9B6a71422665c58Bf9a7ECAe6D0",
    "0xF07cf50d68992ac6Dea462c739D65CC311e76480",
    "0x53E83E786444d603c87036487036CD43a3e91704",
    "0x992228c6903caa66f0e79b1129d36be780eaf6ac",
    "0x82EEED190FF3E197645240a2ad190e1B8801a020",
    "0xFD6Ed83d8e47B1C808efE984cEF965B2CB3393De",
    "0x3e18EDA374Aa344F4A6f0D3Ff73f10e6CeD8aD21",
    "0x1123Aaf2d3AA6e075c9e7E232895818387826026",
    "0x34B365C3a98D0ec12A680047FE299aff2a032554",
    "0x0ea10e39a2923a7FC7354F40Daac938764B71cA8",
    "0x7a984C84F0FafadaAb7D0395e6abe560E26Ff370",
    "0x77730563F9014cF782CFcF8ae2a0FEd111cb7419",
    "0x843a97185dE92a8FD214eFa8E14bF67e97892342",
    "0xC008c0F712c1289a571E2F9336B237bDED5132e0",
    "0x44343Df908f0fB88326d03Ad828524C08F61E4bc",
    "0x27433113B7b2B25E0CC018E0c6eE629A0466683E",
    "0xC268EAf1C21Cae0b5f7b819CaE37ecCD206A8e36",
    "0x6b913B6F2562570cd8f8E746B44439162F0c3798",
    "0x3450265c76c0FB04b4a6b5195aebe00314040C6F",
    "0xbFc4664C36Ff3cc632fDac143d8E546C4Dd7e4D5",
    "0x4A4c729448091355D4F82b2B57dbcc946092b670",
    "0x81d3EC77438b4E99AA99Ba25B1dbc3Fea317Fe3b",
    "0xE51C910738a91eD6C966f6D0D6c25289D4292613",
    "0x99b9C2b49FF03dd1F4d6e537C4D94d73A75e7c4f",
    "0x0659724a5293127789660734d64c18254e7dbd18",
    "0xa2b0ddb3dde52675d1b3c23c082bd7b4eec9460e",
    "0xd53a37f9EB79288589F05DAf586c49574506F6F2",
    "0xFb82CDc0C8AEa92DA1d02883D466EB6EB9073E90",
    "0x86331216B8fCF873Ea91a20757a43F4B718Ca324",
    "0xdBA015a0a174461a56644F3743a39aDFf4307e10",
    "0x154827328a10e1c5C2878acBa12BC6a4ED3C6b2A",
    "0xdB9Ea2b61F7d2A7a903B21920E0Fc746d53691e6",
    "0x8aa51a7cfb4a7f27ca299a8460b618b3a234da2a",
    "0x47a511b96f180D378F00f6cd64F9AB3393c6C8d7",
    "0xe0293E633002682911814624548548F90f244478",
    "0x58EFa9AAE017589b9fadBeA3ed6F09730635Efaf",
    "0x7e7b814D0771170C1345749a0506b35802056baC",
    "0x03F15ECC984669237aaC41392b5dD6cF3132ff35",
    "0xe28f847bC1bc35d7ba1334C379cec11e7BBeD273",
    "0x021ac107832f1c10400e3190281d3fFed4F38bC6",
    "0x91A625B8DF39B14ACdE602401bEF2ed8695cf3eA",
    "0x9C6A79A0c922Ae123Fd3378f13be9F5f421702C3",
    "0xA3Bbcd67e63812F8ADcc39e3d0dE72bb1b77f621",
    "0x19CC350a22EB342E91A2199AbacC8c5bBd87c7A5",
    "0xbc713c6Fd2Ad5e965A2E3f8Db40F13448527545E",
    "0x2108007b64b3968b4a1C21fa1aF0ea8E7b2d3912",
    "0x2108007b64b3968b4a1C21fa1aF0ea8E7b2d3912",
    "0x3a0bEf9700474A00b10A1063B59685DE6E690c08",
    "0x8303881cd4CFB33422EfC89705c2030dBC502995",
    "0xD5017ce378720F890AB00F774c7Ab553bbbBeA50",
    "0x47d150897c96b99A09D3796b67DE8487D1f0063e",
    "0xB4A8d9a37A9f7Ab8b464E288fa022E2Ef53fE9e6",
    "0x266Db4743755109a5926D6fDeD5ED6F6a284aB98",
    "0xde5eff16da045fde0c0438fa3cce330d9ae643ff",
    "0x585FaaCF6cfC7c379414334c30E1097A26C7cba6",
    "0x8Fc99f13d3Fed6bb25ea4061e01fE925B1019a42",
    "0x629A23c89Fa389CC3633DB70547F436af2692E59",
    "0x25D295635e747ec6fF3F0c1E19e30A335De66ed5",
    "0x25D295635e747ec6fF3F0c1E19e30A335De66ed5",
    "0x9D080bc9e24a5A8446D4D864414b4A7A03CcC377",
    "0x0e04Ba718d3C7AC4d7c8fA357ab73ABdD45d89dC",
    "0x0e04Ba718d3C7AC4d7c8fA357ab73ABdD45d89dC",
    "0x0e04Ba718d3C7AC4d7c8fA357ab73ABdD45d89dC",
    "0x9110730b731a8e8b3492F2E27fbE401D01067050",
    "0x42Fab76321440273044ef6A157E86A9777B5809b",
    "0xf0fe0b903331348E9aE28a94Dd548C8c66cB46a6",
    "0xcdd69BA6300BBc239E1DE3CEe86088F3688A7160",
    "0x91f02F52e9251fE69a17337Faadc344944FAdE15",
    "0x494b33439f5790168640d55f8B7AC96E6d3bF4F9",
    "0x49fD6b8AD6aa667D03716F4632157538Be1159d4",
    "0xf20f4c3692377d426119A7649B27Cf99B10DD720",
    "0x494b33439f5790168640d55f8B7AC96E6d3bF4F9",
    "0x460Fd5059E7301680fA53E63bbBF7272E643e89C",
    "0x494b33439f5790168640d55f8B7AC96E6d3bF4F9",
    "0x9B17de91387B00d9CF910eC0cb236221E45669c9",
]

def normalize(addr: str) -> str:
    """Lowercase for consistent deduplication."""
    return addr.strip().lower()

def parse_addresses(raw_list: list[str]) -> list[str]:
    """Parse, lowercase-normalise, and deduplicate. Returns list in insertion order."""
    seen = set()
    unique = []
    for line in raw_list:
        line = line.strip()
        if not line:
            continue
        if not line.startswith("0x") or len(line) != 42:
            print(f"  [SKIP] Looks invalid: {line}")
            continue
        addr = normalize(line)
        if addr not in seen:
            seen.add(addr)
            unique.append(addr)
    return unique

def get_bytecode(address: str, api_key: str, retries: int = 5) -> str | None:
    """
    Calls Etherscan proxy → eth_getCode via requests.Session.
    Handles rate-limits recursively with exponential backoff.
    """
    params = {
        "module": "proxy",
        "action": "eth_getCode",
        "address": address,
        "tag": "latest",
        "apikey": api_key,
        "chainid": 1
    }
    url = "https://api.etherscan.io/v2/api"
    
    try:
        resp = session.get(url, params=params, timeout=10)
        data = resp.json()
        result = data.get("result", "")
        
        # Etherscan free tier rate limit catch
        if isinstance(result, str) and "rate limit" in result.lower():
            time.sleep(6)
            return get_bytecode(address, api_key, retries)
            
        return result
    except Exception as e:
        if retries > 0:
            backoff = (6 - retries) * 3  # Waits 3s, 6s, 9s, 12s, 15s
            time.sleep(backoff)
            return get_bytecode(address, api_key, retries - 1)
        print(f"    [HTTP ERROR] {e}")
        return None

def is_contract(bytecode: str) -> bool:
    """True if bytecode is non-empty (i.e. not '0x' or '0x0')."""
    return bytecode not in ("0x", "0x0", "", None)

RPCS = [
    "https://bsc-dataseed.binance.org/",
    "https://polygon-rpc.com",
    "https://arb1.arbitrum.io/rpc",
    "https://mainnet.base.org",
    "https://mainnet.optimism.io",
    "https://api.avax.network/ext/bc/C/rpc",
    "https://rpc.ftm.tools",
    "https://evm.cronos.org",
    "https://rpc.linea.build",
    "https://forno.celo.org",
    "https://rpc.gnosischain.com",
    "https://rpc.blast.io"
]

def is_contract_cross_chain(address: str) -> bool:
    """Checks public RPC nodes of major EVM chains to see if the address is a contract."""
    payload = {
        "jsonrpc": "2.0",
        "method": "eth_getCode",
        "params": [address, "latest"],
        "id": 1
    }
    for rpc in RPCS:
        try:
            resp = session.post(rpc, json=payload, timeout=4)
            data = resp.json()
            result = data.get("result", "0x")
            if result not in ("0x", "0x0", "", None):
                return True  # Found a contract on this chain!
        except Exception:
            pass  # Silently skip if the public RPC fails or times out
        time.sleep(0.1)  # Be polite to public nodes
    return False

# ─── MAIN ─────────────────────────────────────────────────────────────────────

def main():
    api_key = os.getenv("ETHERSCAN_API_KEY")
    if not api_key:
        print("[ERROR] Please set your ETHERSCAN_API_KEY in the .env file.")
        print("        Get a free key at: https://etherscan.io/myapikey")
        return

    addresses = parse_addresses(RAW_ADDRESSES)
    total = len(addresses)
    print(f"Unique addresses to classify: {total}\n")

    eoas      = []
    contracts = []
    errors    = []

    for i, addr in enumerate(addresses, 1):
        bytecode = get_bytecode(addr, api_key)

        if bytecode is None:
            errors.append(addr)
            label = "ERROR   "
        elif is_contract(bytecode):
            contracts.append(addr)
            label = "ETH_CONT"
        else:
            # If it's an EOA on Ethereum, check if it's a contract on another chain
            if is_contract_cross_chain(addr):
                contracts.append(addr)
                label = "L2_CONT "
            else:
                eoas.append(addr)
                label = "EOA     "

        print(f"  [{i:>3}/{total}] {label}  {addr}")

        # Respect Etherscan free-tier rate limit (5 req/sec)
        if i < total:
            time.sleep(0.25)

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f"""
{'='*60}
RESULTS
{'='*60}
  EOA (wallet) addresses : {len(eoas)}
  Contract addresses     : {len(contracts)}
  Errors / skipped       : {len(errors)}
{'='*60}
""")

    # ── Save output files ─────────────────────────────────────────────────────
    with open("eoa_addresses.txt", "w") as f:
        f.write("\n".join(eoas))
    print(f"Saved {len(eoas):>3} EOA addresses      → eoa_addresses.txt")

    with open("contract_addresses.txt", "w") as f:
        f.write("\n".join(contracts))
    print(f"Saved {len(contracts):>3} contract addresses → contract_addresses.txt")

    if errors:
        with open("error_addresses.txt", "w") as f:
            f.write("\n".join(errors))
        print(f"Saved {len(errors):>3} errored addresses  → error_addresses.txt")

if __name__ == "__main__":
    main()
