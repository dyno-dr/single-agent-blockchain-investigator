"""
backend/tools/rugpull_tool.py
─────────────────────────────────────────────────────────────────────────────
Tool: RugpullTool

PURPOSE:
  Analyses an Ethereum creator wallet for rugpull risk using both behavioural
  features (F1-F7) and the new Funding Provenance features (FP1-FP8).

WHAT IT DOES:
  1. Fetches normal and internal transactions via EtherscanClient.
  2. Identifies the deployment timestamp.
  3. Fetches the first transaction timestamp for all upstream funding sources
     (for FP3 fresh-wallet detection) concurrently.
  4. Loads known entities and the SQLite investigation graph.
  5. Computes Funding Provenance features.
  6. Evaluates all rules via `RugpullEngine` and scores the result.
  7. Returns a structured `RugpullReport`.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import structlog

from backend.blockchain.etherscan_client import EtherscanClient
from backend.forensics.rugpull.engine import RugpullEngine, RugpullReport
from backend.forensics.rugpull.funding_graph import (
    FunderGraph,
    extract_funding_provenance,
)
from backend.tools.base import BaseTool

logger = structlog.get_logger(__name__)

KNOWN_ENTITIES_PATH = Path(__file__).parent.parent / "blockchain" / "known_entities.json"


class RugpullTool(BaseTool):
    """
    Analyses a creator wallet for rugpull risk.

    Usage:
        tool = RugpullTool()
        report = await tool.run(
            wallet=address,
            settings=settings,
            http_client=http_client,
            rate_limiter=rate_limiter,
        )
    """

    name = "analyze_rugpull_risk"
    description = "Analyse an Ethereum creator wallet for rugpull risk, including funding provenance."

    async def run(
        self,
        **kwargs: Any
    ) -> RugpullReport:
        wallet: str = kwargs["wallet"]
        settings: Any = kwargs["settings"]
        http_client: Any = kwargs["http_client"]
        rate_limiter: Any = kwargs["rate_limiter"]
        
        logger.info("rugpull_tool_start", wallet=wallet)

        client = EtherscanClient(
            settings=settings,
            http_client=http_client,
            rate_limiter=rate_limiter,
        )

        # 1. Fetch raw txs — retry up to 3 times with backoff on transient NOTOK
        normal_txs = []
        for attempt in range(3):
            try:
                normal_txs = await client.get_transactions(wallet)
                break  # success
            except Exception as e:
                logger.warning(
                    "rugpull_tool_normal_tx_fail",
                    wallet=wallet,
                    error=str(e),
                    attempt=attempt + 1,
                )
                if attempt < 2:
                    await asyncio.sleep(2.0 * (attempt + 1))  # 2s, 4s

        internal_txs = []
        try:
            internal_txs = await client.get_internal_transactions(wallet)
        except Exception as e:
            logger.warning("rugpull_tool_internal_tx_fail", wallet=wallet, error=str(e))

        # If we have absolutely no data after retries, return early to avoid
        # a false CLEAN verdict — the engine cannot score without transactions.
        if not normal_txs and not internal_txs:
            from backend.forensics.rugpull.engine import RugpullReport
            from backend.forensics.rugpull.extractor import extract_features
            from datetime import UTC, datetime
            logger.warning(
                "rugpull_tool_no_data_abort",
                wallet=wallet,
                msg="No tx data available after retries — skipping rugpull scoring",
            )
            fv = extract_features(wallet.lower(), {"normal_txs": [], "internal_txs": []})
            return RugpullReport(
                wallet_address=wallet.lower(),
                analyzed_at=datetime.now(UTC),
                features=fv,
                score=0,
                verdict="INSUFFICIENT_DATA",
                triggered_rules=[],
                all_rules=[],
                score_breakdown={},
                multihop_addresses=[],
                narrative={"note": "Etherscan fetch failed after retries; score is unreliable."},
            )

        all_txs = normal_txs + internal_txs
        raw_data = {"normal_txs": normal_txs, "internal_txs": internal_txs}

        # 2. Find deploy timestamp
        deploy_txs = sorted(
            [tx for tx in normal_txs if tx.get("to", "") == "" and tx.get("contractAddress")],
            key=lambda t: int(t.get("timeStamp", 0))
        )
        if deploy_txs:
            deploy_timestamp = int(deploy_txs[0].get("timeStamp", 0))
        else:
            # Fallback to last tx or current time if no deployment
            import time
            deploy_timestamp = int(all_txs[-1].get("timeStamp", 0)) if all_txs else int(time.time())

        # 3. Identify all upstream funders before deployment
        addr_lower = wallet.lower()
        senders = {
            tx.get("from", "").lower()
            for tx in all_txs
            if tx.get("to", "").lower() == addr_lower
            and int(tx.get("value", "0")) > 0
            and int(tx.get("timeStamp", 0)) <= deploy_timestamp
            and tx.get("from")
        }

        # 4. Fetch wallet ages concurrently
        wallet_age_lookup: dict[str, int | None] = {}
        
        async def fetch_age(sender: str):
            try:
                txs = await client.get_transactions(sender, offset=1, page=1, sort="asc")
                if txs:
                    return sender, int(txs[0].get("timeStamp", 0))
            except Exception:
                pass
            return sender, None

        if senders:
            results = await asyncio.gather(*(fetch_age(s) for s in senders))
            for s, age in results:
                wallet_age_lookup[s] = age

        # 5. Load known entities
        known_entities: dict[str, dict] = {}
        if KNOWN_ENTITIES_PATH.exists():
            with open(KNOWN_ENTITIES_PATH) as f:
                raw_entities = json.load(f)
            for category, entries in raw_entities.items():
                if category.startswith("_"):
                    continue
                if isinstance(entries, dict):
                    for k, info in entries.items():
                        known_entities[k.lower()] = info

        # 6. Extract Funding Provenance
        funder_graph_db = FunderGraph("investigation_history.db")
        fp_result = extract_funding_provenance(
            wallet_address=wallet,
            txs=all_txs,
            deploy_timestamp=deploy_timestamp,
            known_entities=known_entities,
            wallet_age_lookup=wallet_age_lookup,
            funder_graph_db=funder_graph_db,
        )

        # 7. Run Engine
        engine = RugpullEngine()
        report = engine.run(wallet, raw_data, fp_result=fp_result)
        
        logger.info("rugpull_tool_complete", wallet=wallet, verdict=report.verdict, score=report.score)
        return report
