"""
test_langgraph.py
─────────────────────────────────────────────────────────────────────────────
Standalone CLI test runner for the full LangGraph investigation pipeline.

Usage:
    venv\\Scripts\\python.exe test_langgraph.py <WALLET_ADDRESS>

What it does:
  1. Initialises the database (runs migrations).
  2. Creates a proper investigation row in the DB (so FK constraints hold).
  3. Runs the full LangGraph graph (profiler → planner → detector → reporter → memory).
  4. Prints a full report including:
     - All 7+ forensic rule findings
     - All rugpull rule (RUG-001 … RUG-FP8) findings
     - Risk score and verdict
     - Report title, summary, and recommendations
"""

from __future__ import annotations

import asyncio
import os
import sys

import httpx
from aiolimiter import AsyncLimiter

from backend.agent.graph import investigation_graph
from backend.persistence.database import get_db_direct, init_db
from backend.persistence.repositories import InvestigationRepository
from backend.settings.base import get_settings


async def main() -> None:
    # ── 1. Load settings + env ────────────────────────────────────────────────
    if not os.environ.get("ETHERSCAN_API_KEY"):
        from dotenv import load_dotenv
        load_dotenv()

    settings = get_settings()

    # ── 2. Init database ──────────────────────────────────────────────────────
    await init_db()

    # ── 3. Resolve wallet from CLI arg ────────────────────────────────────────
    wallet = (
        sys.argv[1]
        if len(sys.argv) > 1
        else "0x07cb37ed2198fc7a2a1671ac94311738a548b877"
    )
    wallet = wallet.lower()
    print(f"\n{'='*70}")
    print(f"  BLOCKCHAIN INVESTIGATOR — Single Wallet Test")
    print(f"  Wallet  : {wallet}")
    print(f"{'='*70}\n")

    # ── 4. Create a proper investigation row (fixes FK constraint) ────────────
    db = await get_db_direct()
    try:
        repo = InvestigationRepository(db)
        inv_row = await repo.create(
            wallet_address=wallet,
            depth=1,
            lookback_days=90,
            max_transactions=500,
        )
        investigation_id: str = inv_row["id"]
        print(f"Investigation ID : {investigation_id}")
        print(f"Running pipeline ...\n")
    finally:
        await db.close()

    # ── 5. Build shared HTTP client ───────────────────────────────────────────
    http_client = httpx.AsyncClient(timeout=60.0)
    rate_limiter = AsyncLimiter(5, 1.0)

    try:
        # ── 6. Build initial agent state ─────────────────────────────────────
        initial_state = {
            "investigation_id": investigation_id,
            "wallet_address": wallet,
            "depth": 1,
            "lookback_days": 90,
            "max_transactions": 500,
            "chain": "ETHEREUM",
            "status": "RUNNING",
            "current_phase": "INIT",
            "error_message": None,
            "wallet_profiles": {},
            "wallets_to_trace": [wallet],
            "traced_wallets": [],
            "current_depth": 0,
            "trace_candidates": [],
            "forensics_reports": {},
            "rugpull_reports": {},
            "risk_score": 0.0,
            "risk_level": "LOW",
            "trace_strategy": "FORWARD_ONLY",
            "planner_reasoning": "",
            "trace_directive": {},
            "report_title": "",
            "report_summary": "",
            "report_findings": [],
            "report_recommendations": [],
            "graph_nodes": [],
            "graph_edges": [],
            "reasoning_log": [],
            "errors": [],
            "settings": settings,
            "http_client": http_client,
            "rate_limiter": rate_limiter,
        }

        # ── 7. Run the full LangGraph pipeline ───────────────────────────────
        final_state = await investigation_graph.ainvoke(initial_state)

        # ── 8. Print full report ──────────────────────────────────────────────
        risk_score = final_state.get("risk_score", 0.0)
        risk_level = final_state.get("risk_level", "LOW")

        print(f"\n{'='*70}")
        print(f"  INVESTIGATION COMPLETE")
        print(f"{'='*70}")
        print(f"  Wallet     : {wallet}")
        print(f"  Risk Score : {risk_score}/100")
        print(f"  Risk Level : {risk_level}")

        # Report title + summary
        title = final_state.get("report_title", "")
        summary = final_state.get("report_summary", "")
        if title:
            print(f"\n  REPORT TITLE:\n  {title}")
        if summary:
            print(f"\n  SUMMARY:\n  {summary}")

        # ── Forensic rule findings (7 base rules + 2 new) ────────────────────
        forensics_reports = final_state.get("forensics_reports", {})
        all_forensic_findings = []
        for w, report in forensics_reports.items():
            for finding in getattr(report, "findings", []):
                all_forensic_findings.append(finding)

        if all_forensic_findings:
            print(f"\n  FORENSIC RULE FINDINGS ({len(all_forensic_findings)}):")
            print(f"  {'-'*60}")
            for f in all_forensic_findings:
                triggered_flag = "✓ TRIGGERED" if getattr(f, "triggered", False) else "  not triggered"
                print(f"  [{triggered_flag}] {f.rule_id}: {f.rule_name}")
                print(f"    Severity    : {f.severity}")
                if hasattr(f, "description") and f.description:
                    print(f"    Description : {f.description}")
                if hasattr(f, "reasoning") and f.reasoning:
                    print(f"    Reasoning   : {f.reasoning}")
                if hasattr(f, "tx_hash") and f.tx_hash:
                    print(f"    Evidence TX : {f.tx_hash}")
                print()
        else:
            print("\n  FORENSIC RULE FINDINGS: None triggered.")

        # ── Rugpull rule findings ─────────────────────────────────────────────
        rug_reports = final_state.get("rugpull_reports", {})
        if rug_reports:
            for w, report in rug_reports.items():
                score = report.get("score", 0)
                verdict = report.get("verdict", "UNKNOWN")
                triggered_rules = [
                    r for r in report.get("triggered_rules", [])
                    if r.get("triggered")
                ]
                print(f"\n  RUGPULL ENGINE RESULTS:")
                print(f"  {'-'*60}")
                print(f"  Score   : {score}/100")
                print(f"  Verdict : {verdict}")

                if triggered_rules:
                    print(f"\n  Triggered Rugpull Rules ({len(triggered_rules)}):")
                    for rule in triggered_rules:
                        print(f"    [{rule.get('rule_id')}] {rule.get('rule_name')}")
                        print(f"      Severity    : {rule.get('severity', 'N/A')}")
                        desc = rule.get("description", "")
                        if desc:
                            print(f"      Description : {desc.encode('cp1252', errors='replace').decode('cp1252')}")
                        obs = rule.get("observation", "")
                        if obs:
                            print(f"      Observation : {obs}")
                        print()
                else:
                    print("  No rugpull rules triggered.")

        # ── Recommendations ───────────────────────────────────────────────────
        recommendations = final_state.get("report_recommendations", [])
        if recommendations:
            print(f"\n  RECOMMENDATIONS ({len(recommendations)}):")
            print(f"  {'-'*60}")
            for i, rec in enumerate(recommendations, 1):
                print(f"  {i}. {rec}")

        print(f"\n{'='*70}\n")

    finally:
        await http_client.aclose()


if __name__ == "__main__":
    asyncio.run(main())
