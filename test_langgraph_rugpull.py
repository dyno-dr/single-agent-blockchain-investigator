import asyncio
import os
import json
from backend.agent.graph import compile_investigator_graph
from backend.forensics.models import InvestigationSettings
from backend.agent.state import AgentState

async def main():
    graph = compile_investigator_graph()
    settings = InvestigationSettings(
        max_depth=1,
        max_hops=1,
        risk_threshold=36.0,
        enable_heuristic_rules=True
    )
    
    # 0x07cb37ed2198fc7a2a1671ac94311738a548b877 is one of the high-confidence rugpulls.
    initial_state = {
        "wallet_address": "0x07cb37ed2198fc7a2a1671ac94311738a548b877",
        "investigation_id": "test_rugpull",
        "settings": settings,
        "current_depth": 0,
        "reasoning_log": [],
        "errors": []
    }
    
    # Needs ETHERSCAN_API_KEY
    if not os.environ.get("ETHERSCAN_API_KEY"):
        from dotenv import load_dotenv
        load_dotenv()
        
    print("Running LangGraph workflow...")
    final_state = await graph.ainvoke(initial_state)
    
    print("\n--- RESULTS ---")
    print(f"Risk Score: {final_state.get('risk_score')}")
    print(f"Risk Level: {final_state.get('risk_level')}")
    
    rug_reports = final_state.get("rugpull_reports", {})
    if rug_reports:
        for wallet, report in rug_reports.items():
            print(f"Rugpull Score for {wallet}: {report.get('score')}")
            for rule in report.get('triggered_rules', []):
                if rule.get('triggered'):
                    print(f"  - {rule.get('rule_id')}: {rule.get('rule_name')} ({rule.get('severity')})")
    
    final_report = final_state.get("final_report", "")
    print("\n--- FINAL REPORT SNIPPET ---")
    print(final_report[:500] + "...")

if __name__ == "__main__":
    asyncio.run(main())
