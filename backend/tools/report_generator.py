"""
backend/tools/report_generator.py
─────────────────────────────────────────────────────────────────────────────
Tool: ReportGeneratorTool

PURPOSE:
    Generates a natural-language forensic report using the Gemini LLM.
    Accepts a ReportContext (the bounded LLM input) and returns a structured
    dict with title, summary, recommendations, and model_used.

MAP-REDUCE BOUNDARY:
    This tool is the Reduce step of the Map-Reduce context boundary defined
    in the architecture spec. It ONLY accepts a ReportContext — never raw
    AgentState, WalletProfiles, or transaction arrays. The StateCondenser
    (state_condenser.py) performs the Map step before this tool is called.

DESIGN DECISIONS:
    1. Accepts ReportContext — a frozen Pydantic model that enforces the
       context boundary at the type level. reporter_node.py cannot pass
       raw state here even accidentally.
    2. Falls back to a deterministic template if the LLM call fails for
       any reason (network error, API quota, invalid JSON response).
       Investigations are never blocked by LLM failures.
    3. Uses langchain_google_genai.ChatGoogleGenerativeAI for Gemini calls.
       The model/key are read from settings.llm.model / settings.llm.api_key.
    4. JSON response parsing strips markdown fences before json.loads() to
       handle models that wrap output in ```json blocks.
"""

from __future__ import annotations

import json
from typing import Any

import structlog

from backend.forensics.models import ReportContext
from backend.tools.base import BaseTool

logger = structlog.get_logger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Prompt template
# ─────────────────────────────────────────────────────────────────────────────

_REPORT_PROMPT = """\
You are a blockchain forensics analyst. Generate a concise forensic investigation report.

INVESTIGATION DETAILS:
  Wallet: {wallet}
  Risk Score: {risk_score}/100
  Risk Level: {risk_level}
  Wallets Analysed: {wallets_analyzed}
  Transactions (root wallet): {total_transactions}
  Balance: {balance_eth:.4f} ETH
  Wallet Age: {wallet_age_days:.0f} days

FORENSIC FINDINGS ({finding_count} total):
{findings_text}

ENTITY CONTACTS:
  Mixer/Tornado Cash: {mixer}
  Centralised Exchange: {cex}
  Bridge: {bridge}

TRACE SUMMARY:
  Wallets traced: {total_wallets_traced}
  Max depth: {max_depth_reached}
  Flagged wallets: {flagged_wallets}
  Notable destinations: {notable_destinations}

ERRORS DURING INVESTIGATION: {errors}

Respond ONLY with a valid JSON object (no markdown fences, no preamble):
{{
  "title": "<concise 6-10 word report title>",
  "summary": "<2-3 sentence executive summary covering risk level, key findings, and context>",
  "recommendations": [
    "<specific actionable recommendation 1>",
    "<specific actionable recommendation 2>",
    "<specific actionable recommendation 3>"
  ]
}}"""


class ReportGeneratorTool(BaseTool):
    """
    Generates a natural-language forensic report using the Gemini LLM.

    Accepts a bounded ReportContext — never raw AgentState.
    Falls back to a deterministic template if the LLM is unavailable.

    Usage:
        tool = ReportGeneratorTool()
        result = await tool.run(
            report_context=report_context,
            settings=settings,
        )
        # result: {title, summary, findings, recommendations, model_used}
    """

    name = "report_generator"
    description = (
        "Generate a natural-language forensic report from a bounded ReportContext "
        "using the Gemini LLM. Falls back to deterministic template on LLM failure."
    )

    async def run(
        self,
        *,
        report_context: ReportContext,
        settings: Any,
        **_kwargs: Any,
    ) -> dict[str, Any]:
        """
        Generate the investigation report title, summary, and recommendations.

        Args:
            report_context: Bounded ReportContext from StateCondenser.
            settings:       Application settings (reads llm sub-model).

        Returns:
            Dict with: title, summary, findings, recommendations, model_used.
        """
        ctx = report_context
        model_used = settings.llm.model

        # ── Build deterministic fallback values ───────────────────────────────
        fallback_title = f"Forensic Investigation — {ctx.wallet_address[:10]}…"
        fallback_summary = (
            f"Investigation of wallet {ctx.wallet_address} completed with risk "
            f"score {ctx.risk_score:.1f}/100 ({ctx.risk_level}). "
            f"{len(ctx.triggered_rules)} forensic finding(s) detected across "
            f"{ctx.wallets_analyzed} wallet(s)."
        )
        fallback_recs = [
            "Monitor wallet for continued suspicious activity.",
            "Review transactions with flagged counterparties.",
            "Report findings to compliance team if thresholds are exceeded.",
        ]

        # Build findings text for prompt — includes Observation (description)
        # AND Reasoning so the LLM's narrative summary can reflect *why* each
        # finding matters, not just what was observed.
        findings_text = "\n".join(
            f"  [{f.severity}] {f.rule_name}: {f.description}"
            + (f" Why this matters: {f.reasoning}" if f.reasoning else "")
            for f in ctx.triggered_rules
        ) or "  No significant findings detected."

        notable_text = (
            ", ".join(ctx.trace_summary.notable_destinations)
            if ctx.trace_summary.notable_destinations
            else "None"
        )

        # ── Attempt LLM generation ────────────────────────────────────────────
        try:
            from langchain_google_genai import ChatGoogleGenerativeAI
            from langchain_core.messages import HumanMessage

            prompt = _REPORT_PROMPT.format(
                wallet=ctx.wallet_address,
                risk_score=round(ctx.risk_score, 1),
                risk_level=ctx.risk_level,
                wallets_analyzed=ctx.wallets_analyzed,
                total_transactions=ctx.total_transactions,
                balance_eth=ctx.balance_eth,
                wallet_age_days=ctx.wallet_age_days,
                finding_count=len(ctx.triggered_rules),
                findings_text=findings_text,
                mixer="YES — HIGH RISK" if ctx.mixer_contact else "No",
                cex="Yes" if ctx.cex_contact else "No",
                bridge="Yes" if ctx.bridge_contact else "No",
                total_wallets_traced=ctx.trace_summary.total_wallets_traced,
                max_depth_reached=ctx.trace_summary.max_depth_reached,
                flagged_wallets=ctx.trace_summary.flagged_wallets,
                notable_destinations=notable_text,
                errors="None" if not getattr(ctx, "errors", None) else "; ".join(ctx.errors),
            )

            llm = ChatGoogleGenerativeAI(
                model=settings.llm.model,
                google_api_key=settings.llm.google_api_key,
                temperature=settings.llm.temperature,
                max_output_tokens=min(settings.llm.max_tokens, 2048),
            )

            response = await llm.ainvoke([HumanMessage(content=prompt)])
            text = response.content.strip()

            # Strip markdown fences if present
            if text.startswith("```"):
                parts = text.split("```")
                text = parts[1]
                if text.lower().startswith("json"):
                    text = text[4:]
                text = text.strip()

            parsed = json.loads(text)
            title = str(parsed.get("title", fallback_title))
            summary = str(parsed.get("summary", fallback_summary))
            recommendations = parsed.get("recommendations", fallback_recs)
            if not isinstance(recommendations, list):
                recommendations = fallback_recs

            logger.info(
                "report_generator_llm_success",
                wallet=ctx.wallet_address,
                risk_level=ctx.risk_level,
                findings=len(ctx.triggered_rules),
            )

            return {
                "title": title,
                "summary": summary,
                "findings": [r.model_dump(mode="json") for r in ctx.triggered_rules],
                "recommendations": recommendations,
                "model_used": model_used,
            }

        except Exception as exc:
            logger.warning(
                "report_generator_llm_failed",
                wallet=ctx.wallet_address,
                error=str(exc),
            )
            return {
                "title": fallback_title,
                "summary": fallback_summary,
                "findings": [r.model_dump(mode="json") for r in ctx.triggered_rules],
                "recommendations": fallback_recs,
                "model_used": f"{model_used} (fallback — LLM error)",
            }