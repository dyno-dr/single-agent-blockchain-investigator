"""
backend/forensics/rugpull/engine.py
─────────────────────────────────────────────────────────────────────────────
Orchestrator for the rugpull creator triage pipeline.

PIPELINE:
  1. Receive raw Etherscan data (already fetched by the caller).
  2. Run FeatureExtractor → FeatureVector
  3. Run all rules        → list[RugRuleResult]
  4. Run scorer           → RugpullScore (score + verdict)
  5. Return RugpullReport (self-contained, serialisable)

DESIGN:
  - The engine is stateless. No DB access, no API calls.
  - Raw Etherscan data is passed in by the caller (typically the main
    forensics engine or a LangGraph tool node that already fetched it).
  - RugpullReport is a frozen Pydantic model — safe to pass between nodes
    and serialise to JSON / the investigation DB.

USAGE (from a tool or agent node):
    from backend.forensics.rugpull import RugpullEngine

    raw = {"normal_txs": [...], "internal_txs": [...]}
    report = RugpullEngine().run(address="0xabc...", raw_data=raw)
    print(report.verdict, report.score)
    # Multi-hop: follow up on ownership transfer targets
    for addr in report.multihop_addresses:
        queue_for_investigation(addr)
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

from backend.forensics.rugpull.extractor import FeatureVector, extract_features
from backend.forensics.rugpull.rules import RugRuleResult, evaluate_all
from backend.forensics.rugpull.scorer import RugpullScore, compute_score
from backend.settings.base import get_settings


# ─────────────────────────────────────────────────────────────────────────────
# Report model
# ─────────────────────────────────────────────────────────────────────────────

class RugpullReport(BaseModel):
    """
    Full output of the rugpull triage pipeline for one wallet.

    This is the object returned by RugpullEngine.run() and passed to the
    LLM report generator / persisted to the investigation DB.
    """

    model_config = {"frozen": True}

    # ── Identity ──────────────────────────────────────────────────────────────
    wallet_address: str
    analyzed_at: datetime

    # ── Feature values ────────────────────────────────────────────────────────
    features: FeatureVector

    # ── Scoring ───────────────────────────────────────────────────────────────
    score: int                              # 0-100
    verdict: str                            # CLEAN / WEAK_PATTERN / ... / HIGH_CONFIDENCE_RUGPULL
    override_applied: str | None = None     # override reason if verdict was modified

    # ── Rule findings ─────────────────────────────────────────────────────────
    triggered_rules: list[dict[str, Any]] = Field(default_factory=list)
    all_rules: list[dict[str, Any]] = Field(default_factory=list)
    score_breakdown: dict[str, int] = Field(default_factory=dict)

    # ── Multi-hop hook ────────────────────────────────────────────────────────
    multihop_addresses: list[str] = Field(
        default_factory=list,
        description=(
            "Addresses extracted from transferOwnership() calls post-deployment. "
            "The investigation system should queue these for their own triage cycle."
        ),
    )

    # ── Narrative context (computed, not a severity trigger) ──────────────────
    narrative: dict[str, Any] = Field(default_factory=dict)

    # ── Summary ───────────────────────────────────────────────────────────────
    @property
    def is_suspicious(self) -> bool:
        return self.verdict not in ("CLEAN", "INSUFFICIENT_DEPLOYMENT_HISTORY")

    @property
    def summary_line(self) -> str:
        triggered = len(self.triggered_rules)
        return (
            f"[{self.verdict}] score={self.score}/100  "
            f"rules_fired={triggered}  "
            f"multihop_targets={len(self.multihop_addresses)}  "
            f"wallet={self.wallet_address}"
        )


def _rule_to_dict(r: RugRuleResult) -> dict[str, Any]:
    return {
        "rule_id": r.rule_id,
        "rule_name": r.rule_name,
        "triggered": r.triggered,
        "severity": r.severity,
        "description": r.description,
        "reasoning": r.reasoning,
        "details": r.details,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Engine
# ─────────────────────────────────────────────────────────────────────────────

class RugpullEngine:
    """
    Stateless orchestrator for the rugpull creator triage pipeline.

    Can be instantiated with a specific RugpullProfileConfig override for
    testing; by default it reads from the application Settings singleton.
    """

    def __init__(self, cfg: Any | None = None) -> None:
        if cfg is None:
            cfg = get_settings().rugpull
        self._cfg = cfg

    def run(self, address: str, raw_data: dict) -> RugpullReport:
        """
        Execute the full triage pipeline for one wallet.

        Args:
            address:  Wallet address (any case — normalised internally).
            raw_data: Dict with "normal_txs" and "internal_txs" lists,
                      as returned by EtherscanClient.

        Returns:
            RugpullReport — fully populated, frozen, serialisable.
        """
        addr = address.lower().strip()

        # ── Step 1: Feature extraction ────────────────────────────────────────
        fv: FeatureVector = extract_features(addr, raw_data)

        # ── Step 2: Rule evaluation ───────────────────────────────────────────
        results: list[RugRuleResult] = evaluate_all(fv, self._cfg)

        # ── Step 3: Scoring ───────────────────────────────────────────────────
        scored: RugpullScore = compute_score(results, self._cfg)

        # ── Step 4: Narrative context (non-trigger features) ──────────────────
        narrative = _build_narrative(fv)

        # ── Step 5: Assemble report ───────────────────────────────────────────
        triggered = [r for r in results if r.triggered]

        return RugpullReport(
            wallet_address=addr,
            analyzed_at=datetime.now(UTC),
            features=fv,
            score=scored.score,
            verdict=scored.verdict,
            override_applied=scored.override_applied,
            triggered_rules=[_rule_to_dict(r) for r in triggered],
            all_rules=[_rule_to_dict(r) for r in results],
            score_breakdown=scored.score_breakdown,
            multihop_addresses=fv.ownership_transfer_targets,
            narrative=narrative,
        )

    def run_batch(
        self,
        wallets: list[tuple[str, dict]],
    ) -> list[RugpullReport]:
        """
        Run triage for multiple wallets.

        Args:
            wallets: List of (address, raw_data) tuples.

        Returns:
            List of RugpullReport in the same order as input.
        """
        return [self.run(addr, raw) for addr, raw in wallets]


# ─────────────────────────────────────────────────────────────────────────────
# Narrative builder
# ─────────────────────────────────────────────────────────────────────────────

def _build_narrative(fv: FeatureVector) -> dict[str, Any]:
    """
    Build a narrative context dict for features that are NOT severity triggers
    but are still useful for human-readable report generation.

    These are computed and reported, but never affect the score or verdict.
    """
    narrative: dict[str, Any] = {}

    # F4 burstiness (narrative — genuine deployers are MORE bursty)
    if fv.f4_burstiness is not None:
        level = "high" if fv.f4_burstiness > 0.1 else "low"
        narrative["burstiness"] = {
            "value": round(fv.f4_burstiness, 4),
            "level": level,
            "note": (
                "Burstiness measures how clustered deployments are in time "
                "(Goh-Barabási parameter, range [-1,+1]). "
                "NOT a severity trigger: genuine professional deployers are "
                "statistically more bursty (median 0.17) than rugpull creators "
                "(median 0.06), so high burstiness actually leans genuine."
            ),
        }

    # F5 nonce entropy (narrative — groups too similar)
    if fv.f5_nonce_entropy is not None:
        narrative["nonce_entropy"] = {
            "value": round(fv.f5_nonce_entropy, 4),
            "note": (
                "Shannon entropy of inter-transaction time gaps (bits). "
                "Low = robotic/scripted, high = human variation. "
                "NOT a primary trigger: rugpull (4.67) and genuine (4.54) "
                "group medians are nearly identical (Δ=0.09 bits). "
                "Only flagged if below 3.0 (rugpull p25=3.85)."
            ),
        }

    # F7 within-wallet similarity (narrative — hypothesis inverted)
    if fv.f7_within_wallet_sim is not None:
        narrative["within_wallet_template_similarity"] = {
            "value": round(fv.f7_within_wallet_sim, 4),
            "note": (
                "Average pairwise Levenshtein similarity of pre-deployment "
                "setup sequences across this wallet's deployments. "
                "NOT a severity trigger: genuine professional deployers score "
                "HIGHER (median 0.28) than rugpull creators (0.19) — "
                "consistent professional toolchains look more similar, not less. "
                "Cross-wallet comparison (vs known rugpull templates in DB) is "
                "the valid use of this signal, handled at runtime."
            ),
        }

    # Funding sources (for NEW-B cross-wallet check at runtime)
    narrative["funding_sources"] = {
        "count": len(fv.all_funding_sources),
        "addresses": fv.all_funding_sources,
        "note": (
            "Unique addresses that sent ETH to this wallet. "
            "Cross-wallet funder check (NEW-B) compares these against the "
            "creator_funding_sources DB table at runtime."
        ),
    }

    return narrative
