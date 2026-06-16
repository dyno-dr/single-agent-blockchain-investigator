"""
backend/api/routers/investigation.py
─────────────────────────────────────────────────────────────────────────────
POST /investigate — start a new investigation
GET  /investigate/{investigation_id} — poll investigation status

Phase 3: background task calls the LangGraph agent via SessionManager.
"""

from __future__ import annotations

from typing import Annotated, Any

import aiosqlite
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
import structlog

from backend.constants import ErrorCode, InvestigationStatus
from backend.dependencies import AuthDep, HttpClientDep, RateLimiterDep, SettingsDep
from backend.exceptions import EtherscanException
from backend.persistence.database import get_db
from backend.persistence.repositories import InvestigationRepository
from backend.schemas.request import InvestigationRequest
from backend.schemas.response import InvestigationResponse

logger = structlog.get_logger(__name__)

router = APIRouter(tags=["Investigation"])

DbDep = Annotated[aiosqlite.Connection, Depends(get_db)]


# ─────────────────────────────────────────────────────────────────────────────
# POST /investigate
# ─────────────────────────────────────────────────────────────────────────────


@router.post(
    "/investigate",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=InvestigationResponse,
    summary="Start a new wallet investigation",
    description=(
        "Starts an asynchronous forensic investigation of the given Ethereum wallet. "
        "Returns 202 immediately with the investigation ID. "
        "Poll GET /investigate/{id} to track status."
    ),
)
async def start_investigation(
    body: InvestigationRequest,
    background_tasks: BackgroundTasks,
    settings: SettingsDep,
    http_client: HttpClientDep,
    rate_limiter: RateLimiterDep,
    db: DbDep,
    _auth: AuthDep,
) -> InvestigationResponse:
    repo = InvestigationRepository(db)

    row = await repo.create(
        wallet_address=body.wallet_address,
        depth=body.depth,
        lookback_days=body.lookback_days,
        max_transactions=body.max_transactions,
    )

    investigation_id = row["id"]

    logger.info(
        "investigation_created",
        investigation_id=investigation_id,
        wallet=body.wallet_address,
        depth=body.depth,
        lookback_days=body.lookback_days,
    )

    # Build the coroutine now (while we still have all dependencies in scope)
    # and hand it to SessionManager as a task.
    coro = _run_agent(
        investigation_id=investigation_id,
        wallet=body.wallet_address,
        depth=body.depth,
        lookback_days=body.lookback_days,
        max_transactions=body.max_transactions,
        http_client=http_client,
        rate_limiter=rate_limiter,
        settings=settings,
    )

    from backend.agent.session_manager import get_session_manager
    session_manager = get_session_manager()
    await session_manager.start_session(
        investigation_id=investigation_id,
        wallet_address=body.wallet_address,
        coro=coro,
    )

    return InvestigationResponse(**row)


# ─────────────────────────────────────────────────────────────────────────────
# GET /investigate/{investigation_id}
# ─────────────────────────────────────────────────────────────────────────────


@router.get(
    "/investigate/{investigation_id}",
    response_model=InvestigationResponse,
    summary="Get investigation status",
    description="Returns the current state of an investigation by ID.",
    responses={404: {"description": "Investigation not found."}},
)
async def get_investigation(
    investigation_id: str,
    db: DbDep,
    _auth: AuthDep,
) -> InvestigationResponse:
    repo = InvestigationRepository(db)
    row = await repo.get(investigation_id)

    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{investigation_id}' not found.",
        )

    return InvestigationResponse(**row)


# ─────────────────────────────────────────────────────────────────────────────
# Agent coroutine — runs inside the asyncio.Task created by SessionManager
# ─────────────────────────────────────────────────────────────────────────────


async def _run_agent(
    investigation_id: str,
    wallet: str,
    depth: int,
    lookback_days: int,
    max_transactions: int,
    http_client: Any,
    rate_limiter: Any,
    settings: Any,
) -> None:
    """
    Full LangGraph agent pipeline. Runs as an asyncio.Task inside SessionManager.

    Builds the initial AgentState, invokes the compiled graph, then
    persists the final risk score and status to the database.

    NOTE: Report persistence (the `reports` table row) is handled inside
    the LangGraph graph by memory_node, which performs an existence check
    before INSERT. Do NOT duplicate report_repo.create() here — doing so
    raises RepositoryException("A report already exists...") because
    memory_node already inserted the row by the time ainvoke() returns.
    """
    from backend.agent.graph import investigation_graph
    from backend.persistence.database import get_db_direct

    db = None
    try:
        db = await get_db_direct()
        repo = InvestigationRepository(db)

        # Mark RUNNING
        await repo.update_status(
            investigation_id,
            status=InvestigationStatus.RUNNING.value,
        )
        await repo.update_phase(investigation_id, phase="INIT")

        # Build initial AgentState
        initial_state = {
            "investigation_id": investigation_id,
            "wallet_address": wallet,
            "depth": depth,
            "lookback_days": lookback_days,
            "max_transactions": max_transactions,
            "settings": settings,
            "http_client": http_client,
            "rate_limiter": rate_limiter,
            # Agent-managed fields
            "wallet_profiles": {},
            "forensics_reports": {},
            "traced_wallets": [],
            "wallets_to_trace": [],
            "graph_nodes": [],
            "graph_edges": [],
            "reasoning_log": [],
            "errors": [],
            "current_phase": "INIT",
            "trace_strategy": "FORWARD_ONLY",
            "trace_candidates": [],
            "risk_score": 0.0,
            "risk_level": "LOW",
            "report_title": "",
            "report_summary": "",
            "report_findings": [],
            "report_recommendations": [],
        }

        logger.info(
            "agent_graph_start",
            investigation_id=investigation_id,
            wallet=wallet,
            depth=depth,
        )

        # Run the LangGraph graph
        final_state = await investigation_graph.ainvoke(initial_state)

        # Extract results
        risk_score = float(final_state.get("risk_score", 0.0))
        risk_level = str(final_state.get("risk_level", "LOW"))
        report_findings = final_state.get("report_findings", [])

        # Mark COMPLETE
        await repo.update_status(
            investigation_id,
            status=InvestigationStatus.COMPLETE.value,
            risk_score=risk_score,
            risk_level=risk_level,
        )
        await repo.update_phase(investigation_id, phase="DONE")

        logger.info(
            "agent_graph_complete",
            investigation_id=investigation_id,
            wallet=wallet,
            risk_score=risk_score,
            risk_level=risk_level,
            findings=len(report_findings),
        )

    except EtherscanException as exc:
        logger.error(
            "investigation_etherscan_error",
            investigation_id=investigation_id,
            wallet=wallet,
            error_code=exc.error_code.value,
            message=exc.message,
        )
        if db:
            repo = InvestigationRepository(db)
            await repo.mark_failed(
                investigation_id,
                error_message=exc.message,
                error_code=exc.error_code.value,
            )

    except Exception as exc:
        logger.exception(
            "investigation_unexpected_error",
            investigation_id=investigation_id,
            wallet=wallet,
        )
        if db:
            repo = InvestigationRepository(db)
            await repo.mark_failed(
                investigation_id,
                error_message=f"Unexpected error: {type(exc).__name__}: {exc}",
                error_code=ErrorCode.INTERNAL_ERROR.value,
            )

    finally:
        if db:
            try:
                await db.close()
            except Exception:
                pass


# Backward compatibility: tests patch the legacy investigation pipeline entry point.
# The router now uses _run_agent internally, but the old module-level symbol is
# preserved so tests that patch backend.api.routers.investigation._run_investigation_pipeline
# continue to work without change.
_run_investigation_pipeline = _run_agent
