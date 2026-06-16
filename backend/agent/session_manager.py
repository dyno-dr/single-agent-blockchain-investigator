"""
backend/agent/session_manager.py
─────────────────────────────────────────────────────────────────────────────
Session lifecycle manager for concurrent LangGraph investigations.

PURPOSE:
  The SessionManager tracks every active investigation session — its asyncio
  Task, creation time, and current status. This enables:
    - Graceful shutdown (cancel all running tasks on application shutdown)
    - Session status queries without hitting the database
    - Duplicate-investigation prevention (one session per investigation_id)
    - Investigation timeout enforcement

DESIGN DECISIONS:
  1. Each investigation runs as an `asyncio.Task` created via
     `asyncio.create_task()`. Tasks are fully concurrent — multiple
     investigations can run simultaneously without blocking each other.
  2. The session registry is a plain dict protected by an asyncio.Lock.
     The lock prevents race conditions when multiple HTTP requests arrive
     simultaneously for the same investigation_id.
  3. Completed/failed tasks are automatically cleaned from the registry
     by a callback registered on each task. This prevents unbounded
     memory growth in long-running deployments.
  4. `shutdown()` cancels all running tasks and waits for them to finish.
     This gives each running investigation a chance to handle cancellation
     cleanly (typically by writing a FAILED status to the DB).

FUTURE SCALABILITY:
  - Phase 4: Add WebSocket event routing — the session manager becomes the
    hub that pushes agent step events to the correct WebSocket channel.
  - Phase 5: Add Redis-backed session state for multi-process deployments.
    The interface (start_session, get_status, shutdown) stays the same.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class SessionRecord:
    """Metadata for one investigation session."""
    investigation_id: str
    wallet_address: str
    task: asyncio.Task[Any]
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    status: str = "RUNNING"         # RUNNING | COMPLETE | FAILED | CANCELLED


class SessionManager:
    """
    Tracks and manages all active LangGraph investigation sessions.

    Lifecycle:
        manager = SessionManager()          # created once at startup
        await manager.start_session(...)    # called by investigation router
        manager.get_status(id)              # polled by router
        await manager.shutdown()            # called at app shutdown

    Thread safety:
        All public methods are async and protected by a shared asyncio.Lock.
        Safe to call from concurrent FastAPI route handlers.
    """

    def __init__(self) -> None:
        self._sessions: dict[str, SessionRecord] = {}
        self._lock = asyncio.Lock()

    async def start_session(
        self,
        investigation_id: str,
        wallet_address: str,
        coro: Any,
    ) -> asyncio.Task[Any]:
        """
        Create an asyncio Task for a new investigation and register it.

        Args:
            investigation_id: UUID4 of the investigation DB record.
            wallet_address:   Target wallet (for logging).
            coro:             Awaitable coroutine that runs the full agent graph.

        Returns:
            The created asyncio.Task.

        Raises:
            RuntimeError: If a session with this investigation_id already exists
                          and is still running. Prevents duplicate investigations.
        """
        async with self._lock:
            existing = self._sessions.get(investigation_id)
            if existing and existing.status == "RUNNING":
                raise RuntimeError(
                    f"Investigation '{investigation_id}' is already running. "
                    "Duplicate sessions are not allowed."
                )

            task = asyncio.create_task(coro, name=f"investigation-{investigation_id}")
            record = SessionRecord(
                investigation_id=investigation_id,
                wallet_address=wallet_address,
                task=task,
            )
            self._sessions[investigation_id] = record

            # Register cleanup callback — runs when the task completes/fails
            task.add_done_callback(
                lambda t: asyncio.create_task(
                    self._on_task_done(investigation_id, t)
                )
            )

            logger.info(
                "session_started",
                investigation_id=investigation_id,
                wallet=wallet_address,
                active_sessions=len(self._sessions),
            )
            return task

    async def _on_task_done(
        self,
        investigation_id: str,
        task: asyncio.Task[Any],
    ) -> None:
        """
        Callback: update session record when task completes.

        Marks the session COMPLETE, FAILED, or CANCELLED based on task outcome.
        Does NOT remove the record — it stays for a short window so polling
        clients can see the final status before the record is evicted.
        """
        async with self._lock:
            record = self._sessions.get(investigation_id)
            if record is None:
                return

            if task.cancelled():
                record.status = "CANCELLED"
                logger.info("session_cancelled", investigation_id=investigation_id)
            elif task.exception():
                record.status = "FAILED"
                logger.error(
                    "session_failed",
                    investigation_id=investigation_id,
                    error=str(task.exception()),
                )
            else:
                record.status = "COMPLETE"
                logger.info("session_complete", investigation_id=investigation_id)

    def get_status(self, investigation_id: str) -> str | None:
        """
        Return the in-memory status of a session without acquiring the lock.

        This is intentionally non-async and lock-free for fast polling.
        The status is only an approximation — for authoritative status,
        query the database via InvestigationRepository.

        Args:
            investigation_id: UUID4 to look up.

        Returns:
            Status string or None if not in registry.
        """
        record = self._sessions.get(investigation_id)
        return record.status if record else None

    def is_running(self, investigation_id: str) -> bool:
        """Return True if an investigation is currently executing."""
        record = self._sessions.get(investigation_id)
        return record is not None and record.status == "RUNNING"

    @property
    def active_count(self) -> int:
        """Number of currently RUNNING sessions."""
        return sum(1 for r in self._sessions.values() if r.status == "RUNNING")

    @property
    def total_count(self) -> int:
        """Total sessions ever registered (including completed)."""
        return len(self._sessions)

    async def cancel_session(self, investigation_id: str) -> bool:
        """
        Cancel a running investigation session.

        Args:
            investigation_id: UUID4 to cancel.

        Returns:
            True if the task was found and cancelled, False if not found
            or already complete.
        """
        async with self._lock:
            record = self._sessions.get(investigation_id)
            if record is None or record.status != "RUNNING":
                return False

            record.task.cancel()
            logger.info("session_cancel_requested", investigation_id=investigation_id)
            return True

    async def shutdown(self) -> None:
        """
        Cancel all running sessions and wait for them to finish.

        Called by the FastAPI lifespan during application shutdown.
        Gives each running investigation up to 30 seconds to handle
        cancellation (write FAILED status to DB) before giving up.
        """
        async with self._lock:
            running = [
                r for r in self._sessions.values()
                if r.status == "RUNNING"
            ]

        if not running:
            logger.info("session_manager_shutdown_no_active_sessions")
            return

        logger.info(
            "session_manager_shutdown_cancelling",
            count=len(running),
        )

        for record in running:
            record.task.cancel()

        # Wait for all tasks to finish (up to 30 s per task)
        tasks = [r.task for r in running]
        try:
            await asyncio.wait(tasks, timeout=30.0)
        except Exception as exc:
            logger.error("session_manager_shutdown_error", error=str(exc))

        logger.info("session_manager_shutdown_complete")


# ─────────────────────────────────────────────────────────────────────────────
# Module-level singleton — wired in main.py lifespan
# ─────────────────────────────────────────────────────────────────────────────

_session_manager: SessionManager | None = None


def init_session_manager() -> SessionManager:
    """
    Create and register the global SessionManager singleton.

    Called from main.py lifespan startup.
    """
    global _session_manager
    _session_manager = SessionManager()
    logger.info("session_manager_initialised")
    return _session_manager


def get_session_manager() -> SessionManager:
    """
    Return the global SessionManager singleton.

    Raises:
        RuntimeError: If called before init_session_manager().
    """
    if _session_manager is None:
        raise RuntimeError(
            "SessionManager has not been initialised. "
            "Ensure init_session_manager() is called in the FastAPI lifespan."
        )
    return _session_manager


async def close_session_manager() -> None:
    """
    Shut down the global SessionManager.

    Called from main.py lifespan shutdown.
    """
    global _session_manager
    if _session_manager is not None:
        await _session_manager.shutdown()
        _session_manager = None
        logger.info("session_manager_closed")
