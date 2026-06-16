"""
backend/persistence/database.py
─────────────────────────────────────────────────────────────────────────────
aiosqlite database setup, connection management, and lifespan integration.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
import os
from pathlib import Path

import aiosqlite
import structlog

from backend.settings import get_settings

logger = structlog.get_logger(__name__)

# Module-level connection singleton
_db: aiosqlite.Connection | None = None


# ─────────────────────────────────────────────────────────────────────────────
# PRAGMA helpers
# ─────────────────────────────────────────────────────────────────────────────

async def _apply_pragmas(conn: aiosqlite.Connection, is_memory: bool) -> None:
    settings = get_settings()

    if not is_memory:
        await conn.execute("PRAGMA journal_mode = WAL;")

    await conn.execute(f"PRAGMA busy_timeout = {settings.db.busy_timeout_ms};")
    await conn.execute("PRAGMA synchronous = NORMAL;")
    await conn.execute("PRAGMA foreign_keys = ON;")
    await conn.execute("PRAGMA temp_store = MEMORY;")
    await conn.commit()

    if not is_memory:
        async with conn.execute("PRAGMA journal_mode;") as cursor:
            row = await cursor.fetchone()
            mode = row[0] if row else "unknown"
            if mode != "wal":
                logger.warning("wal_mode_not_active", actual_mode=mode)
            else:
                logger.debug("wal_mode_confirmed")


# ─────────────────────────────────────────────────────────────────────────────
# Schema migration runner
# ─────────────────────────────────────────────────────────────────────────────

async def _run_migrations(conn: aiosqlite.Connection) -> None:
    await conn.execute("""
        CREATE TABLE IF NOT EXISTS schema_version (
            version     TEXT    PRIMARY KEY,
            applied_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            description TEXT
        );
    """)
    await conn.commit()

    migrations_dir = Path(__file__).parent / "migrations"
    if not migrations_dir.exists():
        logger.warning("migrations_directory_not_found", path=str(migrations_dir))
        return

    sql_files = sorted(
        f for f in migrations_dir.iterdir()
        if f.suffix == ".sql" and not f.name.startswith("_")
    )

    if not sql_files:
        logger.debug("no_migration_scripts_found")
        return

    async with conn.execute("SELECT version FROM schema_version;") as cursor:
        applied = {row[0] for row in await cursor.fetchall()}

    for sql_file in sql_files:
        version = sql_file.stem
        if version in applied:
            logger.debug("migration_already_applied", version=version)
            continue

        logger.info("applying_migration", version=version)
        sql = sql_file.read_text(encoding="utf-8")

        try:
            await conn.executescript(sql)
            await conn.execute(
                "INSERT INTO schema_version (version, description) VALUES (?, ?);",
                (version, sql_file.name),
            )
            await conn.commit()
            logger.info("migration_applied", version=version)
        except Exception as exc:
            logger.error("migration_failed", version=version, error=str(exc))
            raise


# ─────────────────────────────────────────────────────────────────────────────
# Lifecycle functions  (called from backend/main.py lifespan)
# ─────────────────────────────────────────────────────────────────────────────

async def init_db() -> None:
    global _db

    if _db is not None:
        raise RuntimeError("init_db() called but a connection is already open.")

    settings = get_settings()
    db_path = settings.database_url
    is_memory = db_path == ":memory:"

    if not is_memory:
        data_dir = os.path.dirname(db_path)
        if data_dir:
            os.makedirs(data_dir, exist_ok=True)

    logger.info("database_opening", path=db_path if not is_memory else ":memory:")

    _db = await aiosqlite.connect(db_path)
    _db.row_factory = aiosqlite.Row

    await _apply_pragmas(_db, is_memory=is_memory)
    await _run_migrations(_db)

    logger.info("database_ready", path=db_path if not is_memory else ":memory:")


async def close_db() -> None:
    global _db

    if _db is None:
        logger.warning("close_db_called_but_no_connection_open")
        return

    await _db.close()
    _db = None
    logger.info("database_closed")


# ─────────────────────────────────────────────────────────────────────────────
# FastAPI dependency  — async generator, used with Depends()
# ─────────────────────────────────────────────────────────────────────────────

async def get_db() -> AsyncIterator[aiosqlite.Connection]:
    """Yield the shared connection for FastAPI route handlers."""
    if _db is None:
        raise RuntimeError(
            "Database not initialised. Ensure init_db() is called in lifespan."
        )
    yield _db


# ─────────────────────────────────────────────────────────────────────────────
# Direct accessor — sync, for agent nodes that already have a live app context
# ─────────────────────────────────────────────────────────────────────────────

def get_db_conn() -> aiosqlite.Connection:
    """
    Return the live singleton connection directly (not as an async generator).

    Use in agent nodes and tools that cannot use FastAPI Depends().
    Different name from get_db() to avoid Python overwriting the generator.
    """
    if _db is None:
        raise RuntimeError(
            "Database not initialised. Ensure init_db() is called before use."
        )
    return _db


# ─────────────────────────────────────────────────────────────────────────────
# Background task helper — opens its OWN connection (for background tasks)
# ─────────────────────────────────────────────────────────────────────────────

async def get_db_direct() -> aiosqlite.Connection:
    """
    Open a fresh aiosqlite connection for background tasks.

    Background tasks run outside the FastAPI request lifecycle so they
    cannot use Depends(get_db). This opens an independent connection,
    applies PRAGMAs, and returns it. The caller MUST close it:

        db = await get_db_direct()
        try:
            ...
        finally:
            await db.close()
    """
    settings = get_settings()
    db_url = settings.database_url
    is_memory = db_url == ":memory:"

    conn = await aiosqlite.connect(db_url)
    conn.row_factory = aiosqlite.Row
    await _apply_pragmas(conn, is_memory)
    return conn
