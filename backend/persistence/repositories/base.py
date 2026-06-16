"""
backend/persistence/repositories/base.py
─────────────────────────────────────────────────────────────────────────────
Abstract base class for all repository objects.

PURPOSE:
  Provides the shared plumbing every repository needs: a reference to the
  aiosqlite connection, a standard row-to-dict conversion, and a reusable
  helper for serialising / deserialising JSON blob columns. Concrete
  repositories inherit from this class and add their domain-specific methods.

DESIGN DECISIONS:
  1. The repository pattern keeps SQL out of route handlers. Each repository
     owns exactly one table and exposes an async interface that returns plain
     Python dicts (not ORM objects). This makes mocking straightforward:
     replace the repository, not the database connection.
  2. `_row_to_dict` converts an aiosqlite.Row (sqlite3.Row) to a plain dict.
     This is necessary because sqlite3.Row is indexable but not a dict, and
     serialising it with json.dumps fails without the conversion.
  3. JSON blob helpers (`_load_json` / `_dump_json`) centralise the pattern of
     "column is TEXT in DB but dict/list in Python". Repositories call these
     rather than scattering json.loads/json.dumps throughout query methods.
  4. `_utc_now` provides a consistent ISO-8601 UTC timestamp string. All
     timestamp columns are TEXT; using a helper ensures uniform formatting
     across every INSERT.
  5. No base SELECT/INSERT/UPDATE/DELETE is provided — column sets differ too
     much across tables to abstract usefully. The base class only provides
     the shared infrastructure, not generic CRUD.

FUTURE SCALABILITY:
  - Add `_begin_transaction()` context manager for multi-step operations that
    must be atomic (e.g., create investigation + create initial evidence).
  - Replace aiosqlite.Connection with asyncpg.Connection when migrating to
    PostgreSQL. Only `_row_to_dict` needs updating (asyncpg Record already
    behaves like a dict).
"""

from __future__ import annotations

from datetime import UTC, datetime
import json
from typing import Any

import aiosqlite
import structlog

logger = structlog.get_logger(__name__)


class BaseRepository:
    """
    Shared base for all persistence repositories.

    All concrete repositories receive an open aiosqlite.Connection via
    dependency injection and delegate every database operation to it.
    No connection management happens inside repositories — that is the
    responsibility of database.py and the FastAPI lifespan.

    Args:
        conn: Open aiosqlite.Connection. Must remain open for the lifetime
              of the repository instance (i.e., the duration of one request).
    """

    def __init__(self, conn: aiosqlite.Connection) -> None:
        self._conn = conn

    # ─────────────────────────────────────────────────────────────────────────
    # Row helpers
    # ─────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _row_to_dict(row: aiosqlite.Row) -> dict[str, Any]:
        """
        Convert an aiosqlite.Row to a plain Python dict.

        aiosqlite sets `row_factory = aiosqlite.Row` so rows support both
        index and column-name access, but they are NOT dicts. This conversion
        is required before json.dumps or dict spreading.

        Args:
            row: A row returned by aiosqlite cursor.fetchone() or fetchall().

        Returns:
            Plain dict mapping column name → value.
        """
        return dict(row)

    @staticmethod
    def _rows_to_dicts(rows: list[aiosqlite.Row]) -> list[dict[str, Any]]:
        """
        Convert a list of aiosqlite.Row objects to a list of plain dicts.

        Args:
            rows: Rows returned by cursor.fetchall().

        Returns:
            List of plain dicts.
        """
        return [dict(row) for row in rows]

    # ─────────────────────────────────────────────────────────────────────────
    # JSON blob helpers
    # ─────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _dump_json(value: Any) -> str | None:
        if value is None:
            return None
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)

    @staticmethod
    def _load_json(value: str | None) -> Any:
        """
        Deserialise a JSON TEXT column value back to a Python object.

        Returns None if value is None or empty string (graceful handling of
        rows inserted without a JSON blob).

        Args:
            value: TEXT column value from SQLite, or None.

        Returns:
            Deserialised Python object, or None.
        """
        if not value:
            return None
        try:
            return json.loads(value)
        except json.JSONDecodeError as exc:
            logger.warning("json_deserialise_failed", error=str(exc), snippet=value[:80])
            return None

    # ─────────────────────────────────────────────────────────────────────────
    # Timestamp helper
    # ─────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _utc_now() -> str:
        """
        Return the current UTC time as an ISO-8601 string with timezone info.

        Format: "YYYY-MM-DDTHH:MM:SS.ffffff+00:00"

        All timestamp columns in the schema are TEXT. Using this helper
        ensures every timestamp is formatted identically and sorts correctly
        as a string (ISO-8601 lexicographic order = chronological order).

        Returns:
            UTC timestamp string.
        """
        return datetime.now(UTC).isoformat()
