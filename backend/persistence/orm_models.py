"""
backend/persistence/orm_models.py
─────────────────────────────────────────────────────────────────────────────
SQLAlchemy Core table definitions for the persistence layer.

PURPOSE:
  Defines every table column, type, constraint, and index used by the
  blockchain investigator. These definitions are the single source of truth
  for the database schema. The SQL migration in 001_initial_schema.sql is
  generated from — and must stay in sync with — these definitions.

DESIGN DECISIONS:
  1. SQLAlchemy Core (Table + Column) is used instead of ORM (declarative
     Base + mapped classes). This keeps the persistence layer thin: no ORM
     session management, no lazy loading surprises, no identity map. aiosqlite
     queries are written as raw parameterised SQL; these Table objects are used
     only for schema definition and introspection.
  2. All primary keys are TEXT (UUID4 strings). SQLite INTEGER PRIMARY KEY
     is auto-increment, which leaks row counts to clients. UUID4 prevents
     enumeration attacks and is portable to PostgreSQL without schema changes.
  3. All timestamps are TEXT in ISO-8601 format with UTC timezone
     ("YYYY-MM-DDTHH:MM:SS.ffffff+00:00"). SQLite has no native TIMESTAMP
     type; storing as TEXT preserves full microsecond precision, is human-
     readable in the DB browser, and sorts lexicographically.
  4. JSON blobs (reasoning_log, findings, graph_data) are stored as TEXT.
     SQLite has no JSON column type. The repositories are responsible for
     json.dumps / json.loads. This keeps the schema agnostic of serialisation
     format and avoids coupling to SQLite's JSON1 extension availability.
  5. Foreign keys reference UUIDs, not integer row IDs, to preserve referential
     integrity across export/import and eventual multi-DB migration.
  6. Indexes are defined for every foreign key column and every column used
     in WHERE clauses by the repository query patterns (wallet_address,
     status, created_at). Over-indexing is intentional for a read-heavy
     forensic workload.

TABLES:
  investigations  — one row per investigation session
  evidence        — one forensic finding per row, FK → investigations
  reports         — one report per investigation, FK → investigations

FUTURE SCALABILITY:
  - Add `reasoning_steps` table when agent memory node ships (Phase 3).
  - Add `graph_snapshots` table when visualization layer ships (Phase 3).
  - Migrate to asyncpg + SQLAlchemy async ORM when moving to PostgreSQL.
    Column types map cleanly: TEXT→VARCHAR/UUID, REAL→NUMERIC, BLOB→BYTEA.
"""

from __future__ import annotations

from sqlalchemy import (
    Column,
    Index,
    Integer,
    MetaData,
    Table,
    Text,
    UniqueConstraint,
)

# ─────────────────────────────────────────────────────────────────────────────
# Metadata registry — all tables registered here
# ─────────────────────────────────────────────────────────────────────────────

metadata = MetaData()


# ─────────────────────────────────────────────────────────────────────────────
# investigations
# ─────────────────────────────────────────────────────────────────────────────

investigations = Table(
    "investigations",
    metadata,
    # ── Identity ──────────────────────────────────────────────────────────────
    Column("id", Text, primary_key=True, comment="UUID4 investigation session ID"),
    Column(
        "wallet_address",
        Text,
        nullable=False,
        comment="EIP-55 checksummed Ethereum address under investigation",
    ),

    # ── Lifecycle ─────────────────────────────────────────────────────────────
    Column(
        "status",
        Text,
        nullable=False,
        default="PENDING",
        comment="InvestigationStatus enum value: PENDING|RUNNING|COMPLETE|FAILED",
    ),
    Column(
        "phase",
        Text,
        nullable=True,
        comment="Current agent Phase enum value (last completed node)",
    ),
    Column(
        "created_at",
        Text,
        nullable=False,
        comment="ISO-8601 UTC timestamp — investigation creation time",
    ),
    Column(
        "started_at",
        Text,
        nullable=True,
        comment="ISO-8601 UTC timestamp — agent execution start",
    ),
    Column(
        "completed_at",
        Text,
        nullable=True,
        comment="ISO-8601 UTC timestamp — terminal state reached",
    ),

    # ── Request parameters ────────────────────────────────────────────────────
    Column(
        "depth",
        Integer,
        nullable=False,
        default=2,
        comment="Trace depth requested (1–3)",
    ),
    Column(
        "lookback_days",
        Integer,
        nullable=False,
        default=90,
        comment="Transaction lookback window in days",
    ),
    Column(
        "max_transactions",
        Integer,
        nullable=False,
        default=500,
        comment="Maximum transactions to fetch per wallet",
    ),

    # ── Risk assessment ───────────────────────────────────────────────────────
    Column(
        "risk_score",
        Text,
        nullable=True,
        comment="Computed risk score as decimal string (0.0–100.0)",
    ),
    Column(
        "risk_level",
        Text,
        nullable=True,
        comment="RiskLevel enum: LOW|MEDIUM|HIGH|CRITICAL",
    ),

    # ── Agent output blobs ────────────────────────────────────────────────────
    Column(
        "reasoning_log",
        Text,
        nullable=True,
        comment="JSON array of ActionType-tagged reasoning steps from MEMORY node",
    ),
    Column(
        "error_message",
        Text,
        nullable=True,
        comment="Human-readable failure reason; populated on FAILED status",
    ),
    Column(
        "error_code",
        Text,
        nullable=True,
        comment="ErrorCode enum value; populated on FAILED status",
    ),

    # ── Metadata ──────────────────────────────────────────────────────────────
    Column(
        "chain",
        Text,
        nullable=False,
        default="ETHEREUM",
        comment="Chain enum value — always ETHEREUM in Phase 1",
    ),
    Column(
        "request_id",
        Text,
        nullable=True,
        comment="HTTP request_id from RequestIDMiddleware for log correlation",
    ),
)

# Query-pattern indexes for investigations
Index("ix_investigations_wallet_address", investigations.c.wallet_address)
Index("ix_investigations_status", investigations.c.status)
Index("ix_investigations_created_at", investigations.c.created_at)
Index("ix_investigations_risk_level", investigations.c.risk_level)


# ─────────────────────────────────────────────────────────────────────────────
# evidence
# ─────────────────────────────────────────────────────────────────────────────

evidence = Table(
    "evidence",
    metadata,
    # ── Identity ──────────────────────────────────────────────────────────────
    Column("id", Text, primary_key=True, comment="UUID4 evidence item ID"),
    Column(
        "investigation_id",
        Text,
        nullable=False,
        comment="FK → investigations.id",
    ),

    # ── Rule identification ───────────────────────────────────────────────────
    Column(
        "rule_id",
        Text,
        nullable=False,
        comment="Forensic rule identifier: RULE-001 through RULE-007",
    ),
    Column(
        "rule_name",
        Text,
        nullable=False,
        comment="Human-readable rule name for display",
    ),
    Column(
        "rule_category",
        Text,
        nullable=True,
        comment="RuleCategory enum: VOLUME|TIMING|PATTERN|COUNTERPARTY",
    ),

    # ── Finding ───────────────────────────────────────────────────────────────
    Column(
        "severity",
        Text,
        nullable=False,
        comment="Severity enum: LOW|MEDIUM|HIGH|CRITICAL",
    ),
    Column(
        "description",
        Text,
        nullable=False,
        comment="Human-readable description of what was detected",
    ),
    Column(
        "details",
        Text,
        nullable=True,
        comment="JSON object with rule-specific evidence details",
    ),

    # ── Transaction context ───────────────────────────────────────────────────
    Column(
        "wallet_address",
        Text,
        nullable=False,
        comment="Wallet address the finding applies to (may differ from root wallet)",
    ),
    Column(
        "tx_hash",
        Text,
        nullable=True,
        comment="0x-prefixed transaction hash if finding is tx-specific",
    ),
    Column(
        "block_number",
        Integer,
        nullable=True,
        comment="Block number of the triggering transaction",
    ),
    Column(
        "value_eth",
        Text,
        nullable=True,
        comment="ETH value involved as decimal string (avoids float precision loss)",
    ),

    # ── Timestamps ────────────────────────────────────────────────────────────
    Column(
        "detected_at",
        Text,
        nullable=False,
        comment="ISO-8601 UTC timestamp when rule fired",
    ),
)

# Query-pattern indexes for evidence
Index("ix_evidence_investigation_id", evidence.c.investigation_id)
Index("ix_evidence_rule_id", evidence.c.rule_id)
Index("ix_evidence_severity", evidence.c.severity)
Index("ix_evidence_wallet_address", evidence.c.wallet_address)
Index("ix_evidence_tx_hash", evidence.c.tx_hash)


# ─────────────────────────────────────────────────────────────────────────────
# reports
# ─────────────────────────────────────────────────────────────────────────────

reports = Table(
    "reports",
    metadata,
    # ── Identity ──────────────────────────────────────────────────────────────
    Column("id", Text, primary_key=True, comment="UUID4 report ID"),
    Column(
        "investigation_id",
        Text,
        nullable=False,
        comment="FK → investigations.id (one report per investigation)",
    ),

    # ── Report content ────────────────────────────────────────────────────────
    Column(
        "title",
        Text,
        nullable=False,
        comment="Generated report title",
    ),
    Column(
        "summary",
        Text,
        nullable=False,
        comment="LLM-generated executive summary paragraph",
    ),
    Column(
        "findings_json",
        Text,
        nullable=False,
        comment="JSON array of structured finding objects",
    ),
    Column(
        "recommendations_json",
        Text,
        nullable=True,
        comment="JSON array of recommendation strings",
    ),
    Column(
        "graph_data",
        Text,
        nullable=True,
        comment="JSON object with nodes + edges for visualization layer",
    ),

    # ── Risk summary ──────────────────────────────────────────────────────────
    Column(
        "risk_score",
        Text,
        nullable=False,
        comment="Final risk score as decimal string",
    ),
    Column(
        "risk_level",
        Text,
        nullable=False,
        comment="RiskLevel enum: LOW|MEDIUM|HIGH|CRITICAL",
    ),
    Column(
        "evidence_count",
        Integer,
        nullable=False,
        default=0,
        comment="Total number of evidence items in this report",
    ),

    # ── Metadata ──────────────────────────────────────────────────────────────
    Column(
        "generated_at",
        Text,
        nullable=False,
        comment="ISO-8601 UTC timestamp when report was generated",
    ),
    Column(
        "model_used",
        Text,
        nullable=True,
        comment="LLM model string used to generate the summary",
    ),

    # Each investigation can have at most one report
    UniqueConstraint("investigation_id", name="uq_reports_investigation_id"),
)

# Query-pattern indexes for reports
Index("ix_reports_investigation_id", reports.c.investigation_id)
Index("ix_reports_risk_level", reports.c.risk_level)
Index("ix_reports_generated_at", reports.c.generated_at)
