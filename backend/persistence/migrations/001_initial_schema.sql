-- backend/persistence/migrations/001_initial_schema.sql
-- ─────────────────────────────────────────────────────────────────────────────
-- Initial database schema: investigations, evidence, reports.
--
-- DESIGN NOTES:
--   - All PKs are TEXT (UUID4) — no auto-increment integer leakage.
--   - All timestamps are TEXT ISO-8601 UTC — SQLite has no TIMESTAMP type.
--   - JSON blobs stored as TEXT; deserialization handled in repositories.
--   - Foreign key constraints declared; enforcement requires PRAGMA foreign_keys=ON
--     which is set at connection init in database.py.
--   - schema_version tracking is managed by database.py; this file is applied
--     exactly once and its filename stem recorded as the version key.
-- ─────────────────────────────────────────────────────────────────────────────

-- ─────────────────────────────────────────────────────────────────────────────
-- investigations
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS investigations (
    -- Identity
    id                  TEXT    PRIMARY KEY,
    wallet_address      TEXT    NOT NULL,

    -- Lifecycle
    status              TEXT    NOT NULL DEFAULT 'PENDING',
    phase               TEXT,
    created_at          TEXT    NOT NULL,
    started_at          TEXT,
    completed_at        TEXT,

    -- Request parameters
    depth               INTEGER NOT NULL DEFAULT 2,
    lookback_days       INTEGER NOT NULL DEFAULT 90,
    max_transactions    INTEGER NOT NULL DEFAULT 500,

    -- Risk assessment
    risk_score          TEXT,
    risk_level          TEXT,

    -- Agent output blobs
    reasoning_log       TEXT,
    error_message       TEXT,
    error_code          TEXT,

    -- Metadata
    chain               TEXT    NOT NULL DEFAULT 'ETHEREUM',
    request_id          TEXT,

    -- Constraints
    CHECK (status IN ('PENDING', 'RUNNING', 'COMPLETE', 'FAILED')),
    CHECK (risk_level IS NULL OR risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    CHECK (depth BETWEEN 1 AND 3)
);

CREATE INDEX IF NOT EXISTS ix_investigations_wallet_address
    ON investigations (wallet_address);

CREATE INDEX IF NOT EXISTS ix_investigations_status
    ON investigations (status);

CREATE INDEX IF NOT EXISTS ix_investigations_created_at
    ON investigations (created_at);

CREATE INDEX IF NOT EXISTS ix_investigations_risk_level
    ON investigations (risk_level);


-- ─────────────────────────────────────────────────────────────────────────────
-- evidence
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS evidence (
    -- Identity
    id                  TEXT    PRIMARY KEY,
    investigation_id    TEXT    NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,

    -- Rule identification
    rule_id             TEXT    NOT NULL,
    rule_name           TEXT    NOT NULL,
    rule_category       TEXT,

    -- Finding
    severity            TEXT    NOT NULL,
    description         TEXT    NOT NULL,
    details             TEXT,

    -- Transaction context
    wallet_address      TEXT    NOT NULL,
    tx_hash             TEXT,
    block_number        INTEGER,
    value_eth           TEXT,

    -- Timestamps
    detected_at         TEXT    NOT NULL,

    -- Constraints
    CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'))
);

CREATE INDEX IF NOT EXISTS ix_evidence_investigation_id
    ON evidence (investigation_id);

CREATE INDEX IF NOT EXISTS ix_evidence_rule_id
    ON evidence (rule_id);

CREATE INDEX IF NOT EXISTS ix_evidence_severity
    ON evidence (severity);

CREATE INDEX IF NOT EXISTS ix_evidence_wallet_address
    ON evidence (wallet_address);

CREATE INDEX IF NOT EXISTS ix_evidence_tx_hash
    ON evidence (tx_hash);


-- ─────────────────────────────────────────────────────────────────────────────
-- reports
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS reports (
    -- Identity
    id                      TEXT    PRIMARY KEY,
    investigation_id        TEXT    NOT NULL UNIQUE
                                    REFERENCES investigations(id) ON DELETE CASCADE,

    -- Report content
    title                   TEXT    NOT NULL,
    summary                 TEXT    NOT NULL,
    findings_json           TEXT    NOT NULL,
    recommendations_json    TEXT,
    graph_data              TEXT,

    -- Risk summary
    risk_score              TEXT    NOT NULL,
    risk_level              TEXT    NOT NULL,
    evidence_count          INTEGER NOT NULL DEFAULT 0,

    -- Metadata
    generated_at            TEXT    NOT NULL,
    model_used              TEXT,

    -- Constraints
    CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'))
);

CREATE INDEX IF NOT EXISTS ix_reports_investigation_id
    ON reports (investigation_id);

CREATE INDEX IF NOT EXISTS ix_reports_risk_level
    ON reports (risk_level);

CREATE INDEX IF NOT EXISTS ix_reports_generated_at
    ON reports (generated_at);