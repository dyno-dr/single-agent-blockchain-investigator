-- backend/persistence/migrations/002_evidence_reasoning.sql
-- ─────────────────────────────────────────────────────────────────────────────
-- Adds the `reasoning` column to the evidence table.
--
-- RATIONALE:
--   Phase 3 exposes the full Observation / Evidence / Reasoning triad per
--   finding. The description field holds the Observation; details holds the
--   Evidence; reasoning (this column) holds the forensic "so what" — why the
--   finding is significant for AML / forensic analysis.
--
--   The column was already populated in every RuleResult object but was never
--   persisted to the DB row. This migration adds the missing column so that
--   GET /report/{id} can surface reasoning in every FindingSchema.
-- ─────────────────────────────────────────────────────────────────────────────

ALTER TABLE evidence ADD COLUMN reasoning TEXT;
