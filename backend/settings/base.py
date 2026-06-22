"""
backend/settings/base.py
─────────────────────────────────────────────────────────────────────────────
Typed application configuration using pydantic-settings.

PURPOSE:
  Single source of truth for all runtime configuration. Every tunable
  parameter in the architecture spec maps to a typed, validated field here.
  No magic strings scattered across the codebase.

DESIGN DECISIONS:
  1. pydantic-settings reads from environment variables and .env files
     automatically, with full type coercion and validation.
  2. Settings is partitioned into nested sub-models (AppSettings,
     EtherscanSettings, etc.) for clarity and forward compatibility.
     When the multi-agent framework arrives, new agent-specific sub-models
     slot in without touching existing fields.
  3. `get_settings()` is cached via @lru_cache — the Settings object is
     constructed exactly once per process, making it safe to call anywhere
     without performance cost.
  4. All secrets (API keys, secret key) have `repr=False` to prevent
     accidental logging of sensitive values.
  5. Validator for CORS_ORIGINS handles both JSON arrays and
     comma-separated strings, since both forms appear in .env files.

BUG FIX (database_url):
  The original database_url property checked os.path.isabs(path). For the
  special SQLite in-memory path ":memory:", os.path.isabs(":memory:") returns
  False, causing it to be joined with the project root, yielding a broken path
  like "/project/root/:memory:" instead of ":memory:". This made init_db()'s
  is_memory check fail and would attempt to open a literal file named ":memory:".
  Fixed by short-circuiting the property to return ":memory:" immediately when
  that exact string is the configured path.

BUG FIX (nested sub-model .env loading):
  pydantic-settings v2 does NOT automatically propagate the parent Settings'
  `env_file` to nested BaseSettings sub-models constructed via
  `Field(default_factory=SubModel)`. Each sub-model is its own independent
  BaseSettings and only reads real OS environment variables unless its own
  model_config also specifies `env_file=".env"`. Previously, only the root
  Settings class had `env_file=".env"`, so every sub-model (EtherscanSettings,
  LLMSettings, etc.) silently fell back to field defaults for any value not
  also present as a real OS environment variable — e.g. ETHERSCAN_API_KEY and
  GOOGLE_API_KEY resolved to "not-configured" even though .env had real values.
  Fixed by adding `env_file=".env", env_file_encoding="utf-8"` to every
  sub-model's model_config.

FUTURE SCALABILITY:
  - Add PostgresDatabaseSettings when migrating from SQLite.
  - Add RedisSettings when adding shared agent context (Phase 2+).
  - Add MultiChainSettings when adding cross-chain support (Phase 3+).
  - The nested model pattern keeps each expansion isolated.
"""

from __future__ import annotations

from functools import lru_cache
import os
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# ─────────────────────────────────────────────────────────────────────────────
# Sub-models: partitioned by concern
# ─────────────────────────────────────────────────────────────────────────────


class AppSettings(BaseSettings):
    """Core application identity and runtime mode."""

    model_config = SettingsConfigDict(
        env_prefix="APP_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    name: str = Field(
        default="Single-Agent Blockchain Investigator",
        description="Human-readable application name.",
    )
    version: str = Field(
        default="1.0.0",
        description="Semantic version string; injected into /health and /version responses.",
    )
    env: str = Field(
        default="development",
        pattern="^(development|staging|production)$",
        description="Runtime environment: development | staging | production.",
    )
    debug: bool = Field(
        default=False,
        description="Enable debug mode. Never True in production.",
    )


class APISettings(BaseSettings):
    """FastAPI server binding and access control configuration."""

    model_config = SettingsConfigDict(
        env_prefix="API_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    host: str = Field(default="0.0.0.0")
    port: int = Field(default=8000, ge=1, le=65535)
    reload: bool = Field(
        default=False,
        description="uvicorn --reload flag. True in development only.",
    )
    workers: int = Field(
        default=1,
        ge=1,
        description="Number of uvicorn workers. Keep at 1 for SQLite safety.",
    )
    prefix: str = Field(
        default="/api/v1",
        description="Global API path prefix for all versioned routes.",
    )
    key: str = Field(
        default="dev-api-key-change-in-production",
        repr=False,
        description="X-API-Key header value. Lightweight auth for research use.",
    )


class CORSSettings(BaseSettings):
    """Cross-Origin Resource Sharing configuration."""

    model_config = SettingsConfigDict(
        env_prefix="CORS_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    origins: Any = Field(
        default=["http://localhost:5173", "http://localhost:3000"],
        description="Allowed origins. Comma-separated string or JSON array in env.",
    )
    allow_credentials: bool = Field(default=True)

    @field_validator("origins", mode="before")
    @classmethod
    def parse_origins(cls, v: Any) -> list[str]:
        """Accept both JSON arrays and comma-separated strings from .env."""
        if isinstance(v, str):
            if v.strip().startswith("["):
                import json
                return json.loads(v)
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        return v


class EtherscanSettings(BaseSettings):
    """Etherscan API client configuration."""

    model_config = SettingsConfigDict(
        env_prefix="ETHERSCAN_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    api_key: str = Field(
        default="not-configured",
        repr=False,
        description="Etherscan API key. Obtain from etherscan.io/myapikey.",
    )
    base_url: str = Field(
        default="https://api.etherscan.io/v2/api",
        description="Etherscan API base URL (v2). Override for testnets.",
    )
    timeout_seconds: int = Field(default=30, ge=5, le=120)
    max_retries: int = Field(default=3, ge=1, le=5)
    retry_backoff_base: float = Field(
        default=1.0,
        ge=0.1,
        description="Base seconds for exponential backoff (1s, 2s, 4s).",
    )


class RateLimiterSettings(BaseSettings):
    """AsyncTokenBucket rate limiter configuration."""

    model_config = SettingsConfigDict(
        env_prefix="RATE_LIMIT_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    requests_per_second: float = Field(
        default=4.5,
        gt=0.0,
        le=10.0,
        description="Sustained request rate. 10% below Etherscan free tier (5/s).",
    )
    burst_capacity: int = Field(
        default=5,
        ge=1,
        description="Token bucket capacity for absorbing short bursts.",
    )


class LLMSettings(BaseSettings):
    """Google Gemini LLM configuration."""

    model_config = SettingsConfigDict(
        env_prefix="GEMINI_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    api_key: str = Field(
        default="not-configured",
        repr=False,
        description="Google AI Studio API key.",
    )
    model: str = Field(
        default="gemini-2.0-flash",
        description="Gemini model ID.",
    )
    max_tokens: int = Field(default=8192, ge=256, le=32768)
    temperature: float = Field(
        default=0.1,
        ge=0.0,
        le=1.0,
    )
    google_api_key: str = Field(
        default="not-configured",
        repr=False,
        alias="GOOGLE_API_KEY",
        description="Alias — Google SDK reads this env var automatically.",
    )


class DatabaseSettings(BaseSettings):
    """SQLite + aiosqlite persistence configuration."""

    model_config = SettingsConfigDict(
        env_prefix="DATABASE_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    path: str = Field(
        default="data/investigations.db",
        description="Path to SQLite DB file. Use ':memory:' for in-memory (tests).",
    )
    wal_mode: bool = Field(
        default=True,
        description="Enable WAL journal mode to prevent 'database is locked' errors.",
    )
    busy_timeout_ms: int = Field(
        default=5000,
        ge=100,
        description="PRAGMA busy_timeout in milliseconds.",
    )
    pool_size: int = Field(
        default=5,
        ge=1,
        description="aiosqlite connection pool size (future).",
    )


class InvestigationDefaults(BaseSettings):
    """Default parameters for investigation requests."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    DEFAULT_INVESTIGATION_DEPTH: int = Field(default=2, ge=1, le=3)
    DEFAULT_LOOKBACK_DAYS: int = Field(default=90, ge=1)
    DEFAULT_MAX_TRANSACTIONS: int = Field(default=500, ge=10)
    DEFAULT_FLAG_THRESHOLD_ETH: float = Field(default=10.0, gt=0.0)
    DEFAULT_MIN_TRACE_VALUE_ETH: float = Field(default=0.05, gt=0.0)
    DEFAULT_MAX_TRACE_NODES: int = Field(default=500, ge=10)
    DEFAULT_MAX_FAN_OUT_PER_NODE: int = Field(default=50, ge=5)
    MAX_TRANSACTIONS_HARD_CAP: int = Field(default=1000, ge=100)


class TraceScoringWeights(BaseSettings):
    """Layer 1 TraceScorer weight configuration."""

    model_config = SettingsConfigDict(
        env_prefix="TRACE_WEIGHT_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    value: float = Field(default=0.30, ge=0.0, le=1.0)
    recency: float = Field(default=0.20, ge=0.0, le=1.0)
    novelty: float = Field(default=0.30, ge=0.0, le=1.0)
    rule: float = Field(default=0.20, ge=0.0, le=1.0)

    @model_validator(mode="after")
    def weights_sum_to_one(self) -> TraceScoringWeights:
        total = self.value + self.recency + self.novelty + self.rule
        if abs(total - 1.0) > 0.001:
            raise ValueError(
                f"Trace scoring weights must sum to 1.0. Got {total:.3f}. "
                f"Adjust TRACE_WEIGHT_* in .env."
            )
        return self


class RiskScoringConfig(BaseSettings):
    """RiskScorer severity weight and threshold configuration."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    RISK_WEIGHT_CRITICAL: float = Field(default=40.0, gt=0.0)
    RISK_WEIGHT_HIGH: float = Field(default=20.0, gt=0.0)
    RISK_WEIGHT_MEDIUM: float = Field(default=10.0, gt=0.0)
    RISK_WEIGHT_LOW: float = Field(default=5.0, gt=0.0)

    RISK_THRESHOLD_CRITICAL: float = Field(default=80.0, ge=0.0, le=100.0)
    RISK_THRESHOLD_HIGH: float = Field(default=50.0, ge=0.0, le=100.0)
    RISK_THRESHOLD_MEDIUM: float = Field(default=25.0, ge=0.0, le=100.0)


class ForensicRulesConfig(BaseSettings):
    """Per-rule configurable thresholds for the forensics engine."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    RULE_001_LARGE_TRANSFER_ETH: float = Field(default=10.0, gt=0.0)
    RULE_002_RAPID_SUCCESSION_TX_COUNT: int = Field(default=5, ge=2)
    RULE_002_RAPID_SUCCESSION_WINDOW_SECONDS: int = Field(default=300, ge=10)
    RULE_003_HIGH_FANOUT_UNIQUE_ADDRESSES: int = Field(default=20, ge=5)
    RULE_004_DORMANCY_THRESHOLD_DAYS: int = Field(default=180, ge=30)
    RULE_004_ACTIVATION_WINDOW_HOURS: int = Field(default=48, ge=1)
    RULE_005_BURST_MULTIPLIER: float = Field(default=3.0, ge=1.5)
    RULE_005_ROLLING_WINDOW_DAYS: int = Field(default=30, ge=7)
    RULE_006_ROUND_NUMBER_MIN_OCCURRENCES: int = Field(default=3, ge=2)
    RULE_007_NEW_WALLET_AGE_HOURS: int = Field(default=24, ge=1)


class SessionSettings(BaseSettings):
    """Session lifecycle and WebSocket configuration."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    SESSION_TIMEOUT_SECONDS: int = Field(default=3600, ge=60)
    WS_PING_INTERVAL_SECONDS: int = Field(default=30, ge=5)
    WS_RECONNECT_WINDOW_SECONDS: int = Field(default=60, ge=10)
    WS_MAX_EVENT_QUEUE_SIZE: int = Field(default=1000, ge=100)


class GraphRendererConfig(BaseSettings):
    """Frontend graph renderer threshold configuration."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    GRAPH_RENDERER_CANVAS_THRESHOLD: int = Field(
        default=500,
        ge=100,
        description="node_count >= this value → Canvas renderer.",
    )
    GRAPH_RENDERER_WEBGL_THRESHOLD: int = Field(
        default=5000,
        ge=500,
        description="node_count >= this value → WebGL renderer.",
    )


class LoggingSettings(BaseSettings):
    """Structured logging configuration (structlog)."""

    model_config = SettingsConfigDict(
        env_prefix="LOG_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    level: str = Field(
        default="INFO",
        pattern="^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$",
    )
    format: str = Field(
        default="json",
        pattern="^(json|console)$",
        description="json for production/parsing; console for human-readable dev.",
    )
    file: str = Field(
        default="",
        description="Path to log file. Empty string = stdout only.",
    )


# ─────────────────────────────────────────────────────────────────────────────
# Rugpull Creator Profiling: empirically-derived thresholds
# ─────────────────────────────────────────────────────────────────────────────


class RugpullProfileConfig(BaseSettings):
    """
    Empirically-derived thresholds for the rugpull creator flagging system.

    SOURCE: scripts/derive_rugpull_thresholds_v2.py run against
            50 confirmed rugpull creator addresses + 20 genuine deployer addresses.

    CRITICAL NOTES FROM v2 ANALYSIS (read before editing thresholds):
      - F1 (warmup): hypothesis INVERTED — rugpull median (8.75h) > genuine
        (2.61h). Only flag extreme burner-wallet case (< 15 min).
      - F2 (funding CV): CONFIRMED — best single feature, 64% separation.
        Low CV = scripted automated funding. UNDEFINED for 1-deployment wallets.
      - F3 (dry-run): REDESIGNED — v1 70% threshold was too strict.
        v2 uses 40% Jaccard, 6-hour window, cap of 10 per deployment.
      - F4 (burstiness): INVERTED — genuine pro-deployers are MORE bursty.
        Dropped as severity trigger; raw deployment count used instead.
      - F5 (nonce entropy): TOO WEAK — groups nearly identical (4.67 vs 4.54).
        Contextual narrative only; never a standalone severity trigger.
      - F7 (within-wallet similarity): INVERTED — genuine deployers score
        higher (0.28) than rugpulls (0.19). Within-wallet NOT a trigger.
        Cross-wallet comparison handled at rule-engine runtime.
      - F6 (gas-window timing): excluded — requires block-level gas data.

    Re-run scripts/derive_rugpull_thresholds_v2.py when address set changes.
    All fields are overridable via .env using the RUG_ prefix.
    """

    model_config = SettingsConfigDict(
        env_prefix="RUG_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ── F1: Warmup Hours ─────────────────────────────────────────────────────
    # DATA FINDING: hypothesis WRONG. Rugpull median (8.75h) > genuine (2.61h).
    # Only flag extreme burner-wallet case (< 15 min). Minor supporting signal.
    RUG_001_BURNER_THRESHOLD_HOURS: float = Field(
        default=0.25,
        gt=0.0,
        description="F1: warmup under this many hours = extreme burner-wallet signal only.",
    )

    # ── F2: Funding CV ───────────────────────────────────────────────────────
    # DATA FINDING: CONFIRMED — 64% separation. Best single feature.
    # Low CV = scripted/automated funding pipeline (same funder, same timing).
    # UNDEFINED for wallets with < 2 deployments — return None, do NOT flag.
    RUG_002_HIGH_CV_MAX: float = Field(
        default=0.9956,
        ge=0.0,
        description="F2 HIGH: funding CV at or below this value -> HIGH severity.",
    )
    RUG_002_MEDIUM_CV_MAX: float = Field(
        default=1.2546,
        ge=0.0,
        description="F2 MEDIUM: funding CV at or below this value -> MEDIUM severity.",
    )
    RUG_002_CLEAN_FLOOR_CV_MIN: float = Field(
        default=0.6420,
        ge=0.0,
        description="F2: genuine group p25 — values above this are rarely suspicious.",
    )

    # ── F3: Dry-Run Count ────────────────────────────────────────────────────
    # DATA FINDING: REDESIGNED in v2. v1 70% threshold was too strict.
    # Feature extractor params (also must match rugpull_features.py):
    RUG_003_HIGH_COUNT: int = Field(
        default=3,
        ge=1,
        description="F3 HIGH: 3+ dry-run transactions across deployments.",
    )
    RUG_003_MEDIUM_COUNT: int = Field(
        default=1,
        ge=1,
        description="F3 MEDIUM: 1-2 dry-run transactions.",
    )
    RUG_003_SIMILARITY_THRESHOLD: float = Field(
        default=0.40,
        gt=0.0,
        le=1.0,
        description="F3: Jaccard k-mer similarity threshold for dry-run detection (v2=0.40, v1=0.70).",
    )
    RUG_003_WINDOW_HOURS: int = Field(
        default=6,
        ge=1,
        description="F3: hours before deployment to scan for dry-run candidates (v2=6h, v1=1h).",
    )
    RUG_003_MAX_COUNT_CAP: int = Field(
        default=10,
        ge=1,
        description="F3: per-deployment cap on dry-run count to suppress batch-deploy false positives.",
    )

    # ── F4: Deployment Count ─────────────────────────────────────────────────
    # DATA FINDING: burstiness INVERTED (genuine more bursty). Dropped as trigger.
    # Raw deployment count used as proxy for sustained repeat operator activity.
    RUG_004_HIGH_DEPLOYMENT_COUNT: int = Field(
        default=20,
        ge=1,
        description="F4 HIGH: 20+ deployments from same wallet.",
    )
    RUG_004_MEDIUM_DEPLOYMENT_COUNT: int = Field(
        default=10,
        ge=1,
        description="F4 MEDIUM: 10+ deployments from same wallet.",
    )

    # ── F5: Nonce Entropy ────────────────────────────────────────────────────
    # DATA FINDING: TOO WEAK — groups nearly identical (4.67 vs 4.54 median).
    # Only report as narrative context. No severity trigger.
    RUG_005_SCRIPTED_ENTROPY_MAX: float = Field(
        default=3.0,
        ge=0.0,
        description="F5: below this entropy = clearly automated, but context only (not a severity trigger).",
    )

    # ── F7: Template Similarity ──────────────────────────────────────────────
    # DATA FINDING: within-wallet similarity INVERTED (genuine=0.28, rugpull=0.19).
    # Within-wallet: compute + report, NO severity trigger.
    # Cross-wallet: checked at runtime against creator_templates DB table.
    RUG_007_CROSS_WALLET_SIMILARITY_MIN: float = Field(
        default=0.75,
        ge=0.0,
        le=1.0,
        description="F7: cross-wallet setup-sequence similarity threshold for runtime DB comparison.",
    )

    # ── NEW-A: Single Deployment (Burner Wallet) ──────────────────────────────
    # DATA FINDING: 54% of rugpull group had exactly 1 deployment.
    # F2, F4, F7 are undefined for these wallets.
    RUG_NEW_A_SINGLE_DEPLOY_WARMUP_MAX_HOURS: float = Field(
        default=2.0,
        gt=0.0,
        description="NEW-A MEDIUM: single-deploy wallet with warmup below this -> MEDIUM severity.",
    )

    # ── NEW-B: Cross-wallet Funding Source ────────────────────────────────────
    # Flag HIGH if a funding source has funded N+ known rugpull wallets.
    # Checked at runtime from creator_funding_sources DB table.
    RUG_NEW_B_FUNDER_MIN_KNOWN_WALLETS: int = Field(
        default=3,
        ge=1,
        description="NEW-B HIGH: funder that has funded this many+ known-bad wallets -> HIGH severity.",
    )

    # ── Scoring weights ───────────────────────────────────────────────────────
    # Used in rugpull_scorer.py to convert per-feature severities to a 0-100 score.
    SCORE_CRITICAL: int = Field(default=40, ge=1)
    SCORE_HIGH: int = Field(default=25, ge=1)
    SCORE_MEDIUM: int = Field(default=10, ge=1)
    SCORE_LOW: int = Field(default=5, ge=1)

    # ── Verdict bands (minimum score for each verdict level) ──────────────────
    VERDICT_WEAK_MIN: int = Field(default=16, ge=0)
    VERDICT_MODERATE_MIN: int = Field(default=36, ge=0)
    VERDICT_STRONG_MIN: int = Field(default=66, ge=0)
    VERDICT_HIGH_CONFIDENCE_MIN: int = Field(default=100, ge=0)

    # ── Override rule ─────────────────────────────────────────────────────────
    # If RUG-007 cross-wallet match fires -> verdict = at least STRONG_PATTERN
    # regardless of score. Direct linkage outweighs probabilistic score.
    RUG_007_CROSS_MATCH_OVERRIDES_VERDICT: bool = Field(
        default=True,
        description="F7: cross-wallet match forces verdict to STRONG_PATTERN minimum.",
    )

    # ── Multi-hop ownership transfer detection ────────────────────────────────
    # When a deployment has owner_transfer_to set, the rule engine queues that
    # address for secondary analysis. These constants control detection window.
    OWNERSHIP_TRANSFER_WINDOW_HOURS: int = Field(
        default=48,
        ge=1,
        description="Scan this many hours post-deployment for transferOwnership() calls.",
    )


# ─────────────────────────────────────────────────────────────────────────────
# Root Settings: composes all sub-models
# ─────────────────────────────────────────────────────────────────────────────


class Settings(BaseSettings):
    """
    Root application settings.

    Composes all sub-model settings into a single object. Reads from
    environment variables and the .env file at project root.

    Usage:
        settings = get_settings()
        settings.app.version
        settings.etherscan.api_key
        settings.db.path

    Design Note:
        Sub-models use their own env_prefix. The root Settings object
        reads APP_, API_, CORS_, ETHERSCAN_, etc. directly from the
        environment. The `secret_key` field lives at the root level
        since it cross-cuts security concerns.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Root-level secret (cross-cutting)
    secret_key: str = Field(
        default="INSECURE-DEFAULT-CHANGE-IN-PRODUCTION",
        repr=False,
        description="Used for session signing. Generate with: openssl rand -hex 32",
    )

    # Nested sub-models — each reads its own env_prefix
    app: AppSettings = Field(default_factory=AppSettings)
    api: APISettings = Field(default_factory=APISettings)
    cors: CORSSettings = Field(default_factory=CORSSettings)
    etherscan: EtherscanSettings = Field(default_factory=EtherscanSettings)
    rate_limiter: RateLimiterSettings = Field(default_factory=RateLimiterSettings)
    llm: LLMSettings = Field(default_factory=LLMSettings)
    db: DatabaseSettings = Field(default_factory=DatabaseSettings)
    investigation: InvestigationDefaults = Field(default_factory=InvestigationDefaults)
    trace_scoring: TraceScoringWeights = Field(default_factory=TraceScoringWeights)
    risk_scoring: RiskScoringConfig = Field(default_factory=RiskScoringConfig)
    forensic_rules: ForensicRulesConfig = Field(default_factory=ForensicRulesConfig)
    session: SessionSettings = Field(default_factory=SessionSettings)
    graph_renderer: GraphRendererConfig = Field(default_factory=GraphRendererConfig)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)
    rugpull: RugpullProfileConfig = Field(default_factory=RugpullProfileConfig)

    @property
    def is_production(self) -> bool:
        return self.app.env == "production"

    @property
    def is_development(self) -> bool:
        return self.app.env == "development"

    @property
    def database_url(self) -> str:
        """
        Absolute path to the SQLite database file.

        BUG FIX: ':memory:' is the SQLite special in-memory identifier.
        os.path.isabs(':memory:') returns False, which would cause the
        original code to join it with the project root, yielding a broken
        path like '/project/:memory:'. We short-circuit for this special
        value and return it as-is. All other relative paths are resolved
        to absolute using the project root as the anchor.
        """
        path = self.db.path

        # Short-circuit: SQLite in-memory identifier must never be path-joined
        if path == ":memory:":
            return ":memory:"

        if not os.path.isabs(path):
            project_root = os.path.dirname(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            )
            return os.path.join(project_root, path)
        return path


# ─────────────────────────────────────────────────────────────────────────────
# Cached accessor — call anywhere, construct once
# ─────────────────────────────────────────────────────────────────────────────


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """
    Return the application Settings singleton.

    Cached via @lru_cache — the Settings object is constructed exactly once
    per process. Safe to call from any module without performance cost.

    In tests, call `get_settings.cache_clear()` before patching environment
    variables to force a fresh Settings construction.
    """
    return Settings()
