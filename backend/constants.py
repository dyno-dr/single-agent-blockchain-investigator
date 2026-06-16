"""
backend/constants.py
─────────────────────────────────────────────────────────────────────────────
Project-wide constants, enumerations, and type aliases.

PURPOSE:
  Centralizes every sentinel value, string constant, and domain enum so they
  can be imported from one place and tested independently. No magic strings
  in business logic; all switch statements operate on these enums.

DESIGN DECISIONS:
  1. StrEnum for enums used in JSON/API responses, where the value IS the
     string representation (e.g., risk_level="HIGH").
  2. Type aliases declared here to provide a single reference for future
     type-checking migrations (e.g., WalletAddress = str → NewType in Phase 2).
  3. Rule IDs are module-level string constants (not enum members) so they
     can be used as dict keys without .value unwrapping.

FUTURE SCALABILITY:
  When the multi-agent framework ships:
  - AgentRole enum slots in here.
  - Chain enum expands with BITCOIN, SOLANA, etc.
  - No existing constant needs modification.
"""

from __future__ import annotations

from enum import Enum


# ─────────────────────────────────────────────────────────────────────────────
# Type Aliases (semantic clarity; not enforced at runtime)
# ─────────────────────────────────────────────────────────────────────────────

WalletAddress = str       # EIP-55 checksummed Ethereum address
TxHash = str              # 0x-prefixed 66-char hex string
SessionId = str           # UUID4 string
BlockNumber = int
TimestampSeconds = int    # Unix epoch seconds


# ─────────────────────────────────────────────────────────────────────────────
# Application
# ─────────────────────────────────────────────────────────────────────────────

AGENT_VERSION = "1.0.0"

# Header key for API key authentication
API_KEY_HEADER = "X-API-Key"

# Health check status values
HEALTH_OK = "ok"
HEALTH_DEGRADED = "degraded"
HEALTH_DOWN = "down"


# ─────────────────────────────────────────────────────────────────────────────
# Investigation Lifecycle
# ─────────────────────────────────────────────────────────────────────────────


class InvestigationStatus(str, Enum):
    """Lifecycle states for an investigation session."""

    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETE = "COMPLETE"
    FAILED = "FAILED"


class Phase(str, Enum):
    """
    LangGraph agent node phases.
    Maps directly to node names in agent/graph.py.
    """

    INIT = "INIT"
    PROFILING = "PROFILING"
    TX_FETCH = "TX_FETCH"
    TRACING = "TRACING"
    DETECTING = "DETECTING"
    REPORTING = "REPORTING"
    PERSISTING = "PERSISTING"
    DONE = "DONE"
    ERROR = "ERROR"
    FAILED = "FAILED"


# ─────────────────────────────────────────────────────────────────────────────
# Risk Assessment
# ─────────────────────────────────────────────────────────────────────────────


class RiskLevel(str, Enum):
    """
    Investigation risk level output.
    Maps to risk_score thresholds in RiskScorer.
    """

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Severity(str, Enum):
    """
    Forensic rule finding severity.
    Maps to severity_weight in RiskScorer.
    """

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# ─────────────────────────────────────────────────────────────────────────────
# Forensic Rule Categories
# ─────────────────────────────────────────────────────────────────────────────


class RuleCategory(str, Enum):
    """Forensic rule classification for grouping in reports."""

    TRANSFER_PATTERN = "TRANSFER_PATTERN"
    TIMING = "TIMING"
    NETWORK = "NETWORK"
    LIFECYCLE = "LIFECYCLE"


# ─────────────────────────────────────────────────────────────────────────────
# Transaction Data Model
# ─────────────────────────────────────────────────────────────────────────────


class TransactionDirection(str, Enum):
    """Direction of a transaction relative to the target wallet."""

    INCOMING = "INCOMING"
    OUTGOING = "OUTGOING"
    INTERNAL = "INTERNAL"


class TransactionType(str, Enum):
    """Transaction type classification."""

    TRANSFER = "TRANSFER"
    CONTRACT_CALL = "CONTRACT_CALL"
    TOKEN_TRANSFER = "TOKEN_TRANSFER"


# ─────────────────────────────────────────────────────────────────────────────
# Tracing Engine
# ─────────────────────────────────────────────────────────────────────────────


class PruningDecision(str, Enum):
    """
    Per-hop decision made by the PruningEngine.

    EXPAND  → continue tracing through this node
    SKIP    → edge below value threshold (dust)
    HALT    → terminal node (CEX / visited / depth exhausted)
    SAMPLE  → high fan-out; trace top-N edges by value only
    """

    EXPAND = "EXPAND"
    SKIP = "SKIP"
    HALT = "HALT"
    SAMPLE = "SAMPLE"


class TraceStrategy(str, Enum):
    """
    Layer 2 trace strategy selected by PLANNER node.
    Constrained enum — LLM must choose from this set (no free-form strings).
    """

    FORWARD_ONLY = "FORWARD_ONLY"
    BACKWARD_ONLY = "BACKWARD_ONLY"
    BIDIRECTIONAL = "BIDIRECTIONAL"
    FORWARD_THEN_PIVOT = "FORWARD_THEN_PIVOT"
    SKIP = "SKIP"


class EntityType(str, Enum):
    """Graph node entity classification from known_entities.json."""

    KNOWN_CEX = "known_cex"
    KNOWN_DEX = "known_dex"
    MIXER_SUSPECTED = "mixer_suspected"
    BRIDGE = "bridge"
    UNKNOWN = "unknown"


# ─────────────────────────────────────────────────────────────────────────────
# WebSocket Event Types
# ─────────────────────────────────────────────────────────────────────────────


class WsEventType(str, Enum):
    """
    WebSocket event type identifiers.
    Every server→client message carries one of these type values.
    Frontend AgentMonitor switches on these to route rendering.
    """

    SESSION_CREATED = "SESSION_CREATED"
    PHASE_START = "PHASE_START"
    TOOL_CALL = "TOOL_CALL"
    AGENT_STEP = "AGENT_STEP"
    RATE_LIMITED = "RATE_LIMITED"
    RULE_TRIGGERED = "RULE_TRIGGERED"
    TRACE_PRUNED = "TRACE_PRUNED"
    PROGRESS = "PROGRESS"
    COMPLETE = "COMPLETE"
    ERROR = "ERROR"
    FAILED = "FAILED"
    PING = "PING"
    PONG = "PONG"


# ─────────────────────────────────────────────────────────────────────────────
# Reasoning Log
# ─────────────────────────────────────────────────────────────────────────────


class ActionType(str, Enum):
    """Reasoning log step classification for the MEMORY node."""

    TOOL_CALL = "TOOL_CALL"
    DECISION = "DECISION"
    OBSERVATION = "OBSERVATION"
    CONCLUSION = "CONCLUSION"


# ─────────────────────────────────────────────────────────────────────────────
# Graph Renderer
# ─────────────────────────────────────────────────────────────────────────────


class GraphRendererMode(str, Enum):
    """
    Renderer mode hint returned with graph API response.
    Frontend uses this instead of computing thresholds client-side,
    keeping threshold logic in one place (backend settings).
    """

    SVG = "svg"        # D3.js SVG — < 500 nodes
    CANVAS = "canvas"  # react-force-graph-2d — 500–5k nodes
    WEBGL = "webgl"    # react-force-graph — > 5k nodes


# ─────────────────────────────────────────────────────────────────────────────
# Forensic Rule IDs — canonical identifiers
# ─────────────────────────────────────────────────────────────────────────────

RULE_LARGE_TRANSFER = "RULE-001"
RULE_RAPID_SUCCESSION = "RULE-002"
RULE_HIGH_FANOUT = "RULE-003"
RULE_DORMANT_ACTIVATION = "RULE-004"
RULE_ACTIVITY_BURST = "RULE-005"
RULE_ROUND_NUMBERS = "RULE-006"
RULE_NEW_WALLET_INTERACTION = "RULE-007"

ALL_RULE_IDS: tuple[str, ...] = (
    RULE_LARGE_TRANSFER,
    RULE_RAPID_SUCCESSION,
    RULE_HIGH_FANOUT,
    RULE_DORMANT_ACTIVATION,
    RULE_ACTIVITY_BURST,
    RULE_ROUND_NUMBERS,
    RULE_NEW_WALLET_INTERACTION,
)


# ─────────────────────────────────────────────────────────────────────────────
# Chain Identifiers
# ─────────────────────────────────────────────────────────────────────────────


class Chain(str, Enum):
    """
    Supported blockchain networks.
    Phase 1: ETHEREUM only.
    Phase 3+: BITCOIN, SOLANA, POLYGON, ARBITRUM will be added here.
    """

    ETHEREUM = "ethereum"
    ETHEREUM_GOERLI = "ethereum_goerli"
    ETHEREUM_SEPOLIA = "ethereum_sepolia"


# ─────────────────────────────────────────────────────────────────────────────
# Error Codes
# ─────────────────────────────────────────────────────────────────────────────


class ErrorCode(str, Enum):
    """Structured error codes for programmatic error handling."""

    ETHERSCAN_UNREACHABLE = "ETHERSCAN_UNREACHABLE"
    ETHERSCAN_RATE_LIMIT = "ETHERSCAN_RATE_LIMIT"
    ETHERSCAN_INVALID_ADDRESS = "ETHERSCAN_INVALID_ADDRESS"
    LLM_UNAVAILABLE = "LLM_UNAVAILABLE"
    LLM_INVALID_OUTPUT = "LLM_INVALID_OUTPUT"
    DATABASE_LOCKED = "DATABASE_LOCKED"
    DATABASE_WRITE_FAILED = "DATABASE_WRITE_FAILED"
    INVESTIGATION_TIMEOUT = "INVESTIGATION_TIMEOUT"
    INVESTIGATION_NOT_FOUND = "INVESTIGATION_NOT_FOUND"
    INVALID_WALLET_ADDRESS = "INVALID_WALLET_ADDRESS"
    MAX_RETRIES_EXCEEDED = "MAX_RETRIES_EXCEEDED"
    INTERNAL_ERROR = "INTERNAL_ERROR"