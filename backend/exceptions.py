"""
backend/exceptions.py
─────────────────────────────────────────────────────────────────────────────
Centralized application exception hierarchy.

PURPOSE:
  Defines every typed exception the application can raise. All business logic,
  repositories, tools, and agent nodes raise exceptions from this hierarchy —
  never bare Python builtins. This makes exception handling exhaustive,
  structured, and auditable.

DESIGN DECISIONS:
  1. `BaseApplicationException` is the root. Catching it catches everything
     application-defined. FastAPI exception handlers in main.py are registered
     against this type so unhandled domain exceptions return structured JSON,
     not Python stack traces.
  2. Every exception carries:
       - `error_code`   : machine-readable ErrorCode enum value
       - `message`      : human-readable description (safe to expose to clients)
       - `context`      : arbitrary dict for structured logging metadata
       - `timestamp`    : UTC ISO string — when the exception was raised
     This schema is consumed directly by the global exception handler and by
     structlog when logging error events.
  3. Exception sub-classes are partitioned by architectural layer:
       Infrastructure   → DatabaseException, ConfigurationException
       Domain           → ValidationException, InvestigationException
       Integration      → ExternalServiceException (Etherscan, LLM)
       Data access      → RepositoryException
     Each layer only raises exceptions from its own sub-tree, preventing
     cross-layer leakage of error semantics.
  4. `HTTPAwareException` adds an `http_status_code` field for exceptions that
     should translate directly to specific HTTP responses. The global FastAPI
     handler reads this field when present.
  5. All exceptions are dataclass-style (explicit fields) rather than using
     `*args`. This prevents the `Exception("some string")` anti-pattern and
     enforces that callers always provide structured context.

FUTURE SCALABILITY:
  - Add `AgentException` sub-tree when the LangGraph layer ships.
  - Add `CrossChainException` when multi-chain support is added.
  - Exception classes are imported by the global handler — add new sub-classes
    here and the handler automatically catches them without modification.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from backend.constants import ErrorCode

# ─────────────────────────────────────────────────────────────────────────────
# Root exception
# ─────────────────────────────────────────────────────────────────────────────


class BaseApplicationException(Exception):
    """
    Root of the application exception hierarchy.

    All exceptions raised by application code (business logic, repositories,
    tools, agent nodes) inherit from this class. The global FastAPI exception
    handler in main.py catches this type and converts it to a structured JSON
    response.

    Args:
        error_code: Machine-readable error classification (ErrorCode enum).
        message: Human-readable error description. Safe to include in API
            responses — must not contain internal paths, stack details, or
            sensitive data.
        context: Optional dict of structured metadata for log correlation
            (e.g., session_id, wallet_address, rule_id). Never include secrets.
        cause: Optional chained exception (the original Python exception that
            triggered this one). Stored for logging; not exposed in responses.
    """

    def __init__(
        self,
        error_code: ErrorCode,
        message: str,
        context: dict[str, Any] | None = None,
        cause: BaseException | None = None,
    ) -> None:
        super().__init__(message)
        self.error_code: ErrorCode = error_code
        self.message: str = message
        self.context: dict[str, Any] = context or {}
        self.cause: BaseException | None = cause
        self.timestamp: str = datetime.now(UTC).isoformat()

    def to_dict(self) -> dict[str, Any]:
        """
        Serialize the exception to a dict suitable for JSON responses and logs.

        Returns:
            Dict with error_code, message, context, and timestamp. Does NOT
            include the `cause` exception — that is for server-side logging only.
        """
        return {
            "error_code": self.error_code.value,
            "message": self.message,
            "context": self.context,
            "timestamp": self.timestamp,
        }

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"error_code={self.error_code!r}, "
            f"message={self.message!r}, "
            f"context={self.context!r}"
            f")"
        )


# ─────────────────────────────────────────────────────────────────────────────
# HTTP-aware mixin
# ─────────────────────────────────────────────────────────────────────────────


class HTTPAwareException(BaseApplicationException):
    """
    Exception sub-class that carries an HTTP status code.

    Used by the global FastAPI exception handler to determine the correct
    HTTP response status. Exceptions that should map to specific status codes
    (400, 401, 403, 404, 422, 429) inherit from this class.

    Args:
        http_status_code: The HTTP status code the handler should return.
            All other args forwarded to BaseApplicationException.
    """

    def __init__(
        self,
        error_code: ErrorCode,
        message: str,
        http_status_code: int = 500,
        context: dict[str, Any] | None = None,
        cause: BaseException | None = None,
    ) -> None:
        super().__init__(
            error_code=error_code,
            message=message,
            context=context,
            cause=cause,
        )
        self.http_status_code: int = http_status_code

    def to_dict(self) -> dict[str, Any]:
        base = super().to_dict()
        base["http_status_code"] = self.http_status_code
        return base


# ─────────────────────────────────────────────────────────────────────────────
# Infrastructure exceptions
# ─────────────────────────────────────────────────────────────────────────────


class DatabaseException(BaseApplicationException):
    """
    Raised when a database operation fails at the infrastructure level.

    Examples:
        - SQLite is locked after busy_timeout exhausted
        - WAL checkpoint failure
        - Schema migration failure
        - Connection pool exhaustion

    The RepositoryException (below) is for higher-level data-access failures;
    DatabaseException is for low-level driver/connection-level errors.
    """

    def __init__(
        self,
        message: str,
        context: dict[str, Any] | None = None,
        cause: BaseException | None = None,
        error_code: ErrorCode = ErrorCode.DATABASE_WRITE_FAILED,
    ) -> None:
        super().__init__(
            error_code=error_code,
            message=message,
            context=context,
            cause=cause,
        )


class DatabaseLockedError(DatabaseException):
    """
    Raised specifically when SQLite raises a 'database is locked' error.

    This occurs when the busy_timeout (5000ms) is exhausted under write
    contention. The write-queue bulk-insert pattern in memory_node.py
    is designed to prevent this, but we catch it explicitly for diagnostics.
    """

    def __init__(
        self,
        message: str = "SQLite database is locked. Busy timeout exhausted.",
        context: dict[str, Any] | None = None,
        cause: BaseException | None = None,
    ) -> None:
        super().__init__(
            message=message,
            context=context,
            cause=cause,
            error_code=ErrorCode.DATABASE_LOCKED,
        )


class ConfigurationException(BaseApplicationException):
    """
    Raised when application configuration is invalid or missing.

    Raised during startup when required settings are absent or fail
    validation. Application should not start if this is raised.

    Examples:
        - Missing required API key
        - Invalid database path
        - Trace weight config doesn't sum to 1.0
    """

    def __init__(
        self,
        message: str,
        context: dict[str, Any] | None = None,
        cause: BaseException | None = None,
    ) -> None:
        super().__init__(
            error_code=ErrorCode.INTERNAL_ERROR,
            message=message,
            context=context,
            cause=cause,
        )


# ─────────────────────────────────────────────────────────────────────────────
# Domain exceptions
# ─────────────────────────────────────────────────────────────────────────────


class ValidationException(HTTPAwareException):
    """
    Raised when domain-level validation fails.

    Distinct from Pydantic's RequestValidationError (which handles request
    schema validation). ValidationException is for business rule violations:
    invalid Ethereum address format, investigation depth out of range, etc.

    HTTP 422 by default.
    """

    def __init__(
        self,
        message: str,
        context: dict[str, Any] | None = None,
        cause: BaseException | None = None,
        error_code: ErrorCode = ErrorCode.INVALID_WALLET_ADDRESS,
    ) -> None:
        super().__init__(
            error_code=error_code,
            message=message,
            http_status_code=422,
            context=context,
            cause=cause,
        )


class InvalidWalletAddressError(ValidationException):
    """
    Raised when a wallet address fails EIP-55 / hex format validation.

    Provides a specific error code and a user-friendly message that names
    the offending address (safe — it came from user input, not internal state).
    """

    def __init__(
        self,
        address: str,
        context: dict[str, Any] | None = None,
    ) -> None:
        ctx = {"address": address, **(context or {})}
        super().__init__(
            message=(
                f"Invalid Ethereum address: '{address}'. "
                "Must be a 0x-prefixed 40-character hexadecimal string."
            ),
            context=ctx,
            error_code=ErrorCode.INVALID_WALLET_ADDRESS,
        )


class InvestigationException(HTTPAwareException):
    """
    Raised for investigation lifecycle errors.

    Examples:
        - Investigation session not found
        - Investigation already running for this session
        - Investigation timed out
        - Error count exceeded threshold (error_count > 3)

    HTTP 404 for not-found; 409 for lifecycle conflicts; 500 for internals.
    The `http_status_code` parameter lets callers specify the appropriate code.
    """

    def __init__(
        self,
        message: str,
        http_status_code: int = 500,
        context: dict[str, Any] | None = None,
        cause: BaseException | None = None,
        error_code: ErrorCode = ErrorCode.INTERNAL_ERROR,
    ) -> None:
        super().__init__(
            error_code=error_code,
            message=message,
            http_status_code=http_status_code,
            context=context,
            cause=cause,
        )


class InvestigationNotFoundError(InvestigationException):
    """
    Raised when a requested investigation session_id does not exist in the DB.
    HTTP 404.
    """

    def __init__(
        self,
        session_id: str,
        context: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=f"Investigation not found: '{session_id}'.",
            http_status_code=404,
            context={"session_id": session_id, **(context or {})},
            error_code=ErrorCode.INVESTIGATION_NOT_FOUND,
        )


class InvestigationTimeoutError(InvestigationException):
    """
    Raised when an investigation exceeds SESSION_TIMEOUT_SECONDS.
    HTTP 504.
    """

    def __init__(
        self,
        session_id: str,
        timeout_seconds: int,
        context: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=(
                f"Investigation '{session_id}' timed out after "
                f"{timeout_seconds} seconds."
            ),
            http_status_code=504,
            context={
                "session_id": session_id,
                "timeout_seconds": timeout_seconds,
                **(context or {}),
            },
            error_code=ErrorCode.INVESTIGATION_TIMEOUT,
        )


# ─────────────────────────────────────────────────────────────────────────────
# Data access exceptions
# ─────────────────────────────────────────────────────────────────────────────


class RepositoryException(BaseApplicationException):
    """
    Raised by repository methods when a data access operation fails.

    Wraps DatabaseException for higher-level data-access errors: record not
    found, constraint violation, unexpected query result shape. Repositories
    translate raw DB driver errors into RepositoryExceptions so callers
    don't need to handle aiosqlite internals.

    Design:
        Repositories CATCH DatabaseException and re-raise as RepositoryException
        with structured context added (table_name, operation, record_id).
        Only the RepositoryException surfaces to callers.
    """

    def __init__(
        self,
        message: str,
        operation: str | None = None,
        table: str | None = None,
        record_id: str | None = None,
        context: dict[str, Any] | None = None,
        cause: BaseException | None = None,
        error_code: ErrorCode = ErrorCode.DATABASE_WRITE_FAILED,
    ) -> None:
        ctx: dict[str, Any] = {}
        if operation:
            ctx["operation"] = operation
        if table:
            ctx["table"] = table
        if record_id:
            ctx["record_id"] = record_id
        if context:
            ctx.update(context)

        super().__init__(
            error_code=error_code,
            message=message,
            context=ctx,
            cause=cause,
        )


# ─────────────────────────────────────────────────────────────────────────────
# External service exceptions
# ─────────────────────────────────────────────────────────────────────────────


class ExternalServiceException(HTTPAwareException):
    """
    Raised when an external service call fails.

    Sub-classed for specific integrations (Etherscan, LLM). The `service_name`
    field identifies the integration for log routing and monitoring alerts.

    HTTP 503 by default (service unavailable / dependency down).
    """

    def __init__(
        self,
        service_name: str,
        message: str,
        http_status_code: int = 503,
        context: dict[str, Any] | None = None,
        cause: BaseException | None = None,
        error_code: ErrorCode = ErrorCode.INTERNAL_ERROR,
    ) -> None:
        ctx = {"service": service_name, **(context or {})}
        super().__init__(
            error_code=error_code,
            message=message,
            http_status_code=http_status_code,
            context=ctx,
            cause=cause,
        )
        self.service_name: str = service_name


class EtherscanException(ExternalServiceException):
    """
    Raised when the Etherscan API is unreachable or returns an error.

    Covers:
        - Network connectivity failures (HTTPX timeout, connection refused)
        - HTTP 429 (rate limit exceeded — after retry budget exhausted)
        - HTTP 5xx (Etherscan server error)
        - API-level errors (result="Error", message="Invalid address")
    """

    def __init__(
        self,
        message: str,
        http_status_code: int = 503,
        context: dict[str, Any] | None = None,
        cause: BaseException | None = None,
        error_code: ErrorCode = ErrorCode.ETHERSCAN_UNREACHABLE,
    ) -> None:
        super().__init__(
            service_name="etherscan",
            message=message,
            http_status_code=http_status_code,
            context=context,
            cause=cause,
            error_code=error_code,
        )


class EtherscanRateLimitError(EtherscanException):
    """
    Raised when Etherscan returns HTTP 429 and all retries are exhausted.

    Distinct from the transient rate-limiting handled by AsyncTokenBucket
    (which sleeps and retries). This exception only fires when the retry
    budget (max_retries) is fully consumed — indicating a sustained overload.
    """

    def __init__(
        self,
        wait_ms: int | None = None,
        context: dict[str, Any] | None = None,
        cause: BaseException | None = None,
    ) -> None:
        ctx = {"wait_ms": wait_ms, **(context or {})} if wait_ms else (context or {})
        super().__init__(
            message="Etherscan rate limit exceeded. All retries exhausted.",
            http_status_code=429,
            context=ctx,
            cause=cause,
            error_code=ErrorCode.ETHERSCAN_RATE_LIMIT,
        )


class LLMException(ExternalServiceException):
    """
    Raised when the LLM (Anthropic Claude) is unavailable or returns invalid output.

    Covers:
        - API connectivity failures
        - Invalid structured output (LLM returned non-enum TraceStrategy)
        - Token limit errors
        - Authentication failures
    """

    def __init__(
        self,
        message: str,
        http_status_code: int = 503,
        context: dict[str, Any] | None = None,
        cause: BaseException | None = None,
        error_code: ErrorCode = ErrorCode.LLM_UNAVAILABLE,
    ) -> None:
        super().__init__(
            service_name="anthropic",
            message=message,
            http_status_code=http_status_code,
            context=context,
            cause=cause,
            error_code=error_code,
        )


class LLMInvalidOutputError(LLMException):
    """
    Raised when the LLM returns output that fails structured validation.

    The TraceDirective fallback (FORWARD_ONLY + K=3) is applied before this
    exception is raised — this exception only fires if the fallback itself
    is somehow malformed (should never happen in practice, but is guarded).
    """

    def __init__(
        self,
        raw_output: str,
        expected_schema: str,
        context: dict[str, Any] | None = None,
        cause: BaseException | None = None,
    ) -> None:
        ctx = {
            "raw_output_preview": raw_output[:200],
            "expected_schema": expected_schema,
            **(context or {}),
        }
        super().__init__(
            message=(
                f"LLM returned output that does not match '{expected_schema}' schema. "
                "Fallback strategy applied."
            ),
            http_status_code=500,
            context=ctx,
            cause=cause,
            error_code=ErrorCode.LLM_INVALID_OUTPUT,
        )


# ─────────────────────────────────────────────────────────────────────────────
# Retry exhaustion exception
# ─────────────────────────────────────────────────────────────────────────────


class MaxRetriesExceededError(BaseApplicationException):
    """
    Raised when a retry loop (tenacity or manual) exhausts its attempt budget.

    Wraps the most recent underlying exception in `cause`. Used by the
    EtherscanClient's retry handler; may be used by future tool retry logic.
    """

    def __init__(
        self,
        operation: str,
        attempts: int,
        context: dict[str, Any] | None = None,
        cause: BaseException | None = None,
    ) -> None:
        super().__init__(
            error_code=ErrorCode.MAX_RETRIES_EXCEEDED,
            message=(
                f"Operation '{operation}' failed after {attempts} attempts."
            ),
            context={"operation": operation, "attempts": attempts, **(context or {})},
            cause=cause,
        )
