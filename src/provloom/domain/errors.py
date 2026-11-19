from __future__ import annotations


class ProvLoomError(Exception):
    """Base domain error."""


class AdapterReadError(ProvLoomError):
    """Raised when an ingestion adapter encounters an unreadable record."""


class LogParseError(ProvLoomError):
    """Raised when raw payload cannot be parsed into ParsedEnvelope."""


class NormalizationError(ProvLoomError):
    """Raised when an event violates OCSF structural invariants."""


class InvalidTimeRangeError(ProvLoomError):
    """Raised when query or lifecycle time bounds are invalid."""


class ScopeViolationError(ProvLoomError):
    """Raised when a caller attempts to access data outside its AccessScope."""


class QueryLimitExceededError(ProvLoomError):
    """Raised when requested page size or traversal depth exceeds hard guardrails."""
