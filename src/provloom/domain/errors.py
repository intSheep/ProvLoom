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


class RuleValidationError(ProvLoomError):
    """Raised when a detection rule YAML or structured spec is malformed."""


class RuleUnsupportedError(ProvLoomError):
    """Raised when attempting to enable or execute an unsupported detection rule."""


class DetectionPermissionError(ProvLoomError):
    """Raised when caller lacks permission to mutate or execute detection rules."""


class DetectionExecutionError(ProvLoomError):
    """Raised when rule execution fails or exceeds safety guardrails."""
