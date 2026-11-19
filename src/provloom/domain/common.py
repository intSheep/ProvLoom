from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Generic, TypeVar

from provloom.domain.errors import InvalidTimeRangeError, QueryLimitExceededError

T = TypeVar("T")


@dataclass(frozen=True)
class AccessScope:
    """Row-level isolation context required on every query."""

    tenant_id: str
    allowed_sources: frozenset[str] | None = None

    def permits_source(self, source_id: str) -> bool:
        return self.allowed_sources is None or source_id in self.allowed_sources


@dataclass(frozen=True)
class TimeRange:
    start_time: datetime
    end_time: datetime

    def __post_init__(self) -> None:
        if self.start_time.tzinfo is None or self.end_time.tzinfo is None:
            raise InvalidTimeRangeError("TimeRange requires timezone-aware UTC datetimes")
        if self.end_time < self.start_time:
            raise InvalidTimeRangeError("end_time must be >= start_time")


@dataclass(frozen=True)
class PageSpec:
    limit: int = 100
    cursor: str | None = None

    def validate(self, max_limit: int) -> PageSpec:
        if self.limit < 1 or self.limit > max_limit:
            raise QueryLimitExceededError(f"limit must be between 1 and {max_limit}")
        return self


@dataclass(frozen=True)
class PageResult(Generic[T]):
    items: tuple[T, ...]
    next_cursor: str | None = None
    truncated: bool = False
