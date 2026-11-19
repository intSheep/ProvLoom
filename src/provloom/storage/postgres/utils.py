from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def ensure_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def require_utc(dt: datetime) -> datetime:
    res = ensure_utc(dt)
    assert res is not None
    return res


def parse_offset(cursor: str | None) -> int:
    if not cursor:
        return 0
    try:
        val = int(cursor)
        return max(val, 0)
    except ValueError:
        return 0


def next_offset_cursor(offset: int, limit: int, fetched_count: int) -> tuple[str | None, bool]:
    has_more = fetched_count > limit
    return (str(offset + limit) if has_more else None, has_more)


def extract_nested(payload: dict[str, Any], dotted_key: str) -> Any:
    if dotted_key in payload:
        return payload[dotted_key]
    cur: Any = payload
    for part in dotted_key.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur
