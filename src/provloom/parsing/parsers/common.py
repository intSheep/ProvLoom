from __future__ import annotations

import json
from typing import Any

from provloom.domain.errors import LogParseError
from provloom.domain.raw_models import RawEvent


def decode_raw_object(raw_event: RawEvent) -> dict[str, Any]:
    if raw_event.raw_metadata.get("format") == "csv":
        if raw_event.raw_metadata.get("csv_malformed"):
            raise LogParseError("Malformed CSV row: column count mismatch")
        fields = raw_event.raw_metadata.get("csv_fields")
        if isinstance(fields, dict):
            return dict(fields)

    try:
        parsed = json.loads(raw_event.raw_payload)
    except json.JSONDecodeError as exc:
        raise LogParseError(f"Invalid JSON payload: {exc}") from exc

    if not isinstance(parsed, dict):
        raise LogParseError("Expected JSON object at top level")
    return parsed


def coerce_optional_int(value: Any) -> int | None:
    if value is None or value == "" or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise LogParseError(f"Invalid integer field value: {value!r}") from exc
