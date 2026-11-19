from __future__ import annotations

from datetime import datetime, timezone

from provloom.domain.errors import LogParseError


def parse_utc_timestamp(value: object) -> datetime:
    if isinstance(value, (int, float)):
        ts = float(value)
        if ts > 1e12:
            ts /= 1000.0
        return datetime.fromtimestamp(ts, tz=timezone.utc)

    if not isinstance(value, str) or not value.strip():
        raise LogParseError(f"Missing or empty timestamp: {value!r}")

    raw = value.strip()
    if raw.replace(".", "", 1).isdigit():
        ts = float(raw)
        if ts > 1e12:
            ts /= 1000.0
        return datetime.fromtimestamp(ts, tz=timezone.utc)

    iso_candidate = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
    try:
        dt = datetime.fromisoformat(iso_candidate)
    except ValueError:
        for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
            try:
                dt = datetime.strptime(raw, fmt)
                break
            except ValueError:
                continue
        else:
            raise LogParseError(f"Unsupported timestamp format: {raw!r}") from None

    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)
