from __future__ import annotations

from typing import Any

from provloom.domain.errors import LogParseError
from provloom.domain.parsed_models import ParsedEnvelope
from provloom.domain.raw_models import RawEvent
from provloom.parsing.interfaces import LogParser
from provloom.parsing.parsers.common import clean_sentinel, coerce_optional_int, decode_raw_object
from provloom.parsing.time_utils import parse_utc_timestamp

_ZEEK_CONN_COLS = (
    "ts",
    "uid",
    "id.orig_h",
    "id.orig_p",
    "id.resp_h",
    "id.resp_p",
    "proto",
    "service",
    "duration",
    "orig_bytes",
    "resp_bytes",
    "conn_state",
)


def _decode_raw_zeek_tsv_line(raw_payload: str) -> dict[str, Any]:
    stripped = raw_payload.strip()
    if not stripped or stripped.startswith("#"):
        raise LogParseError("Zeek TSV header/comment line is not an event record")
    cols = stripped.split("\t")
    if len(cols) < len(_ZEEK_CONN_COLS):
        raise LogParseError(
            f"Zeek TSV row missing header schema or expected columns (got {len(cols)})"
        )
    out: dict[str, Any] = {"_path": "conn"}
    for key, raw_val in zip(_ZEEK_CONN_COLS, cols[: len(_ZEEK_CONN_COLS)], strict=True):
        cleaned = clean_sentinel(raw_val)
        if cleaned is not None:
            out[key] = cleaned
    return out


class ZeekJsonParser(LogParser):
    @property
    def parser_id(self) -> str:
        return "zeek_json"

    @property
    def parser_version(self) -> str:
        return "1.1.0"

    def supports(self, raw_event: RawEvent) -> bool:
        return raw_event.source_type.lower().startswith("zeek")

    def parse(self, raw_event: RawEvent) -> ParsedEnvelope:
        if (
            raw_event.raw_metadata.get("format") != "zeek_tsv"
            and not raw_event.raw_payload.lstrip().startswith(("{", "<"))
            and "\t" in raw_event.raw_payload
        ):
            flat = _decode_raw_zeek_tsv_line(raw_event.raw_payload)
        else:
            obj = decode_raw_object(raw_event)
            flat = dict(obj)

        # Normalize nested Zeek {"id": {"orig_h": ...}} and OTRF flat id_orig_h keys.
        if isinstance(flat.get("id"), dict):
            id_obj = flat.pop("id")
            for k, v in id_obj.items():
                flat.setdefault(f"id.{k}", v)
        for flat_key, dotted_key in (
            ("id_orig_h", "id.orig_h"),
            ("id_orig_p", "id.orig_p"),
            ("id_resp_h", "id.resp_h"),
            ("id_resp_p", "id.resp_p"),
        ):
            if flat_key in flat and dotted_key not in flat:
                flat[dotted_key] = flat[flat_key]

        occurred_at = parse_utc_timestamp(
            flat.get("ts") or flat.get("@timestamp") or flat.get("timestamp")
        )
        for port_key in ("id.orig_p", "id.resp_p", "orig_bytes", "resp_bytes"):
            if port_key in flat:
                cleaned_int = clean_sentinel(flat[port_key])
                if cleaned_int is None:
                    flat.pop(port_key, None)
                else:
                    flat[port_key] = coerce_optional_int(cleaned_int)

        st = raw_event.source_type.lower()
        inferred_path = None
        if "_" in st:
            suffix = st.split("_", 1)[1]
            if suffix not in {"tsv", "json", "jsonl"}:
                inferred_path = suffix

        ev_dataset = (
            flat.get("event", {}).get("dataset") if isinstance(flat.get("event"), dict) else None
        )
        stream_val = flat.get("@stream")
        if stream_val is None and isinstance(ev_dataset, str) and "." in ev_dataset:
            stream_val = ev_dataset.split(".", 1)[-1]

        log_path = str(flat.get("_path") or stream_val or inferred_path or "unknown")
        orig_uid = flat.get("uid") or raw_event.external_event_uid

        return ParsedEnvelope(
            raw_event_id=raw_event.raw_event_id,
            tenant_scope=raw_event.tenant_scope,
            source_id=raw_event.source_id,
            parser_id=self.parser_id,
            parser_version=self.parser_version,
            occurred_at=occurred_at,
            event_code=log_path,
            vendor="Zeek",
            product="Zeek Network Security Monitor",
            original_event_uid=str(orig_uid) if orig_uid is not None else None,
            extracted_fields=flat,
        )
