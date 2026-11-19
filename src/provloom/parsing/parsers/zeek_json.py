from __future__ import annotations

from typing import Any

from provloom.domain.parsed_models import ParsedEnvelope
from provloom.domain.raw_models import RawEvent
from provloom.parsing.interfaces import LogParser
from provloom.parsing.parsers.common import coerce_optional_int, decode_raw_object
from provloom.parsing.time_utils import parse_utc_timestamp


class ZeekJsonParser(LogParser):
    @property
    def parser_id(self) -> str:
        return "zeek_json"

    @property
    def parser_version(self) -> str:
        return "1.0.0"

    def supports(self, raw_event: RawEvent) -> bool:
        return raw_event.source_type.lower().startswith("zeek")

    def parse(self, raw_event: RawEvent) -> ParsedEnvelope:
        obj = decode_raw_object(raw_event)
        flat: dict[str, Any] = dict(obj)
        # Normalize nested Zeek {"id": {"orig_h": ...}} into standard dotted keys.
        if isinstance(flat.get("id"), dict):
            id_obj = flat.pop("id")
            for k, v in id_obj.items():
                flat.setdefault(f"id.{k}", v)

        occurred_at = parse_utc_timestamp(flat.get("ts") or flat.get("@timestamp"))
        for port_key in ("id.orig_p", "id.resp_p", "orig_bytes", "resp_bytes"):
            if port_key in flat and flat[port_key] is not None:
                flat[port_key] = coerce_optional_int(flat[port_key])

        st = raw_event.source_type.lower()
        inferred_path = st.split("_", 1)[1] if "_" in st else None
        log_path = str(flat.get("_path") or inferred_path or "unknown")
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
