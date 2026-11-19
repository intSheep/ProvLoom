from __future__ import annotations

from typing import Any

from provloom.domain.errors import LogParseError
from provloom.domain.parsed_models import ParsedEnvelope
from provloom.domain.raw_models import RawEvent
from provloom.parsing.interfaces import LogParser
from provloom.parsing.parsers.common import coerce_optional_int, decode_raw_object
from provloom.parsing.time_utils import parse_utc_timestamp


class SysmonParser(LogParser):
    @property
    def parser_id(self) -> str:
        return "sysmon"

    @property
    def parser_version(self) -> str:
        return "1.0.0"

    def supports(self, raw_event: RawEvent) -> bool:
        return raw_event.source_type.lower().startswith("sysmon")

    def parse(self, raw_event: RawEvent) -> ParsedEnvelope:
        obj = decode_raw_object(raw_event)
        flat: dict[str, Any] = {}
        if isinstance(obj.get("Event"), dict):
            ev = obj["Event"]
            if isinstance(ev.get("System"), dict):
                flat.update(ev["System"])
            if isinstance(ev.get("EventData"), dict):
                flat.update(ev["EventData"])
        else:
            flat.update(obj)

        event_id = flat.get("EventID")
        if event_id is None:
            raise LogParseError("Sysmon record missing EventID")

        ts_raw = flat.get("UtcTime") or flat.get("TimeCreated") or flat.get("@timestamp")
        occurred_at = parse_utc_timestamp(ts_raw)

        for int_key in ("ProcessId", "ParentProcessId", "SourcePort", "DestinationPort"):
            if int_key in flat and flat[int_key] is not None:
                flat[int_key] = coerce_optional_int(flat[int_key])

        orig_uid = flat.get("EventRecordID") or raw_event.external_event_uid
        return ParsedEnvelope(
            raw_event_id=raw_event.raw_event_id,
            tenant_scope=raw_event.tenant_scope,
            source_id=raw_event.source_id,
            parser_id=self.parser_id,
            parser_version=self.parser_version,
            occurred_at=occurred_at,
            event_code=str(event_id),
            vendor="Microsoft",
            product="Sysmon",
            original_event_uid=str(orig_uid) if orig_uid is not None else None,
            extracted_fields=flat,
        )
