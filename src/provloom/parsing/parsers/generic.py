from __future__ import annotations

from provloom.domain.parsed_models import ParsedEnvelope
from provloom.domain.raw_models import RawEvent
from provloom.parsing.interfaces import LogParser
from provloom.parsing.parsers.common import decode_raw_object
from provloom.parsing.time_utils import parse_utc_timestamp


class GenericJsonCsvParser(LogParser):
    """Fallback parser for custom sources so valid records reach OCSF passthrough."""

    @property
    def parser_id(self) -> str:
        return "generic"

    @property
    def parser_version(self) -> str:
        return "1.0.0"

    def supports(self, raw_event: RawEvent) -> bool:
        return True

    def parse(self, raw_event: RawEvent) -> ParsedEnvelope:
        fields = decode_raw_object(raw_event)
        ts_val = (
            fields.get("timestamp")
            or fields.get("time")
            or fields.get("@timestamp")
            or fields.get("UtcTime")
            or fields.get("ts")
        )
        occurred_at = parse_utc_timestamp(ts_val) if ts_val is not None else raw_event.ingested_at
        ev_code = fields.get("event_type") or fields.get("EventID")
        orig_uid = fields.get("event_uid") or fields.get("id") or raw_event.external_event_uid
        return ParsedEnvelope(
            raw_event_id=raw_event.raw_event_id,
            tenant_scope=raw_event.tenant_scope,
            source_id=raw_event.source_id,
            parser_id=self.parser_id,
            parser_version=self.parser_version,
            occurred_at=occurred_at,
            event_code=str(ev_code) if ev_code is not None else None,
            vendor="Custom",
            product=raw_event.source_type,
            original_event_uid=str(orig_uid) if orig_uid is not None else None,
            extracted_fields=fields,
        )
