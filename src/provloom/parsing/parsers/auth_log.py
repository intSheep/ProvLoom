from __future__ import annotations

from provloom.domain.parsed_models import ParsedEnvelope
from provloom.domain.raw_models import RawEvent
from provloom.parsing.interfaces import LogParser
from provloom.parsing.parsers.common import coerce_optional_int, decode_raw_object
from provloom.parsing.time_utils import parse_utc_timestamp


class AuthLogParser(LogParser):
    @property
    def parser_id(self) -> str:
        return "auth"

    @property
    def parser_version(self) -> str:
        return "1.0.0"

    def supports(self, raw_event: RawEvent) -> bool:
        return raw_event.source_type.lower() in {"auth", "win_security", "linux_auth", "iam"}

    def parse(self, raw_event: RawEvent) -> ParsedEnvelope:
        fields = decode_raw_object(raw_event)
        ts_val = fields.get("TimeCreated") or fields.get("timestamp") or fields.get("time")
        occurred_at = parse_utc_timestamp(ts_val)
        if "LogonType" in fields:
            fields["LogonType"] = coerce_optional_int(fields["LogonType"])
        if "SourcePort" in fields:
            fields["SourcePort"] = coerce_optional_int(fields["SourcePort"])

        ev_code = str(fields.get("EventID") or fields.get("event_type") or "auth")
        orig_uid = (
            fields.get("EventRecordID") or fields.get("event_uid") or raw_event.external_event_uid
        )
        return ParsedEnvelope(
            raw_event_id=raw_event.raw_event_id,
            tenant_scope=raw_event.tenant_scope,
            source_id=raw_event.source_id,
            parser_id=self.parser_id,
            parser_version=self.parser_version,
            occurred_at=occurred_at,
            event_code=ev_code,
            vendor="Identity",
            product="AuthSubsystem",
            original_event_uid=str(orig_uid) if orig_uid is not None else None,
            extracted_fields=fields,
        )
