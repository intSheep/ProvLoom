from __future__ import annotations

from provloom.domain.parsed_models import ParsedEnvelope
from provloom.domain.raw_models import RawEvent
from provloom.parsing.interfaces import LogParser
from provloom.parsing.parsers.common import (
    clean_sentinel,
    coerce_optional_int,
    decode_raw_object,
    detect_winlog_channel,
    flatten_winlogbeat_ecs,
)
from provloom.parsing.time_utils import parse_utc_timestamp

_AUTH_SENTINEL_KEYS = (
    "IpAddress",
    "ServiceName",
    "TargetUserSid",
    "TargetUserName",
    "TargetDomainName",
)


class AuthLogParser(LogParser):
    @property
    def parser_id(self) -> str:
        return "auth"

    @property
    def parser_version(self) -> str:
        return "1.1.0"

    def supports(self, raw_event: RawEvent) -> bool:
        st = raw_event.source_type.lower()
        if st in {"auth", "win_security", "linux_auth", "iam"}:
            return True
        if st in {"winlogbeat", "winlog", "windows", "xmlwineventlog"}:
            return detect_winlog_channel(raw_event.raw_payload) == "security"
        return False

    def parse(self, raw_event: RawEvent) -> ParsedEnvelope:
        obj = decode_raw_object(raw_event)
        fields = flatten_winlogbeat_ecs(obj) if isinstance(obj.get("winlog"), dict) else dict(obj)

        if not fields.get("Computer") and fields.get("Hostname"):
            fields["Computer"] = fields["Hostname"]
        if not fields.get("EventRecordID") and fields.get("RecordNumber") is not None:
            fields["EventRecordID"] = str(fields["RecordNumber"])

        for key in _AUTH_SENTINEL_KEYS:
            if key in fields:
                cleaned = clean_sentinel(fields[key])
                if cleaned is None:
                    fields.pop(key, None)
                else:
                    fields[key] = cleaned

        ts_val = (
            fields.get("TimeCreated")
            or fields.get("timestamp")
            or fields.get("time")
            or fields.get("@timestamp")
            or fields.get("EventTime")
        )
        occurred_at = parse_utc_timestamp(ts_val)

        for int_key in ("LogonType", "SourcePort"):
            if int_key in fields:
                cleaned_int = clean_sentinel(fields[int_key])
                if cleaned_int is None:
                    fields.pop(int_key, None)
                else:
                    fields[int_key] = coerce_optional_int(cleaned_int)

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
