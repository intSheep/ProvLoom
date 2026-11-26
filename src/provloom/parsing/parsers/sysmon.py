from __future__ import annotations

from typing import Any

from provloom.domain.errors import LogParseError
from provloom.domain.parsed_models import ParsedEnvelope
from provloom.domain.raw_models import RawEvent
from provloom.parsing.interfaces import LogParser
from provloom.parsing.parsers.common import (
    clean_sentinel,
    coerce_optional_int,
    decode_raw_object,
    detect_winlog_channel,
    extract_sha256_hash,
    flatten_winlogbeat_ecs,
)
from provloom.parsing.time_utils import parse_utc_timestamp

_SENTINEL_STR_KEYS = (
    "User",
    "ProcessGuid",
    "Image",
    "CommandLine",
    "ParentProcessGuid",
    "ParentImage",
    "ParentCommandLine",
    "TargetFilename",
    "SourceIp",
    "DestinationIp",
    "Protocol",
    "QueryName",
    "QueryResults",
)


class SysmonParser(LogParser):
    @property
    def parser_id(self) -> str:
        return "sysmon"

    @property
    def parser_version(self) -> str:
        return "1.1.0"

    def supports(self, raw_event: RawEvent) -> bool:
        st = raw_event.source_type.lower()
        if st.startswith("sysmon"):
            return True
        if st in {"winlogbeat", "winlog", "windows", "xmlwineventlog"}:
            return detect_winlog_channel(raw_event.raw_payload) == "sysmon"
        return False

    def parse(self, raw_event: RawEvent) -> ParsedEnvelope:
        obj = decode_raw_object(raw_event)
        flat: dict[str, Any] = {}
        if isinstance(obj.get("Event"), dict):
            ev = obj["Event"]
            if isinstance(ev.get("System"), dict):
                flat.update(ev["System"])
            if isinstance(ev.get("EventData"), dict):
                flat.update(ev["EventData"])
        elif isinstance(obj.get("winlog"), dict):
            flat = flatten_winlogbeat_ecs(obj)
        else:
            flat.update(obj)

        if not flat.get("Computer") and flat.get("Hostname"):
            flat["Computer"] = flat["Hostname"]
        if not flat.get("EventRecordID") and flat.get("RecordNumber") is not None:
            flat["EventRecordID"] = str(flat["RecordNumber"])
        if "sha256" not in flat and flat.get("Hashes"):
            sha = extract_sha256_hash(flat["Hashes"])
            if sha:
                flat["sha256"] = sha

        for key in _SENTINEL_STR_KEYS:
            if key in flat:
                cleaned = clean_sentinel(flat[key])
                if cleaned is None:
                    flat.pop(key, None)
                else:
                    flat[key] = cleaned

        event_id = flat.get("EventID")
        if event_id is None:
            raise LogParseError("Sysmon record missing EventID")

        ts_raw = (
            flat.get("UtcTime")
            or flat.get("TimeCreated")
            or flat.get("@timestamp")
            or flat.get("EventTime")
        )
        occurred_at = parse_utc_timestamp(ts_raw)

        for int_key in ("ProcessId", "ParentProcessId", "SourcePort", "DestinationPort"):
            if int_key in flat:
                cleaned_int = clean_sentinel(flat[int_key])
                if cleaned_int is None:
                    flat.pop(int_key, None)
                else:
                    flat[int_key] = coerce_optional_int(cleaned_int)

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
