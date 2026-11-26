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
    flatten_winlogbeat_ecs,
)
from provloom.parsing.time_utils import parse_utc_timestamp


class PowerShellParser(LogParser):
    @property
    def parser_id(self) -> str:
        return "powershell"

    @property
    def parser_version(self) -> str:
        return "1.0.0"

    def supports(self, raw_event: RawEvent) -> bool:
        st = raw_event.source_type.lower()
        if "powershell" in st:
            return True
        if st in {"winlogbeat", "winlog", "windows", "xmlwineventlog"}:
            return detect_winlog_channel(raw_event.raw_payload) == "powershell"
        return False

    def parse(self, raw_event: RawEvent) -> ParsedEnvelope:
        obj = decode_raw_object(raw_event)
        flat: dict[str, Any] = (
            flatten_winlogbeat_ecs(obj) if isinstance(obj.get("winlog"), dict) else dict(obj)
        )

        event_id = flat.get("EventID")
        if event_id is None:
            raise LogParseError("PowerShell record missing EventID")

        ts_raw = (
            flat.get("EventTime")
            or flat.get("@timestamp")
            or flat.get("TimeCreated")
            or flat.get("EventReceivedTime")
        )
        occurred_at = parse_utc_timestamp(ts_raw)

        host_val = clean_sentinel(flat.get("Computer") or flat.get("Hostname") or flat.get("host"))
        if host_val:
            flat["Computer"] = str(host_val)

        orig_uid = (
            flat.get("EventRecordID") or flat.get("RecordNumber") or raw_event.external_event_uid
        )
        if orig_uid is not None:
            flat["EventRecordID"] = str(orig_uid)

        raw_pid = clean_sentinel(flat.get("ProcessId") or flat.get("ExecutionProcessID"))
        if raw_pid is not None:
            pid_int = coerce_optional_int(raw_pid)
            if pid_int is not None and pid_int > 0:
                flat["ProcessId"] = pid_int
            else:
                flat.pop("ProcessId", None)

        if not flat.get("User"):
            dom = clean_sentinel(flat.get("Domain"))
            acct = clean_sentinel(flat.get("AccountName"))
            if dom and acct:
                flat["User"] = f"{dom}\\{acct}"
            elif acct:
                flat["User"] = str(acct)

        script_text = (
            clean_sentinel(flat.get("ScriptBlockText"))
            or clean_sentinel(flat.get("Payload"))
            or clean_sentinel(flat.get("Message"))
            or clean_sentinel(flat.get("message"))
            or ""
        )
        flat["ScriptBlockText"] = str(script_text)

        script_path = clean_sentinel(flat.get("Path"))
        if script_path:
            flat["ScriptPath"] = str(script_path)
            flat["ScriptName"] = str(script_path).replace("/", "\\").rsplit("\\", 1)[-1]
        else:
            flat.setdefault("ScriptName", str(flat.get("SourceName") or "PowerShell"))

        sb_id = clean_sentinel(flat.get("ScriptBlockId"))
        if sb_id:
            flat["ScriptBlockId"] = str(sb_id)
        flat["ScriptTypeId"] = 5

        return ParsedEnvelope(
            raw_event_id=raw_event.raw_event_id,
            tenant_scope=raw_event.tenant_scope,
            source_id=raw_event.source_id,
            parser_id=self.parser_id,
            parser_version=self.parser_version,
            occurred_at=occurred_at,
            event_code=str(event_id),
            vendor="Microsoft",
            product="PowerShell",
            original_event_uid=str(orig_uid) if orig_uid is not None else None,
            extracted_fields=flat,
        )
