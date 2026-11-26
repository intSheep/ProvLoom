from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from typing import Any

from provloom.domain.errors import LogParseError
from provloom.domain.raw_models import RawEvent

_MSG_KV_RE = re.compile(r"^([A-Za-z][A-Za-z0-9_]+):\s*(.*)$")
_SHA256_RE = re.compile(r"SHA256=([0-9A-Fa-f]{64})")


def clean_sentinel(value: Any) -> Any:
    if isinstance(value, str):
        s = value.strip()
        if s in {"", "-", "(empty)"}:
            return None
        return s
    return value


def parse_sysmon_message_kvs(message: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in message.splitlines():
        m = _MSG_KV_RE.match(line.strip())
        if m:
            out[m.group(1)] = m.group(2).strip()
    return out


def extract_sha256_hash(raw_hashes: Any) -> str | None:
    if not isinstance(raw_hashes, str) or not raw_hashes.strip():
        return None
    m = _SHA256_RE.search(raw_hashes)
    return m.group(1).lower() if m else None


def _strip_ns(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def parse_win_xml_event(raw_xml: str) -> dict[str, Any]:
    try:
        root = ET.fromstring(raw_xml.strip())
    except ET.ParseError as exc:
        raise LogParseError(f"Invalid Windows Event XML: {exc}") from exc

    if _strip_ns(root.tag) != "Event":
        raise LogParseError(f"Expected <Event> root element, got <{_strip_ns(root.tag)}>")

    flat: dict[str, Any] = {}
    for child in root:
        cname = _strip_ns(child.tag)
        if cname == "System":
            for sub in child:
                sname = _strip_ns(sub.tag)
                if sname == "Provider" and sub.attrib.get("Name"):
                    flat["Provider"] = sub.attrib["Name"]
                elif sname == "TimeCreated" and sub.attrib.get("SystemTime"):
                    flat["TimeCreated"] = sub.attrib["SystemTime"]
                elif sub.text and sub.text.strip():
                    flat[sname] = sub.text.strip()
        elif cname in {"EventData", "UserData"}:
            for data in child.iter():
                if _strip_ns(data.tag) == "Data" and data.attrib.get("Name"):
                    val = clean_sentinel(data.text)
                    if val is not None:
                        flat[data.attrib["Name"]] = val

    if "sha256" not in flat and flat.get("Hashes"):
        sha = extract_sha256_hash(flat["Hashes"])
        if sha:
            flat["sha256"] = sha
    return flat


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def flatten_winlogbeat_ecs(obj: dict[str, Any]) -> dict[str, Any]:
    """Flatten ECS Winlogbeat records into canonical Sysmon/Security/PowerShell keys."""
    flat: dict[str, Any] = dict(obj)
    wl = obj.get("winlog")
    if not isinstance(wl, dict):
        return flat

    ed = as_dict(wl.get("event_data"))
    ev = as_dict(obj.get("event"))
    host = as_dict(obj.get("host"))
    proc = as_dict(obj.get("process"))
    parent = as_dict(proc.get("parent"))
    file_obj = as_dict(obj.get("file"))
    dns_obj = as_dict(obj.get("dns"))
    hash_obj = as_dict(obj.get("hash"))
    src_obj = as_dict(obj.get("source"))
    dst_obj = as_dict(obj.get("destination"))
    net_obj = as_dict(obj.get("network"))
    wl_user = as_dict(wl.get("user"))
    msg_kvs = parse_sysmon_message_kvs(str(obj.get("message") or ""))

    def _pick(*cands: Any) -> Any:
        for c in cands:
            cleaned = clean_sentinel(c)
            if cleaned is not None:
                return cleaned
        return None

    eid = wl.get("event_id") if wl.get("event_id") is not None else ev.get("code")
    if eid is not None:
        flat.setdefault("EventID", eid)
    if wl.get("record_id") is not None:
        flat.setdefault("EventRecordID", str(wl["record_id"]))
    if host.get("name") or wl.get("computer_name"):
        flat.setdefault("Computer", str(host.get("name") or wl.get("computer_name")).strip())
    if wl.get("channel"):
        flat.setdefault("Channel", str(wl["channel"]))
    if wl.get("provider_name") or ev.get("provider"):
        flat.setdefault("Provider", str(wl.get("provider_name") or ev.get("provider")))

    utc_time = _pick(ed.get("UtcTime"), msg_kvs.get("UtcTime"), obj.get("@timestamp"))
    if utc_time is not None:
        flat.setdefault("UtcTime", utc_time)
    time_created = _pick(ed.get("TimeCreated"), obj.get("@timestamp"), ev.get("created"))
    if time_created is not None:
        flat.setdefault("TimeCreated", time_created)

    user_val = _pick(ed.get("User"), msg_kvs.get("User"))
    if user_val is None and wl_user.get("name"):
        dom = clean_sentinel(wl_user.get("domain"))
        uname = clean_sentinel(wl_user.get("name"))
        user_val = f"{dom}\\{uname}" if dom and uname else uname
    if user_val is not None:
        flat.setdefault("User", user_val)

    mappings: tuple[tuple[str, Any], ...] = (
        (
            "ProcessGuid",
            _pick(ed.get("ProcessGuid"), proc.get("entity_id"), msg_kvs.get("ProcessGuid")),
        ),
        ("ProcessId", _pick(ed.get("ProcessId"), proc.get("pid"), msg_kvs.get("ProcessId"))),
        ("Image", _pick(ed.get("Image"), proc.get("executable"), msg_kvs.get("Image"))),
        (
            "CommandLine",
            _pick(ed.get("CommandLine"), proc.get("command_line"), msg_kvs.get("CommandLine")),
        ),
        (
            "ParentProcessGuid",
            _pick(
                ed.get("ParentProcessGuid"),
                parent.get("entity_id"),
                msg_kvs.get("ParentProcessGuid"),
            ),
        ),
        (
            "ParentProcessId",
            _pick(ed.get("ParentProcessId"), parent.get("pid"), msg_kvs.get("ParentProcessId")),
        ),
        (
            "ParentImage",
            _pick(ed.get("ParentImage"), parent.get("executable"), msg_kvs.get("ParentImage")),
        ),
        (
            "ParentCommandLine",
            _pick(
                ed.get("ParentCommandLine"),
                parent.get("command_line"),
                msg_kvs.get("ParentCommandLine"),
            ),
        ),
        (
            "TargetFilename",
            _pick(ed.get("TargetFilename"), file_obj.get("path"), msg_kvs.get("TargetFilename")),
        ),
        ("SourceIp", _pick(ed.get("SourceIp"), src_obj.get("ip"), msg_kvs.get("SourceIp"))),
        ("SourcePort", _pick(ed.get("SourcePort"), src_obj.get("port"), msg_kvs.get("SourcePort"))),
        (
            "DestinationIp",
            _pick(ed.get("DestinationIp"), dst_obj.get("ip"), msg_kvs.get("DestinationIp")),
        ),
        (
            "DestinationPort",
            _pick(ed.get("DestinationPort"), dst_obj.get("port"), msg_kvs.get("DestinationPort")),
        ),
        ("Protocol", _pick(ed.get("Protocol"), net_obj.get("transport"), msg_kvs.get("Protocol"))),
        (
            "QueryName",
            _pick(
                ed.get("QueryName"),
                (dns_obj.get("question") or {}).get("name")
                if isinstance(dns_obj.get("question"), dict)
                else None,
                msg_kvs.get("QueryName"),
            ),
        ),
        ("TargetUserSid", _pick(ed.get("TargetUserSid"), wl_user.get("identifier"))),
        ("TargetUserName", _pick(ed.get("TargetUserName"), wl_user.get("name"))),
        ("TargetDomainName", _pick(ed.get("TargetDomainName"), wl_user.get("domain"))),
        ("LogonType", _pick(ed.get("LogonType"))),
        ("IpAddress", _pick(ed.get("IpAddress"), src_obj.get("ip"))),
        ("ServiceName", _pick(ed.get("ServiceName"))),
        ("ScriptBlockText", _pick(ed.get("ScriptBlockText"), ed.get("Payload"))),
        ("ScriptBlockId", _pick(ed.get("ScriptBlockId"))),
        ("Path", _pick(ed.get("Path"))),
    )
    for key, val in mappings:
        if val is not None:
            flat.setdefault(key, val)

    sha = _pick(
        hash_obj.get("sha256"),
        (proc.get("hash") or {}).get("sha256") if isinstance(proc.get("hash"), dict) else None,
    )
    if sha is None:
        sha = extract_sha256_hash(ed.get("Hashes") or msg_kvs.get("Hashes"))
    if sha is not None:
        flat.setdefault("sha256", str(sha).lower())

    resolved = dns_obj.get("resolved_ip")
    if isinstance(resolved, list) and resolved:
        joined = ";".join(str(x).strip() for x in resolved if clean_sentinel(x) is not None)
        if joined:
            flat.setdefault("QueryResults", joined)
    elif qres := _pick(ed.get("QueryResults"), msg_kvs.get("QueryResults")):
        flat.setdefault("QueryResults", qres)

    return flat


def detect_winlog_channel(raw_payload: str) -> str | None:
    stripped = raw_payload.lstrip()
    if stripped.startswith("<"):
        lower = stripped.lower()
        if "microsoft-windows-sysmon" in lower:
            return "sysmon"
        if "microsoft-windows-security-auditing" in lower or "<channel>security</channel>" in lower:
            return "security"
        if "powershell" in lower:
            return "powershell"
        return None
    if not stripped.startswith("{"):
        return None
    try:
        obj = json.loads(stripped)
    except json.JSONDecodeError:
        return None
    if not isinstance(obj, dict):
        return None
    wl = as_dict(obj.get("winlog"))
    ev = as_dict(obj.get("event"))
    hints = " ".join(
        str(x or "").lower()
        for x in (
            wl.get("channel"),
            wl.get("provider_name"),
            ev.get("module"),
            ev.get("provider"),
            obj.get("Channel"),
            obj.get("SourceName"),
        )
    )
    if "sysmon" in hints:
        return "sysmon"
    if "security" in hints:
        return "security"
    if "powershell" in hints:
        return "powershell"
    return None


def decode_raw_object(raw_event: RawEvent) -> dict[str, Any]:
    if raw_event.raw_metadata.get("format") == "csv":
        if raw_event.raw_metadata.get("csv_malformed"):
            raise LogParseError("Malformed CSV row: column count mismatch")
        fields = raw_event.raw_metadata.get("csv_fields")
        if isinstance(fields, dict):
            return dict(fields)

    if raw_event.raw_metadata.get("format") == "zeek_tsv":
        if raw_event.raw_metadata.get("tsv_malformed"):
            raise LogParseError("Malformed Zeek TSV row: column count mismatch")
        fields = raw_event.raw_metadata.get("tsv_fields")
        if isinstance(fields, dict):
            return dict(fields)

    stripped = raw_event.raw_payload.lstrip()
    if (
        raw_event.raw_metadata.get("format") == "xml"
        or raw_event.source_type.lower().startswith("xml")
    ) and stripped.startswith("<"):
        return parse_win_xml_event(raw_event.raw_payload)

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
