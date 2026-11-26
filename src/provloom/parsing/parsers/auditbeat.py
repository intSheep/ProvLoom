from __future__ import annotations

import ipaddress
from typing import Any

from provloom.domain.parsed_models import ParsedEnvelope
from provloom.domain.raw_models import RawEvent
from provloom.parsing.interfaces import LogParser
from provloom.parsing.parsers.common import (
    as_dict,
    clean_sentinel,
    coerce_optional_int,
    decode_raw_object,
)
from provloom.parsing.time_utils import parse_utc_timestamp

_EXEC_SYSCALLS = frozenset({"execve", "execveat"})
_FILE_WRITE_SYSCALLS = frozenset(
    {"creat", "ftruncate", "truncate", "rename", "renameat", "unlink", "unlinkat", "chmod", "chown"}
)
_FILE_OPEN_SYSCALLS = frozenset({"open", "openat", "read", "stat", "lstat", "access"})
_NET_SYSCALLS = frozenset({"connect", "accept", "accept4"})
_AUTH_MSG_TYPES = frozenset(
    {"user_auth", "user_acct", "user_login", "user_start", "cred_acq", "cred_refr"}
)


def _is_valid_ip(val: Any) -> str | None:
    s = clean_sentinel(val)
    if not isinstance(s, str):
        return None
    try:
        ipaddress.ip_address(s)
        return s
    except ValueError:
        return None


def _is_write_open_flags(raw_flags: Any) -> bool:
    if not isinstance(raw_flags, str) or not raw_flags.strip():
        return False
    try:
        flags = int(raw_flags.strip(), 16)
    except ValueError:
        return False
    # Linux open/openat: O_WRONLY (1), O_RDWR (2), O_CREAT (0x40), O_TRUNC (0x200)
    return (flags & 0x3) in {1, 2} or (flags & 0x240) != 0


def _pick_audit_file(obj: dict[str, Any], auditd: dict[str, Any]) -> tuple[str | None, bool]:
    file_obj = as_dict(obj.get("file"))
    raw_paths = auditd.get("paths")
    paths: list[Any] = raw_paths if isinstance(raw_paths, list) else []
    has_mutating_path = any(
        isinstance(p, dict) and str(p.get("nametype") or "").upper() in {"CREATE", "DELETE"}
        for p in paths
    )
    if file_obj.get("path"):
        return str(file_obj["path"]), has_mutating_path
    for target_type in ("CREATE", "DELETE", "NORMAL"):
        for p in paths:
            if (
                isinstance(p, dict)
                and str(p.get("nametype") or "").upper() == target_type
                and p.get("name")
            ):
                return str(p["name"]), has_mutating_path
    summary = as_dict(auditd.get("summary"))
    sum_obj = as_dict(summary.get("object"))
    if sum_obj.get("type") == "file" and sum_obj.get("primary"):
        return str(sum_obj["primary"]), has_mutating_path
    return None, has_mutating_path


class AuditbeatParser(LogParser):
    @property
    def parser_id(self) -> str:
        return "auditbeat"

    @property
    def parser_version(self) -> str:
        return "1.0.0"

    def supports(self, raw_event: RawEvent) -> bool:
        st = raw_event.source_type.lower()
        if st.startswith(("auditbeat", "linux_audit")):
            return True
        return st in {"ecs", "beats", "linux"} and '"auditd"' in raw_event.raw_payload

    def parse(self, raw_event: RawEvent) -> ParsedEnvelope:
        obj = decode_raw_object(raw_event)
        occurred_at = parse_utc_timestamp(obj.get("@timestamp") or obj.get("timestamp"))

        flat: dict[str, Any] = dict(obj)
        host = as_dict(obj.get("host"))
        agent = as_dict(obj.get("agent"))
        auditd = as_dict(obj.get("auditd"))
        data = as_dict(auditd.get("data"))
        summary = as_dict(auditd.get("summary"))
        sum_actor = as_dict(summary.get("actor"))
        proc = as_dict(obj.get("process"))
        ev = as_dict(obj.get("event"))
        user = as_dict(obj.get("user"))
        eff_user = as_dict(user.get("effective"))
        dst = as_dict(obj.get("destination"))
        src = as_dict(obj.get("source"))
        net = as_dict(obj.get("network"))
        svc = as_dict(obj.get("service"))

        host_name = clean_sentinel(
            host.get("name") or host.get("hostname") or agent.get("hostname")
        )
        if host_name:
            flat["host_name"] = host_name
        if host.get("id"):
            flat["host_id"] = str(host["id"])

        seq = auditd.get("sequence")
        orig_uid = str(seq) if seq is not None else raw_event.external_event_uid
        if orig_uid is not None:
            flat["event_uid"] = orig_uid

        if proc.get("pid") is not None:
            flat["pid"] = coerce_optional_int(clean_sentinel(proc["pid"]))
        if proc.get("ppid") is not None:
            flat["ppid"] = coerce_optional_int(clean_sentinel(proc["ppid"]))
        exe = clean_sentinel(proc.get("executable") or summary.get("how"))
        if exe:
            flat["executable"] = exe
        if proc.get("name"):
            flat["process_name"] = str(proc["name"])
        args_val = proc.get("args")
        cmd_line = clean_sentinel(proc.get("title")) or (
            " ".join(str(a) for a in args_val) if isinstance(args_val, list) and args_val else exe
        )
        if cmd_line:
            flat["cmd_line"] = cmd_line
        if proc.get("working_directory"):
            flat["working_dir"] = str(proc["working_directory"])

        user_name = None
        for cand_user in (
            user.get("name"),
            eff_user.get("name"),
            sum_actor.get("primary"),
            sum_actor.get("secondary"),
        ):
            c = clean_sentinel(cand_user)
            if isinstance(c, str) and c.lower() != "unset":
                user_name = c
                break
        if user_name:
            flat["user_name"] = user_name
        user_uid = clean_sentinel(user.get("id") or eff_user.get("id"))
        if user_uid is not None:
            flat["user_uid"] = str(user_uid)

        file_path, mut_path = _pick_audit_file(obj, auditd)
        if file_path:
            flat["file_path"] = file_path

        sock = as_dict(data.get("socket"))
        dst_ip = _is_valid_ip(dst.get("ip") or sock.get("addr"))
        if dst_ip:
            flat["dst_ip"] = dst_ip
        raw_dport = clean_sentinel(dst.get("port") or sock.get("port"))
        if raw_dport is not None:
            flat["dst_port"] = coerce_optional_int(raw_dport)
        src_ip = _is_valid_ip(src.get("ip"))
        if src_ip:
            flat["src_ip"] = src_ip
        raw_sport = clean_sentinel(src.get("port"))
        if raw_sport is not None:
            flat["src_port"] = coerce_optional_int(raw_sport)
        if net.get("transport") or dst_ip:
            flat["protocol"] = str(net.get("transport") or "tcp").lower()

        flat["service_name"] = str(svc.get("name") or proc.get("name") or "auditd")

        syscall = str(data.get("syscall") or "").lower()
        msg_type = str(auditd.get("message_type") or "").lower()
        action = str(ev.get("action") or "").lower()

        if syscall in _EXEC_SYSCALLS or action == "executed":
            ev_code = "execve"
        elif (syscall in _NET_SYSCALLS or action == "connected-to") and dst_ip is not None:
            ev_code = "network_connect"
        elif msg_type in _AUTH_MSG_TYPES or action in {
            "was-authorized",
            "logged-in",
            "authenticated",
        }:
            ev_code = "auth"
        elif file_path is not None and (
            syscall in _FILE_WRITE_SYSCALLS
            or mut_path
            or (syscall == "open" and _is_write_open_flags(data.get("a1")))
            or (syscall == "openat" and _is_write_open_flags(data.get("a2")))
        ):
            ev_code = "file_write"
        elif file_path is not None and syscall in _FILE_OPEN_SYSCALLS:
            ev_code = "file_read"
        else:
            ev_code = syscall or msg_type or "other"

        return ParsedEnvelope(
            raw_event_id=raw_event.raw_event_id,
            tenant_scope=raw_event.tenant_scope,
            source_id=raw_event.source_id,
            parser_id=self.parser_id,
            parser_version=self.parser_version,
            occurred_at=occurred_at,
            event_code=ev_code,
            vendor="Elastic",
            product="Auditbeat",
            original_event_uid=str(orig_uid) if orig_uid is not None else None,
            extracted_fields=flat,
        )
