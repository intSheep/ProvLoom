from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Any
from uuid import NAMESPACE_URL, uuid5

import yaml

from provloom.domain.enums import NormalizationStatus
from provloom.domain.errors import NormalizationError
from provloom.domain.ocsf_models import NormalizedEvent
from provloom.domain.parsed_models import ParsedEnvelope
from provloom.normalization.fallback import FallbackNormalizer
from provloom.normalization.interfaces import (
    MappingRegistry,
    MappingSpecSummary,
    NormalizationService,
    OcsfMapper,
)


def _assign_dotted(target: dict[str, Any], dotted_path: str, value: Any) -> None:
    parts = dotted_path.split(".")
    cur = target
    for p in parts[:-1]:
        nxt = cur.get(p)
        if not isinstance(nxt, dict):
            nxt = {}
            cur[p] = nxt
        cur = nxt
    cur[parts[-1]] = value


def _normalize_dns_answers(raw_val: Any) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    if isinstance(raw_val, list):
        for elem in raw_val:
            if isinstance(elem, dict) and elem.get("rdata") is not None:
                items.append(dict(elem))
            elif elem is not None:
                s = str(elem).strip()
                if s:
                    items.append({"rdata": s})
    elif isinstance(raw_val, str):
        for part in raw_val.replace(",", ";").split(";"):
            s = part.strip()
            if s:
                items.append({"rdata": s})
    return items


def _ensure_file_object_defaults(file_obj: dict[str, Any]) -> None:
    file_obj.setdefault("type_id", 1)
    if not file_obj.get("name"):
        raw_path = str(file_obj.get("path") or "").strip()
        basename = raw_path.replace("/", "\\").rsplit("\\", 1)[-1]
        file_obj["name"] = basename or "unknown"


_ACTOR_KEYS: tuple[str, ...] = ("process", "user", "invoked_by", "session", "app_name", "app_uid")
_ENDPOINT_KEYS: tuple[str, ...] = (
    "ip",
    "uid",
    "name",
    "hostname",
    "svc_name",
    "instance_uid",
    "interface_uid",
    "interface_name",
    "domain",
)


def _has_any_attr(obj: Any, keys: tuple[str, ...]) -> bool:
    if not isinstance(obj, dict):
        return False
    for k in keys:
        val = obj.get(k)
        if val is not None and val != "" and val != {} and val != []:
            return True
    return False


def _product_name_fallback(payload: dict[str, Any], default: str = "system") -> str:
    meta = payload.get("metadata")
    if isinstance(meta, dict):
        prod = meta.get("product")
        if isinstance(prod, dict) and prod.get("name"):
            return str(prod["name"])
    return default


def _finalize_ocsf_v140_objects(payload: dict[str, Any], class_uid: int) -> None:
    if class_uid in (1001, 1007, 1009, 5001):
        payload.setdefault("device", {})
    if class_uid in (1001, 1007, 1009, 6003):
        payload.setdefault("actor", {})
    if class_uid == 3002:
        payload.setdefault("user", {})
    if class_uid == 6001:
        payload.setdefault("web_resources", [])
    if class_uid == 6002:
        payload.setdefault("app", {})

    dev = payload.get("device")
    if isinstance(dev, dict):
        dev.setdefault("type_id", 0)
        if isinstance(dev.get("os"), dict):
            dev["os"].setdefault("type_id", 0)

    conn = payload.get("connection_info")
    if isinstance(conn, dict):
        conn.setdefault("direction_id", 0)

    top_file = payload.get("file")
    if isinstance(top_file, dict):
        _ensure_file_object_defaults(top_file)

    if class_uid == 1007:
        actor = payload.get("actor")
        if isinstance(actor, dict) and not _has_any_attr(actor, _ACTOR_KEYS):
            proc = payload.get("process")
            if isinstance(proc, dict):
                parent = proc.get("parent_process")
                cand = (
                    parent
                    if payload.get("activity_id") == 1
                    and isinstance(parent, dict)
                    and (parent.get("pid") is not None or parent.get("uid"))
                    else proc
                )
                actor_proc: dict[str, Any] = {}
                if cand.get("uid"):
                    actor_proc["uid"] = cand["uid"]
                if cand.get("pid") is not None:
                    actor_proc["pid"] = cand["pid"]
                if isinstance(cand.get("file"), dict):
                    actor_proc["file"] = dict(cand["file"])
                if actor_proc.get("pid") is not None or actor_proc.get("uid"):
                    actor["process"] = actor_proc
            if not _has_any_attr(actor, _ACTOR_KEYS):
                actor["app_name"] = _product_name_fallback(payload)

    if class_uid == 1001:
        actor = payload.get("actor")
        if isinstance(actor, dict) and not _has_any_attr(actor, _ACTOR_KEYS):
            actor["app_name"] = _product_name_fallback(payload)

    if class_uid == 1009:
        script = payload.setdefault("script", {})
        if isinstance(script, dict):
            raw_tid = script.get("type_id")
            if isinstance(raw_tid, bool) or raw_tid is None:
                script["type_id"] = 0
            elif isinstance(raw_tid, str):
                script["type_id"] = int(raw_tid) if raw_tid.strip().isdigit() else 0
            sc = script.get("script_content")
            if isinstance(sc, str):
                script["script_content"] = {"value": sc}
            elif isinstance(sc, dict):
                val = sc.get("value")
                sc["value"] = "" if val is None else str(val)
            else:
                script["script_content"] = {"value": str(payload.get("message") or "")}
            if isinstance(script.get("file"), dict):
                _ensure_file_object_defaults(script["file"])
        actor = payload.get("actor")
        if isinstance(actor, dict) and not _has_any_attr(actor, _ACTOR_KEYS):
            actor["app_name"] = _product_name_fallback(payload, default="script")

    if (
        class_uid == 4003
        and not _has_any_attr(payload.get("src_endpoint"), _ENDPOINT_KEYS)
        and not _has_any_attr(payload.get("dst_endpoint"), _ENDPOINT_KEYS)
        and isinstance(dev, dict)
        and (dev.get("hostname") or dev.get("ip"))
    ):
        payload["src_endpoint"] = {k: dev[k] for k in ("hostname", "ip") if dev.get(k)}

    if class_uid == 3002:
        svc = payload.get("service")
        has_svc = isinstance(svc, dict) and bool(svc.get("name") or svc.get("uid"))
        if (
            not has_svc
            and not _has_any_attr(payload.get("dst_endpoint"), _ENDPOINT_KEYS)
            and isinstance(dev, dict)
            and (dev.get("hostname") or dev.get("ip"))
        ):
            payload["dst_endpoint"] = {k: dev[k] for k in ("hostname", "ip") if dev.get(k)}

    for proc_holder in (payload.get("process"), (payload.get("actor") or {}).get("process")):
        if isinstance(proc_holder, dict):
            pfile = proc_holder.get("file")
            if isinstance(pfile, dict):
                _ensure_file_object_defaults(pfile)
            parent = proc_holder.get("parent_process")
            if isinstance(parent, dict) and isinstance(parent.get("file"), dict):
                _ensure_file_object_defaults(parent["file"])

    meta = payload.get("metadata")
    if isinstance(meta, dict):
        profiles: set[str] = {str(p) for p in (meta.get("profiles") or []) if isinstance(p, str)}
        if (
            class_uid in (3002, 4001, 4003, 6001, 6002, 6003) and payload.get("device") is not None
        ) or (class_uid in (4001, 4003, 6001, 6002) and payload.get("actor") is not None):
            profiles.add("host")
        if any(
            payload.get(k) is not None
            for k in ("disposition", "disposition_id", "action", "action_id", "firewall_rule")
        ):
            profiles.add("security_control")
        if profiles:
            meta["profiles"] = sorted(profiles)


class YamlOcsfMapper(OcsfMapper):
    def __init__(self, spec: MappingSpecSummary, field_map: dict[str, str]) -> None:
        self._spec = spec
        self._field_map = field_map

    @property
    def spec(self) -> MappingSpecSummary:
        return self._spec

    def matches(self, parsed: ParsedEnvelope) -> bool:
        if parsed.parser_id != self._spec.parser_id:
            return False
        if self._spec.event_code is None:
            return True
        return parsed.event_code == self._spec.event_code

    def map_event(self, parsed: ParsedEnvelope) -> NormalizedEvent:
        ev_id = uuid5(NAMESPACE_URL, f"provloom:event:{parsed.raw_event_id}")
        payload: dict[str, Any] = {
            "category_uid": self._spec.category_uid,
            "class_uid": self._spec.class_uid,
            "activity_id": self._spec.activity_id,
            "type_uid": self._spec.class_uid * 100 + self._spec.activity_id,
            "severity_id": 1,
            "time": int(parsed.occurred_at.timestamp() * 1000),
            "metadata": {
                "version": self._spec.ocsf_version,
                "uid": str(ev_id),
                "original_uid": parsed.original_event_uid,
                "product": {
                    "vendor_name": parsed.vendor or "Unknown",
                    "name": parsed.product or parsed.parser_id,
                },
            },
        }
        consumed_keys: set[str] = set()
        for ocsf_path, src_key in self._field_map.items():
            if src_key in parsed.extracted_fields:
                consumed_keys.add(src_key)
                val = parsed.extracted_fields[src_key]
                if val is None or val == "":
                    continue
                if ocsf_path in ("answers", "answers.rdata"):
                    ans_objs = _normalize_dns_answers(val)
                    if ans_objs:
                        payload["answers"] = ans_objs
                elif ocsf_path == "file.hashes.value":
                    _assign_dotted(
                        payload,
                        "file.hashes",
                        [{"algorithm_id": 3, "algorithm": "SHA-256", "value": str(val)}],
                    )
                elif ocsf_path == "web_resources.url_string":
                    payload["web_resources"] = [{"name": str(val), "url_string": str(val)}]
                else:
                    _assign_dotted(payload, ocsf_path, val)

        _finalize_ocsf_v140_objects(payload, self._spec.class_uid)

        orig_uid = payload["metadata"].get("original_uid") or parsed.original_event_uid
        if orig_uid is not None:
            orig_uid = str(orig_uid)
            payload["metadata"]["original_uid"] = orig_uid

        explicit_unmapped = (
            dict(payload["unmapped"]) if isinstance(payload.get("unmapped"), dict) else {}
        )
        rest_unmapped = {k: v for k, v in parsed.extracted_fields.items() if k not in consumed_keys}
        merged_unmapped = {**explicit_unmapped, **rest_unmapped}
        if merged_unmapped:
            payload["unmapped"] = merged_unmapped

        return NormalizedEvent(
            event_id=ev_id,
            raw_event_id=parsed.raw_event_id,
            tenant_scope=parsed.tenant_scope,
            source_id=parsed.source_id,
            ocsf_version=self._spec.ocsf_version,
            category_uid=self._spec.category_uid,
            class_uid=self._spec.class_uid,
            activity_id=self._spec.activity_id,
            event_time=parsed.occurred_at,
            normalization_status=NormalizationStatus.MAPPED,
            mapping_rule_id=self._spec.rule_id,
            original_event_uid=orig_uid,
            ocsf_payload=payload,
            unmapped_fields=merged_unmapped,
        )


class DefaultMappingRegistry(MappingRegistry):
    def __init__(self) -> None:
        self._mappers: list[OcsfMapper] = []

    def register(self, mapper: OcsfMapper) -> None:
        self._mappers.append(mapper)

    def match(self, parsed: ParsedEnvelope) -> OcsfMapper | None:
        for mapper in self._mappers:
            if mapper.matches(parsed):
                return mapper
        return None

    def list_specs(self) -> Sequence[MappingSpecSummary]:
        return tuple(m.spec for m in self._mappers)

    @classmethod
    def from_yaml_dir(cls, directory: str | Path) -> DefaultMappingRegistry:
        reg = cls()
        root = Path(directory)
        if not root.is_dir():
            raise NormalizationError(f"Mappings directory does not exist: {root}")
        for path in sorted(root.glob("*.yaml")):
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
            if not isinstance(doc, dict):
                continue
            match_cfg = doc.get("match", {})
            target_cfg = doc.get("target", {})
            spec = MappingSpecSummary(
                rule_id=str(doc["rule_id"]),
                rule_version=str(doc.get("rule_version", "1.0.0")),
                ocsf_version=str(doc.get("ocsf_version", "1.4.0")),
                parser_id=str(match_cfg["parser_id"]),
                event_code=(
                    str(match_cfg["event_code"])
                    if match_cfg.get("event_code") is not None
                    else None
                ),
                category_uid=int(target_cfg["category_uid"]),
                class_uid=int(target_cfg["class_uid"]),
                activity_id=int(target_cfg["activity_id"]),
            )
            fields = {str(k): str(v) for k, v in (doc.get("fields") or {}).items()}
            reg.register(YamlOcsfMapper(spec=spec, field_map=fields))
        return reg


class DefaultNormalizationService(NormalizationService):
    def __init__(
        self,
        registry: MappingRegistry,
        ocsf_version: str = "1.4.0",
    ) -> None:
        self._registry = registry
        self._fallback = FallbackNormalizer(ocsf_version=ocsf_version)

    def normalize(self, parsed: ParsedEnvelope) -> NormalizedEvent:
        mapper = self._registry.match(parsed)
        if mapper is None:
            return self._fallback.wrap(parsed)
        return mapper.map_event(parsed)
