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
                if val is not None and val != "":
                    _assign_dotted(payload, ocsf_path, val)

        orig_uid = payload["metadata"].get("original_uid") or parsed.original_event_uid
        if orig_uid is not None:
            orig_uid = str(orig_uid)
            payload["metadata"]["original_uid"] = orig_uid

        unmapped = {k: v for k, v in parsed.extracted_fields.items() if k not in consumed_keys}
        if unmapped:
            payload["unmapped"] = unmapped

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
            unmapped_fields=unmapped,
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
                ocsf_version=str(doc.get("ocsf_version", "1.3.0")),
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
        ocsf_version: str = "1.3.0",
    ) -> None:
        self._registry = registry
        self._fallback = FallbackNormalizer(ocsf_version=ocsf_version)

    def normalize(self, parsed: ParsedEnvelope) -> NormalizedEvent:
        mapper = self._registry.match(parsed)
        if mapper is None:
            return self._fallback.wrap(parsed)
        return mapper.map_event(parsed)
