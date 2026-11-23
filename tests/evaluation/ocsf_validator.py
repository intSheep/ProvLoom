from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from functools import lru_cache
from pathlib import Path
from typing import Any

OCSF_V140_SCHEMA_PATH = Path(__file__).resolve().parent / "fixtures" / "ocsf_v1_4_0_schema.json"
PINNED_OCSF_VERSION = "1.4.0"
PINNED_OCSF_TAG = "1.4.0"
PINNED_OCSF_COMMIT = "6109cc5e834c1adfee67dda6c9bcfa5e37f79012"

_INT_BASE_TYPES: frozenset[str] = frozenset({"integer_t", "long_t"})
_FLOAT_BASE_TYPES: frozenset[str] = frozenset({"float_t"})
_BOOL_BASE_TYPES: frozenset[str] = frozenset({"boolean_t"})


@lru_cache(maxsize=1)
def load_ocsf_v140_schema() -> dict[str, Any]:
    doc = json.loads(OCSF_V140_SCHEMA_PATH.read_text(encoding="utf-8"))
    assert isinstance(doc, dict)
    assert doc.get("schema_version") == PINNED_OCSF_VERSION
    assert doc.get("source_commit") == PINNED_OCSF_COMMIT
    return doc


def _resolve_scalar_base(type_name: str, scalar_types: Mapping[str, str]) -> str:
    cur = type_name
    visited: set[str] = set()
    while cur in scalar_types and cur not in visited:
        visited.add(cur)
        nxt = scalar_types[cur]
        if nxt == cur:
            break
        cur = nxt
    return cur


def _is_present_value(val: Any) -> bool:
    if val is None:
        return False
    if isinstance(val, (dict, list)) and len(val) == 0:
        return False
    return not (isinstance(val, str) and val == "")


def _has_nonempty_path(obj: Mapping[str, Any], dotted_key: str) -> bool:
    cur: Any = obj
    for part in dotted_key.split("."):
        if not isinstance(cur, Mapping) or part not in cur:
            return False
        cur = cur[part]
    return _is_present_value(cur)


def _check_constraints(
    obj: Mapping[str, Any],
    constraints: Mapping[str, Any] | None,
    path_prefix: str,
) -> list[str]:
    if not constraints:
        return []
    errs: list[str] = []
    at_least_one = constraints.get("at_least_one")
    if isinstance(at_least_one, Sequence) and not isinstance(at_least_one, (str, bytes)):
        keys = [str(k) for k in at_least_one]
        if not any(_has_nonempty_path(obj, k) for k in keys):
            errs.append(f"{path_prefix}: violated OCSF at_least_one constraint {keys}")
    just_one = constraints.get("just_one")
    if isinstance(just_one, Sequence) and not isinstance(just_one, (str, bytes)):
        keys = [str(k) for k in just_one]
        present = sum(1 for k in keys if _has_nonempty_path(obj, k))
        if present != 1:
            errs.append(
                f"{path_prefix}: violated OCSF just_one constraint {keys} (found {present})"
            )
    return errs


def _validate_value(
    val: Any,
    type_name: str,
    is_array: bool,
    path: str,
    active_profiles: frozenset[str],
    objects: Mapping[str, Mapping[str, Any]],
    scalar_types: Mapping[str, str],
    allow_provloom_metadata_original_uid: bool,
    check_required_nested: bool,
    *,
    object_constraints: Mapping[str, Mapping[str, Any]] | None = None,
    enum_keys: Sequence[str] | None = None,
    check_enums: bool = True,
    check_constraints: bool = True,
) -> list[str]:
    errs: list[str] = []
    if val is None:
        return errs

    if is_array:
        if not isinstance(val, list):
            return [f"{path}: expected array of {type_name}, got {type(val).__name__}"]
        for idx, item in enumerate(val):
            errs.extend(
                _validate_value(
                    item,
                    type_name,
                    False,
                    f"{path}[{idx}]",
                    active_profiles,
                    objects,
                    scalar_types,
                    allow_provloom_metadata_original_uid,
                    check_required_nested,
                    object_constraints=object_constraints,
                    enum_keys=enum_keys,
                    check_enums=check_enums,
                    check_constraints=check_constraints,
                )
            )
        return errs

    if type_name in ("object", "json_t"):
        if not isinstance(val, dict):
            return [f"{path}: expected JSON object, got {type(val).__name__}"]
        return errs

    if type_name in objects:
        if not isinstance(val, dict):
            return [f"{path}: expected OCSF object '{type_name}', got {type(val).__name__}"]
        obj_attrs = objects[type_name]
        if check_required_nested:
            for req_k, req_spec in obj_attrs.items():
                prof = req_spec.get("profile")
                if prof and prof not in active_profiles:
                    continue
                if req_spec.get("requirement") == "required" and (
                    req_k not in val or val[req_k] is None
                ):
                    errs.append(f"{path}.{req_k}: missing required attribute on '{type_name}'")
        if check_constraints and object_constraints is not None:
            errs.extend(_check_constraints(val, object_constraints.get(type_name), path))

        for k, sub_v in val.items():
            if (
                allow_provloom_metadata_original_uid
                and type_name == "metadata"
                and k == "original_uid"
            ):
                if sub_v is not None and not isinstance(sub_v, str):
                    errs.append(f"{path}.original_uid: expected string, got {type(sub_v).__name__}")
                continue
            if k not in obj_attrs:
                errs.append(
                    f"{path}.{k}: unknown attribute on OCSF {PINNED_OCSF_VERSION} object '{type_name}'"
                )
                continue
            spec = obj_attrs[k]
            prof = spec.get("profile")
            if prof and prof not in active_profiles and sub_v is not None:
                errs.append(
                    f"{path}.{k}: attribute belongs to profile '{prof}' not declared in metadata.profiles"
                )
            errs.extend(
                _validate_value(
                    sub_v,
                    str(spec["type"]),
                    bool(spec.get("is_array", False)),
                    f"{path}.{k}",
                    active_profiles,
                    objects,
                    scalar_types,
                    allow_provloom_metadata_original_uid,
                    check_required_nested,
                    object_constraints=object_constraints,
                    enum_keys=spec.get("enum_keys"),
                    check_enums=check_enums,
                    check_constraints=check_constraints,
                )
            )
        return errs

    base_t = _resolve_scalar_base(type_name, scalar_types)
    type_ok = True
    if base_t in _INT_BASE_TYPES:
        if isinstance(val, bool) or not isinstance(val, int):
            errs.append(f"{path}: expected {type_name} (int), got {type(val).__name__} ({val!r})")
            type_ok = False
    elif base_t in _FLOAT_BASE_TYPES:
        if isinstance(val, bool) or not isinstance(val, (int, float)):
            errs.append(f"{path}: expected {type_name} (float), got {type(val).__name__} ({val!r})")
            type_ok = False
    elif base_t in _BOOL_BASE_TYPES:
        if not isinstance(val, bool):
            errs.append(f"{path}: expected {type_name} (bool), got {type(val).__name__} ({val!r})")
            type_ok = False
    else:
        if not isinstance(val, str):
            errs.append(f"{path}: expected {type_name} (str), got {type(val).__name__} ({val!r})")
            type_ok = False

    if type_ok and check_enums and enum_keys:
        val_key = str(val).lower() if isinstance(val, bool) else str(val)
        if val_key not in enum_keys:
            errs.append(
                f"{path}: value {val!r} not in OCSF {PINNED_OCSF_VERSION} enum {list(enum_keys)}"
            )
    return errs


def validate_ocsf_v140_event(
    payload: Mapping[str, Any],
    *,
    allow_provloom_metadata_original_uid: bool = False,
    check_required: bool = True,
    check_enums: bool = True,
    check_constraints: bool = True,
) -> list[str]:
    schema = load_ocsf_v140_schema()
    events: Mapping[str, Any] = schema["events"]
    objects: Mapping[str, Mapping[str, Any]] = schema["objects"]
    object_constraints: Mapping[str, Mapping[str, Any]] = schema.get("object_constraints") or {}
    scalar_types: Mapping[str, str] = schema["scalar_types"]

    errs: list[str] = []
    raw_cid = payload.get("class_uid")
    if isinstance(raw_cid, bool) or not isinstance(raw_cid, int):
        return [f"class_uid: expected integer, got {raw_cid!r}"]

    ev_schema = events.get(str(raw_cid))
    if ev_schema is None:
        return [f"class_uid: unknown class_uid {raw_cid} in OCSF {PINNED_OCSF_VERSION}"]

    meta = payload.get("metadata")
    active_profiles: frozenset[str] = frozenset()
    if isinstance(meta, Mapping):
        ver = meta.get("version")
        if ver != PINNED_OCSF_VERSION:
            errs.append(f"metadata.version: expected {PINNED_OCSF_VERSION!r}, got {ver!r}")
        profs = meta.get("profiles")
        if isinstance(profs, list):
            active_profiles = frozenset(str(p) for p in profs if isinstance(p, str))
    elif check_required:
        errs.append("metadata: missing required metadata object")

    raw_cat = payload.get("category_uid")
    if raw_cat != ev_schema["category_uid"]:
        errs.append(
            f"category_uid: expected {ev_schema['category_uid']} for {ev_schema['name']} ({raw_cid}), got {raw_cat!r}"
        )

    raw_act = payload.get("activity_id")
    raw_type_uid = payload.get("type_uid")
    if isinstance(raw_act, int) and not isinstance(raw_act, bool):
        expected_type_uid = raw_cid * 100 + raw_act
        if raw_type_uid is not None and raw_type_uid != expected_type_uid:
            errs.append(
                f"type_uid: expected {expected_type_uid} (class_uid*100 + activity_id), got {raw_type_uid!r}"
            )

    ev_attrs: Mapping[str, Any] = ev_schema["attributes"]
    if check_required:
        for req_k, req_spec in ev_attrs.items():
            prof = req_spec.get("profile")
            if prof and prof not in active_profiles:
                continue
            if req_spec.get("requirement") == "required" and (
                req_k not in payload or payload[req_k] is None
            ):
                errs.append(
                    f"{req_k}: missing required top-level attribute on "
                    f"'{ev_schema['name']}' ({raw_cid})"
                )
    if check_constraints:
        errs.extend(_check_constraints(payload, ev_schema.get("constraints"), ev_schema["name"]))

    for k, v in payload.items():
        if k not in ev_attrs:
            errs.append(
                f"{k}: unknown top-level attribute on OCSF {PINNED_OCSF_VERSION} "
                f"class '{ev_schema['name']}' ({raw_cid})"
            )
            continue
        spec = ev_attrs[k]
        prof = spec.get("profile")
        if prof and prof not in active_profiles and v is not None:
            errs.append(
                f"{k}: attribute belongs to profile '{prof}' not declared in metadata.profiles"
            )
        errs.extend(
            _validate_value(
                v,
                str(spec["type"]),
                bool(spec.get("is_array", False)),
                k,
                active_profiles,
                objects,
                scalar_types,
                allow_provloom_metadata_original_uid,
                check_required,
                object_constraints=object_constraints,
                enum_keys=spec.get("enum_keys"),
                check_enums=check_enums,
                check_constraints=check_constraints,
            )
        )

    return errs


def validate_ocsf_v140_field_path(
    field_path: str,
    class_uids: Sequence[int] | None = None,
    *,
    allow_provloom_envelope: bool = True,
) -> list[str]:
    if allow_provloom_envelope and field_path in {
        "source_id",
        "ocsf_version",
        "original_event_uid",
        "metadata.original_uid",
    }:
        return []
    parts = field_path.split(".")
    if parts[0] == "unmapped" and len(parts) >= 2:
        return []

    schema = load_ocsf_v140_schema()
    events: Mapping[str, Any] = schema["events"]
    objects: Mapping[str, Mapping[str, Any]] = schema["objects"]

    target_cids = (
        [str(c) for c in class_uids]
        if class_uids
        else [cid for cid in sorted(events.keys(), key=int) if cid != "0"]
    )
    valid_classes: list[int] = []
    last_reason = (
        f"Field {field_path!r} not found in any target OCSF {PINNED_OCSF_VERSION} event class"
    )

    for cid_str in target_cids:
        ev = events.get(cid_str)
        if ev is None:
            return [f"Unknown OCSF {PINNED_OCSF_VERSION} class_uid: {cid_str}"]
        cur_attrs: Mapping[str, Any] = ev["attributes"]
        ok = True
        for idx, part in enumerate(parts):
            if part not in cur_attrs:
                ok = False
                last_reason = f"Segment {part!r} of {field_path!r} does not exist on class {cid_str} ({ev['name']})"
                break
            spec = cur_attrs[part]
            t_name = str(spec["type"])
            if idx < len(parts) - 1:
                if t_name not in objects:
                    ok = False
                    last_reason = f"Segment {part!r} of {field_path!r} has scalar type {t_name!r}, cannot traverse further"
                    break
                cur_attrs = objects[t_name]
            else:
                if t_name in objects or t_name in ("object", "json_t"):
                    ok = False
                    last_reason = f"Leaf {part!r} of {field_path!r} is OCSF object '{t_name}', not a scalar value"
                    break
        if ok:
            valid_classes.append(int(cid_str))

    if class_uids:
        missing = [c for c in class_uids if c not in valid_classes]
        if missing:
            return [f"{field_path!r} invalid for class_uid(s) {missing}: {last_reason}"]
        return []
    return [] if valid_classes else [last_reason]
