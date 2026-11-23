from __future__ import annotations

import json
import os
import socket
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from sqlalchemy import text

from provloom.config import AppConfig, DetectionConfig
from provloom.domain.common import TimeRange
from provloom.domain.enums import BatchStatus, NormalizationStatus, RawProcessStatus
from provloom.domain.ocsf_models import NormalizedEvent
from provloom.domain.raw_models import IngestBatch, RawEvent
from provloom.runtime import ProvLoomRuntime

EVAL_ROOT = Path(__file__).resolve().parent
REPO_ROOT = EVAL_ROOT.parents[1]
BASE_EVAL_TIME = datetime(2026, 11, 20, 0, 0, tzinfo=UTC)
EVAL_TIME_WINDOW = TimeRange(
    start_time=datetime(2019, 1, 1, tzinfo=UTC),
    end_time=datetime(2027, 1, 1, tzinfo=UTC),
)
DEFAULT_PG_EVAL_URL = "postgresql+psycopg://provloom:provloom@127.0.0.1:5432/provloom"


def get_available_eval_db_urls() -> list[tuple[str, str]]:
    urls: list[tuple[str, str]] = [("sqlite", "sqlite+pysqlite:///:memory:")]
    pg_url = os.getenv("PROVLOOM_EVAL_PG_URL", DEFAULT_PG_EVAL_URL)
    try:
        with socket.create_connection(("127.0.0.1", 5432), timeout=0.5):
            urls.append(("postgresql", pg_url))
    except OSError:
        pass
    return urls


def build_eval_runtime(db_url: str) -> ProvLoomRuntime:
    return ProvLoomRuntime.build(
        AppConfig(
            database_url=db_url,
            detection=DetectionConfig(max_matches_per_rule=2000, max_execution_seconds=30.0),
        )
    )


def cleanup_eval_tenant(rt: ProvLoomRuntime, tenant_id: str) -> None:
    if str(rt.engine.url).startswith("sqlite"):
        return
    with rt.engine.begin() as conn:
        conn.execute(
            text(
                "DELETE FROM detection_signal_matches WHERE signal_id IN "
                "(SELECT signal_id FROM detection_signals WHERE tenant_scope = :t)"
            ),
            {"t": tenant_id},
        )
        conn.execute(
            text(
                "DELETE FROM relation_evidences WHERE relation_id IN "
                "(SELECT relation_id FROM relations WHERE tenant_scope = :t)"
            ),
            {"t": tenant_id},
        )
        for tbl in (
            "detection_candidate_groups",
            "detection_signals",
            "detection_rule_matches",
            "detection_executions",
            "detection_rules",
            "relations",
            "entity_merges",
            "entity_identifiers",
            "entities",
            "normalized_events",
            "pipeline_failures",
            "raw_events",
            "ingest_batches",
        ):
            conn.execute(text(f"DELETE FROM {tbl} WHERE tenant_scope = :t"), {"t": tenant_id})


def _has_nonempty_key(obj: dict[str, Any], keys: tuple[str, ...]) -> bool:
    for k in keys:
        v = obj.get(k)
        if v is None:
            continue
        if isinstance(v, (dict, list)) and len(v) == 0:
            continue
        if isinstance(v, str) and v == "":
            continue
        return True
    return False


def apply_ocsf_v140_synthetic_defaults(
    payload: dict[str, Any],
    cls_uid: int,
    tid: str,
) -> None:
    if cls_uid in (1001, 1007, 1009, 5001) and "device" not in payload:
        payload["device"] = {"type_id": 0}
    if cls_uid in (1001, 1007, 1009, 6003) and "actor" not in payload:
        payload["actor"] = {}
    if cls_uid == 3002 and "user" not in payload:
        payload["user"] = {}
    if isinstance(payload.get("device"), dict):
        payload["device"].setdefault("type_id", 0)
        if isinstance(payload["device"].get("os"), dict):
            payload["device"]["os"].setdefault("type_id", 0)
    if isinstance(payload.get("connection_info"), dict):
        payload["connection_info"].setdefault("direction_id", 0)

    proc_candidates: list[dict[str, Any]] = []
    if isinstance(payload.get("process"), dict):
        proc_candidates.append(payload["process"])
        if isinstance(payload["process"].get("parent_process"), dict):
            proc_candidates.append(payload["process"]["parent_process"])
    if isinstance(payload.get("actor"), dict) and isinstance(payload["actor"].get("process"), dict):
        ap = payload["actor"]["process"]
        proc_candidates.append(ap)
        if isinstance(ap.get("parent_process"), dict):
            proc_candidates.append(ap["parent_process"])

    for proc_obj in proc_candidates:
        if not _has_nonempty_key(proc_obj, ("pid", "uid")):
            proc_obj["uid"] = f"proc-{tid}"
        if isinstance(proc_obj.get("file"), dict):
            proc_obj["file"].setdefault("type_id", 1)
            if "name" not in proc_obj["file"]:
                raw_p = str(
                    proc_obj["file"].get("path") or proc_obj["file"].get("internal_name") or ""
                ).strip()
                proc_obj["file"]["name"] = raw_p.replace("/", "\\").rsplit("\\", 1)[-1] or "unknown"

    if isinstance(payload.get("file"), dict):
        f_obj = payload["file"]
        f_obj.setdefault("type_id", 1)
        if "name" not in f_obj:
            raw_p = str(f_obj.get("path") or f_obj.get("internal_name") or "").strip()
            f_obj["name"] = raw_p.replace("/", "\\").rsplit("\\", 1)[-1] or "unknown"

    for user_obj in (
        payload.get("user"),
        payload["actor"].get("user") if isinstance(payload.get("actor"), dict) else None,
    ):
        if isinstance(user_obj, dict) and not _has_nonempty_key(
            user_obj, ("account", "name", "uid")
        ):
            user_obj["uid"] = f"user-{tid}"

    ep_keys = (
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
    for ep_key in ("src_endpoint", "dst_endpoint"):
        ep_obj = payload.get(ep_key)
        if isinstance(ep_obj, dict) and not _has_nonempty_key(ep_obj, ep_keys):
            ep_obj["uid"] = f"ep-{tid}"

    if cls_uid in (4001, 4003) and not _has_nonempty_key(payload, ("src_endpoint", "dst_endpoint")):
        payload["src_endpoint"] = {"uid": f"ep-{tid}"}

    if cls_uid == 3002 and not _has_nonempty_key(payload, ("service", "dst_endpoint")):
        payload["dst_endpoint"] = {"uid": f"auth-dst-{tid}"}

    if isinstance(payload.get("actor"), dict) and not _has_nonempty_key(
        payload["actor"], ("process", "user", "invoked_by", "session", "app_name", "app_uid")
    ):
        payload["actor"]["app_name"] = "synthetic-actor"

    if isinstance(payload.get("device"), dict) and not _has_nonempty_key(
        payload["device"],
        ("ip", "uid", "name", "hostname", "instance_uid", "interface_uid", "interface_name"),
    ):
        payload["device"]["uid"] = f"dev-{tid}"

    meta = payload.get("metadata")
    if isinstance(meta, dict):
        profiles: set[str] = {str(p) for p in (meta.get("profiles") or []) if isinstance(p, str)}
        if (
            cls_uid in (3002, 4001, 4003, 6001, 6002, 6003) and payload.get("device") is not None
        ) or (cls_uid in (4001, 4003, 6001, 6002) and payload.get("actor") is not None):
            profiles.add("host")
        if any(
            payload.get(k) is not None
            for k in ("disposition", "disposition_id", "action", "action_id", "firewall_rule")
        ):
            profiles.add("security_control")
        if profiles:
            meta["profiles"] = sorted(profiles)


def build_case_ocsf_payload(
    c: dict[str, Any],
    ev_id: UUID,
    ev_time: datetime,
    *,
    include_provloom_original_uid: bool = True,
) -> tuple[str, dict[str, Any]]:
    tid = str(c["test_event_id"])
    ocsf_ver = str(c.get("ocsf_version", "1.4.0"))
    meta_ver = str(c.get("metadata_version", ocsf_ver))
    cls_uid = int(c["class_uid"])
    cat_uid = int(c["category_uid"])
    act_uid = int(c["activity_id"])
    meta_obj: dict[str, Any] = {
        "version": meta_ver,
        "uid": str(ev_id),
        "product": {"vendor_name": "ProvLoomEval", "name": "SyntheticOracle"},
    }
    if include_provloom_original_uid:
        meta_obj["original_uid"] = tid
    raw_profiles = c.get("metadata_profiles")
    if isinstance(raw_profiles, list):
        meta_obj["profiles"] = [str(p) for p in raw_profiles if isinstance(p, str)]

    payload: dict[str, Any] = {
        "category_uid": cat_uid,
        "class_uid": cls_uid,
        "activity_id": act_uid,
        "type_uid": cls_uid * 100 + act_uid,
        "severity_id": int(c.get("severity_id", 1)),
        "time": int(ev_time.timestamp() * 1000),
        "metadata": meta_obj,
    }
    raw_fields = json.loads(json.dumps(dict(c["ocsf_fields"])))
    for k, v in raw_fields.items():
        payload[k] = v

    if bool(c.get("strict_ocsf_v140", ocsf_ver == "1.4.0")):
        apply_ocsf_v140_synthetic_defaults(payload, cls_uid, tid)

    return ocsf_ver, payload


def seed_synthetic_ocsf_cases(
    rt: ProvLoomRuntime,
    tenant_id: str,
    cases: list[dict[str, Any]],
) -> dict[str, UUID]:
    batch_id = uuid4()
    batch = IngestBatch(
        batch_id=batch_id,
        tenant_scope=tenant_id,
        source_id="synthetic-oracle",
        source_type="ocsf_synthetic",
        adapter_type="oracle",
        source_uri="memory://oracle",
        total_count=len(cases),
        accepted_count=len(cases),
        duplicate_count=0,
        failed_count=0,
        received_at=BASE_EVAL_TIME,
        status=BatchStatus.COMPLETED,
    )
    id_map: dict[str, UUID] = {}
    with rt.uow_factory() as uow:
        uow.raw_events.create_batch(batch)
        for idx, c in enumerate(cases):
            tid = str(c["test_event_id"])
            raw_id = uuid5(NAMESPACE_URL, f"provloom:eval:raw:{tenant_id}:{tid}")
            ev_id = uuid5(NAMESPACE_URL, f"provloom:eval:ev:{tenant_id}:{tid}")
            id_map[tid] = ev_id
            ev_time = BASE_EVAL_TIME + timedelta(seconds=idx)
            cls_uid = int(c["class_uid"])
            cat_uid = int(c["category_uid"])
            act_uid = int(c["activity_id"])
            ocsf_ver, payload = build_case_ocsf_payload(c, ev_id, ev_time)

            uow.raw_events.insert_raw_if_absent(
                RawEvent(
                    raw_event_id=raw_id,
                    batch_id=batch_id,
                    tenant_scope=tenant_id,
                    source_id="synthetic-oracle",
                    source_type="ocsf_synthetic",
                    external_event_uid=tid,
                    raw_fingerprint=f"{idx:064x}",
                    raw_payload=json.dumps(
                        {"test_event_id": tid, "ocsf": payload}, ensure_ascii=False
                    ),
                    raw_metadata={},
                    ingested_at=ev_time,
                    process_status=RawProcessStatus.NORMALIZED,
                )
            )
            uow.normalized_events.upsert(
                NormalizedEvent(
                    event_id=ev_id,
                    raw_event_id=raw_id,
                    tenant_scope=tenant_id,
                    source_id="synthetic-oracle",
                    ocsf_version=ocsf_ver,
                    category_uid=cat_uid,
                    class_uid=cls_uid,
                    activity_id=act_uid,
                    event_time=ev_time,
                    normalization_status=NormalizationStatus.MAPPED,
                    mapping_rule_id="synthetic_oracle_direct",
                    original_event_uid=tid,
                    ocsf_payload=payload,
                    unmapped_fields=dict(payload.get("unmapped") or {}),
                )
            )
    return id_map
