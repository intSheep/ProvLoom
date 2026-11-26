from __future__ import annotations

import json
import unittest
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

import pytest

from provloom.detection.domain.rule import ExecutionStatus, RuleStatus
from provloom.domain.common import AccessScope, PageSpec
from provloom.domain.enums import NormalizationStatus, OcsfClassUid
from provloom.domain.ocsf_models import NormalizedEvent
from provloom.query.interfaces import EventSearchFilter
from provloom.query.ops_interfaces import ReplayRequest
from tests.evaluation.helpers import (
    BASE_EVAL_TIME,
    EVAL_ROOT,
    EVAL_TIME_WINDOW,
    REPO_ROOT,
    build_case_ocsf_payload,
    build_eval_runtime,
    cleanup_eval_tenant,
    get_available_eval_db_urls,
    seed_synthetic_ocsf_cases,
)
from tests.evaluation.ocsf_validator import PINNED_OCSF_VERSION, validate_ocsf_v140_event


@pytest.mark.integration
class SigmaHqCompatibilityAndCorrectnessTests(unittest.TestCase):
    def test_sigmahq_45_rules_five_stage_compatibility_and_zero_silent_degradation(self) -> None:
        manifest = json.loads(
            (EVAL_ROOT / "fixtures" / "sigmahq_rules" / "manifest.json").read_text()
        )
        self.assertEqual(len(manifest), 45)

        rt = build_eval_runtime("sqlite+pysqlite:///:memory:")
        parsed_ok = 0
        mapped_ok = 0
        datacov_ok = 0
        compiled_ok = 0

        for item in manifest:
            raw_yaml = (REPO_ROOT / item["local_fixture_path"]).read_text(encoding="utf-8")
            view = rt.detection_service.validate_detection_rule(raw_yaml)
            c = view.rule.compatibility
            if c.parse_success:
                parsed_ok += 1
            if c.mapping_success:
                mapped_ok += 1
            if c.mapping_success and c.data_coverage:
                datacov_ok += 1
            if c.compile_success:
                compiled_ok += 1
                assert view.compiled_sql is not None
                self.assertIn("det_p_", view.compiled_sql)
            else:
                self.assertEqual(view.rule.status, RuleStatus.UNSUPPORTED)
                self.assertGreaterEqual(
                    len(c.unsupported_reasons),
                    1,
                    f"Unsupported rule {item['rule_id']} must explicitly report reasons",
                )

        self.assertEqual(parsed_ok, 45)
        self.assertEqual(mapped_ok, 32)
        self.assertEqual(datacov_ok, 23)
        self.assertEqual(compiled_ok, 32)

        # Verify unsupported rejection audit (#25) is explicitly separated and rejected.
        unsup_audit = json.loads(
            (EVAL_ROOT / "ground_truth" / "unsupported_audit_oracle.json").read_text()
        )
        self.assertEqual(len(unsup_audit), 1)
        m25 = next(m for m in manifest if m["rule_id"] == unsup_audit[0]["rule_id"])
        v25 = rt.detection_service.validate_detection_rule(
            (REPO_ROOT / m25["local_fixture_path"]).read_text(encoding="utf-8")
        )
        self.assertEqual(v25.rule.status, RuleStatus.UNSUPPORTED)
        self.assertIn(
            "Unmapped Sigma field: 'ParentImage'", v25.rule.compatibility.unsupported_reasons
        )

    def test_all_9_builtin_classes_plus_1009_and_sigmahq_cases_validate_against_ocsf_v140(
        self,
    ) -> None:
        gt_entries = json.loads(
            (EVAL_ROOT / "ground_truth" / "sigmahq_ground_truth.json").read_text()
        )
        self.assertEqual(len(gt_entries), 32)
        case_count = 0
        seen_classes: set[int] = set()
        for g in gt_entries:
            for case in g["cases"]:
                case_count += 1
                seen_classes.add(int(case["class_uid"]))
                ver, pure = build_case_ocsf_payload(
                    case, uuid4(), BASE_EVAL_TIME, include_provloom_original_uid=False
                )
                self.assertEqual(ver, PINNED_OCSF_VERSION)
                errs = validate_ocsf_v140_event(
                    pure,
                    allow_provloom_metadata_original_uid=False,
                    check_enums=True,
                    check_constraints=True,
                )
                self.assertEqual(errs, [], f"{case['test_event_id']} failed OCSF v1.4.0: {errs}")
        self.assertEqual(case_count, 133)
        self.assertIn(1009, seen_classes)

        # Also validate all 9 existing built-in classes (1001,1007,3002,4001,4003,5001,6001,6002,6003) + 0 passthrough.
        rt = build_eval_runtime("sqlite+pysqlite:///:memory:")
        rt.ops_service.load_builtin_examples("all_9_cls")
        rt.ops_service.import_raw_content(
            tenant_scope="all_9_cls",
            source_id="app-suite",
            source_type="app",
            adapter_type="jsonl",
            raw_text="\n".join(
                [
                    '{"event_uid":"w1","event_type":"web_access","timestamp":"2026-11-18T08:02:00Z","hostname":"win01.corp.local","username":"alice","domain":"CORP","service_name":"portal","listen_port":8443,"resource_path":"/admin"}',
                    '{"event_uid":"l1","event_type":"service_start","timestamp":"2026-11-18T08:03:00Z","hostname":"win01.corp.local","service_name":"portal","listen_port":8443}',
                    '{"event_uid":"a1","event_type":"api_call","timestamp":"2026-11-18T08:04:00Z","hostname":"win01.corp.local","username":"alice","domain":"CORP","service_name":"portal","listen_port":8443,"operation":"ListUsers","src_ip":"10.10.1.99"}',
                ]
            ),
        )
        rt.ops_service.import_raw_content(
            tenant_scope="all_9_cls",
            source_id="edr-unmapped",
            source_type="sysmon",
            adapter_type="jsonl",
            raw_text='{"EventRecordID":"9999","EventID":7,"UtcTime":"2026-11-18T08:05:00Z","Computer":"win01.corp.local"}',
        )
        scope = AccessScope("all_9_cls")
        evs = rt.query_service.search_events(
            scope, EVAL_TIME_WINDOW, EventSearchFilter(include_fallback=True), PageSpec(limit=200)
        ).items
        norm_classes = {e.class_uid for e in evs}
        for required_cid in (0, 1001, 1007, 3002, 4001, 4003, 5001, 6001, 6002, 6003):
            self.assertIn(required_cid, norm_classes)
        for s in evs:
            det = rt.query_service.get_event(scope, s.event_id)
            assert det is not None
            self.assertEqual(det.normalized.ocsf_version, PINNED_OCSF_VERSION)
            self.assertEqual(
                det.normalized.ocsf_payload["metadata"]["version"], PINNED_OCSF_VERSION
            )
            self.assertEqual(
                validate_ocsf_v140_event(
                    det.normalized.ocsf_payload,
                    allow_provloom_metadata_original_uid=True,
                    check_enums=True,
                    check_constraints=True,
                ),
                [],
            )

    def test_sigmahq_32_executable_rules_ground_truth_correctness_and_5x_determinism(self) -> None:
        manifest = json.loads(
            (EVAL_ROOT / "fixtures" / "sigmahq_rules" / "manifest.json").read_text()
        )
        manifest_by_id = {m["rule_id"]: m for m in manifest}
        exec_gt = json.loads((EVAL_ROOT / "ground_truth" / "sigmahq_ground_truth.json").read_text())
        self.assertEqual(len(exec_gt), 32)
        all_cases = [c for g in exec_gt for c in g["cases"]]

        for dialect_label, db_url in get_available_eval_db_urls():
            rt = build_eval_runtime(db_url)
            tenant_id = f"pytest_eval_shq_{dialect_label}"
            cleanup_eval_tenant(rt, tenant_id)
            try:
                seed_synthetic_ocsf_cases(rt, tenant_id, all_cases)
                scope = AccessScope(tenant_id=tenant_id)
                supported_rule_ids: list[str] = []

                for g in exec_gt:
                    rid = str(g["rule_id"])
                    m = manifest_by_id[rid]
                    raw_yaml = (REPO_ROOT / m["local_fixture_path"]).read_text(encoding="utf-8")
                    imported = rt.detection_service.import_detection_rule(
                        scope, raw_yaml, source_reference=m["sigmahq_path"]
                    )
                    self.assertTrue(imported.rule.compatibility.is_supported)
                    supported_rule_ids.append(rid)

                    res = rt.detection_service.test_detection_rule(
                        scope=scope, time_range=EVAL_TIME_WINDOW, rule_id=rid, max_matches=500
                    )
                    self.assertIsNone(res.failure_reason)
                    self.assertIs(res.rule.compatibility.execution_success, True)
                    matched_uids = {
                        hit.evidence_references[0].original_event_uid
                        for hit in res.matches
                        if hit.evidence_references
                    }
                    for case in g["cases"]:
                        tid = str(case["test_event_id"])
                        exp = bool(case["expected_match"])
                        act = tid in matched_uids
                        self.assertEqual(
                            act,
                            exp,
                            f"[{dialect_label}] Rule {g['filename']} failed on {tid}: "
                            f"expected={exp}, actual={act}",
                        )

                # Determinism: 5 consecutive batch runs must produce identical match sets and 0 duplicates.
                baseline_pairs: tuple[tuple[str, str], ...] | None = None
                for run_idx in range(5):
                    ex = rt.detection_service.execute_rule_batch(
                        scope=scope,
                        time_range=EVAL_TIME_WINDOW,
                        rule_ids=supported_rule_ids,
                        max_matches_per_rule=500,
                    )
                    self.assertEqual(ex.status, ExecutionStatus.COMPLETED)
                    self.assertEqual(ex.rules_evaluated, 32)
                    stored = rt.detection_service.search_rule_matches(
                        scope, EVAL_TIME_WINDOW, page=PageSpec(limit=500)
                    ).items
                    pairs = tuple(
                        sorted((str(hit.primary_event_id), hit.rule_id) for hit in stored)
                    )
                    if run_idx == 0:
                        self.assertGreaterEqual(ex.matches_created, 64)
                        self.assertEqual(ex.matches_deduplicated, 0)
                        baseline_pairs = pairs
                    else:
                        self.assertEqual(ex.matches_created, 0)
                        self.assertEqual(ex.matches_deduplicated, len(pairs))
                        self.assertEqual(pairs, baseline_pairs)
            finally:
                cleanup_eval_tenant(rt, tenant_id)

    def test_robustness_malformed_inputs_and_legacy_v130_compatibility_plus_replay_upgrade(
        self,
    ) -> None:
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

        # Confirm every robustness case genuinely fails strict OCSF v1.4.0 validation.
        for item in robustness:
            _, p = build_case_ocsf_payload(
                item["case"], uuid4(), BASE_EVAL_TIME, include_provloom_original_uid=False
            )
            errs = validate_ocsf_v140_event(p, allow_provloom_metadata_original_uid=False)
            self.assertGreaterEqual(len(errs), 1, f"{item['test_id']} must violate OCSF schema")

        for dialect_label, db_url in get_available_eval_db_urls():
            rt = build_eval_runtime(db_url)
            rob_tenant = f"pytest_rob_{dialect_label}"
            leg_tenant = f"pytest_leg_{dialect_label}"
            rep_tenant = f"pytest_rep_{dialect_label}"
            for t in (rob_tenant, leg_tenant, rep_tenant):
                cleanup_eval_tenant(rt, t)
            try:
                # 1) Robustness suite: zero SQL crashes, exact expected NO_MATCH.
                seed_synthetic_ocsf_cases(rt, rob_tenant, [x["case"] for x in robustness])
                for item in robustness:
                    ryaml = sem_by_id.get(item["rule_id"]) or manifest_by_id[item["rule_id"]]
                    res = rt.detection_service.test_detection_rule(
                        AccessScope(rob_tenant), EVAL_TIME_WINDOW, raw_yaml=ryaml
                    )
                    self.assertIsNone(res.failure_reason)
                    self.assertIs(res.rule.compatibility.execution_success, True)
                    uids = {m.evidence_references[0].original_event_uid for m in res.matches}
                    self.assertEqual(
                        item["case"]["test_event_id"] in uids, item["case"]["expected_match"]
                    )

                # 2) Historical OCSF 1.3.0 compatibility suite (string[] and scalar DNS answers).
                seed_synthetic_ocsf_cases(rt, leg_tenant, [x["case"] for x in legacy])
                for item in legacy:
                    ryaml = sem_by_id.get(item["rule_id"]) or manifest_by_id[item["rule_id"]]
                    res = rt.detection_service.test_detection_rule(
                        AccessScope(leg_tenant), EVAL_TIME_WINDOW, raw_yaml=ryaml
                    )
                    self.assertIsNone(res.failure_reason)
                    uids = {m.evidence_references[0].original_event_uid for m in res.matches}
                    self.assertEqual(
                        item["case"]["test_event_id"] in uids,
                        item["case"]["expected_match"],
                        f"[{dialect_label}] Legacy {item['test_id']} mismatch",
                    )

                # 3) Explicit replay conversion from 1.3.0 derived DNS event -> 1.4.0 without mutating raw_events.
                raw_dns = '{"ts":"2026-11-18T08:00:04.900Z","uid":"C9xDns01","_path":"dns","id.orig_h":"10.10.1.25","id.orig_p":59812,"id.resp_h":"10.10.0.53","id.resp_p":53,"proto":"udp","query":"cdn-update.example.net","answers":["198.51.100.42"],"rcode_name":"NOERROR"}'
                rt.ops_service.import_raw_content(
                    tenant_scope=rep_tenant,
                    source_id="zeek-dns",
                    source_type="zeek_dns",
                    adapter_type="jsonl",
                    raw_text=raw_dns,
                )
                rep_scope = AccessScope(rep_tenant)
                pre_ev_sum = rt.query_service.search_events(
                    rep_scope, EVAL_TIME_WINDOW, EventSearchFilter(), PageSpec(limit=10)
                ).items[0]
                pre_det = rt.query_service.get_event(
                    rep_scope, pre_ev_sum.event_id, include_raw=True
                )
                assert pre_det is not None and pre_det.raw is not None
                orig_raw_payload = pre_det.raw.raw_payload
                orig_raw_fp = pre_det.raw.raw_fingerprint

                # Simulate pre-upgrade v1.3.0 derived NormalizedEvent in DB before replay.
                legacy_payload = dict(pre_det.normalized.ocsf_payload)
                legacy_meta = dict(legacy_payload["metadata"])
                legacy_meta["version"] = "1.3.0"
                legacy_payload["metadata"] = legacy_meta
                legacy_payload["answers"] = ["198.51.100.42"]
                with rt.uow_factory() as uow:
                    uow.purge_derived_data(rep_tenant)
                    uow.normalized_events.upsert(
                        NormalizedEvent(
                            event_id=pre_det.normalized.event_id,
                            raw_event_id=pre_det.normalized.raw_event_id,
                            tenant_scope=rep_tenant,
                            source_id=pre_det.normalized.source_id,
                            ocsf_version="1.3.0",
                            category_uid=4,
                            class_uid=int(OcsfClassUid.DNS_ACTIVITY),
                            activity_id=6,
                            event_time=pre_det.normalized.event_time,
                            normalization_status=NormalizationStatus.MAPPED,
                            mapping_rule_id="zeek_dns_4003",
                            original_event_uid=pre_det.normalized.original_event_uid,
                            ocsf_payload=legacy_payload,
                            unmapped_fields=pre_det.normalized.unmapped_fields,
                        )
                    )

                receipt = rt.ops_service.trigger_replay(rep_scope, ReplayRequest())
                self.assertEqual(receipt.replayed_raw_events, 1)
                post_det = rt.query_service.get_event(
                    rep_scope, pre_ev_sum.event_id, include_raw=True
                )
                assert post_det is not None and post_det.raw is not None
                # Raw input remains 100% immutable; derived event is now valid OCSF v1.4.0 with answers[].rdata.
                self.assertEqual(post_det.raw.raw_payload, orig_raw_payload)
                self.assertEqual(post_det.raw.raw_fingerprint, orig_raw_fp)
                self.assertEqual(post_det.normalized.ocsf_version, PINNED_OCSF_VERSION)
                self.assertEqual(
                    post_det.normalized.ocsf_payload["metadata"]["version"], PINNED_OCSF_VERSION
                )
                self.assertEqual(
                    post_det.normalized.ocsf_payload["answers"], [{"rdata": "198.51.100.42"}]
                )
                self.assertEqual(
                    validate_ocsf_v140_event(
                        post_det.normalized.ocsf_payload, allow_provloom_metadata_original_uid=True
                    ),
                    [],
                )
            finally:
                for t in (rob_tenant, leg_tenant, rep_tenant):
                    cleanup_eval_tenant(rt, t)

    def test_public_datasets_known_hits_unknown_isolation_and_savepoint_recovery(self) -> None:
        pub_gt = json.loads(
            (EVAL_ROOT / "ground_truth" / "public_dataset_ground_truth.json").read_text()
        )
        manifest = json.loads(
            (EVAL_ROOT / "fixtures" / "sigmahq_rules" / "manifest.json").read_text()
        )

        for dialect_label, db_url in get_available_eval_db_urls():
            rt = build_eval_runtime(db_url)
            for ds in pub_gt["datasets"]:
                tenant_id = f"pytest_pub_{dialect_label}_{ds['dataset_id']}"
                cleanup_eval_tenant(rt, tenant_id)
                try:
                    scope = AccessScope(tenant_id=tenant_id)
                    raw_text = (REPO_ROOT / ds["fixture_path"]).read_text(encoding="utf-8")
                    rt.ops_service.import_raw_content(
                        tenant_scope=tenant_id,
                        source_id=ds["dataset_id"],
                        source_type=ds["source_type"],
                        adapter_type=ds["adapter_type"],
                        raw_text=raw_text,
                    )
                    for m in manifest:
                        raw_y = (REPO_ROOT / m["local_fixture_path"]).read_text(encoding="utf-8")
                        rt.detection_service.import_detection_rule(
                            scope, raw_y, source_reference=m["sigmahq_path"]
                        )
                    ex = rt.detection_service.execute_rule_batch(scope, EVAL_TIME_WINDOW)
                    self.assertEqual(ex.status, ExecutionStatus.COMPLETED)
                    matches = rt.detection_service.search_rule_matches(
                        scope, EVAL_TIME_WINDOW, page=PageSpec(limit=500)
                    ).items
                    counts_by_rule: dict[str, int] = {}
                    for hit in matches:
                        counts_by_rule[hit.rule_id] = counts_by_rule.get(hit.rule_id, 0) + 1
                    for exp_hit in ds["expected_known_attack_hits"]:
                        self.assertGreaterEqual(
                            counts_by_rule.get(exp_hit["rule_id"], 0),
                            int(exp_hit["min_expected_matches"]),
                            f"[{dialect_label}] Missing expected hit in {ds['dataset_id']} for {exp_hit['rule_file']}",
                        )
                finally:
                    cleanup_eval_tenant(rt, tenant_id)

            sp_tenant = f"pytest_savepoint_{dialect_label}"
            cleanup_eval_tenant(rt, sp_tenant)
            try:
                sp_scope = AccessScope(tenant_id=sp_tenant)
                rt.ops_service.load_builtin_examples(sp_tenant)
                orig_match_batch = rt.detection_service._event_matcher.match_batch
                call_n = 0

                def _flaky_match_batch(
                    *args: object,
                    _orig: object = orig_match_batch,
                    **kwargs: object,
                ) -> object:
                    nonlocal call_n
                    call_n += 1
                    if call_n == 1:
                        uow_arg = kwargs["uow"]
                        from sqlalchemy import text as sa_text

                        uow_arg._conn.execute(sa_text("SELECT 1 FROM non_existent_table_xyz"))  # type: ignore[attr-defined]
                    return _orig(*args, **kwargs)  # type: ignore[operator]

                with patch.object(
                    rt.detection_service._event_matcher,
                    "match_batch",
                    side_effect=_flaky_match_batch,
                ):
                    ex_sp = rt.detection_service.execute_rule_batch(sp_scope, EVAL_TIME_WINDOW)
                self.assertEqual(ex_sp.status, ExecutionStatus.PARTIAL_FAILURE)
                self.assertEqual(len(ex_sp.failures), 1)
                self.assertGreater(ex_sp.rules_evaluated, 1)
            finally:
                cleanup_eval_tenant(rt, sp_tenant)

        # Verify historical raw OCSF official examples retain their original metadata.version verbatim.
        ocsf_dir = EVAL_ROOT / "fixtures" / "public_datasets" / "ocsf_examples"
        route53_doc = json.loads((ocsf_dir / "1_1_0_route53.ocsf").read_text(encoding="utf-8"))
        self.assertEqual(route53_doc["metadata"]["version"], "1.1.0")
        self.assertIsInstance(route53_doc["answers"], list)
        self.assertIn("rdata", route53_doc["answers"][0])

        xml_sample = Path(
            EVAL_ROOT
            / "fixtures"
            / "public_datasets"
            / "splunk_attack_data"
            / "T1021_001_mstsc_sysmon_xml_sample.log"
        ).read_text(encoding="utf-8")
        rt_xml = build_eval_runtime("sqlite+pysqlite:///:memory:")
        rt_xml.ops_service.import_raw_content(
            tenant_scope="xml_check",
            source_id="splunk-xml",
            source_type="sysmon",
            adapter_type="jsonl",
            raw_text=xml_sample,
        )
        xml_failures = rt_xml.ops_service.list_failures(
            AccessScope("xml_check"), None, None, PageSpec(limit=20)
        ).items
        self.assertEqual(len(xml_failures), 5)
