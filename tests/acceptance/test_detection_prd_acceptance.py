from __future__ import annotations

import unittest
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from provloom.api.app import create_app
from provloom.config import AppConfig, DetectionConfig
from provloom.detection.domain.rule import DetectionType, RuleStatus
from provloom.domain.common import AccessScope, PageSpec, TimeRange
from provloom.domain.enums import Certainty, EntityType
from provloom.query.interfaces import EntitySearchFilter
from provloom.query.ops_interfaces import ReplayRequest
from provloom.runtime import ProvLoomRuntime

WINDOW = TimeRange(
    start_time=datetime(2026, 11, 18, 7, 0, tzinfo=UTC),
    end_time=datetime(2026, 11, 18, 9, 0, tzinfo=UTC),
)
SCOPE = AccessScope(tenant_id="default")


def _new_runtime(exec_token: str | None = None) -> ProvLoomRuntime:
    cfg = AppConfig(
        database_url="sqlite+pysqlite:///:memory:",
        detection=DetectionConfig(execution_token=exec_token),
    )
    return ProvLoomRuntime.build(config=cfg)


@pytest.mark.acceptance
class DetectionPrdAcceptanceTests(unittest.TestCase):
    def test_ac01_import_sigma_yaml_preserves_metadata_and_raw_yaml(self) -> None:
        rt = _new_runtime()
        sigma_yaml = """title: Suspicious Certutil Download
id: 10101010-2020-4040-8080-909090909090
version: 2.1.0
description: Detects certutil urlcache download flag
level: high
tags:
  - attack.command_and_control
  - attack.t1105
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\certutil.exe'
    CommandLine|contains: '-urlcache'
  condition: selection
"""
        view = rt.detection_service.import_detection_rule(
            scope=SCOPE,
            raw_yaml=sigma_yaml,
            source_reference="https://github.com/SigmaHQ/sigma/rules/windows/certutil.yml",
        )
        r = view.rule
        self.assertEqual(r.rule_id, "10101010-2020-4040-8080-909090909090")
        self.assertEqual(r.version, "2.1.0")
        self.assertEqual(r.raw_content, sigma_yaml)
        self.assertIn("attack.t1105", r.attack_tags)
        self.assertEqual(
            r.source_reference,
            "https://github.com/SigmaHQ/sigma/rules/windows/certutil.yml",
        )
        self.assertEqual(r.status, RuleStatus.ENABLED)

    def test_ac02_identify_unsupported_sigma_semantics_without_silent_ignore(self) -> None:
        rt = _new_runtime()
        unsupported_yaml = """title: Unsupported Timeframe & Unmapped Field
id: 20202020-3030-4040-8080-111111111111
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\cmd.exe'
    NonExistentVendorField: 'secret'
  timeframe: 10m
  condition: selection
"""
        view = rt.detection_service.import_detection_rule(SCOPE, unsupported_yaml)
        self.assertTrue(view.rule.compatibility.parse_success)
        self.assertFalse(view.rule.compatibility.is_supported)
        self.assertEqual(view.rule.status, RuleStatus.UNSUPPORTED)
        self.assertGreater(len(view.rule.compatibility.unsupported_reasons), 0)

        client = TestClient(create_app(rt))
        enable_res = client.post(
            f"/api/v1/detection/rules/{view.rule.rule_id}/enable",
            headers={"X-Tenant-Id": "default"},
        )
        self.assertEqual(enable_res.status_code, 422)

    def test_ac03_map_supported_sigma_rules_to_ocsf_fields_and_data_coverage(self) -> None:
        rt = _new_runtime()
        sigma_yaml = """title: LSASS Process Access Check
id: 30303030-4040-4040-8080-222222222222
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    ParentImage|endswith: '\\cmd.exe'
    CommandLine|contains: '-nop'
  condition: selection
"""
        view = rt.detection_service.validate_detection_rule(sigma_yaml)
        c = view.rule.compatibility
        self.assertTrue(c.parse_success and c.mapping_success and c.compile_success)
        self.assertTrue(c.data_coverage)
        self.assertEqual(c.mapped_class_uids, (1007,))
        self.assertEqual(c.field_mappings["Image"], "process.file.path")
        self.assertEqual(c.field_mappings["ParentImage"], "process.parent_process.file.path")
        self.assertEqual(c.field_mappings["CommandLine"], "process.cmd_line")

    def test_ac04_execute_single_event_detection_via_sql_backend(self) -> None:
        rt = _new_runtime()
        rt.ops_service.load_builtin_examples("default")
        ps_rule_id = "6d4b1e8c-91b2-4e45-8c01-100700000001"

        ex = rt.detection_service.execute_rule(SCOPE, ps_rule_id, WINDOW)
        self.assertEqual(ex.status.value, "COMPLETED")
        self.assertEqual(ex.matches_created, 1)

        matches = rt.detection_service.search_rule_matches(SCOPE, WINDOW, rule_id=ps_rule_id).items
        self.assertEqual(len(matches), 1)
        # Matches win01 staging powershell (9001), excludes win02 benign Get-Date (9101).
        self.assertEqual(matches[0].evidence_references[0].original_event_uid, "9001")

    def test_ac05_execute_basic_one_hop_graph_relation_detection(self) -> None:
        rt = _new_runtime()
        rt.ops_service.load_builtin_examples("default")
        # Also inject a candidate-only firewall flow to verify deterministic_only filtering.
        rt.ops_service.import_raw_content(
            tenant_scope="default",
            source_id="fw-cand",
            source_type="firewall",
            adapter_type="csv",
            raw_text=(
                "event_uid,timestamp,src_ip,src_port,dst_ip,dst_port,protocol,action,bytes_sent\n"
                "fw-9999,2026-11-18T08:05:00Z,10.10.1.25,55555,198.51.100.77,8443,tcp,ALLOW,128\n"
            ),
        )

        rel_rule_id = "custom-rel-proc-connects-external"
        ex = rt.detection_service.execute_rule(SCOPE, rel_rule_id, WINDOW)
        self.assertEqual(ex.matches_created, 1)

        matches = rt.detection_service.search_rule_matches(SCOPE, WINDOW, rule_id=rel_rule_id).items
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].detection_type, DetectionType.RELATION)
        self.assertEqual(matches[0].matched_values["certainty"], Certainty.DETERMINISTIC.value)
        self.assertGreaterEqual(len(matches[0].evidence_references), 3)

    def test_ac06_and_ac10_rule_match_and_signal_trace_to_ocsf_and_raw_logs(self) -> None:
        rt = _new_runtime()
        rt.ops_service.load_builtin_examples("default")
        rt.detection_service.execute_rule_batch(SCOPE, WINDOW)

        signals = rt.detection_service.search_signals(SCOPE, WINDOW).items
        self.assertGreaterEqual(len(signals), 4)

        for sig in signals:
            matches = rt.detection_service.get_signal_matches(SCOPE, sig.signal_id)
            assert matches is not None and len(matches) >= 1
            evidences = rt.detection_service.get_signal_evidence(SCOPE, sig.signal_id)
            assert evidences is not None and len(evidences) >= 1
            for ev in evidences:
                self.assertTrue(len(ev.raw_payload) > 10)
                self.assertEqual(ev.ocsf_payload["metadata"]["version"], "1.3.0")
                ev_detail = rt.query_service.get_event(SCOPE, ev.event_id, include_raw=True)
                assert ev_detail is not None and ev_detail.raw is not None
                self.assertEqual(ev_detail.raw.raw_event_id, ev.raw_event_id)

    def test_ac07_signal_associates_multiple_rule_matches_on_same_entity(self) -> None:
        rt = _new_runtime()
        rt.ops_service.load_builtin_examples("default")
        # Second suspicious PowerShell execution under the same ProcessGuid on win01.
        rt.ops_service.import_raw_content(
            tenant_scope="default",
            source_id="edr-sysmon",
            source_type="sysmon",
            adapter_type="jsonl",
            raw_text=(
                '{"EventRecordID":"9009","EventID":1,"UtcTime":"2026-11-18T08:00:09.000Z",'
                '"Computer":"win01.corp.local","User":"CORP\\\\alice",'
                '"ProcessGuid":"{11111111-0001-0001-0001-000000000002}","ProcessId":4120,'
                '"Image":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe",'
                '"CommandLine":"powershell.exe -EncodedCommand ZQBjAGgAbwA="}'
            ),
        )
        ps_rule_id = "6d4b1e8c-91b2-4e45-8c01-100700000001"
        rt.detection_service.execute_rule(SCOPE, ps_rule_id, WINDOW)

        sigs = rt.detection_service.search_signals(
            SCOPE, WINDOW, signal_type=f"rule:{ps_rule_id}"
        ).items
        self.assertEqual(len(sigs), 1)
        self.assertEqual(sigs[0].occurrence_count, 2)
        self.assertEqual(len(sigs[0].rule_match_ids), 2)
        linked = rt.detection_service.get_signal_matches(SCOPE, sigs[0].signal_id)
        assert linked is not None
        self.assertEqual(len(linked), 2)

    def test_ac08_duplicate_events_and_repeated_runs_never_duplicate_rule_matches(self) -> None:
        rt = _new_runtime()
        rt.ops_service.load_builtin_examples("default")
        ex1 = rt.detection_service.execute_rule_batch(SCOPE, WINDOW)
        self.assertGreater(ex1.matches_created, 0)

        # Re-ingest identical examples AND re-run batch detection.
        rt.ops_service.load_builtin_examples("default")
        ex2 = rt.detection_service.execute_rule_batch(SCOPE, WINDOW)
        self.assertEqual(ex2.matches_created, 0)
        self.assertEqual(ex2.matches_deduplicated, ex1.matches_created)

        # Replay from raw_events also rebuilds cleanly without FK errors and re-detects deterministically.
        rt.ops_service.trigger_replay(SCOPE, ReplayRequest())
        ex3 = rt.detection_service.execute_rule_batch(SCOPE, WINDOW)
        self.assertEqual(ex3.matches_created, ex1.matches_created)

    def test_ac09_candidate_group_preserves_members_and_deterministic_basis(self) -> None:
        rt = _new_runtime()
        rt.ops_service.load_builtin_examples("default")
        rt.detection_service.execute_rule_batch(SCOPE, WINDOW)

        groups = rt.detection_service.search_candidate_groups(SCOPE, WINDOW).items
        self.assertGreaterEqual(len(groups), 1)

        ps_entity = rt.query_service.search_entities(
            SCOPE,
            WINDOW,
            EntitySearchFilter(
                entity_types=(EntityType.PROCESS,),
                identifier_query="11111111-0001-0001-0001-000000000002",
            ),
            PageSpec(limit=5),
        ).items[0]

        ps_groups = rt.detection_service.search_candidate_groups(
            SCOPE, WINDOW, entity_id=ps_entity.entity_id
        ).items
        self.assertEqual(len(ps_groups), 1)
        grp = ps_groups[0]
        self.assertIn("links", grp.grouping_basis)
        self.assertGreaterEqual(len(grp.signal_ids), 3)

        members = rt.detection_service.get_candidate_group_members(SCOPE, grp.group_id)
        assert members is not None
        self.assertEqual(len(members.signals), len(grp.signal_ids))
        self.assertGreaterEqual(len(members.rule_matches), len(grp.signal_ids))

    def test_ac11_web_console_and_rest_api_serve_rules_sandbox_matches_and_signals(self) -> None:
        rt = _new_runtime()
        client = TestClient(create_app(rt))

        assert client.post("/api/v1/ops/batches/examples").status_code == 200
        rules_res = client.get("/api/v1/detection/rules?source=SIGMA")
        self.assertEqual(rules_res.status_code, 200)
        self.assertGreaterEqual(len(rules_res.json()["items"]), 7)

        test_res = client.post(
            "/api/v1/detection/rules/test",
            json={
                "time_range": {
                    "start_time": "2026-11-18T07:00:00Z",
                    "end_time": "2026-11-18T09:00:00Z",
                },
                "rule_id": "6d4b1e8c-91b2-4e45-8c01-100700000001",
            },
        )
        self.assertEqual(test_res.status_code, 200)
        test_payload = test_res.json()
        self.assertIn("SELECT", test_payload["compiled_sql"])
        self.assertEqual(len(test_payload["matches"]), 1)

        batch_res = client.post(
            "/api/v1/detection/execute-batch",
            json={
                "time_range": {
                    "start_time": "2026-11-18T07:00:00Z",
                    "end_time": "2026-11-18T09:00:00Z",
                }
            },
        )
        self.assertEqual(batch_res.status_code, 200)

        sig_res = client.post(
            "/api/v1/detection/signals/search",
            json={
                "time_range": {
                    "start_time": "2026-11-18T07:00:00Z",
                    "end_time": "2026-11-18T09:00:00Z",
                }
            },
        )
        self.assertEqual(sig_res.status_code, 200)
        self.assertGreaterEqual(len(sig_res.json()["items"]), 4)

        if Path("web/dist/index.html").is_file():
            spa_res = client.get("/detection")
            self.assertEqual(spa_res.status_code, 200)
            self.assertIn("text/html", spa_res.headers["content-type"])

    def test_ac12_enforces_tenant_source_scope_execution_token_and_query_limits(self) -> None:
        rt = _new_runtime(exec_token="sec-ops-secret")
        client = TestClient(create_app(rt))

        client.post(
            "/api/v1/ops/batches/examples",
            headers={"X-Tenant-Id": "tenant-alpha"},
        )

        # Unauthenticated execution is rejected with 403.
        unauth_exec = client.post(
            "/api/v1/detection/execute-batch",
            headers={"X-Tenant-Id": "tenant-alpha"},
            json={
                "time_range": {
                    "start_time": "2026-11-18T07:00:00Z",
                    "end_time": "2026-11-18T09:00:00Z",
                }
            },
        )
        self.assertEqual(unauth_exec.status_code, 403)

        # Read-only role header is rejected even if token is supplied.
        ro_exec = client.post(
            "/api/v1/detection/execute-batch",
            headers={
                "X-Tenant-Id": "tenant-alpha",
                "X-Detection-Exec-Token": "sec-ops-secret",
                "X-Detection-Role": "readonly",
            },
            json={
                "time_range": {
                    "start_time": "2026-11-18T07:00:00Z",
                    "end_time": "2026-11-18T09:00:00Z",
                }
            },
        )
        self.assertEqual(ro_exec.status_code, 403)

        # Authorized execution succeeds on tenant-alpha.
        ok_exec = client.post(
            "/api/v1/detection/execute-batch",
            headers={
                "X-Tenant-Id": "tenant-alpha",
                "X-Detection-Exec-Token": "sec-ops-secret",
            },
            json={
                "time_range": {
                    "start_time": "2026-11-18T07:00:00Z",
                    "end_time": "2026-11-18T09:00:00Z",
                }
            },
        )
        self.assertEqual(ok_exec.status_code, 200)
        self.assertGreater(ok_exec.json()["matches_created"], 0)

        # Tenant isolation: tenant-beta sees 0 Signals from tenant-alpha.
        beta_sigs = client.post(
            "/api/v1/detection/signals/search",
            headers={"X-Tenant-Id": "tenant-beta"},
            json={
                "time_range": {
                    "start_time": "2026-11-18T07:00:00Z",
                    "end_time": "2026-11-18T09:00:00Z",
                }
            },
        )
        self.assertEqual(beta_sigs.status_code, 200)
        self.assertEqual(len(beta_sigs.json()["items"]), 0)

        # Source-level isolation: restricting X-Allowed-Sources to auth-dc hides Sysmon/Zeek Signals.
        auth_only_sigs = client.post(
            "/api/v1/detection/signals/search",
            headers={
                "X-Tenant-Id": "tenant-alpha",
                "X-Allowed-Sources": "auth-ad",
            },
            json={
                "time_range": {
                    "start_time": "2026-11-18T07:00:00Z",
                    "end_time": "2026-11-18T09:00:00Z",
                }
            },
        ).json()["items"]
        for s in auth_only_sigs:
            self.assertEqual(s["source_ids"], ["auth-ad"])

        # Hard limit guardrails: limit > 500 is rejected with 422.
        over_limit = client.post(
            "/api/v1/detection/matches/search",
            headers={"X-Tenant-Id": "tenant-alpha"},
            json={
                "time_range": {
                    "start_time": "2026-11-18T07:00:00Z",
                    "end_time": "2026-11-18T09:00:00Z",
                },
                "limit": 5000,
            },
        )
        self.assertEqual(over_limit.status_code, 422)
