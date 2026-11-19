from __future__ import annotations

import unittest
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from provloom.api.app import create_app
from provloom.config import AppConfig
from provloom.domain.common import AccessScope, PageSpec, TimeRange
from provloom.domain.enums import (
    Certainty,
    Direction,
    EntityType,
    NormalizationStatus,
    OcsfClassUid,
    PipelineStage,
    RelationType,
    ResolutionState,
)
from provloom.domain.graph_models import GraphTraversalSpec
from provloom.query.interfaces import EntitySearchFilter, EventSearchFilter
from provloom.query.ops_interfaces import ReplayRequest, SampleImportRequest
from provloom.runtime import ProvLoomRuntime

WINDOW = TimeRange(
    start_time=datetime(2026, 11, 18, 7, 0, tzinfo=timezone.utc),
    end_time=datetime(2026, 11, 18, 9, 0, tzinfo=timezone.utc),
)
SCOPE = AccessScope(tenant_id="default")


def _new_memory_runtime() -> ProvLoomRuntime:
    cfg = AppConfig(database_url="sqlite+pysqlite:///:memory:")
    return ProvLoomRuntime.build(config=cfg)


@pytest.mark.acceptance
class PrdAcceptanceMatrixTests(unittest.TestCase):
    def test_ac01_raw_logs_ingested_and_preserved(self) -> None:
        rt = _new_memory_runtime()
        receipts = rt.ops_service.load_builtin_examples("default")
        self.assertEqual(len(receipts), 6)
        self.assertEqual(sum(r.accepted_count for r in receipts), 11)

        # Malformed line + missing file are recorded in pipeline_failures, never silently lost.
        bad_raw = rt.ops_service.import_raw_content(
            tenant_scope="default",
            source_id="edr-sysmon",
            source_type="sysmon",
            adapter_type="jsonl",
            raw_text='{"broken_json": \n',
        )
        self.assertEqual(bad_raw.accepted_count, 1)

        missing_batch = rt.ops_service.submit_import(
            SampleImportRequest(
                tenant_scope="default",
                source_id="missing-src",
                source_type="sysmon",
                adapter_type="jsonl",
                source_uri="/nonexistent/missing.jsonl",
            )
        )
        self.assertEqual(missing_batch.failed_count, 1)

        ingest_failures = rt.ops_service.list_failures(
            SCOPE, batch_id=None, stage=PipelineStage.INGEST, page=PageSpec(limit=20)
        )
        parse_failures = rt.ops_service.list_failures(
            SCOPE, batch_id=None, stage=PipelineStage.PARSE, page=PageSpec(limit=20)
        )
        self.assertEqual(len(ingest_failures.items), 1)
        self.assertEqual(len(parse_failures.items), 1)

        events = rt.query_service.search_events(
            SCOPE, WINDOW, EventSearchFilter(), PageSpec(limit=50)
        )
        first_detail = rt.query_service.get_event(SCOPE, events.items[0].event_id, include_raw=True)
        assert first_detail is not None and first_detail.raw is not None
        self.assertTrue(len(first_detail.raw.raw_payload) > 10)
        self.assertEqual(len(first_detail.raw.raw_fingerprint), 64)

    def test_ac02_supported_logs_mapped_to_ocsf_without_silent_drop(self) -> None:
        rt = _new_memory_runtime()
        rt.ops_service.load_builtin_examples("default")
        # Inject an application event (6001) and an unsupported Sysmon EventID 7 (ImageLoad).
        rt.ops_service.import_raw_content(
            tenant_scope="default",
            source_id="web-gw",
            source_type="app",
            adapter_type="jsonl",
            raw_text=(
                '{"event_uid":"app-1","event_type":"web_access","timestamp":"2026-11-18T08:02:00Z",'
                '"hostname":"win01.corp.local","username":"alice","domain":"CORP",'
                '"service_name":"portal","listen_port":8443,"resource_path":"/admin","extra_tag":"v1"}'
            ),
        )
        rt.ops_service.import_raw_content(
            tenant_scope="default",
            source_id="edr-sysmon",
            source_type="sysmon",
            adapter_type="jsonl",
            raw_text=(
                '{"EventRecordID":"9999","EventID":7,"UtcTime":"2026-11-18T08:03:00Z",'
                '"Computer":"win01.corp.local","ImageLoaded":"C:\\\\Temp\\\\evil.dll"}'
            ),
        )

        wide_window = TimeRange(
            start_time=datetime(2026, 11, 1, 0, 0, tzinfo=timezone.utc),
            end_time=datetime(2026, 11, 19, 0, 0, tzinfo=timezone.utc),
        )
        all_events = rt.query_service.search_events(
            SCOPE, wide_window, EventSearchFilter(include_fallback=True), PageSpec(limit=50)
        )
        observed_classes = {e.class_uid for e in all_events.items}
        for expected in (
            int(OcsfClassUid.PROCESS_ACTIVITY),
            int(OcsfClassUid.FILE_ACTIVITY),
            int(OcsfClassUid.NETWORK_ACTIVITY),
            int(OcsfClassUid.AUTHENTICATION),
            int(OcsfClassUid.DNS_ACTIVITY),
            int(OcsfClassUid.WEB_RESOURCES_ACTIVITY),
            int(OcsfClassUid.INVENTORY_INFO),
            int(OcsfClassUid.BASE_EVENT),
        ):
            self.assertIn(expected, observed_classes)

        fallback_summary = next(
            e
            for e in all_events.items
            if e.normalization_status == NormalizationStatus.UNSUPPORTED_PASSTHROUGH
        )
        fb_detail = rt.query_service.get_event(SCOPE, fallback_summary.event_id)
        assert fb_detail is not None
        self.assertEqual(fb_detail.normalized.ocsf_version, "1.3.0")
        self.assertEqual(fb_detail.normalized.original_event_uid, "9999")
        self.assertEqual(fb_detail.normalized.unmapped_fields["ImageLoaded"], "C:\\Temp\\evil.dll")

    def test_ac03_same_process_events_linked_by_stable_identity(self) -> None:
        rt = _new_memory_runtime()
        rt.ops_service.load_builtin_examples("default")

        procs = rt.query_service.search_entities(
            SCOPE,
            WINDOW,
            EntitySearchFilter(
                entity_types=(EntityType.PROCESS,),
                identifier_query="11111111-0001-0001-0001-000000000002",
            ),
            PageSpec(limit=10),
        )
        self.assertEqual(len(procs.items), 1)
        ps_entity = procs.items[0]

        rels = rt.query_service.get_entity_relations(
            SCOPE, ps_entity.entity_id, WINDOW, direction=Direction.BOTH
        )
        rel_types = {r.relation_type for r in rels.items}
        # Spawned (1007), wrote file (1001), connected to network (4001) all linked to this single entity.
        self.assertTrue(
            {RelationType.SPAWNS, RelationType.WRITES, RelationType.CONNECTS_TO} <= rel_types
        )

    def test_ac04_process_spawn_relation_generated(self) -> None:
        rt = _new_memory_runtime()
        rt.ops_service.load_builtin_examples("default")

        cmd_procs = rt.query_service.search_entities(
            SCOPE,
            WINDOW,
            EntitySearchFilter(
                entity_types=(EntityType.PROCESS,),
                identifier_query="11111111-0001-0001-0001-000000000001",
            ),
            PageSpec(limit=10),
        )
        self.assertEqual(len(cmd_procs.items), 1)
        spawns = rt.query_service.get_entity_relations(
            SCOPE,
            cmd_procs.items[0].entity_id,
            WINDOW,
            direction=Direction.OUTBOUND,
            relation_types=(RelationType.SPAWNS,),
        )
        self.assertEqual(len(spawns.items), 1)
        self.assertEqual(spawns.items[0].certainty, Certainty.DETERMINISTIC)

    def test_ac05_process_network_connection_relation_generated(self) -> None:
        rt = _new_memory_runtime()
        rt.ops_service.load_builtin_examples("default")

        ps = rt.query_service.search_entities(
            SCOPE,
            WINDOW,
            EntitySearchFilter(
                entity_types=(EntityType.PROCESS,),
                identifier_query="11111111-0001-0001-0001-000000000002",
            ),
            PageSpec(limit=5),
        ).items[0]
        conns = rt.query_service.get_entity_relations(
            SCOPE,
            ps.entity_id,
            WINDOW,
            direction=Direction.OUTBOUND,
            relation_types=(RelationType.CONNECTS_TO,),
        )
        self.assertEqual(len(conns.items), 1)
        dst = rt.query_service.get_entity(SCOPE, conns.items[0].dst_entity_id)
        assert dst is not None
        self.assertEqual(dst.entity.entity_type, EntityType.NETWORK_ENDPOINT)
        self.assertEqual(dst.entity.display_label, "198.51.100.42:443/tcp")

    def test_ac06_firewall_and_endpoint_connections_correlated_by_five_tuple(self) -> None:
        # Test normal order (Endpoint -> Zeek -> Firewall)
        rt = _new_memory_runtime()
        rt.ops_service.load_builtin_examples("default")
        ps = rt.query_service.search_entities(
            SCOPE,
            WINDOW,
            EntitySearchFilter(identifier_query="11111111-0001-0001-0001-000000000002"),
            PageSpec(limit=5),
        ).items[0]
        conn_edge = rt.query_service.get_entity_relations(
            SCOPE, ps.entity_id, WINDOW, Direction.OUTBOUND, (RelationType.CONNECTS_TO,)
        ).items[0]
        # Aggregated Sysmon (9003) + Zeek (C9xConn01) + Firewall (fw-7001)
        self.assertEqual(conn_edge.evidence_count, 3)

        # Also test reverse arrival order (Assets -> Firewall -> Sysmon)
        rt_rev = _new_memory_runtime()
        ex = Path("tests/fixtures/examples")
        for sid, st, ad, fn in (
            ("cmdb", "asset", "asset", "assets_sample.json"),
            ("fw", "firewall", "csv", "firewall_sample.csv"),
            ("edr", "sysmon", "jsonl", "sysmon_sample.jsonl"),
        ):
            rt_rev.ops_service.submit_import(
                SampleImportRequest("default", sid, st, ad, str(ex / fn))
            )
        ps_rev = rt_rev.query_service.search_entities(
            SCOPE,
            WINDOW,
            EntitySearchFilter(identifier_query="11111111-0001-0001-0001-000000000002"),
            PageSpec(limit=5),
        ).items[0]
        rev_edge = rt_rev.query_service.get_entity_relations(
            SCOPE, ps_rev.entity_id, WINDOW, Direction.OUTBOUND, (RelationType.CONNECTS_TO,)
        ).items[0]
        self.assertEqual(rev_edge.evidence_count, 2)

    def test_ac07_graph_relation_traces_back_to_raw_logs(self) -> None:
        rt = _new_memory_runtime()
        rt.ops_service.load_builtin_examples("default")

        ps = rt.query_service.search_entities(
            SCOPE,
            WINDOW,
            EntitySearchFilter(identifier_query="11111111-0001-0001-0001-000000000002"),
            PageSpec(limit=5),
        ).items[0]
        conn_edge = rt.query_service.get_entity_relations(
            SCOPE, ps.entity_id, WINDOW, Direction.OUTBOUND, (RelationType.CONNECTS_TO,)
        ).items[0]
        evidences = rt.query_service.get_relation_evidence(SCOPE, conn_edge.relation_id)
        self.assertEqual(len(evidences.items), 3)
        sources = {ev.source_id for ev in evidences.items}
        self.assertEqual(sources, {"edr-sysmon", "sensor-zeek-conn", "edge-fw-01"})
        self.assertTrue(any("fw-7001" in ev.raw_payload for ev in evidences.items))
        self.assertTrue(any('"EventRecordID":"9003"' in ev.raw_payload for ev in evidences.items))

    def test_ac08_duplicate_import_is_idempotent_and_replay_deterministic(self) -> None:
        rt = _new_memory_runtime()
        rt.ops_service.load_builtin_examples("default")

        entities_before = {
            e.entity_id
            for e in rt.query_service.search_entities(
                SCOPE, None, EntitySearchFilter(), PageSpec(limit=200)
            ).items
        }
        snap_before = rt.ops_service.get_metrics_snapshot(SCOPE)

        # Second import of exact same files
        second_receipts = rt.ops_service.load_builtin_examples("default")
        self.assertEqual(sum(r.accepted_count for r in second_receipts), 0)
        self.assertEqual(sum(r.duplicate_count for r in second_receipts), 11)

        entities_after_dup = {
            e.entity_id
            for e in rt.query_service.search_entities(
                SCOPE, None, EntitySearchFilter(), PageSpec(limit=200)
            ).items
        }
        self.assertEqual(entities_before, entities_after_dup)
        self.assertEqual(
            rt.ops_service.get_metrics_snapshot(SCOPE).ingested_total,
            snap_before.ingested_total,
        )

        # Full deterministic rebuild from raw_events preserves identical canonical entity IDs
        replay_receipt = rt.ops_service.trigger_replay(SCOPE, ReplayRequest())
        self.assertEqual(replay_receipt.replayed_raw_events, 11)
        entities_after_replay = {
            e.entity_id
            for e in rt.query_service.search_entities(
                SCOPE, None, EntitySearchFilter(), PageSpec(limit=200)
            ).items
        }
        self.assertEqual(entities_before, entities_after_replay)

    def test_ac09_uncertain_entities_and_relations_not_force_merged(self) -> None:
        rt = _new_memory_runtime()
        rt.ops_service.load_builtin_examples("default")

        # 1. Same process name + same PID 4120 on win01 vs win02 MUST stay two distinct entities
        ps_list = rt.query_service.search_entities(
            SCOPE,
            WINDOW,
            EntitySearchFilter(
                entity_types=(EntityType.PROCESS,), identifier_query="powershell.exe"
            ),
            PageSpec(limit=20),
        )
        self.assertEqual(len(ps_list.items), 2)
        self.assertNotEqual(ps_list.items[0].entity_id, ps_list.items[1].entity_id)

        # 2. Ambiguous short hostname + bare process name without GUID/PID remains PROVISIONAL
        rt.ops_service.import_raw_content(
            tenant_scope="default",
            source_id="legacy-agent",
            source_type="sysmon",
            adapter_type="jsonl",
            raw_text=(
                '{"EventRecordID":"9500","EventID":1,"UtcTime":"2026-11-18T08:00:10Z",'
                '"Computer":"WORKSTATION","Image":"cmd.exe"}'
            ),
        )
        provisionals = rt.query_service.search_entities(
            SCOPE,
            WINDOW,
            EntitySearchFilter(resolution_states=(ResolutionState.PROVISIONAL,)),
            PageSpec(limit=20),
        )
        self.assertGreaterEqual(len(provisionals.items), 2)

        # 3. fw-7002 (external SNAT 203.0.113.10 -> 198.51.100.42:443 at +80ms) NOT merged into win01 process
        c2_ep = rt.query_service.search_entities(
            SCOPE,
            WINDOW,
            EntitySearchFilter(
                entity_types=(EntityType.NETWORK_ENDPOINT,),
                identifier_query="198.51.100.42:443/tcp",
            ),
            PageSpec(limit=5),
        ).items[0]
        inbound_to_c2 = rt.query_service.get_entity_relations(
            SCOPE, c2_ep.entity_id, WINDOW, Direction.INBOUND
        )
        self.assertEqual(len(inbound_to_c2.items), 2)

        # 4. Partial 4-tuple (missing src_port) emits CANDIDATE only, hidden by default
        rt.ops_service.import_raw_content(
            tenant_scope="default",
            source_id="netflow-partial",
            source_type="firewall",
            adapter_type="csv",
            raw_text=(
                "event_uid,timestamp,src_ip,src_port,dst_ip,dst_port,protocol,action,bytes_sent\n"
                "fw-partial-1,2026-11-18T08:00:05.500Z,10.10.1.25,,198.51.100.42,443,tcp,ALLOW,200\n"
            ),
        )
        det_only = rt.query_service.get_entity_relations(
            SCOPE, c2_ep.entity_id, WINDOW, Direction.INBOUND, include_candidates=False
        )
        with_cand = rt.query_service.get_entity_relations(
            SCOPE, c2_ep.entity_id, WINDOW, Direction.INBOUND, include_candidates=True
        )
        self.assertEqual(len(det_only.items), 2)
        self.assertEqual(len(with_cand.items), 3)
        self.assertTrue(any(r.certainty == Certainty.CANDIDATE for r in with_cand.items))

    def test_ac10_query_api_enforces_scope_time_limit_and_returns_graph(self) -> None:
        rt = _new_memory_runtime()
        client = TestClient(create_app(rt))

        self.assertEqual(client.get("/healthz").status_code, 200)
        self.assertEqual(client.get("/").status_code, 200)
        self.assertEqual(client.get("/metrics").status_code, 200)

        seed_res = client.post("/api/v1/ops/batches/examples", headers={"X-Tenant-Id": "default"})
        self.assertEqual(seed_res.status_code, 200)
        self.assertEqual(seed_res.json()["accepted_total"], 11)

        # Tenant isolation: another tenant sees 0 entities and 0 events
        other_ents = client.post(
            "/api/v1/entities/search",
            headers={"X-Tenant-Id": "tenant-b"},
            json={"limit": 50},
        )
        self.assertEqual(other_ents.json()["items"], [])

        # Locate win01 powershell process and traverse 2-hop graph via HTTP API
        ent_res = client.post(
            "/api/v1/entities/search",
            headers={"X-Tenant-Id": "default"},
            json={"identifier_query": "11111111-0001-0001-0001-000000000002"},
        )
        ps_id = ent_res.json()["items"][0]["entity_id"]

        trav_res = client.post(
            "/api/v1/graph/traverse",
            headers={"X-Tenant-Id": "default"},
            json={
                "seed_entity_id": ps_id,
                "time_range": {
                    "start_time": "2026-11-18T07:50:00Z",
                    "end_time": "2026-11-18T08:10:00Z",
                },
                "max_depth": 2,
                "direction": "BOTH",
            },
        )
        self.assertEqual(trav_res.status_code, 200)
        sub = trav_res.json()
        self.assertGreaterEqual(len(sub["nodes"]), 5)
        self.assertGreaterEqual(len(sub["edges"]), 4)

        # Source whitelist enforcement on get_relation_evidence (powershell CONNECTS_TO has 3 total, 1 from sysmon)
        conn_rel = next(
            e
            for e in sub["edges"]
            if e["relation_type"] == "CONNECTS_TO" and e["src_entity_id"] == ps_id
        )
        restricted_ev = client.get(
            f"/api/v1/relations/{conn_rel['relation_id']}/evidence",
            headers={"X-Tenant-Id": "default", "X-Allowed-Sources": "edr-sysmon"},
        )
        self.assertEqual(len(restricted_ev.json()["items"]), 1)
        self.assertEqual(restricted_ev.json()["items"][0]["source_id"], "edr-sysmon")

        # Hard limit guardrail enforcement (max_depth > 6 rejected)
        over_depth = client.post(
            "/api/v1/graph/traverse",
            headers={"X-Tenant-Id": "default"},
            json={
                "seed_entity_id": ps_id,
                "time_range": {
                    "start_time": "2026-11-18T07:50:00Z",
                    "end_time": "2026-11-18T08:10:00Z",
                },
                "max_depth": 99,
            },
        )
        self.assertEqual(over_depth.status_code, 422)

        from uuid import UUID

        svc_sub = rt.query_service.traverse_graph(
            SCOPE, WINDOW, GraphTraversalSpec(seed_entity_id=UUID(ps_id))
        )
        self.assertGreaterEqual(len(svc_sub.nodes), 5)
