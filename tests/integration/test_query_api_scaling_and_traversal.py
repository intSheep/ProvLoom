from __future__ import annotations

import json
import unittest
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from provloom.api.app import create_app
from provloom.config import AppConfig
from provloom.domain.common import AccessScope, PageSpec, TimeRange
from provloom.domain.enums import EntityType, RelationType
from provloom.query.interfaces import EntitySearchFilter
from provloom.runtime import ProvLoomRuntime

SCOPE = AccessScope(tenant_id="default")
WINDOW = TimeRange(
    start_time=datetime(2026, 11, 18, 7, 0, tzinfo=UTC),
    end_time=datetime(2026, 11, 18, 12, 0, tzinfo=UTC),
)


@pytest.mark.integration
class QueryApiScalingAndTraversalTests(unittest.TestCase):
    def _seed_runtime(self) -> tuple[ProvLoomRuntime, str]:
        rt = ProvLoomRuntime.build(AppConfig(database_url="sqlite+pysqlite:///:memory:"))
        rt.ops_service.import_raw_content(
            tenant_scope="default",
            source_id="edr-sysmon",
            source_type="sysmon",
            adapter_type="jsonl",
            raw_text="\n".join(
                [
                    json.dumps(
                        {
                            "EventRecordID": "1",
                            "EventID": 1,
                            "UtcTime": "2026-11-18T08:00:00Z",
                            "Computer": "ws01.corp.local",
                            "ProcessGuid": "{proc-parent}",
                            "ProcessId": 100,
                            "Image": "C:\\Windows\\explorer.exe",
                            "CommandLine": "explorer.exe",
                        }
                    ),
                    json.dumps(
                        {
                            "EventRecordID": "2",
                            "EventID": 1,
                            "UtcTime": "2026-11-18T08:01:00Z",
                            "Computer": "ws01.corp.local",
                            "ProcessGuid": "{proc-child}",
                            "ProcessId": 200,
                            "Image": "C:\\Windows\\System32\\cmd.exe",
                            "CommandLine": "cmd.exe /c calc",
                            "ParentProcessGuid": "{proc-parent}",
                            "ParentProcessId": 100,
                            "ParentImage": "C:\\Windows\\explorer.exe",
                        }
                    ),
                    json.dumps(
                        {
                            "EventRecordID": "3",
                            "EventID": 11,
                            "UtcTime": "2026-11-18T08:02:00Z",
                            "Computer": "ws01.corp.local",
                            "ProcessGuid": "{proc-child}",
                            "ProcessId": 200,
                            "Image": "C:\\Windows\\System32\\cmd.exe",
                            "TargetFilename": "C:\\Temp\\noise.dll",
                        }
                    ),
                    json.dumps(
                        {
                            "EventRecordID": "4",
                            "EventID": 11,
                            "UtcTime": "2026-11-18T08:03:00Z",
                            "Computer": "ws01.corp.local",
                            "ProcessGuid": "{proc-child}",
                            "ProcessId": 200,
                            "Image": "C:\\Windows\\System32\\cmd.exe",
                            "TargetFilename": "C:\\Temp\\noise.dll",
                        }
                    ),
                    json.dumps(
                        {
                            "EventRecordID": "5",
                            "EventID": 3,
                            "UtcTime": "2026-11-18T08:04:00Z",
                            "Computer": "ws01.corp.local",
                            "ProcessGuid": "{proc-child}",
                            "ProcessId": 200,
                            "Image": "C:\\Windows\\System32\\cmd.exe",
                            "SourceIp": "10.0.0.5",
                            "SourcePort": 51000,
                            "DestinationIp": "198.51.100.10",
                            "DestinationPort": 443,
                            "Protocol": "tcp",
                        }
                    ),
                ]
            ),
        )
        rt.ops_service.import_raw_content(
            tenant_scope="default",
            source_id="other-src",
            source_type="sysmon",
            adapter_type="jsonl",
            raw_text="{bad json",
        )
        procs = rt.query_service.search_entities(
            SCOPE,
            WINDOW,
            EntitySearchFilter(entity_types=(EntityType.PROCESS,), identifier_query="cmd.exe"),
            PageSpec(limit=10),
        ).items
        self.assertEqual(len(procs), 1)
        return rt, str(procs[0].entity_id)

    def test_traverse_both_coverage_projection_and_filtered_neighborhood(self) -> None:
        rt, cmd_eid = self._seed_runtime()
        client = TestClient(create_app(rt))

        # 1. traverse_graph direction="BOTH" should return both parent (INBOUND) and file/net (OUTBOUND)
        trav = client.post(
            "/api/v1/graph/traverse",
            headers={"X-Tenant-Id": "default"},
            json={
                "seed_entity_id": cmd_eid,
                "time_range": {
                    "start_time": "2026-11-18T07:00:00Z",
                    "end_time": "2026-11-18T12:00:00Z",
                },
                "max_depth": 1,
                "direction": "BOTH",
                "include_candidates": True,
            },
        )
        self.assertEqual(trav.status_code, 200, trav.text)
        edge_types = {e["relation_type"] for e in trav.json()["edges"]}
        self.assertEqual(edge_types, {"RUNS", "SPAWNS", "WRITES", "CONNECTS_TO"})

        # 2. Server-side telemetry coverage + AccessScope source restriction
        cov = client.get(
            "/api/v1/telemetry/coverage",
            headers={"X-Tenant-Id": "default"},
            params={
                "start_time": "2026-11-18T07:00:00Z",
                "end_time": "2026-11-18T12:00:00Z",
            },
        )
        self.assertEqual(cov.status_code, 200, cov.text)
        cov_json = cov.json()
        self.assertEqual(cov_json["total_events"], 5)
        self.assertEqual(cov_json["by_source"], {"edr-sysmon": 5})
        self.assertEqual(cov_json["by_class_uid"], {"1001": 2, "1007": 2, "4001": 1})
        self.assertEqual(cov_json["failures_total"], 1)

        cov_scoped = client.get(
            "/api/v1/telemetry/coverage",
            headers={"X-Tenant-Id": "default", "X-Allowed-Sources": "edr-sysmon"},
            params={
                "start_time": "2026-11-18T07:00:00Z",
                "end_time": "2026-11-18T12:00:00Z",
            },
        )
        self.assertEqual(cov_scoped.status_code, 200)
        self.assertEqual(cov_scoped.json()["failures_total"], 0)

        # 3. Search field projection + invalid field path rejection
        search = client.post(
            "/api/v1/events/search",
            headers={"X-Tenant-Id": "default"},
            json={
                "time_range": {
                    "start_time": "2026-11-18T07:00:00Z",
                    "end_time": "2026-11-18T12:00:00Z",
                },
                "class_uids": [1007],
                "fields": ["process.cmd_line", "device.hostname"],
                "limit": 10,
            },
        )
        self.assertEqual(search.status_code, 200, search.text)
        items = search.json()["items"]
        self.assertEqual(len(items), 2)
        self.assertTrue(all(it["projected_fields"] is not None for it in items))
        cmds = {it["projected_fields"].get("process.cmd_line") for it in items}
        self.assertEqual(cmds, {"explorer.exe", "cmd.exe /c calc"})

        bad_search = client.post(
            "/api/v1/events/search",
            headers={"X-Tenant-Id": "default"},
            json={
                "time_range": {
                    "start_time": "2026-11-18T07:00:00Z",
                    "end_time": "2026-11-18T12:00:00Z",
                },
                "fields": ["process.cmd_line; DROP TABLE"],
            },
        )
        self.assertEqual(bad_search.status_code, 422)

        # 4. Filtered & grouped entity neighborhood
        nb = client.get(
            f"/api/v1/entities/{cmd_eid}/neighborhood",
            headers={"X-Tenant-Id": "default"},
            params={
                "start_time": "2026-11-18T07:00:00Z",
                "end_time": "2026-11-18T12:00:00Z",
                "exclude_labels": ["C:\\Temp\\noise.dll"],
                "sort_by": "rare",
                "group_summary": "true",
            },
        )
        self.assertEqual(nb.status_code, 200, nb.text)
        nb_json = nb.json()
        self.assertEqual(nb_json["total_relations_matched"], 3)
        labels = {it["neighbor"]["display_label"] for it in nb_json["items"]}
        self.assertNotIn("C:\\Temp\\noise.dll", labels)
        self.assertIn("198.51.100.10:443/tcp", labels)
        self.assertGreaterEqual(len(nb_json["groups"]), 1)

        nb_net = client.get(
            f"/api/v1/entities/{cmd_eid}/neighborhood",
            headers={"X-Tenant-Id": "default"},
            params={
                "start_time": "2026-11-18T07:00:00Z",
                "end_time": "2026-11-18T12:00:00Z",
                "neighbor_types": ["NETWORK_ENDPOINT"],
                "relation_types": [RelationType.CONNECTS_TO.value],
            },
        )
        self.assertEqual(nb_net.status_code, 200)
        self.assertEqual(nb_net.json()["total_relations_matched"], 1)
