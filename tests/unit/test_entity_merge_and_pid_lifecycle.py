from __future__ import annotations

import unittest
from datetime import UTC, datetime

import pytest

from provloom.config import AppConfig
from provloom.domain.common import AccessScope, PageSpec, TimeRange
from provloom.domain.enums import EntityType, ResolutionState
from provloom.query.interfaces import EntitySearchFilter
from provloom.runtime import ProvLoomRuntime

SCOPE = AccessScope(tenant_id="default")
WINDOW = TimeRange(
    start_time=datetime(2026, 11, 18, 7, 0, tzinfo=UTC),
    end_time=datetime(2026, 11, 18, 10, 0, tzinfo=UTC),
)


@pytest.mark.unit
class EntityLifecycleAndMergeTests(unittest.TestCase):
    def test_pid_reuse_after_termination_creates_distinct_process_entity(self) -> None:
        rt = ProvLoomRuntime.build(AppConfig(database_url="sqlite+pysqlite:///:memory:"))
        # 1. Launch PID 5000 (no ProcessGuid) at 08:00, write file at 08:01, terminate at 08:02, reuse PID 5000 at 08:05
        rt.ops_service.import_raw_content(
            tenant_scope="default",
            source_id="edr",
            source_type="sysmon",
            adapter_type="jsonl",
            raw_text="\n".join(
                [
                    '{"EventRecordID":"1","EventID":1,"UtcTime":"2026-11-18T08:00:00Z","Computer":"h1.corp.local","ProcessId":5000,"Image":"C:\\\\app1.exe"}',
                    '{"EventRecordID":"2","EventID":11,"UtcTime":"2026-11-18T08:01:00Z","Computer":"h1.corp.local","ProcessId":5000,"Image":"C:\\\\app1.exe","TargetFilename":"C:\\\\out.txt"}',
                    '{"EventRecordID":"3","EventID":5,"UtcTime":"2026-11-18T08:02:00Z","Computer":"h1.corp.local","ProcessId":5000,"Image":"C:\\\\app1.exe"}',
                    '{"EventRecordID":"4","EventID":11,"UtcTime":"2026-11-18T08:03:00Z","Computer":"h1.corp.local","ProcessId":5000,"Image":"C:\\\\app1.exe","TargetFilename":"C:\\\\orphan.txt"}',
                    '{"EventRecordID":"5","EventID":1,"UtcTime":"2026-11-18T08:05:00Z","Computer":"h1.corp.local","ProcessId":5000,"Image":"C:\\\\app2.exe"}',
                ]
            ),
        )
        procs = rt.query_service.search_entities(
            SCOPE,
            WINDOW,
            EntitySearchFilter(entity_types=(EntityType.PROCESS,)),
            PageSpec(limit=20),
        ).items
        # Expect: P1 (08:00..08:02 SCOPED_TEMPORAL), Orphan at 08:03 (PROVISIONAL), P2 at 08:05 (SCOPED_TEMPORAL)
        self.assertEqual(len(procs), 3)
        states = sorted(p.resolution_state.value for p in procs)
        self.assertEqual(states, ["PROVISIONAL", "SCOPED_TEMPORAL", "SCOPED_TEMPORAL"])

    def test_authoritative_bridge_merges_entities_with_audit_record(self) -> None:
        rt = ProvLoomRuntime.build(AppConfig(database_url="sqlite+pysqlite:///:memory:"))
        # Host first seen by FQDN only, another record seen by asset_id only, third bridges both.
        rt.ops_service.import_raw_content(
            tenant_scope="default",
            source_id="edr",
            source_type="sysmon",
            adapter_type="jsonl",
            raw_text='{"EventRecordID":"10","EventID":1,"UtcTime":"2026-11-18T08:00:00Z","Computer":"db01.corp.local","ProcessGuid":"{aaaa-1}","ProcessId":100,"Image":"sql.exe"}',
        )
        rt.ops_service.import_raw_content(
            tenant_scope="default",
            source_id="cmdb-partial",
            source_type="asset",
            adapter_type="json",
            raw_text='[{"asset_id":"asset-db-01","os":"Linux"}]',
        )
        hosts_before = rt.query_service.search_entities(
            SCOPE, None, EntitySearchFilter(entity_types=(EntityType.HOST,)), PageSpec(limit=10)
        ).items
        self.assertEqual(len(hosts_before), 2)

        # Bridge manifest unites asset-db-01 and db01.corp.local
        rt.ops_service.import_raw_content(
            tenant_scope="default",
            source_id="cmdb-full",
            source_type="asset",
            adapter_type="json",
            raw_text='[{"asset_id":"asset-db-01","hostname":"db01.corp.local","ip":"10.20.0.10"}]',
        )
        hosts_after = rt.query_service.search_entities(
            SCOPE, None, EntitySearchFilter(entity_types=(EntityType.HOST,)), PageSpec(limit=10)
        ).items
        self.assertEqual(len(hosts_after), 1)
        detail = rt.query_service.get_entity(SCOPE, hosts_after[0].entity_id)
        assert detail is not None
        self.assertEqual(len(detail.merges), 1)
        self.assertIn("authoritative_bridge", detail.merges[0].merge_rule_id)

    def test_local_users_with_same_name_on_different_hosts_stay_separate(self) -> None:
        rt = ProvLoomRuntime.build(AppConfig(database_url="sqlite+pysqlite:///:memory:"))
        rt.ops_service.import_raw_content(
            tenant_scope="default",
            source_id="linux-auth",
            source_type="auth",
            adapter_type="jsonl",
            raw_text="\n".join(
                [
                    '{"EventRecordID":"u1","EventID":4624,"TimeCreated":"2026-11-18T08:00:00Z","Computer":"srv1.corp.local","TargetUserName":"admin","TargetDomainName":"LOCAL"}',
                    '{"EventRecordID":"u2","EventID":4624,"TimeCreated":"2026-11-18T08:01:00Z","Computer":"srv2.corp.local","TargetUserName":"admin","TargetDomainName":"LOCAL"}',
                ]
            ),
        )
        admins = rt.query_service.search_entities(
            SCOPE,
            WINDOW,
            EntitySearchFilter(entity_types=(EntityType.USER,), identifier_query="admin"),
            PageSpec(limit=10),
        ).items
        self.assertEqual(len(admins), 2)
        self.assertTrue(all(u.resolution_state == ResolutionState.SCOPED_TEMPORAL for u in admins))
