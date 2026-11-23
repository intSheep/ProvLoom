from __future__ import annotations

import ast
import unittest
from datetime import UTC, datetime
from pathlib import Path

import pytest

from provloom.detection.compiler.postgres_backend import compile_rule_yaml
from provloom.detection.domain.rule import RuleSeverity, RuleSource, RuleStatus
from provloom.detection.rules.registry import BuiltinRuleRegistry


@pytest.mark.unit
class DetectionCompilerAndDomainTests(unittest.TestCase):
    def test_detection_domain_has_zero_framework_or_io_imports(self) -> None:
        domain_dir = Path("src/provloom/detection/domain")
        forbidden_prefixes = ("sqlalchemy", "fastapi", "uvicorn", "psycopg", "httpx")
        for py_file in sorted(domain_dir.glob("*.py")):
            tree = ast.parse(py_file.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        self.assertFalse(
                            alias.name.startswith(forbidden_prefixes),
                            f"Forbidden import {alias.name} in {py_file}",
                        )
                elif isinstance(node, ast.ImportFrom) and node.module:
                    self.assertFalse(
                        node.module.startswith(forbidden_prefixes),
                        f"Forbidden import {node.module} in {py_file}",
                    )

    def test_sigma_operators_modifiers_and_parameterized_postgres_sql(self) -> None:
        raw_sigma = """
title: Complex Sigma Operator Coverage
id: 12345678-1234-4234-8234-1234567890ab
version: 1.2.0
level: critical
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  sel_proc:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains|all:
      - '-nop'
      - 'Bypass'
    CommandLine|re: 'powershell.*-enc\\s+[A-Za-z0-9+/=]+'
    ProcessId|gte: 100
  filter_parent:
    ParentImage|startswith: 'C:\\Program Files\\Trusted\\'
  condition: sel_proc and not filter_parent
"""
        art = compile_rule_yaml(raw_sigma, source_reference="unit-test")
        self.assertTrue(art.rule.compatibility.parse_success)
        self.assertTrue(art.rule.compatibility.mapping_success)
        self.assertTrue(art.rule.compatibility.data_coverage)
        self.assertTrue(art.rule.compatibility.compile_success)
        self.assertEqual(art.rule.status, RuleStatus.ENABLED)
        self.assertEqual(art.rule.severity, RuleSeverity.CRITICAL)
        self.assertEqual(art.rule.compatibility.field_mappings["Image"], "process.file.path")
        self.assertEqual(art.rule.compatibility.field_mappings["CommandLine"], "process.cmd_line")
        assert art.event_query is not None
        sql = art.event_query.postgres_sql
        # Verify strictly parameterized bind placeholders (never raw literal interpolation).
        self.assertNotIn("Bypass", sql)
        self.assertIn("%(det_p_", sql)
        self.assertIn("normalized_events.tenant_scope", sql)

    def test_rejects_arbitrary_sql_python_and_unsupported_sigma_semantics(self) -> None:
        sql_injection_rule = """
rule_type: provloom_custom
rule_id: evil-sql
rule_name: Forbidden Raw SQL
sql: "SELECT * FROM users; DROP TABLE raw_events;"
"""
        evil_art = compile_rule_yaml(sql_injection_rule)
        self.assertFalse(evil_art.rule.compatibility.parse_success)
        self.assertEqual(evil_art.rule.status, RuleStatus.ERROR)
        self.assertTrue(
            any("forbidden" in r.lower() for r in evil_art.rule.compatibility.unsupported_reasons)
        )

        corr_sigma = """
title: Base Login
id: aaaaaaaa-1111-4111-8111-111111111111
name: base_login
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
  condition: selection
---
title: Brute Force Correlation
id: bbbbbbbb-2222-4222-8222-222222222222
correlation:
  type: event_count
  rules:
    - base_login
  group-by:
    - IpAddress
  timespan: 5m
  condition:
    gte: 10
"""
        corr_art = compile_rule_yaml(corr_sigma)
        self.assertTrue(corr_art.rule.compatibility.parse_success)
        self.assertFalse(corr_art.rule.compatibility.compile_success)
        self.assertEqual(corr_art.rule.status, RuleStatus.UNSUPPORTED)
        self.assertTrue(
            any("correlation" in r.lower() for r in corr_art.rule.compatibility.unsupported_reasons)
        )

        expand_sigma = """
title: Placeholder Expand Rule
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|expand: '%AdminUsers%'
  condition: selection
"""
        exp_art = compile_rule_yaml(expand_sigma)
        self.assertTrue(exp_art.rule.compatibility.parse_success)
        self.assertFalse(exp_art.rule.compatibility.mapping_success)
        self.assertEqual(exp_art.rule.status, RuleStatus.UNSUPPORTED)
        self.assertTrue(
            any("modifier" in r.lower() for r in exp_art.rule.compatibility.unsupported_reasons)
        )

    def test_builtin_rule_compatibility_statistics_evaluation(self) -> None:
        registry = BuiltinRuleRegistry()
        builtins = registry.load_builtins()
        total = len(builtins)
        self.assertGreaterEqual(total, 12)
        parsed_ok = sum(1 for a in builtins if a.rule.compatibility.parse_success)
        mapped_ok = sum(1 for a in builtins if a.rule.compatibility.mapping_success)
        compiled_ok = sum(1 for a in builtins if a.rule.compatibility.compile_success)
        unsupported = [a for a in builtins if not a.rule.compatibility.is_supported]

        self.assertEqual(parsed_ok, total)
        self.assertEqual(mapped_ok, total - 1)
        self.assertEqual(compiled_ok, total - 1)
        self.assertEqual(len(unsupported), 1)
        self.assertEqual(unsupported[0].rule.source, RuleSource.SIGMA)
        self.assertTrue(len(unsupported[0].rule.compatibility.unsupported_reasons) >= 1)

    def test_regression_no_silent_semantic_distortion_from_upstream_pipeline(self) -> None:
        # Defect #1 regression: file_event rules referencing ParentImage must NOT map to file.name.
        file_parent_yaml = """
title: Office Macro from Suspicious Parent
logsource:
  category: file_event
  product: windows
detection:
  sel_cmd:
    ParentImage|endswith: '\\wscript.exe'
  sel_ext:
    TargetFilename|endswith: '.docm'
  condition: all of sel_*
"""
        art = compile_rule_yaml(file_parent_yaml)
        self.assertTrue(art.rule.compatibility.parse_success)
        self.assertFalse(art.rule.compatibility.mapping_success)
        self.assertEqual(art.rule.status, RuleStatus.UNSUPPORTED)
        self.assertNotEqual(art.rule.compatibility.field_mappings.get("ParentImage"), "file.name")
        self.assertIn(
            "Unmapped Sigma field: 'ParentImage'",
            art.rule.compatibility.unsupported_reasons,
        )

        # registry_set rules referencing Image must NOT collide onto reg_key.path.
        reg_yaml = """
title: Registry Run Key by Binary
logsource:
  category: registry_set
  product: windows
detection:
  selection:
    Image|endswith: '\\reg.exe'
    TargetObject|contains: 'CurrentVersion\\Run'
  condition: selection
"""
        reg_art = compile_rule_yaml(reg_yaml)
        self.assertFalse(reg_art.rule.compatibility.mapping_success)
        self.assertNotEqual(reg_art.rule.compatibility.field_mappings.get("Image"), "reg_key.path")

    def test_regression_windash_base64_case_and_postgres_regex_bounds(self) -> None:
        # Defects #3, #4, #5 regression: windash (SigmaExpansion), base64 case-sensitivity,
        # inline (?i) + |m regex flag merging, and {1,256} POSIX ARE DUPMAX decomposition.
        sigma_yaml = """
title: Compiler Edge Case Regression
logsource:
  category: process_creation
  product: windows
detection:
  sel_windash:
    CommandLine|contains|windash: ' -ma '
  sel_b64:
    CommandLine|base64|contains: 'IEX'
  sel_re_flags:
    CommandLine|re|m: '(?i)^net\\s+user'
  sel_re_dup:
    ParentCommandLine|re: '\\\\[^\\\\]{1,256}$'
  condition: 1 of sel_*
"""
        art = compile_rule_yaml(sigma_yaml)
        self.assertTrue(art.rule.compatibility.compile_success)
        assert art.event_query is not None
        sql = art.event_query.postgres_sql
        # Base64 without |cased uses default case-insensitive LIKE; |base64|cased uses exact LIKE.
        self.assertIn("lower(", sql)
        self.assertNotIn("(?m)(?i)", sql)
        self.assertIn("~*", sql)

        # Unsplittable multi-char group repetition > 255 fails explicitly at compile stage.
        bad_group_dup = """
title: Unsupported Group Repetition Over 255
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|re: '(?:abc){1,300}'
  condition: selection
"""
        bad_art = compile_rule_yaml(bad_group_dup)
        self.assertTrue(bad_art.rule.compatibility.mapping_success)
        self.assertFalse(bad_art.rule.compatibility.compile_success)
        self.assertEqual(bad_art.rule.status, RuleStatus.UNSUPPORTED)

    def test_ocsf_v140_version_contract_and_field_catalog_schema_consistency(self) -> None:
        from pathlib import Path

        import yaml

        from provloom.config import AppConfig
        from provloom.detection.compiler.ocsf_pipeline import (
            DEFAULT_PROVLOOM_COVERED_FIELDS,
            KNOWN_OCSF_V14_FIELDS,
        )
        from provloom.domain.common import AccessScope, PageSpec, TimeRange
        from provloom.domain.enums import OcsfClassUid
        from provloom.query.interfaces import EventSearchFilter
        from provloom.runtime import ProvLoomRuntime
        from tests.evaluation.ocsf_validator import (
            PINNED_OCSF_VERSION,
            validate_ocsf_v140_event,
            validate_ocsf_v140_field_path,
        )

        self.assertEqual(AppConfig().ocsf_version, PINNED_OCSF_VERSION)
        self.assertEqual(int(OcsfClassUid.SCRIPT_ACTIVITY), 1009)
        self.assertNotIn("answers", KNOWN_OCSF_V14_FIELDS)
        self.assertIn("answers.rdata", KNOWN_OCSF_V14_FIELDS)
        self.assertNotIn("script.script_content", KNOWN_OCSF_V14_FIELDS)
        self.assertIn("script.script_content.value", KNOWN_OCSF_V14_FIELDS)

        for field_path in sorted(KNOWN_OCSF_V14_FIELDS):
            errs = validate_ocsf_v140_field_path(field_path)
            self.assertEqual(
                errs, [], f"KNOWN_OCSF_V14_FIELDS entry {field_path!r} invalid: {errs}"
            )

        for cid, cov_fields in sorted(DEFAULT_PROVLOOM_COVERED_FIELDS.items()):
            for field_path in sorted(cov_fields):
                errs = validate_ocsf_v140_field_path(field_path, [cid])
                self.assertEqual(
                    errs, [], f"Covered field {field_path!r} invalid on class {cid}: {errs}"
                )

        repo_root = Path(__file__).resolve().parents[2]
        for mp in sorted((repo_root / "configs" / "mappings").glob("*.yaml")):
            doc = yaml.safe_load(mp.read_text(encoding="utf-8"))
            self.assertEqual(doc.get("ocsf_version"), PINNED_OCSF_VERSION, f"{mp.name} version")
            target_cid = int(doc["target"]["class_uid"])
            for target_field in doc.get("fields") or {}:
                errs = validate_ocsf_v140_field_path(str(target_field), [target_cid])
                self.assertEqual(errs, [], f"{mp.name} field {target_field!r} invalid: {errs}")

        rt = ProvLoomRuntime.build(AppConfig(database_url="sqlite+pysqlite:///:memory:"))
        rt.ops_service.load_builtin_examples("v140_check")
        summaries = rt.query_service.search_events(
            AccessScope("v140_check"),
            TimeRange(datetime(2020, 1, 1, tzinfo=UTC), datetime(2030, 1, 1, tzinfo=UTC)),
            EventSearchFilter(include_fallback=True),
            PageSpec(limit=100),
        ).items
        self.assertGreaterEqual(len(summaries), 8)
        for s in summaries:
            detail = rt.query_service.get_event(AccessScope("v140_check"), s.event_id)
            assert detail is not None
            self.assertEqual(detail.normalized.ocsf_version, PINNED_OCSF_VERSION)
            self.assertEqual(
                detail.normalized.ocsf_payload["metadata"]["version"], PINNED_OCSF_VERSION
            )
            ev_errs = validate_ocsf_v140_event(
                detail.normalized.ocsf_payload,
                allow_provloom_metadata_original_uid=True,
            )
            self.assertEqual(ev_errs, [], f"Event {s.class_uid} failed OCSF 1.4.0: {ev_errs}")

    def test_dns_answers_rdata_standard_ocsf_and_sibling_attribute_isolation(self) -> None:
        from provloom.config import AppConfig
        from provloom.domain.common import AccessScope, TimeRange
        from provloom.runtime import ProvLoomRuntime
        from tests.evaluation.helpers import seed_synthetic_ocsf_cases

        dns_rule = """
title: DNS TXT Answer RData Isolation Test
id: 99999999-0000-4000-8000-000000000403
logsource:
  category: dns
detection:
  sel_q:
    query: 'txt.c2.example'
  sel_ans:
    QueryResults|contains: 'IEX'
  filter_benign:
    answers: '9.9.9.9'
  condition: sel_q and sel_ans and not filter_benign
"""
        art = compile_rule_yaml(dns_rule)
        self.assertTrue(art.rule.compatibility.compile_success)
        self.assertEqual(art.rule.compatibility.field_mappings.get("QueryResults"), "answers.rdata")
        self.assertEqual(art.rule.compatibility.field_mappings.get("answers"), "answers.rdata")

        dns_neg_only_rule = """
title: DNS Missing Answers Negation Check
id: 99999999-0000-4000-8000-000000000404
logsource:
  category: dns
detection:
  sel_q:
    query: 'nx.c2.example'
  filter_ans:
    answers: '1.1.1.1'
  condition: sel_q and not filter_ans
"""

        cases = [
            {
                "test_event_id": "dns-tp-multi",
                "category_uid": 4,
                "class_uid": 4003,
                "activity_id": 6,
                "ocsf_fields": {
                    "query": {"hostname": "txt.c2.example"},
                    "answers": [
                        {"class": "IN", "type": "TXT", "rdata": "v=spf1 -all"},
                        {"class": "IN", "type": "TXT", "rdata": "IEX (New-Object Net.WebClient)"},
                    ],
                },
            },
            {
                "test_event_id": "dns-tn-sibling-only",
                "category_uid": 4,
                "class_uid": 4003,
                "activity_id": 6,
                "ocsf_fields": {
                    "query": {"hostname": "txt.c2.example"},
                    "answers": [
                        {
                            "class": "IEX",
                            "type": "TXT_IEX",
                            "flags": ["IEX"],
                            "rdata": "v=spf1 -all",
                        }
                    ],
                },
            },
            {
                "test_event_id": "dns-tn-empty",
                "category_uid": 4,
                "class_uid": 4003,
                "activity_id": 6,
                "ocsf_fields": {"query": {"hostname": "txt.c2.example"}, "answers": []},
            },
            {
                "test_event_id": "dns-tp-missing-negated",
                "category_uid": 4,
                "class_uid": 4003,
                "activity_id": 1,
                "ocsf_fields": {"query": {"hostname": "nx.c2.example"}},
            },
        ]
        rt = ProvLoomRuntime.build(AppConfig(database_url="sqlite+pysqlite:///:memory:"))
        seed_synthetic_ocsf_cases(rt, "dns_iso", cases)
        win = TimeRange(datetime(2020, 1, 1, tzinfo=UTC), datetime(2030, 1, 1, tzinfo=UTC))
        res1 = rt.detection_service.test_detection_rule(
            AccessScope("dns_iso"), win, raw_yaml=dns_rule
        )
        matched1 = {m.evidence_references[0].original_event_uid for m in res1.matches}
        self.assertEqual(matched1, {"dns-tp-multi"})

        res2 = rt.detection_service.test_detection_rule(
            AccessScope("dns_iso"), win, raw_yaml=dns_neg_only_rule
        )
        matched2 = {m.evidence_references[0].original_event_uid for m in res2.matches}
        self.assertEqual(matched2, {"dns-tp-missing-negated"})

    def test_script_activity_1009_long_string_value_mapping_and_isolation(self) -> None:
        from provloom.config import AppConfig
        from provloom.domain.common import AccessScope, TimeRange
        from provloom.runtime import ProvLoomRuntime
        from tests.evaluation.helpers import seed_synthetic_ocsf_cases

        ps_rule = """
title: PowerShell Script LongString Value Check
id: 99999999-0000-4000-8000-000000001009
logsource:
  category: ps_script
  product: windows
detection:
  selection:
    ScriptBlockText|contains: 'Invoke-Mimikatz'
  condition: selection
"""
        art = compile_rule_yaml(ps_rule)
        self.assertTrue(art.rule.compatibility.compile_success)
        self.assertEqual(
            art.rule.compatibility.field_mappings.get("ScriptBlockText"),
            "script.script_content.value",
        )
        cases = [
            {
                "test_event_id": "ps-tp-val",
                "category_uid": 1,
                "class_uid": 1009,
                "activity_id": 1,
                "ocsf_fields": {
                    "actor": {},
                    "device": {"type_id": 0},
                    "script": {
                        "type_id": 2,
                        "script_content": {"value": "Invoke-Mimikatz -DumpCreds"},
                    },
                },
            },
            {
                "test_event_id": "ps-tn-sibling",
                "category_uid": 1,
                "class_uid": 1009,
                "activity_id": 1,
                "ocsf_fields": {
                    "actor": {},
                    "device": {"type_id": 0},
                    "script": {
                        "type_id": 2,
                        "name": "Invoke-Mimikatz",
                        "uid": "Invoke-Mimikatz",
                        "script_content": {"value": "Get-Date"},
                    },
                },
            },
        ]
        rt = ProvLoomRuntime.build(AppConfig(database_url="sqlite+pysqlite:///:memory:"))
        seed_synthetic_ocsf_cases(rt, "ps_iso", cases)
        win = TimeRange(datetime(2020, 1, 1, tzinfo=UTC), datetime(2030, 1, 1, tzinfo=UTC))
        res = rt.detection_service.test_detection_rule(AccessScope("ps_iso"), win, raw_yaml=ps_rule)
        matched = {m.evidence_references[0].original_event_uid for m in res.matches}
        self.assertEqual(matched, {"ps-tp-val"})

    def test_sigma_base64_uncased_default_vs_explicit_cased_modifier(self) -> None:
        from provloom.config import AppConfig
        from provloom.domain.common import AccessScope, TimeRange
        from provloom.runtime import ProvLoomRuntime
        from tests.evaluation.helpers import seed_synthetic_ocsf_cases

        b64_uncased_yaml = """
title: Base64 Without Cased
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|base64|contains: 'IEX'
  condition: selection
"""
        b64_cased_yaml = """
title: Base64 With Cased
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|base64|cased|contains: 'IEX'
  condition: selection
"""
        cases = [
            {
                "test_event_id": "b64-upper",
                "category_uid": 1,
                "class_uid": 1007,
                "activity_id": 1,
                "ocsf_fields": {"process": {"cmd_line": "powershell -e SUVY"}},
            },
            {
                "test_event_id": "b64-lower",
                "category_uid": 1,
                "class_uid": 1007,
                "activity_id": 1,
                "ocsf_fields": {"process": {"cmd_line": "powershell -e suvy"}},
            },
        ]
        rt = ProvLoomRuntime.build(AppConfig(database_url="sqlite+pysqlite:///:memory:"))
        seed_synthetic_ocsf_cases(rt, "b64_case", cases)
        win = TimeRange(datetime(2020, 1, 1, tzinfo=UTC), datetime(2030, 1, 1, tzinfo=UTC))

        r_uncased = rt.detection_service.test_detection_rule(
            AccessScope("b64_case"), win, raw_yaml=b64_uncased_yaml
        )
        self.assertEqual(
            {m.evidence_references[0].original_event_uid for m in r_uncased.matches},
            {"b64-upper", "b64-lower"},
        )

        r_cased = rt.detection_service.test_detection_rule(
            AccessScope("b64_case"), win, raw_yaml=b64_cased_yaml
        )
        self.assertEqual(
            {m.evidence_references[0].original_event_uid for m in r_cased.matches},
            {"b64-upper"},
        )

    def test_sigma_exists_with_json_null_and_runtime_error_propagation(self) -> None:
        import re
        from unittest.mock import patch

        from provloom.config import AppConfig
        from provloom.domain.common import AccessScope, TimeRange
        from provloom.runtime import ProvLoomRuntime
        from provloom.storage.postgres.uow import _sqlite_regexp
        from tests.evaluation.helpers import seed_synthetic_ocsf_cases

        with self.assertRaises(re.error):
            _sqlite_regexp("[unclosed", "", "abc")

        exists_yaml = """
title: Exists With JSON Null Check
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|exists: true
  condition: selection
"""
        cases = [
            {
                "test_event_id": "ex-json-null",
                "category_uid": 1,
                "class_uid": 1007,
                "activity_id": 1,
                "ocsf_fields": {"process": {"cmd_line": None}},
            },
            {
                "test_event_id": "ex-missing",
                "category_uid": 1,
                "class_uid": 1007,
                "activity_id": 1,
                "ocsf_fields": {"process": {}},
            },
        ]
        rt = ProvLoomRuntime.build(AppConfig(database_url="sqlite+pysqlite:///:memory:"))
        seed_synthetic_ocsf_cases(rt, "ex_check", cases)
        win = TimeRange(datetime(2020, 1, 1, tzinfo=UTC), datetime(2030, 1, 1, tzinfo=UTC))
        res_ex = rt.detection_service.test_detection_rule(
            AccessScope("ex_check"), win, raw_yaml=exists_yaml
        )
        self.assertEqual(
            {m.evidence_references[0].original_event_uid for m in res_ex.matches},
            {"ex-json-null"},
        )

        with patch.object(
            rt.detection_service._event_matcher,
            "match_batch",
            side_effect=RuntimeError("simulated SQL failure"),
        ):
            res_err = rt.detection_service.test_detection_rule(
                AccessScope("ex_check"), win, raw_yaml=exists_yaml
            )
        self.assertEqual(res_err.rule.status, RuleStatus.ERROR)
        self.assertIs(res_err.rule.compatibility.execution_success, False)
        self.assertIn("simulated SQL failure", res_err.failure_reason or "")

    def test_ocsf_v140_validator_enforces_enums_and_constraints(self) -> None:
        from uuid import uuid4

        from tests.evaluation.ocsf_validator import PINNED_OCSF_VERSION, validate_ocsf_v140_event

        base_uid = str(uuid4())
        valid_meta = {
            "version": PINNED_OCSF_VERSION,
            "uid": base_uid,
            "product": {"vendor_name": "ProvLoom", "name": "Test"},
        }
        valid_1001 = {
            "category_uid": 1,
            "class_uid": 1001,
            "activity_id": 1,
            "type_uid": 100101,
            "severity_id": 1,
            "time": 1763596800000,
            "metadata": dict(valid_meta),
            "device": {"type_id": 0, "uid": "dev-1"},
            "actor": {"app_name": "synthetic-actor"},
            "file": {"type_id": 1, "name": "a.txt"},
        }
        self.assertEqual(
            validate_ocsf_v140_event(
                valid_1001,
                allow_provloom_metadata_original_uid=False,
                check_enums=True,
                check_constraints=True,
            ),
            [],
        )

        valid_6001 = {
            "category_uid": 6,
            "class_uid": 6001,
            "activity_id": 1,
            "type_uid": 600101,
            "severity_id": 1,
            "time": 1763596800000,
            "metadata": {**valid_meta, "profiles": ["host"]},
            "device": {"type_id": 0, "uid": "dev-1"},
            "actor": {"app_name": "browser"},
            "web_resources": [{"name": "https://x.test", "url_string": "https://x.test"}],
        }
        self.assertEqual(
            validate_ocsf_v140_event(
                valid_6001,
                allow_provloom_metadata_original_uid=False,
                check_enums=True,
                check_constraints=True,
            ),
            [],
        )

        bad_enum = {
            "category_uid": 1,
            "class_uid": 1007,
            "activity_id": 88,
            "type_uid": 100788,
            "severity_id": 999,
            "time": 1763596800000,
            "metadata": dict(valid_meta),
            "device": {"type_id": 77, "uid": "dev-1"},
            "process": {"uid": "p-1"},
        }
        enum_errs = validate_ocsf_v140_event(bad_enum, check_enums=True, check_constraints=True)
        self.assertTrue(any("severity_id" in e and "999" in e for e in enum_errs), enum_errs)
        self.assertTrue(any("device.type_id" in e and "77" in e for e in enum_errs), enum_errs)
        self.assertTrue(any("activity_id" in e and "88" in e for e in enum_errs), enum_errs)

        bad_constraints_1007 = {
            "category_uid": 1,
            "class_uid": 1007,
            "activity_id": 1,
            "type_uid": 100701,
            "severity_id": 1,
            "time": 1763596800000,
            "metadata": dict(valid_meta),
            "device": {"type_id": 0},
            "process": {"cmd_line": "x"},
        }
        c_errs = validate_ocsf_v140_event(
            bad_constraints_1007, check_enums=True, check_constraints=True
        )
        self.assertTrue(any("device: violated OCSF at_least_one" in e for e in c_errs), c_errs)
        self.assertTrue(any("process: violated OCSF at_least_one" in e for e in c_errs), c_errs)

        bad_dns_constraints = {
            "category_uid": 4,
            "class_uid": 4003,
            "activity_id": 1,
            "type_uid": 400301,
            "severity_id": 1,
            "time": 1763596800000,
            "metadata": dict(valid_meta),
        }
        dns_errs = validate_ocsf_v140_event(
            bad_dns_constraints, check_enums=True, check_constraints=True
        )
        self.assertTrue(
            any("dns_activity: violated OCSF at_least_one" in e for e in dns_errs), dns_errs
        )

        bad_base_cat = {
            "category_uid": 1,
            "class_uid": 0,
            "activity_id": 0,
            "type_uid": 0,
            "severity_id": 0,
            "time": 1763596800000,
            "metadata": dict(valid_meta),
        }
        cat_errs = validate_ocsf_v140_event(bad_base_cat, check_enums=True, check_constraints=True)
        self.assertTrue(any("category_uid: expected 0" in e for e in cat_errs), cat_errs)

        bad_profile = {
            "category_uid": 4,
            "class_uid": 4001,
            "activity_id": 1,
            "type_uid": 400101,
            "severity_id": 1,
            "time": 1763596800000,
            "metadata": dict(valid_meta),
            "src_endpoint": {"uid": "ep-1"},
            "actor": {"app_name": "curl"},
        }
        prof_errs = validate_ocsf_v140_event(bad_profile, check_enums=True, check_constraints=True)
        self.assertTrue(any("profile 'host'" in e for e in prof_errs), prof_errs)

    def test_missing_field_positive_and_not_semantics_matrix(self) -> None:
        from provloom.domain.common import AccessScope, TimeRange
        from tests.evaluation.helpers import (
            build_eval_runtime,
            cleanup_eval_tenant,
            get_available_eval_db_urls,
            seed_synthetic_ocsf_cases,
        )

        cases = [
            {
                "test_event_id": "m-missing",
                "category_uid": 1,
                "class_uid": 1007,
                "activity_id": 1,
                "ocsf_fields": {"process": {}},
            },
            {
                "test_event_id": "m-null",
                "category_uid": 1,
                "class_uid": 1007,
                "activity_id": 1,
                "ocsf_fields": {"process": {"cmd_line": None}},
            },
            {
                "test_event_id": "m-empty-str",
                "category_uid": 1,
                "class_uid": 1007,
                "activity_id": 1,
                "ocsf_fields": {"process": {"cmd_line": ""}},
            },
            {
                "test_event_id": "m-match",
                "category_uid": 1,
                "class_uid": 1007,
                "activity_id": 1,
                "ocsf_fields": {
                    "process": {
                        "cmd_line": "EvilCmd /run",
                        "file": {"path": "C:\\a.exe", "type_id": 1, "name": "a.exe"},
                    }
                },
            },
            {
                "test_event_id": "m-num-1",
                "category_uid": 1,
                "class_uid": 1007,
                "activity_id": 1,
                "ocsf_fields": {
                    "process": {"file": {"path": "C:\\a.exe", "type_id": 1, "name": "a.exe"}},
                    "unmapped": {"EventID": 1},
                },
            },
            {
                "test_event_id": "m-num-5",
                "category_uid": 1,
                "class_uid": 1007,
                "activity_id": 1,
                "ocsf_fields": {
                    "process": {},
                    "unmapped": {"EventID": 5},
                },
            },
            {
                "test_event_id": "m-num-null",
                "category_uid": 1,
                "class_uid": 1007,
                "activity_id": 1,
                "ocsf_fields": {
                    "process": {},
                    "unmapped": {"EventID": None},
                },
            },
            {
                "test_event_id": "m-bool-true",
                "category_uid": 1,
                "class_uid": 1007,
                "activity_id": 1,
                "ocsf_fields": {
                    "process": {},
                    "unmapped": {"EventID": True},
                },
            },
            {
                "test_event_id": "m-bool-false",
                "category_uid": 1,
                "class_uid": 1007,
                "activity_id": 1,
                "ocsf_fields": {
                    "process": {},
                    "unmapped": {"EventID": False},
                },
            },
            {
                "test_event_id": "d-missing",
                "category_uid": 4,
                "class_uid": 4003,
                "activity_id": 2,
                "ocsf_fields": {"query": {"hostname": "c2.example"}},
            },
            {
                "test_event_id": "d-null",
                "category_uid": 4,
                "class_uid": 4003,
                "activity_id": 2,
                "ocsf_fields": {"query": {"hostname": "c2.example"}, "answers": None},
            },
            {
                "test_event_id": "d-empty-arr",
                "category_uid": 4,
                "class_uid": 4003,
                "activity_id": 2,
                "ocsf_fields": {"query": {"hostname": "c2.example"}, "answers": []},
            },
            {
                "test_event_id": "d-null-elem",
                "category_uid": 4,
                "class_uid": 4003,
                "activity_id": 2,
                "ocsf_fields": {
                    "query": {"hostname": "c2.example"},
                    "answers": [None, {"rdata": None}],
                },
            },
            {
                "test_event_id": "d-match",
                "category_uid": 4,
                "class_uid": 4003,
                "activity_id": 2,
                "ocsf_fields": {
                    "query": {"hostname": "c2.example"},
                    "answers": [{"rdata": "evil.example"}],
                },
            },
        ]

        all_1007 = {
            "m-missing",
            "m-null",
            "m-empty-str",
            "m-match",
            "m-num-1",
            "m-num-5",
            "m-num-null",
            "m-bool-true",
            "m-bool-false",
        }
        queries: list[tuple[str, str, set[str]]] = [
            (
                "sigma_contains",
                "title: S1\nlogsource:\n  category: process_creation\ndetection:\n  sel:\n    CommandLine|contains: evil\n  condition: sel\n",
                {"m-match"},
            ),
            (
                "sigma_wildcard_star",
                "title: S2\nlogsource:\n  category: process_creation\ndetection:\n  sel:\n    CommandLine: '*'\n  condition: sel\n",
                {"m-empty-str", "m-match"},
            ),
            (
                "sigma_cased",
                "title: S3\nlogsource:\n  category: process_creation\ndetection:\n  sel:\n    CommandLine|cased: 'EvilCmd /run'\n  condition: sel\n",
                {"m-match"},
            ),
            (
                "sigma_regex_dotstar",
                "title: S4\nlogsource:\n  category: process_creation\ndetection:\n  sel:\n    CommandLine|re: '.*'\n  condition: sel\n",
                {"m-empty-str", "m-match"},
            ),
            (
                "sigma_number_eq",
                "title: S5\nlogsource:\n  category: process_creation\ndetection:\n  sel:\n    EventID: 1\n  condition: sel\n",
                {"m-num-1"},
            ),
            (
                "sigma_compare_gt",
                "title: S6\nlogsource:\n  category: process_creation\ndetection:\n  sel:\n    EventID|gt: 1\n  condition: sel\n",
                {"m-num-5"},
            ),
            (
                "sigma_neq",
                "title: S7\nlogsource:\n  category: process_creation\ndetection:\n  sel:\n    CommandLine|neq: 'EvilCmd /run'\n  condition: sel\n",
                all_1007 - {"m-match"},
            ),
            (
                "sigma_bool",
                "title: S8\nlogsource:\n  category: process_creation\ndetection:\n  sel:\n    EventID: true\n  condition: sel\n",
                {"m-bool-true"},
            ),
            (
                "sigma_null",
                "title: S9\nlogsource:\n  category: process_creation\ndetection:\n  sel:\n    CommandLine: null\n  condition: sel\n",
                all_1007 - {"m-empty-str", "m-match"},
            ),
            (
                "sigma_exists_true",
                "title: S10\nlogsource:\n  category: process_creation\ndetection:\n  sel:\n    CommandLine|exists: true\n  condition: sel\n",
                {"m-null", "m-empty-str", "m-match"},
            ),
            (
                "sigma_exists_false",
                "title: S11\nlogsource:\n  category: process_creation\ndetection:\n  sel:\n    CommandLine|exists: false\n  condition: sel\n",
                all_1007 - {"m-null", "m-empty-str", "m-match"},
            ),
            (
                "sigma_partial_and_under_not",
                "title: S12\nlogsource:\n  category: process_creation\ndetection:\n  sel_img:\n    Image: 'C:\\a.exe'\n  sel_cmd:\n    CommandLine: 'other'\n  condition: sel_img and not sel_cmd\n",
                {"m-match", "m-num-1"},
            ),
            (
                "dns_answers_pos",
                "title: D1\nlogsource:\n  category: dns\ndetection:\n  sel:\n    answers: 'evil.example'\n  condition: sel\n",
                {"d-match"},
            ),
            (
                "dns_answers_not",
                "title: D2\nlogsource:\n  category: dns\ndetection:\n  sel:\n    answers: 'evil.example'\n  condition: not sel\n",
                {"d-missing", "d-null", "d-empty-arr", "d-null-elem"},
            ),
            (
                "custom_eq",
                "title: C1\nsource: custom\ndetection_type: event\nevent_spec:\n  target_class_uids: [1007]\n  condition:\n    field: process.cmd_line\n    op: eq\n    value: 'EvilCmd /run'\n",
                {"m-match"},
            ),
            (
                "custom_neq",
                "title: C2\nsource: custom\ndetection_type: event\nevent_spec:\n  target_class_uids: [1007]\n  condition:\n    field: process.cmd_line\n    op: neq\n    value: 'EvilCmd /run'\n",
                all_1007 - {"m-match"},
            ),
            (
                "custom_not",
                "title: C3\nsource: custom\ndetection_type: event\nevent_spec:\n  target_class_uids: [1007]\n  condition:\n    not:\n      field: process.cmd_line\n      op: eq\n      value: 'EvilCmd /run'\n",
                all_1007 - {"m-match"},
            ),
        ]

        win = TimeRange(datetime(2020, 1, 1, tzinfo=UTC), datetime(2030, 1, 1, tzinfo=UTC))
        results_by_dialect: dict[str, dict[str, set[str]]] = {}
        for dialect_label, db_url in get_available_eval_db_urls():
            rt = build_eval_runtime(db_url)
            tenant_id = f"pytest_unit_3vl_{dialect_label}"
            cleanup_eval_tenant(rt, tenant_id)
            try:
                seed_synthetic_ocsf_cases(rt, tenant_id, cases)
                scope = AccessScope(tenant_id)
                dialect_hits: dict[str, set[str]] = {}
                for qname, qyaml, expected in queries:
                    res = rt.detection_service.test_detection_rule(
                        scope, win, raw_yaml=qyaml, max_matches=100
                    )
                    self.assertIsNone(
                        res.failure_reason, f"{dialect_label} {qname} failed: {res.failure_reason}"
                    )
                    actual = {
                        str(m.evidence_references[0].original_event_uid)
                        for m in res.matches
                        if m.evidence_references
                        and m.evidence_references[0].original_event_uid is not None
                    }
                    self.assertEqual(actual, expected, f"{dialect_label} {qname} mismatch")
                    dialect_hits[qname] = actual
                results_by_dialect[dialect_label] = dialect_hits
            finally:
                cleanup_eval_tenant(rt, tenant_id)

        if "postgresql" in results_by_dialect:
            self.assertEqual(results_by_dialect["sqlite"], results_by_dialect["postgresql"])

    def test_hash_queries_preserve_algorithm_and_value_within_same_array_element(self) -> None:
        from provloom.domain.common import AccessScope, TimeRange
        from tests.evaluation.helpers import (
            build_eval_runtime,
            cleanup_eval_tenant,
            get_available_eval_db_urls,
            seed_synthetic_ocsf_cases,
        )

        hash_trap = [
            {"algorithm_id": 1, "algorithm": "MD5", "value": "aaaa" * 8},
            {"algorithm_id": 3, "algorithm": "SHA-256", "value": "bbbb" * 16},
        ]
        hash_sha256_hit = [
            {"algorithm_id": 1, "algorithm": "MD5", "value": "cccc" * 8},
            {"algorithm_id": 3, "algorithm": "SHA-256", "value": "aaaa" * 8},
        ]
        hash_md5_only = [{"algorithm_id": 1, "algorithm": "MD5", "value": "aaaa" * 8}]

        cases = [
            {
                "test_event_id": "f-cross-elem-trap",
                "category_uid": 1,
                "class_uid": 1001,
                "activity_id": 1,
                "ocsf_fields": {
                    "file": {
                        "path": "C:\\Temp\\trap.bin",
                        "name": "trap.bin",
                        "type_id": 1,
                        "hashes": hash_trap,
                    }
                },
            },
            {
                "test_event_id": "f-sha256-true-match",
                "category_uid": 1,
                "class_uid": 1001,
                "activity_id": 1,
                "ocsf_fields": {
                    "file": {
                        "path": "C:\\Temp\\hit.bin",
                        "name": "hit.bin",
                        "type_id": 1,
                        "hashes": hash_sha256_hit,
                    }
                },
            },
            {
                "test_event_id": "f-md5-only",
                "category_uid": 1,
                "class_uid": 1001,
                "activity_id": 1,
                "ocsf_fields": {
                    "file": {
                        "path": "C:\\Temp\\md5.bin",
                        "name": "md5.bin",
                        "type_id": 1,
                        "hashes": hash_md5_only,
                    }
                },
            },
            {
                "test_event_id": "f-empty-hashes",
                "category_uid": 1,
                "class_uid": 1001,
                "activity_id": 1,
                "ocsf_fields": {
                    "file": {
                        "path": "C:\\Temp\\empty.bin",
                        "name": "empty.bin",
                        "type_id": 1,
                        "hashes": [],
                    }
                },
            },
            {
                "test_event_id": "f-missing-hashes",
                "category_uid": 1,
                "class_uid": 1001,
                "activity_id": 1,
                "ocsf_fields": {
                    "file": {
                        "path": "C:\\Temp\\missing.bin",
                        "name": "missing.bin",
                        "type_id": 1,
                    }
                },
            },
            {
                "test_event_id": "p-cross-elem-trap",
                "category_uid": 1,
                "class_uid": 1007,
                "activity_id": 1,
                "ocsf_fields": {
                    "process": {
                        "file": {
                            "path": "C:\\Temp\\ptrap.exe",
                            "name": "ptrap.exe",
                            "type_id": 1,
                            "hashes": hash_trap,
                        }
                    }
                },
            },
            {
                "test_event_id": "p-sha256-true-match",
                "category_uid": 1,
                "class_uid": 1007,
                "activity_id": 1,
                "ocsf_fields": {
                    "process": {
                        "file": {
                            "path": "C:\\Temp\\phit.exe",
                            "name": "phit.exe",
                            "type_id": 1,
                            "hashes": hash_sha256_hit,
                        }
                    }
                },
            },
            {
                "test_event_id": "p-md5-only",
                "category_uid": 1,
                "class_uid": 1007,
                "activity_id": 1,
                "ocsf_fields": {
                    "process": {
                        "file": {
                            "path": "C:\\Temp\\pmd5.exe",
                            "name": "pmd5.exe",
                            "type_id": 1,
                            "hashes": hash_md5_only,
                        }
                    }
                },
            },
            {
                "test_event_id": "p-empty-hashes",
                "category_uid": 1,
                "class_uid": 1007,
                "activity_id": 1,
                "ocsf_fields": {
                    "process": {
                        "file": {
                            "path": "C:\\Temp\\pempty.exe",
                            "name": "pempty.exe",
                            "type_id": 1,
                            "hashes": [],
                        }
                    }
                },
            },
            {
                "test_event_id": "p-missing-hashes",
                "category_uid": 1,
                "class_uid": 1007,
                "activity_id": 1,
                "ocsf_fields": {
                    "process": {
                        "file": {
                            "path": "C:\\Temp\\pmissing.exe",
                            "name": "pmissing.exe",
                            "type_id": 1,
                        }
                    }
                },
            },
        ]

        aaaa = "aaaa" * 8
        cccc = "cccc" * 8
        all_1001 = {
            "f-cross-elem-trap",
            "f-sha256-true-match",
            "f-md5-only",
            "f-empty-hashes",
            "f-missing-hashes",
        }
        queries: list[tuple[str, str, set[str]]] = [
            (
                "file_sha256_exact",
                f"title: H1\nlogsource:\n  category: file_event\ndetection:\n  sel:\n    sha256: '{aaaa}'\n  condition: sel\n",
                {"f-sha256-true-match"},
            ),
            (
                "file_md5_exact",
                f"title: H2\nlogsource:\n  category: file_event\ndetection:\n  sel:\n    md5: '{aaaa}'\n  condition: sel\n",
                {"f-cross-elem-trap", "f-md5-only"},
            ),
            (
                "file_sha256_list",
                f"title: H3\nlogsource:\n  category: file_event\ndetection:\n  sel:\n    sha256:\n      - '{aaaa}'\n      - '{cccc}'\n  condition: sel\n",
                {"f-sha256-true-match"},
            ),
            (
                "file_sha256_not_sel",
                f"title: H4\nlogsource:\n  category: file_event\ndetection:\n  sel:\n    sha256: '{aaaa}'\n  condition: not sel\n",
                all_1001 - {"f-sha256-true-match"},
            ),
            (
                "file_sha256_neq",
                f"title: H5\nlogsource:\n  category: file_event\ndetection:\n  sel:\n    sha256|neq: '{aaaa}'\n  condition: sel\n",
                all_1001 - {"f-sha256-true-match"},
            ),
            (
                "file_sha256_null",
                "title: H6\nlogsource:\n  category: file_event\ndetection:\n  sel:\n    sha256: null\n  condition: sel\n",
                {"f-md5-only", "f-empty-hashes", "f-missing-hashes"},
            ),
            (
                "file_sha256_exists_true",
                "title: H7\nlogsource:\n  category: file_event\ndetection:\n  sel:\n    sha256|exists: true\n  condition: sel\n",
                {"f-cross-elem-trap", "f-sha256-true-match"},
            ),
            (
                "file_sha256_exists_false",
                "title: H8\nlogsource:\n  category: file_event\ndetection:\n  sel:\n    sha256|exists: false\n  condition: sel\n",
                {"f-md5-only", "f-empty-hashes", "f-missing-hashes"},
            ),
            (
                "proc_sha256_exact",
                f"title: H9\nlogsource:\n  category: process_creation\ndetection:\n  sel:\n    sha256: '{aaaa}'\n  condition: sel\n",
                {"p-sha256-true-match"},
            ),
            (
                "custom_hash_same_elem",
                f"title: H10\nsource: custom\ndetection_type: event\nevent_spec:\n  target_class_uids: [1001]\n  condition:\n    all:\n      - field: file.hashes.algorithm_id\n        op: eq\n        value: 3\n      - field: file.hashes.value\n        op: eq\n        value: '{aaaa}'\n",
                {"f-sha256-true-match"},
            ),
        ]

        win = TimeRange(datetime(2020, 1, 1, tzinfo=UTC), datetime(2030, 1, 1, tzinfo=UTC))
        results_by_dialect: dict[str, dict[str, set[str]]] = {}
        for dialect_label, db_url in get_available_eval_db_urls():
            rt = build_eval_runtime(db_url)
            tenant_id = f"pytest_unit_hash_{dialect_label}"
            cleanup_eval_tenant(rt, tenant_id)
            try:
                seed_synthetic_ocsf_cases(rt, tenant_id, cases)
                scope = AccessScope(tenant_id)
                dialect_hits: dict[str, set[str]] = {}
                for qname, qyaml, expected in queries:
                    res = rt.detection_service.test_detection_rule(
                        scope, win, raw_yaml=qyaml, max_matches=100
                    )
                    self.assertIsNone(
                        res.failure_reason, f"{dialect_label} {qname} failed: {res.failure_reason}"
                    )
                    actual = {
                        str(m.evidence_references[0].original_event_uid)
                        for m in res.matches
                        if m.evidence_references
                        and m.evidence_references[0].original_event_uid is not None
                    }
                    self.assertEqual(actual, expected, f"{dialect_label} {qname} mismatch")
                    dialect_hits[qname] = actual
                results_by_dialect[dialect_label] = dialect_hits
            finally:
                cleanup_eval_tenant(rt, tenant_id)

        if "postgresql" in results_by_dialect:
            self.assertEqual(results_by_dialect["sqlite"], results_by_dialect["postgresql"])
