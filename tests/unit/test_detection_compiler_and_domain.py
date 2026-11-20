from __future__ import annotations

import ast
import unittest
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
