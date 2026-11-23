from __future__ import annotations

import json
import unittest
from uuid import uuid4

import pytest

from provloom.domain.common import AccessScope
from tests.evaluation.helpers import (
    BASE_EVAL_TIME,
    EVAL_ROOT,
    EVAL_TIME_WINDOW,
    build_case_ocsf_payload,
    build_eval_runtime,
    cleanup_eval_tenant,
    get_available_eval_db_urls,
    seed_synthetic_ocsf_cases,
)
from tests.evaluation.ocsf_validator import PINNED_OCSF_VERSION, validate_ocsf_v140_event


@pytest.mark.integration
class SigmaRuleSemanticsEvaluationTests(unittest.TestCase):
    def test_semantic_oracle_events_strictly_conform_to_ocsf_v140_schema(self) -> None:
        oracle = json.loads((EVAL_ROOT / "rule_semantics" / "semantic_oracle.json").read_text())
        self.assertEqual(len(oracle), 15)
        total = 0
        for dim in oracle:
            for case in dim["cases"]:
                total += 1
                ocsf_ver, pure_payload = build_case_ocsf_payload(
                    case,
                    uuid4(),
                    BASE_EVAL_TIME,
                    include_provloom_original_uid=False,
                )
                self.assertEqual(ocsf_ver, PINNED_OCSF_VERSION)
                errs = validate_ocsf_v140_event(
                    pure_payload,
                    allow_provloom_metadata_original_uid=False,
                    check_enums=True,
                    check_constraints=True,
                )
                self.assertEqual(
                    errs,
                    [],
                    f"Case {case['test_event_id']} failed strict OCSF v1.4.0 schema validation: {errs}",
                )
        self.assertEqual(total, 59)

    def test_all_15_sigma_semantic_dimensions_match_independent_oracle_and_dialect_parity(
        self,
    ) -> None:
        oracle = json.loads((EVAL_ROOT / "rule_semantics" / "semantic_oracle.json").read_text())
        self.assertEqual(len(oracle), 15)
        all_cases = [c for dim in oracle for c in dim["cases"]]

        per_dialect_hits: dict[str, dict[str, set[str]]] = {}
        for dialect_label, db_url in get_available_eval_db_urls():
            rt = build_eval_runtime(db_url)
            tenant_id = f"pytest_eval_semantics_{dialect_label}"
            cleanup_eval_tenant(rt, tenant_id)
            try:
                seed_synthetic_ocsf_cases(rt, tenant_id, all_cases)
                scope = AccessScope(tenant_id=tenant_id)
                per_dialect_hits[dialect_label] = {}

                for dim in oracle:
                    dim_id = str(dim["dimension_id"])
                    res = rt.detection_service.test_detection_rule(
                        scope=scope,
                        time_range=EVAL_TIME_WINDOW,
                        raw_yaml=str(dim["yaml"]),
                        max_matches=500,
                    )
                    self.assertIsNone(
                        res.failure_reason,
                        f"[{dialect_label}] {dim_id} failed execution: {res.failure_reason}",
                    )
                    self.assertTrue(res.rule.compatibility.compile_success)
                    self.assertIs(res.rule.compatibility.execution_success, True)

                    matched_ids = {
                        m.evidence_references[0].original_event_uid
                        for m in res.matches
                        if m.evidence_references
                        and m.evidence_references[0].original_event_uid is not None
                    }
                    per_dialect_hits[dialect_label][dim_id] = matched_ids

                    for case in dim["cases"]:
                        tid = str(case["test_event_id"])
                        expected = bool(case["expected_match"])
                        actual = tid in matched_ids
                        self.assertEqual(
                            actual,
                            expected,
                            f"[{dialect_label}] {dim_id} mismatch on {tid}: "
                            f"expected={expected}, actual={actual} ({case['expected_reason']})",
                        )
            finally:
                cleanup_eval_tenant(rt, tenant_id)

        if "postgresql" in per_dialect_hits:
            self.assertEqual(
                per_dialect_hits["sqlite"],
                per_dialect_hits["postgresql"],
                "SQLite and PostgreSQL 16 produced divergent RuleMatch sets on semantic suite",
            )
