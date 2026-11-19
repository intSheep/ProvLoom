from __future__ import annotations

import unittest
from datetime import datetime, timezone
from uuid import uuid4

from provloom.domain.common import AccessScope, PageSpec, TimeRange
from provloom.domain.errors import InvalidTimeRangeError, QueryLimitExceededError
from provloom.domain.graph_models import GraphTraversalSpec


class DomainContractTests(unittest.TestCase):
    def test_access_scope_source_whitelist(self) -> None:
        restricted = AccessScope(tenant_id="t1", allowed_sources=frozenset({"sysmon"}))
        self.assertTrue(restricted.permits_source("sysmon"))
        self.assertFalse(restricted.permits_source("zeek"))

        unrestricted = AccessScope(tenant_id="t1")
        self.assertTrue(unrestricted.permits_source("zeek"))

    def test_time_range_requires_utc_and_valid_bounds(self) -> None:
        t1 = datetime(2026, 11, 18, 8, 0, tzinfo=timezone.utc)
        t2 = datetime(2026, 11, 18, 9, 0, tzinfo=timezone.utc)
        tr = TimeRange(start_time=t1, end_time=t2)
        self.assertEqual(tr.start_time, t1)

        with self.assertRaises(InvalidTimeRangeError):
            TimeRange(start_time=t2, end_time=t1)

        with self.assertRaises(InvalidTimeRangeError):
            TimeRange(start_time=datetime(2026, 11, 18, 8, 0), end_time=t2)

    def test_page_and_graph_guardrails(self) -> None:
        self.assertEqual(PageSpec(limit=50).validate(max_limit=500).limit, 50)
        with self.assertRaises(QueryLimitExceededError):
            PageSpec(limit=501).validate(max_limit=500)

        spec = GraphTraversalSpec(seed_entity_id=uuid4(), max_depth=3)
        self.assertFalse(spec.include_candidates)
        with self.assertRaises(QueryLimitExceededError):
            GraphTraversalSpec(seed_entity_id=uuid4(), max_depth=7).validate(
                depth_cap=6, nodes_cap=250, edges_cap=600
            )


if __name__ == "__main__":
    unittest.main()
