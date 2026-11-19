from __future__ import annotations

import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from provloom.api.app import create_app
from provloom.cli.main import main as cli_main
from provloom.config import AppConfig
from provloom.domain.common import AccessScope, PageSpec, TimeRange
from provloom.domain.enums import EntityType, RelationType
from provloom.query.interfaces import EntitySearchFilter, EventSearchFilter
from provloom.runtime import ProvLoomRuntime

SCOPE = AccessScope(tenant_id="default")
WINDOW = TimeRange(
    start_time=datetime(2026, 11, 18, 7, 0, tzinfo=timezone.utc),
    end_time=datetime(2026, 11, 18, 10, 0, tzinfo=timezone.utc),
)


@pytest.mark.integration
class CliAndExtendedCoverageTests(unittest.TestCase):
    def test_container_service_app_and_file_read_relations(self) -> None:
        rt = ProvLoomRuntime.build(AppConfig(database_url="sqlite+pysqlite:///:memory:"))
        rt.ops_service.import_raw_content(
            tenant_scope="default",
            source_id="cmdb",
            source_type="asset",
            adapter_type="json",
            raw_text=(
                '[{"asset_id":"node-01","hostname":"k8s01.corp.local","ip":"10.30.0.5",'
                '"container_id":"abcdef0123456789abcdef0123456789","runtime":"containerd",'
                '"service_name":"billing-api","listen_port":8080}]'
            ),
        )
        rt.ops_service.import_raw_content(
            tenant_scope="default",
            source_id="app-audit",
            source_type="app",
            adapter_type="jsonl",
            raw_text="\n".join(
                [
                    '{"event_uid":"lc-1","event_type":"service_start","timestamp":"2026-11-18T08:10:00Z","hostname":"k8s01.corp.local","service_name":"billing-api","listen_port":8080}',
                    '{"event_uid":"api-1","event_type":"api_call","timestamp":"2026-11-18T08:11:00Z","hostname":"k8s01.corp.local","username":"svc_bot","domain":"CORP","service_name":"billing-api","listen_port":8080,"operation":"ExportInvoices"}',
                ]
            ),
        )
        rt.ops_service.import_raw_content(
            tenant_scope="default",
            source_id="edr",
            source_type="sysmon",
            adapter_type="jsonl",
            raw_text=(
                '{"EventRecordID":"fr-1","EventID":"file_read","UtcTime":"2026-11-18T08:12:00Z",'
                '"Computer":"k8s01.corp.local","ProcessGuid":"{c001-1}","ProcessId":900,'
                '"Image":"/usr/bin/cat","TargetFilename":"/etc/shadow",'
                '"sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}'
            ),
        )

        # Verify CONTAINER, SERVICE, and SHA256 searchable FILE entities
        containers = rt.query_service.search_entities(
            SCOPE, None, EntitySearchFilter(entity_types=(EntityType.CONTAINER,)), PageSpec()
        ).items
        self.assertEqual(len(containers), 1)

        by_hash = rt.query_service.search_entities(
            SCOPE,
            None,
            EntitySearchFilter(
                entity_types=(EntityType.FILE,),
                identifier_query="e3b0c44298fc1c149afbf4c8996fb924",
            ),
            PageSpec(),
        ).items
        self.assertEqual(len(by_hash), 1)

        # Verify READS and ACCESSES relations
        file_rels = rt.query_service.get_entity_relations(SCOPE, by_hash[0].entity_id, WINDOW)
        self.assertEqual(file_rels.items[0].relation_type, RelationType.READS)

        services = rt.query_service.search_entities(
            SCOPE, None, EntitySearchFilter(entity_types=(EntityType.SERVICE,)), PageSpec()
        ).items
        self.assertEqual(len(services), 1)
        svc_rels = {
            r.relation_type
            for r in rt.query_service.get_entity_relations(
                SCOPE, services[0].entity_id, WINDOW
            ).items
        }
        self.assertEqual(svc_rels, {RelationType.RUNS, RelationType.ACCESSES})

        # Verify nested OCSF field_equals search
        matched_events = rt.query_service.search_events(
            SCOPE,
            WINDOW,
            EventSearchFilter(field_equals={"api.operation": "ExportInvoices"}),
            PageSpec(),
        )
        self.assertEqual(len(matched_events.items), 1)

    def test_cli_seed_and_replay_commands(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "cli_test.db"
            prev = os.environ.get("PROVLOOM_DATABASE_URL")
            os.environ["PROVLOOM_DATABASE_URL"] = f"sqlite:///{db_path}"
            try:
                self.assertEqual(cli_main(["seed-examples", "--tenant", "cli-t"]), 0)
                self.assertEqual(cli_main(["replay", "--tenant", "cli-t"]), 0)
            finally:
                if prev is None:
                    os.environ.pop("PROVLOOM_DATABASE_URL", None)
                else:
                    os.environ["PROVLOOM_DATABASE_URL"] = prev

    def test_web_dist_assets_and_spa_fallback(self) -> None:
        rt = ProvLoomRuntime.build(AppConfig(database_url="sqlite+pysqlite:///:memory:"))
        client = TestClient(create_app(rt))

        root_res = client.get("/")
        self.assertEqual(root_res.status_code, 200)
        self.assertIn("text/html", root_res.headers["content-type"])

        docs_res = client.get("/docs")
        self.assertEqual(docs_res.status_code, 200)

        api_missing = client.get("/api/v1/nonexistent")
        self.assertEqual(api_missing.status_code, 404)

        web_dist_assets = Path("web/dist/assets")
        if web_dist_assets.is_dir():
            spa_res = client.get("/graph")
            self.assertEqual(spa_res.status_code, 200)
            self.assertIn("text/html", spa_res.headers["content-type"])

            js_files = list(web_dist_assets.glob("*.js"))
            self.assertGreater(len(js_files), 0)
            asset_res = client.get(f"/assets/{js_files[0].name}")
            self.assertEqual(asset_res.status_code, 200)

            missing_asset = client.get("/assets/does-not-exist.js")
            self.assertEqual(missing_asset.status_code, 404)
