from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import uvicorn

from provloom.config import AppConfig
from provloom.domain.common import AccessScope, TimeRange
from provloom.query.ops_interfaces import ReplayRequest, SampleImportRequest
from provloom.runtime import ProvLoomRuntime


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="provloom", description="ProvLoom CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    ingest = sub.add_parser("ingest", help="Ingest and process a local log file batch")
    ingest.add_argument("--tenant", default="default")
    ingest.add_argument("--source-id", required=True)
    ingest.add_argument("--source-type", required=True)
    ingest.add_argument("--adapter", choices=["json", "jsonl", "csv", "asset"], required=True)
    ingest.add_argument("--path", required=True)

    examples = sub.add_parser("seed-examples", help="Ingest built-in standard example suite")
    examples.add_argument("--tenant", default="default")

    replay = sub.add_parser("replay", help="Rebuild normalized events and graph from raw_events")
    replay.add_argument("--tenant", default="default")
    replay.add_argument("--batch-id")

    serve = sub.add_parser("serve", help="Run HTTP Query API and Web Debug Console")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)

    detect = sub.add_parser("detect", help="Run enabled Sigma and Custom detection rules")
    detect.add_argument("--tenant", default="default")
    detect.add_argument("--rule-id", help="Optional single rule_id to execute")

    imp_rule = sub.add_parser("import-rule", help="Import a Sigma or Custom YAML detection rule")
    imp_rule.add_argument("--tenant", default="default")
    imp_rule.add_argument("--path", required=True)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "serve":
        uvicorn.run(
            "provloom.api.app:create_app",
            factory=True,
            host=str(args.host),
            port=int(args.port),
        )
        return 0

    rt = ProvLoomRuntime.build(AppConfig.from_env())
    if args.command == "ingest":
        receipt = rt.ops_service.submit_import(
            SampleImportRequest(
                tenant_scope=str(args.tenant),
                source_id=str(args.source_id),
                source_type=str(args.source_type),
                adapter_type=str(args.adapter),
                source_uri=str(args.path),
            )
        )
        print(json.dumps(receipt.__dict__, default=str, indent=2))
        return 0

    if args.command == "seed-examples":
        receipts = rt.ops_service.load_builtin_examples(tenant_scope=str(args.tenant))
        print(json.dumps([r.__dict__ for r in receipts], default=str, indent=2))
        return 0

    if args.command == "replay":
        batch_ids = (UUID(str(args.batch_id)),) if args.batch_id else None
        rep = rt.ops_service.trigger_replay(
            scope=AccessScope(tenant_id=str(args.tenant)),
            req=ReplayRequest(batch_ids=batch_ids),
        )
        print(json.dumps(rep.__dict__, indent=2))
        return 0

    if args.command == "detect":
        scope = AccessScope(tenant_id=str(args.tenant))
        bounds = rt.ops_service.get_dataset_time_bounds(scope)
        now = datetime.now(UTC)
        window = (
            TimeRange(
                start_time=bounds.start_time - timedelta(minutes=1),
                end_time=bounds.end_time + timedelta(minutes=1),
            )
            if bounds is not None
            else TimeRange(start_time=now - timedelta(days=7), end_time=now + timedelta(minutes=1))
        )
        exec_res = (
            rt.detection_service.execute_rule(scope, str(args.rule_id), window)
            if args.rule_id
            else rt.detection_service.execute_rule_batch(scope, window)
        )
        print(json.dumps(asdict(exec_res), default=str, indent=2))
        return 0

    if args.command == "import-rule":
        rule_path = Path(str(args.path))
        view = rt.detection_service.import_detection_rule(
            scope=AccessScope(tenant_id=str(args.tenant)),
            raw_yaml=rule_path.read_text(encoding="utf-8"),
            source_reference=f"file://{rule_path.name}",
        )
        print(json.dumps(asdict(view), default=str, indent=2))
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
