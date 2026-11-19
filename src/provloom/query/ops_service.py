from __future__ import annotations

import tempfile
from collections.abc import Sequence
from pathlib import Path
from uuid import UUID

from provloom.config import QueryGuardConfig
from provloom.domain.common import AccessScope, PageResult, PageSpec, TimeRange
from provloom.domain.enums import PipelineStage
from provloom.domain.raw_models import (
    IngestBatch,
    IngestBatchSpec,
    IngestReceipt,
    PipelineFailure,
)
from provloom.ingestion.gateway import DefaultIngestionGateway
from provloom.normalization.interfaces import MappingRegistry, MappingSpecSummary
from provloom.observability.interfaces import PipelineMetricsSnapshot
from provloom.observability.prometheus import PrometheusTelemetry
from provloom.pipeline.interfaces import ReplayReceipt, RetryReceipt
from provloom.pipeline.orchestrator import DefaultPipelineOrchestrator, DefaultReplayService
from provloom.query.ops_interfaces import OpsDebugService, ReplayRequest, SampleImportRequest
from provloom.storage.postgres.uow import UnitOfWorkFactory

_EXAMPLE_MANIFEST = (
    ("cmdb-assets", "asset", "asset", "assets_sample.json"),
    ("ad-security", "auth", "jsonl", "auth_sample.jsonl"),
    ("edr-sysmon", "sysmon", "jsonl", "sysmon_sample.jsonl"),
    ("sensor-zeek-dns", "zeek_dns", "jsonl", "zeek_dns_sample.jsonl"),
    ("sensor-zeek-conn", "zeek_conn", "jsonl", "zeek_conn_sample.jsonl"),
    ("edge-fw-01", "firewall", "csv", "firewall_sample.csv"),
)


class DefaultOpsDebugService(OpsDebugService):
    def __init__(
        self,
        uow_factory: UnitOfWorkFactory,
        gateway: DefaultIngestionGateway,
        orchestrator: DefaultPipelineOrchestrator,
        replay_service: DefaultReplayService,
        mapping_registry: MappingRegistry,
        telemetry: PrometheusTelemetry,
        guards: QueryGuardConfig | None = None,
        examples_dir: str | Path = "tests/fixtures/examples",
    ) -> None:
        self._uow_factory = uow_factory
        self._gateway = gateway
        self._orchestrator = orchestrator
        self._replay = replay_service
        self._mappings = mapping_registry
        self._telemetry = telemetry
        self._guards = guards or QueryGuardConfig()
        self._examples_dir = Path(examples_dir)

    def submit_import(self, req: SampleImportRequest) -> IngestReceipt:
        receipt = self._gateway.ingest_batch(
            IngestBatchSpec(
                tenant_scope=req.tenant_scope,
                source_id=req.source_id,
                source_type=req.source_type,
                adapter_type=req.adapter_type,
                source_uri=req.source_uri,
            )
        )
        if receipt.accepted_count > 0:
            self._orchestrator.process_batch(receipt.batch_id)
        return receipt

    def import_raw_content(
        self,
        tenant_scope: str,
        source_id: str,
        source_type: str,
        adapter_type: str,
        raw_text: str,
    ) -> IngestReceipt:
        suffix = f".{adapter_type}" if adapter_type in {"json", "jsonl", "csv"} else ".json"
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", suffix=suffix, delete=True
        ) as tmp:
            tmp.write(raw_text)
            tmp.flush()
            return self.submit_import(
                SampleImportRequest(
                    tenant_scope=tenant_scope,
                    source_id=source_id,
                    source_type=source_type,
                    adapter_type=adapter_type,
                    source_uri=tmp.name,
                )
            )

    def load_builtin_examples(self, tenant_scope: str) -> list[IngestReceipt]:
        receipts: list[IngestReceipt] = []
        for source_id, source_type, adapter_type, filename in _EXAMPLE_MANIFEST:
            path = self._examples_dir / filename
            if path.is_file():
                receipts.append(
                    self.submit_import(
                        SampleImportRequest(
                            tenant_scope=tenant_scope,
                            source_id=source_id,
                            source_type=source_type,
                            adapter_type=adapter_type,
                            source_uri=str(path),
                        )
                    )
                )
        return receipts

    def get_dataset_time_bounds(self, scope: AccessScope) -> TimeRange | None:
        with self._uow_factory() as uow:
            return uow.normalized_events.get_time_bounds(scope)

    def list_batches(self, scope: AccessScope, page: PageSpec) -> PageResult[IngestBatch]:
        validated = page.validate(self._guards.max_page_limit)
        with self._uow_factory() as uow:
            return uow.raw_events.list_batches(scope, validated)

    def get_batch(self, scope: AccessScope, batch_id: UUID) -> IngestBatch | None:
        with self._uow_factory() as uow:
            return uow.raw_events.get_batch(scope, batch_id)

    def list_failures(
        self,
        scope: AccessScope,
        batch_id: UUID | None,
        stage: PipelineStage | None,
        page: PageSpec,
    ) -> PageResult[PipelineFailure]:
        validated = page.validate(self._guards.max_page_limit)
        with self._uow_factory() as uow:
            return uow.raw_events.list_failures(scope, batch_id, stage, validated)

    def trigger_retry(self, scope: AccessScope, batch_id: UUID | None = None) -> RetryReceipt:
        return self._orchestrator.retry_failures(scope=scope, batch_id=batch_id)

    def trigger_replay(self, scope: AccessScope, req: ReplayRequest) -> ReplayReceipt:
        return self._replay.rebuild_from_raw(
            scope=scope, time_range=req.time_range, batch_ids=req.batch_ids
        )

    def get_metrics_snapshot(self, scope: AccessScope) -> PipelineMetricsSnapshot:
        _ = scope
        return self._telemetry.snapshot()

    def list_mapping_specs(self) -> Sequence[MappingSpecSummary]:
        return self._mappings.list_specs()
