from __future__ import annotations

import time
from datetime import UTC, datetime
from uuid import uuid4

from provloom.domain.enums import BatchStatus, PipelineStage, RawProcessStatus
from provloom.domain.errors import AdapterReadError
from provloom.domain.raw_models import (
    IngestBatch,
    IngestBatchSpec,
    IngestReceipt,
    PipelineFailure,
    RawEvent,
)
from provloom.ingestion.adapters.asset_manifest import AssetManifestAdapter
from provloom.ingestion.adapters.csv_file import CsvFileAdapter
from provloom.ingestion.adapters.json_file import JsonFileAdapter, JsonlFileAdapter
from provloom.ingestion.fingerprint import Sha256Fingerprinter
from provloom.ingestion.interfaces import Fingerprinter, IngestionGateway, SourceAdapter
from provloom.observability.interfaces import PipelineTelemetry
from provloom.storage.postgres.uow import UnitOfWorkFactory


class DefaultIngestionGateway(IngestionGateway):
    def __init__(
        self,
        uow_factory: UnitOfWorkFactory,
        telemetry: PipelineTelemetry,
        fingerprinter: Fingerprinter | None = None,
    ) -> None:
        self._uow_factory = uow_factory
        self._telemetry = telemetry
        self._fp = fingerprinter or Sha256Fingerprinter()
        self._adapters: dict[str, SourceAdapter] = {
            a.adapter_type: a
            for a in (
                JsonFileAdapter(),
                JsonlFileAdapter(),
                CsvFileAdapter(),
                AssetManifestAdapter(),
            )
        }

    def get_adapter(self, adapter_type: str) -> SourceAdapter:
        adapter = self._adapters.get(adapter_type)
        if adapter is None:
            raise AdapterReadError(f"Unsupported adapter_type: {adapter_type}")
        return adapter

    def ingest_batch(
        self, batch_spec: IngestBatchSpec, adapter: SourceAdapter | None = None
    ) -> IngestReceipt:
        t0 = time.perf_counter()
        resolved_adapter = adapter or self.get_adapter(batch_spec.adapter_type)
        batch_id = uuid4()
        now = datetime.now(UTC)
        total = 0
        accepted = 0
        duplicate = 0
        failed = 0

        with self._uow_factory() as uow:
            batch = IngestBatch(
                batch_id=batch_id,
                tenant_scope=batch_spec.tenant_scope,
                source_id=batch_spec.source_id,
                source_type=batch_spec.source_type,
                adapter_type=batch_spec.adapter_type,
                source_uri=batch_spec.source_uri,
                received_at=now,
                status=BatchStatus.RUNNING,
            )
            uow.raw_events.create_batch(batch)

            try:
                for item in resolved_adapter.read_records(batch_spec):
                    total += 1
                    fp = self._fp.compute(
                        batch_spec.tenant_scope, batch_spec.source_id, item.raw_payload
                    )
                    raw_ev = RawEvent(
                        raw_event_id=uuid4(),
                        batch_id=batch_id,
                        tenant_scope=batch_spec.tenant_scope,
                        source_id=batch_spec.source_id,
                        source_type=batch_spec.source_type,
                        raw_fingerprint=fp,
                        raw_payload=item.raw_payload,
                        ingested_at=datetime.now(UTC),
                        process_status=RawProcessStatus.PENDING,
                        external_event_uid=item.external_event_uid,
                        raw_metadata=item.raw_metadata,
                    )
                    if uow.raw_events.insert_raw_if_absent(raw_ev):
                        accepted += 1
                        self._telemetry.record_ingest(batch_spec.source_type, "accepted")
                    else:
                        duplicate += 1
                        self._telemetry.record_ingest(batch_spec.source_type, "duplicate")
            except AdapterReadError as exc:
                failed += 1
                self._telemetry.record_ingest(batch_spec.source_type, "failed")
                uow.raw_events.record_failure(
                    PipelineFailure(
                        failure_id=uuid4(),
                        batch_id=batch_id,
                        tenant_scope=batch_spec.tenant_scope,
                        stage=PipelineStage.INGEST,
                        error_code="ADAPTER_READ_ERROR",
                        error_message=str(exc),
                        occurred_at=datetime.now(UTC),
                        raw_snippet=batch_spec.source_uri,
                        retryable=False,
                    )
                )

            status = (
                BatchStatus.FAILED
                if failed > 0 and accepted == 0 and duplicate == 0
                else (BatchStatus.PARTIAL_FAILURE if failed > 0 else BatchStatus.COMPLETED)
            )
            uow.raw_events.update_batch_counts(
                IngestBatch(
                    batch_id=batch_id,
                    tenant_scope=batch_spec.tenant_scope,
                    source_id=batch_spec.source_id,
                    source_type=batch_spec.source_type,
                    adapter_type=batch_spec.adapter_type,
                    source_uri=batch_spec.source_uri,
                    received_at=now,
                    status=status,
                    total_count=total,
                    accepted_count=accepted,
                    duplicate_count=duplicate,
                    failed_count=failed,
                )
            )
            uow.commit()

        self._telemetry.observe_stage_latency(PipelineStage.INGEST, time.perf_counter() - t0)
        return IngestReceipt(
            batch_id=batch_id,
            total_count=total,
            accepted_count=accepted,
            duplicate_count=duplicate,
            failed_count=failed,
        )
