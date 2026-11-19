from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol
from uuid import UUID

from provloom.domain.common import AccessScope, PageResult, PageSpec, TimeRange
from provloom.domain.enums import PipelineStage
from provloom.domain.raw_models import IngestBatch, IngestReceipt, PipelineFailure
from provloom.normalization.interfaces import MappingSpecSummary
from provloom.observability.interfaces import PipelineMetricsSnapshot
from provloom.pipeline.interfaces import ReplayReceipt, RetryReceipt


@dataclass(frozen=True)
class SampleImportRequest:
    tenant_scope: str
    source_id: str
    source_type: str
    adapter_type: str
    source_uri: str


@dataclass(frozen=True)
class ReplayRequest:
    time_range: TimeRange | None = None
    batch_ids: tuple[UUID, ...] | None = None


class OpsDebugService(Protocol):
    """Operational API contract for CLI and Web Debug Console (/api/v1/ops/*)."""

    def submit_import(self, req: SampleImportRequest) -> IngestReceipt: ...
    def import_raw_content(
        self,
        tenant_scope: str,
        source_id: str,
        source_type: str,
        adapter_type: str,
        raw_text: str,
    ) -> IngestReceipt: ...
    def load_builtin_examples(self, tenant_scope: str) -> list[IngestReceipt]: ...
    def get_dataset_time_bounds(self, scope: AccessScope) -> TimeRange | None: ...
    def list_batches(self, scope: AccessScope, page: PageSpec) -> PageResult[IngestBatch]: ...
    def get_batch(self, scope: AccessScope, batch_id: UUID) -> IngestBatch | None: ...
    def list_failures(
        self,
        scope: AccessScope,
        batch_id: UUID | None,
        stage: PipelineStage | None,
        page: PageSpec,
    ) -> PageResult[PipelineFailure]: ...
    def trigger_retry(self, scope: AccessScope, batch_id: UUID | None = None) -> RetryReceipt: ...
    def trigger_replay(self, scope: AccessScope, req: ReplayRequest) -> ReplayReceipt: ...
    def get_metrics_snapshot(self, scope: AccessScope) -> PipelineMetricsSnapshot: ...
    def list_mapping_specs(self) -> Sequence[MappingSpecSummary]: ...
