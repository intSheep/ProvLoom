from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import UUID

from provloom.domain.enums import BatchStatus, PipelineStage, RawProcessStatus


@dataclass(frozen=True)
class IngestBatchSpec:
    tenant_scope: str
    source_id: str
    source_type: str
    adapter_type: str
    source_uri: str


@dataclass(frozen=True)
class RawRecordInput:
    raw_payload: str
    external_event_uid: str | None = None
    raw_metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class IngestBatch:
    batch_id: UUID
    tenant_scope: str
    source_id: str
    source_type: str
    adapter_type: str
    source_uri: str
    received_at: datetime
    status: BatchStatus
    total_count: int = 0
    accepted_count: int = 0
    duplicate_count: int = 0
    failed_count: int = 0


@dataclass(frozen=True)
class RawEvent:
    """Immutable raw record; deduplicated by (tenant_scope, source_id, raw_fingerprint)."""

    raw_event_id: UUID
    batch_id: UUID
    tenant_scope: str
    source_id: str
    source_type: str
    raw_fingerprint: str
    raw_payload: str
    ingested_at: datetime
    process_status: RawProcessStatus = RawProcessStatus.PENDING
    external_event_uid: str | None = None
    raw_metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PipelineFailure:
    failure_id: UUID
    batch_id: UUID
    tenant_scope: str
    stage: PipelineStage
    error_code: str
    error_message: str
    occurred_at: datetime
    raw_event_id: UUID | None = None
    raw_snippet: str | None = None
    retryable: bool = True
    retry_count: int = 0


@dataclass(frozen=True)
class IngestReceipt:
    batch_id: UUID
    total_count: int
    accepted_count: int
    duplicate_count: int
    failed_count: int
