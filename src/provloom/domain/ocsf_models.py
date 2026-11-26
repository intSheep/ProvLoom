from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import UUID

from provloom.domain.common import TimeRange
from provloom.domain.enums import NormalizationStatus
from provloom.domain.raw_models import IngestBatch, PipelineFailure, RawEvent


@dataclass(frozen=True)
class NormalizedEvent:
    """OCSF-normalized event; unsupported events use class_uid=0 and UNSUPPORTED_PASSTHROUGH."""

    event_id: UUID
    raw_event_id: UUID
    tenant_scope: str
    source_id: str
    ocsf_version: str
    category_uid: int
    class_uid: int
    activity_id: int
    event_time: datetime
    normalization_status: NormalizationStatus
    mapping_rule_id: str
    original_event_uid: str | None = None
    ocsf_payload: dict[str, Any] = field(default_factory=dict)
    unmapped_fields: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class NormalizedEventSummary:
    event_id: UUID
    raw_event_id: UUID
    source_id: str
    ocsf_version: str
    category_uid: int
    class_uid: int
    activity_id: int
    event_time: datetime
    normalization_status: NormalizationStatus
    original_event_uid: str | None
    projected_fields: dict[str, Any] | None = None


@dataclass(frozen=True)
class EventWithRawDetail:
    normalized: NormalizedEvent
    raw: RawEvent | None = None


@dataclass(frozen=True)
class TelemetryCoverage:
    time_range: TimeRange
    dataset_time_bounds: TimeRange | None
    total_events: int
    by_source: dict[str, int]
    by_class_uid: dict[int, int]
    by_normalization_status: dict[str, int]
    ingest_batches: tuple[IngestBatch, ...] = ()
    failures_total: int = 0
    failures_by_stage_code: dict[str, int] = field(default_factory=dict)
    sample_failures: tuple[PipelineFailure, ...] = ()
