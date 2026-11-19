from __future__ import annotations

from datetime import datetime
from typing import Any, Generic, TypeVar
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from provloom.domain.enums import (
    BatchStatus,
    Certainty,
    Direction,
    EntityType,
    NormalizationStatus,
    PipelineStage,
    RelationType,
    ResolutionState,
)

T = TypeVar("T")


class ApiModel(BaseModel):
    model_config = ConfigDict(frozen=True, from_attributes=True)


class TimeRangeDto(ApiModel):
    start_time: datetime
    end_time: datetime


class PageResponse(ApiModel, Generic[T]):
    items: list[T]
    next_cursor: str | None = None
    truncated: bool = False


class EventSearchRequest(ApiModel):
    time_range: TimeRangeDto
    sources: list[str] | None = None
    class_uids: list[int] | None = None
    category_uids: list[int] | None = None
    field_equals: dict[str, str | int | bool] | None = None
    include_fallback: bool = True
    limit: int = Field(default=100, ge=1, le=500)
    cursor: str | None = None


class NormalizedEventSummaryDto(ApiModel):
    event_id: UUID
    raw_event_id: UUID
    source_id: str
    ocsf_version: str
    category_uid: int
    class_uid: int
    activity_id: int
    event_time: datetime
    normalization_status: NormalizationStatus
    original_event_uid: str | None = None


class RawEventDto(ApiModel):
    raw_event_id: UUID
    batch_id: UUID
    source_id: str
    source_type: str
    raw_fingerprint: str
    raw_payload: str
    ingested_at: datetime


class EventDetailDto(ApiModel):
    event_id: UUID
    raw_event_id: UUID
    source_id: str
    ocsf_version: str
    category_uid: int
    class_uid: int
    activity_id: int
    event_time: datetime
    normalization_status: NormalizationStatus
    mapping_rule_id: str
    original_event_uid: str | None = None
    ocsf_payload: dict[str, Any]
    unmapped_fields: dict[str, Any]
    raw: RawEventDto | None = None


class EntityDto(ApiModel):
    entity_id: UUID
    entity_type: EntityType
    resolution_state: ResolutionState
    display_label: str
    canonical_key: str | None = None
    valid_from: datetime | None = None
    valid_to: datetime | None = None
    attributes: dict[str, Any]
    merged_into_id: UUID | None = None


class EntityIdentifierDto(ApiModel):
    identifier_id: UUID
    id_namespace: str
    id_value: str
    is_authoritative: bool
    scope_entity_id: UUID | None = None
    valid_from: datetime | None = None
    valid_to: datetime | None = None
    first_seen_event_id: UUID


class EntityMergeDto(ApiModel):
    merge_id: UUID
    source_entity_id: UUID
    target_entity_id: UUID
    merge_rule_id: str
    match_basis: dict[str, Any]
    evidence_event_ids: list[UUID]
    merged_at: datetime


class EntityDetailDto(ApiModel):
    entity: EntityDto
    identifiers: list[EntityIdentifierDto]
    merges: list[EntityMergeDto]


class EntitySearchRequest(ApiModel):
    time_range: TimeRangeDto | None = None
    entity_types: list[EntityType] | None = None
    resolution_states: list[ResolutionState] | None = None
    identifier_query: str | None = None
    limit: int = Field(default=100, ge=1, le=500)
    cursor: str | None = None


class RelationDto(ApiModel):
    relation_id: UUID
    src_entity_id: UUID
    relation_type: RelationType
    dst_entity_id: UUID
    certainty: Certainty
    context_key: str
    correlation_rule_id: str
    first_seen_at: datetime
    last_seen_at: datetime
    evidence_count: int
    correlation_basis: dict[str, Any]


class GraphTraverseRequest(ApiModel):
    seed_entity_id: UUID
    time_range: TimeRangeDto
    max_depth: int = Field(default=2, ge=1, le=6)
    direction: Direction = Direction.BOTH
    relation_types: list[RelationType] | None = None
    include_candidates: bool = False
    max_nodes: int = Field(default=200, ge=1, le=250)
    max_edges: int = Field(default=500, ge=1, le=600)


class SubgraphResponse(ApiModel):
    seed_entity_id: UUID
    nodes: list[EntityDto]
    edges: list[RelationDto]
    truncated: bool = False


class RelationEvidenceDetailDto(ApiModel):
    evidence_id: UUID
    relation_id: UUID
    event_id: UUID
    raw_event_id: UUID
    evidence_role: str
    observed_at: datetime
    source_id: str
    ocsf_class_uid: int
    raw_payload: str
    match_detail: dict[str, Any]


class SampleImportDto(ApiModel):
    source_id: str
    source_type: str
    adapter_type: str
    source_uri: str


class RawPasteImportDto(ApiModel):
    source_id: str
    source_type: str
    adapter_type: str = "jsonl"
    raw_text: str


class IngestBatchDto(ApiModel):
    batch_id: UUID
    source_id: str
    source_type: str
    adapter_type: str
    source_uri: str
    received_at: datetime
    status: BatchStatus
    total_count: int
    accepted_count: int
    duplicate_count: int
    failed_count: int


class PipelineFailureDto(ApiModel):
    failure_id: UUID
    batch_id: UUID
    raw_event_id: UUID | None = None
    stage: PipelineStage
    error_code: str
    error_message: str
    raw_snippet: str | None = None
    retryable: bool
    retry_count: int
    occurred_at: datetime


class ReplayRequestDto(ApiModel):
    time_range: TimeRangeDto | None = None
    batch_ids: list[UUID] | None = None
