from __future__ import annotations

from datetime import datetime
from typing import Any, Generic, TypeVar
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from provloom.detection.domain.rule import (
    DetectionType,
    ExecutionMode,
    ExecutionStatus,
    RuleSeverity,
    RuleSource,
    RuleStatus,
)
from provloom.detection.domain.signal import SignalStatus
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
    fields: list[str] | None = Field(default=None, max_length=25)
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
    projected_fields: dict[str, Any] | None = None


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


class TelemetryCoverageDto(ApiModel):
    time_range: TimeRangeDto
    dataset_time_bounds: TimeRangeDto | None = None
    total_events: int
    by_source: dict[str, int]
    by_class_uid: dict[int, int]
    by_normalization_status: dict[str, int]
    ingest_batches: list[IngestBatchDto] = Field(default_factory=list)
    failures_total: int = 0
    failures_by_stage_code: dict[str, int] = Field(default_factory=dict)
    sample_failures: list[PipelineFailureDto] = Field(default_factory=list)


class NeighborhoodItemDto(ApiModel):
    relation: RelationDto
    neighbor: EntityDto
    direction: Direction


class NeighborhoodGroupSummaryDto(ApiModel):
    relation_type: RelationType
    neighbor_entity_type: EntityType
    certainty: Certainty
    relation_count: int
    evidence_count: int
    sample_neighbor_labels: list[str] = Field(default_factory=list)


class EntityNeighborhoodResponse(ApiModel):
    center_entity: EntityDto
    items: list[NeighborhoodItemDto] = Field(default_factory=list)
    groups: list[NeighborhoodGroupSummaryDto] = Field(default_factory=list)
    total_relations_matched: int = 0
    next_cursor: str | None = None
    truncated: bool = False


class ReplayRequestDto(ApiModel):
    time_range: TimeRangeDto | None = None
    batch_ids: list[UUID] | None = None


# --- Detection Layer DTOs (/api/v1/detection/*) ---


class LogsourceDto(ApiModel):
    category: str | None = None
    product: str | None = None
    service: str | None = None


class RuleCompatibilityDto(ApiModel):
    parse_success: bool
    mapping_success: bool
    data_coverage: bool
    compile_success: bool
    execution_success: bool | None = None
    mapped_class_uids: list[int] = Field(default_factory=list)
    field_mappings: dict[str, str] = Field(default_factory=dict)
    uncovered_fields: list[str] = Field(default_factory=list)
    unsupported_reasons: list[str] = Field(default_factory=list)


class DetectionRuleDto(ApiModel):
    rule_id: str
    rule_name: str
    source: RuleSource
    source_reference: str
    version: str
    description: str
    severity: RuleSeverity
    attack_tags: list[str]
    logsource: LogsourceDto
    detection_type: DetectionType
    raw_content: str
    status: RuleStatus
    compatibility: RuleCompatibilityDto
    created_at: datetime
    updated_at: datetime


class DetectionRuleDetailDto(ApiModel):
    rule: DetectionRuleDto
    compiled_sql: str | None = None
    parsed_summary: dict[str, Any] | None = None


class ValidateRuleRequestDto(ApiModel):
    raw_yaml: str
    source_hint: RuleSource | None = None


class ImportRuleRequestDto(ApiModel):
    raw_yaml: str
    source_reference: str = "api-import"
    source_hint: RuleSource | None = None


class TestRuleRequestDto(ApiModel):
    time_range: TimeRangeDto
    raw_yaml: str | None = None
    rule_id: str | None = None
    max_matches: int = Field(default=100, ge=1, le=500)


class EvidenceReferenceDto(ApiModel):
    event_id: UUID | None = None
    raw_event_id: UUID | None = None
    relation_id: UUID | None = None
    source_id: str = ""
    original_event_uid: str | None = None
    observed_at: datetime | None = None


class RuleMatchDto(ApiModel):
    match_id: UUID
    rule_id: str
    rule_name: str
    rule_version: str
    severity: RuleSeverity
    detection_type: DetectionType
    primary_event_id: UUID | None = None
    matched_event_ids: list[UUID]
    primary_entity_id: UUID | None = None
    related_entity_ids: list[UUID]
    matched_fields: list[str]
    matched_values: dict[str, Any]
    evidence_references: list[EvidenceReferenceDto]
    source_ids: list[str]
    matched_at: datetime
    execution_id: UUID


class RuleTestResponseDto(ApiModel):
    rule: DetectionRuleDto
    parsed_summary: dict[str, Any] | None = None
    field_mappings: dict[str, str]
    compiled_sql: str | None = None
    matches: list[RuleMatchDto]
    failure_reason: str | None = None
    duration_ms: float


class ExecuteRuleRequestDto(ApiModel):
    time_range: TimeRangeDto
    max_matches: int | None = Field(default=None, ge=1, le=500)


class ExecuteRuleBatchRequestDto(ApiModel):
    time_range: TimeRangeDto
    rule_ids: list[str] | None = None
    max_matches_per_rule: int | None = Field(default=None, ge=1, le=500)


class RuleExecutionFailureDto(ApiModel):
    rule_id: str
    stage: str
    error_message: str


class DetectionExecutionDto(ApiModel):
    execution_id: UUID
    tenant_scope: str
    mode: ExecutionMode
    status: ExecutionStatus
    time_range: TimeRangeDto
    rule_ids: list[str]
    rules_evaluated: int
    matches_created: int
    matches_deduplicated: int
    signals_created: int
    signals_updated: int
    candidate_groups_created: int
    duration_ms: float
    failures: list[RuleExecutionFailureDto]
    started_at: datetime
    completed_at: datetime | None = None


class RuleMatchSearchRequestDto(ApiModel):
    time_range: TimeRangeDto
    rule_id: str | None = None
    detection_type: DetectionType | None = None
    severity: RuleSeverity | None = None
    entity_id: UUID | None = None
    limit: int = Field(default=100, ge=1, le=500)
    cursor: str | None = None


class SignalDto(ApiModel):
    signal_id: UUID
    signal_type: str
    title: str
    severity: RuleSeverity
    status: SignalStatus
    primary_entity_id: UUID | None = None
    related_entity_ids: list[UUID]
    rule_match_ids: list[UUID]
    event_ids: list[UUID]
    evidence_refs: list[EvidenceReferenceDto]
    source_ids: list[str]
    attack_tags: list[str]
    first_seen_at: datetime
    last_seen_at: datetime
    occurrence_count: int
    created_at: datetime
    updated_at: datetime


class SignalSearchRequestDto(ApiModel):
    time_range: TimeRangeDto
    status: SignalStatus | None = None
    severity: RuleSeverity | None = None
    entity_id: UUID | None = None
    signal_type: str | None = None
    limit: int = Field(default=100, ge=1, le=500)
    cursor: str | None = None


class UpdateSignalStatusRequestDto(ApiModel):
    status: SignalStatus


class SignalEvidenceDetailDto(ApiModel):
    event_id: UUID
    raw_event_id: UUID
    source_id: str
    ocsf_class_uid: int
    event_time: datetime
    original_event_uid: str | None = None
    ocsf_payload: dict[str, Any]
    raw_payload: str
    relation_id: UUID | None = None
    relation_type: RelationType | None = None
    certainty: Certainty | None = None


class CandidateGroupDto(ApiModel):
    group_id: UUID
    group_key: str
    signal_ids: list[UUID]
    rule_match_ids: list[UUID]
    shared_entity_ids: list[UUID]
    grouping_rule_id: str
    grouping_basis: dict[str, Any]
    certainty: Certainty
    unresolved_ambiguities: list[str]
    source_ids: list[str]
    first_seen_at: datetime
    last_seen_at: datetime
    created_at: datetime
    updated_at: datetime


class CandidateGroupSearchRequestDto(ApiModel):
    time_range: TimeRangeDto
    entity_id: UUID | None = None
    certainty: Certainty | None = None
    limit: int = Field(default=100, ge=1, le=500)
    cursor: str | None = None


class CandidateGroupMembersDto(ApiModel):
    group: CandidateGroupDto
    signals: list[SignalDto]
    rule_matches: list[RuleMatchDto]
