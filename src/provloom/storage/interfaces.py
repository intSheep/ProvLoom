from __future__ import annotations

from collections.abc import Sequence
from contextlib import AbstractContextManager
from datetime import datetime
from typing import Protocol
from uuid import UUID

from provloom.detection.domain.candidate_group import CandidateGroup
from provloom.detection.domain.rule import (
    DetectionExecution,
    DetectionRule,
    DetectionType,
    RuleSeverity,
    RuleSource,
    RuleStatus,
)
from provloom.detection.domain.rule_match import RuleMatch
from provloom.detection.domain.signal import Signal, SignalEvidenceDetail, SignalStatus
from provloom.domain.common import AccessScope, PageResult, PageSpec, TimeRange
from provloom.domain.entity_models import (
    Entity,
    EntityDetail,
    EntityIdentifier,
    EntityMergeAudit,
)
from provloom.domain.enums import (
    Certainty,
    Direction,
    EntityType,
    PipelineStage,
    RawProcessStatus,
    RelationType,
    ResolutionState,
)
from provloom.domain.graph_models import (
    CandidateRelation,
    GraphBuildResult,
    GraphTraversalSpec,
    Relation,
    RelationEvidenceDetail,
    SubgraphResult,
)
from provloom.domain.ocsf_models import (
    EventWithRawDetail,
    NormalizedEvent,
    NormalizedEventSummary,
)
from provloom.domain.raw_models import IngestBatch, PipelineFailure, RawEvent


class RawEventRepository(Protocol):
    def create_batch(self, batch: IngestBatch) -> None: ...
    def update_batch_counts(self, batch: IngestBatch) -> None: ...
    def get_batch(self, scope: AccessScope, batch_id: UUID) -> IngestBatch | None: ...
    def list_batches(self, scope: AccessScope, page: PageSpec) -> PageResult[IngestBatch]: ...
    def insert_raw_if_absent(self, raw_event: RawEvent) -> bool:
        """Returns True if inserted, False on duplicate (tenant, source, raw_fingerprint)."""
        ...

    def update_status(self, raw_event_id: UUID, status: RawProcessStatus) -> None: ...
    def iter_batch_events(
        self, batch_id: UUID, pending_only: bool = True
    ) -> Sequence[RawEvent]: ...
    def iter_for_replay(
        self,
        scope: AccessScope,
        time_range: TimeRange | None = None,
        batch_ids: Sequence[UUID] | None = None,
    ) -> Sequence[RawEvent]: ...
    def record_failure(self, failure: PipelineFailure) -> None: ...
    def list_failures(
        self,
        scope: AccessScope,
        batch_id: UUID | None,
        stage: PipelineStage | None,
        page: PageSpec,
    ) -> PageResult[PipelineFailure]: ...
    def iter_retryable_failures(
        self, scope: AccessScope, batch_id: UUID | None, limit: int
    ) -> Sequence[tuple[PipelineFailure, RawEvent]]: ...
    def resolve_failure(self, failure_id: UUID) -> None: ...
    def increment_failure_retry(self, failure_id: UUID, error_message: str) -> None: ...


class NormalizedEventRepository(Protocol):
    def upsert(self, event: NormalizedEvent) -> None: ...
    def get_time_bounds(self, scope: AccessScope) -> TimeRange | None: ...
    def get_with_raw(
        self,
        scope: AccessScope,
        event_id: UUID,
        time_range: TimeRange | None = None,
        include_raw: bool = True,
    ) -> EventWithRawDetail | None: ...
    def search(
        self,
        scope: AccessScope,
        time_range: TimeRange,
        sources: Sequence[str] | None,
        class_uids: Sequence[int] | None,
        category_uids: Sequence[int] | None,
        field_equals: dict[str, str | int | bool] | None,
        include_fallback: bool,
        page: PageSpec,
    ) -> PageResult[NormalizedEventSummary]: ...


class EntityRepository(Protocol):
    def find_by_identifier(
        self,
        tenant_scope: str,
        entity_type: EntityType,
        id_namespace: str,
        id_value: str,
        scope_entity_id: UUID | None = None,
        at_time: datetime | None = None,
    ) -> Entity | None: ...
    def find_host_by_ip(self, tenant_scope: str, ip: str, at_time: datetime) -> Entity | None: ...
    def save_entity(self, entity: Entity) -> None: ...
    def add_identifier(self, identifier: EntityIdentifier) -> None: ...
    def close_active_identifiers(
        self,
        tenant_scope: str,
        id_namespace: str,
        id_value: str,
        scope_entity_id: UUID | None,
        valid_to: datetime,
    ) -> None: ...
    def merge_entities(self, merge: EntityMergeAudit) -> None: ...
    def get_detail(
        self,
        scope: AccessScope,
        entity_id: UUID,
        time_range: TimeRange | None = None,
        follow_merged: bool = True,
    ) -> EntityDetail | None: ...
    def search(
        self,
        scope: AccessScope,
        time_range: TimeRange | None,
        entity_types: Sequence[EntityType] | None,
        resolution_states: Sequence[ResolutionState] | None,
        identifier_query: str | None,
        page: PageSpec,
    ) -> PageResult[Entity]: ...


class GraphRepository(Protocol):
    """Encapsulates graph storage so backend can evolve from PG recursive CTE to AGE/Neo4j."""

    def upsert_relations(self, relations: Sequence[CandidateRelation]) -> GraphBuildResult: ...
    def find_network_relations_in_window(
        self,
        tenant_scope: str,
        dst_entity_id: UUID,
        around_time: datetime,
        skew_seconds: float,
    ) -> Sequence[Relation]: ...
    def promote_sensor_relation_to_process(
        self,
        sensor_relation_id: UUID,
        process_relation: CandidateRelation,
    ) -> None: ...
    def get_entity_relations(
        self,
        scope: AccessScope,
        entity_id: UUID,
        time_range: TimeRange,
        direction: Direction,
        relation_types: Sequence[RelationType] | None,
        include_candidates: bool,
        page: PageSpec,
    ) -> PageResult[Relation]: ...
    def traverse(
        self,
        scope: AccessScope,
        time_range: TimeRange,
        spec: GraphTraversalSpec,
    ) -> SubgraphResult: ...
    def get_relation_evidence(
        self,
        scope: AccessScope,
        relation_id: UUID,
        time_range: TimeRange | None,
        page: PageSpec,
    ) -> PageResult[RelationEvidenceDetail]: ...


class EventSqlSelector(Protocol):
    def build_select(
        self,
        dialect_name: str,
        scope: AccessScope,
        time_range: TimeRange,
        limit: int,
        event_ids: Sequence[UUID] | None = None,
    ) -> object: ...


class DetectionRepository(Protocol):
    def upsert_rule(
        self, tenant_scope: str, rule: DetectionRule, preserve_status: bool = False
    ) -> DetectionRule: ...
    def get_rule(self, tenant_scope: str, rule_id: str) -> DetectionRule | None: ...
    def list_all_rules(
        self, tenant_scope: str, status: RuleStatus | None = None
    ) -> Sequence[DetectionRule]: ...
    def list_rules(
        self,
        tenant_scope: str,
        source: RuleSource | None,
        status: RuleStatus | None,
        severity: RuleSeverity | None,
        attack_tag: str | None,
        query_text: str | None,
        page: PageSpec,
    ) -> PageResult[DetectionRule]: ...
    def update_rule_status(
        self,
        tenant_scope: str,
        rule_id: str,
        status: RuleStatus,
        updated_at: datetime,
    ) -> DetectionRule | None: ...

    def execute_compiled_event_query(
        self,
        query: EventSqlSelector,
        scope: AccessScope,
        time_range: TimeRange,
        limit: int,
        event_ids: Sequence[UUID] | None = None,
    ) -> Sequence[NormalizedEvent]: ...
    def resolve_event_entities(
        self, tenant_scope: str, event_ids: Sequence[UUID]
    ) -> dict[UUID, tuple[UUID | None, tuple[UUID, ...]]]: ...

    def save_execution(self, execution: DetectionExecution) -> None: ...
    def get_execution(
        self, scope: AccessScope, execution_id: UUID
    ) -> DetectionExecution | None: ...
    def list_executions(
        self, scope: AccessScope, page: PageSpec
    ) -> PageResult[DetectionExecution]: ...

    def insert_rule_match_if_absent(self, match: RuleMatch) -> tuple[RuleMatch, bool]: ...
    def get_rule_match(self, scope: AccessScope, match_id: UUID) -> RuleMatch | None: ...
    def get_rule_matches_by_ids(
        self, scope: AccessScope, match_ids: Sequence[UUID]
    ) -> Sequence[RuleMatch]: ...
    def search_rule_matches(
        self,
        scope: AccessScope,
        time_range: TimeRange,
        rule_id: str | None,
        detection_type: DetectionType | None,
        severity: RuleSeverity | None,
        entity_id: UUID | None,
        page: PageSpec,
    ) -> PageResult[RuleMatch]: ...

    def get_signal_by_dedup_key(self, tenant_scope: str, dedup_key: str) -> Signal | None: ...
    def save_signal(self, signal: Signal) -> None: ...
    def update_signal_status(
        self,
        scope: AccessScope,
        signal_id: UUID,
        status: SignalStatus,
        updated_at: datetime,
    ) -> Signal | None: ...
    def get_signal(self, scope: AccessScope, signal_id: UUID) -> Signal | None: ...
    def list_signals_in_window(
        self, scope: AccessScope, time_range: TimeRange
    ) -> Sequence[Signal]: ...
    def search_signals(
        self,
        scope: AccessScope,
        time_range: TimeRange,
        status: SignalStatus | None,
        severity: RuleSeverity | None,
        entity_id: UUID | None,
        signal_type: str | None,
        page: PageSpec,
    ) -> PageResult[Signal]: ...
    def get_signal_evidence(
        self, scope: AccessScope, signal_id: UUID
    ) -> Sequence[SignalEvidenceDetail]: ...

    def upsert_candidate_group(self, group: CandidateGroup) -> bool: ...
    def get_candidate_group(self, scope: AccessScope, group_id: UUID) -> CandidateGroup | None: ...
    def search_candidate_groups(
        self,
        scope: AccessScope,
        time_range: TimeRange,
        entity_id: UUID | None,
        certainty: Certainty | None,
        page: PageSpec,
    ) -> PageResult[CandidateGroup]: ...


class UnitOfWork(Protocol):
    raw_events: RawEventRepository
    normalized_events: NormalizedEventRepository
    entities: EntityRepository
    graph: GraphRepository
    detection: DetectionRepository

    def purge_derived_data(self, tenant_scope: str) -> None: ...
    def __enter__(self) -> UnitOfWork: ...
    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None: ...
    def commit(self) -> None: ...
    def rollback(self) -> None: ...
    def savepoint(self) -> AbstractContextManager[None]: ...
