from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Protocol
from uuid import UUID

from provloom.domain.common import AccessScope, PageResult, PageSpec, TimeRange
from provloom.domain.entity_models import (
    Entity,
    EntityDetail,
    EntityIdentifier,
    EntityMergeAudit,
)
from provloom.domain.enums import (
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


class UnitOfWork(Protocol):
    raw_events: RawEventRepository
    normalized_events: NormalizedEventRepository
    entities: EntityRepository
    graph: GraphRepository

    def purge_derived_data(self, tenant_scope: str) -> None: ...
    def __enter__(self) -> UnitOfWork: ...
    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None: ...
    def commit(self) -> None: ...
    def rollback(self) -> None: ...
