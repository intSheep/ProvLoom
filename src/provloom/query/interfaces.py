from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol
from uuid import UUID

from provloom.domain.common import AccessScope, PageResult, PageSpec, TimeRange
from provloom.domain.entity_models import Entity, EntityDetail
from provloom.domain.enums import Direction, EntityType, RelationType, ResolutionState
from provloom.domain.graph_models import (
    GraphTraversalSpec,
    Relation,
    RelationEvidenceDetail,
    SubgraphResult,
)
from provloom.domain.ocsf_models import EventWithRawDetail, NormalizedEventSummary


@dataclass(frozen=True)
class EventSearchFilter:
    sources: tuple[str, ...] | None = None
    class_uids: tuple[int, ...] | None = None
    category_uids: tuple[int, ...] | None = None
    field_equals: dict[str, str | int | bool] | None = None
    include_fallback: bool = True


@dataclass(frozen=True)
class EntitySearchFilter:
    entity_types: tuple[EntityType, ...] | None = None
    resolution_states: tuple[ResolutionState, ...] | None = None
    identifier_query: str | None = None


class QueryService(Protocol):
    """Read-only query facade shared by APT Investigation Agents and Web Console."""

    def search_events(
        self,
        scope: AccessScope,
        time_range: TimeRange,
        filters: EventSearchFilter,
        page: PageSpec,
    ) -> PageResult[NormalizedEventSummary]: ...

    def get_event(
        self,
        scope: AccessScope,
        event_id: UUID,
        time_range: TimeRange | None = None,
        include_raw: bool = True,
    ) -> EventWithRawDetail | None: ...

    def search_entities(
        self,
        scope: AccessScope,
        time_range: TimeRange | None,
        filters: EntitySearchFilter,
        page: PageSpec,
    ) -> PageResult[Entity]: ...

    def get_entity(
        self,
        scope: AccessScope,
        entity_id: UUID,
        time_range: TimeRange | None = None,
        follow_merged: bool = True,
    ) -> EntityDetail | None: ...

    def get_entity_relations(
        self,
        scope: AccessScope,
        entity_id: UUID,
        time_range: TimeRange,
        direction: Direction = Direction.BOTH,
        relation_types: Sequence[RelationType] | None = None,
        include_candidates: bool = False,
        page: PageSpec = PageSpec(limit=100),
    ) -> PageResult[Relation]: ...

    def traverse_graph(
        self,
        scope: AccessScope,
        time_range: TimeRange,
        spec: GraphTraversalSpec,
    ) -> SubgraphResult: ...

    def get_relation_evidence(
        self,
        scope: AccessScope,
        relation_id: UUID,
        time_range: TimeRange | None = None,
        page: PageSpec = PageSpec(limit=100),
    ) -> PageResult[RelationEvidenceDetail]: ...
