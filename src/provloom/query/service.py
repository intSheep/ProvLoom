from __future__ import annotations

import time
from collections.abc import Sequence
from uuid import UUID

from provloom.config import QueryGuardConfig
from provloom.domain.common import AccessScope, PageResult, PageSpec, TimeRange
from provloom.domain.entity_models import Entity, EntityDetail
from provloom.domain.enums import Direction, RelationType
from provloom.domain.graph_models import (
    GraphTraversalSpec,
    Relation,
    RelationEvidenceDetail,
    SubgraphResult,
)
from provloom.domain.ocsf_models import EventWithRawDetail, NormalizedEventSummary
from provloom.observability.interfaces import PipelineTelemetry
from provloom.query.interfaces import EntitySearchFilter, EventSearchFilter, QueryService
from provloom.storage.postgres.uow import UnitOfWorkFactory


class DefaultQueryService(QueryService):
    def __init__(
        self,
        uow_factory: UnitOfWorkFactory,
        telemetry: PipelineTelemetry,
        guards: QueryGuardConfig | None = None,
    ) -> None:
        self._uow_factory = uow_factory
        self._telemetry = telemetry
        self._guards = guards or QueryGuardConfig()

    def search_events(
        self,
        scope: AccessScope,
        time_range: TimeRange,
        filters: EventSearchFilter,
        page: PageSpec,
    ) -> PageResult[NormalizedEventSummary]:
        t0 = time.perf_counter()
        validated_page = page.validate(self._guards.max_page_limit)
        with self._uow_factory() as uow:
            res = uow.normalized_events.search(
                scope=scope,
                time_range=time_range,
                sources=filters.sources,
                class_uids=filters.class_uids,
                category_uids=filters.category_uids,
                field_equals=filters.field_equals,
                include_fallback=filters.include_fallback,
                page=validated_page,
            )
        self._telemetry.observe_query_latency("search_events", time.perf_counter() - t0)
        return res

    def get_event(
        self,
        scope: AccessScope,
        event_id: UUID,
        time_range: TimeRange | None = None,
        include_raw: bool = True,
    ) -> EventWithRawDetail | None:
        t0 = time.perf_counter()
        with self._uow_factory() as uow:
            res = uow.normalized_events.get_with_raw(
                scope=scope, event_id=event_id, time_range=time_range, include_raw=include_raw
            )
        self._telemetry.observe_query_latency("get_event", time.perf_counter() - t0)
        return res

    def search_entities(
        self,
        scope: AccessScope,
        time_range: TimeRange | None,
        filters: EntitySearchFilter,
        page: PageSpec,
    ) -> PageResult[Entity]:
        t0 = time.perf_counter()
        validated_page = page.validate(self._guards.max_page_limit)
        with self._uow_factory() as uow:
            res = uow.entities.search(
                scope=scope,
                time_range=time_range,
                entity_types=filters.entity_types,
                resolution_states=filters.resolution_states,
                identifier_query=filters.identifier_query,
                page=validated_page,
            )
        self._telemetry.observe_query_latency("search_entities", time.perf_counter() - t0)
        return res

    def get_entity(
        self,
        scope: AccessScope,
        entity_id: UUID,
        time_range: TimeRange | None = None,
        follow_merged: bool = True,
    ) -> EntityDetail | None:
        t0 = time.perf_counter()
        with self._uow_factory() as uow:
            res = uow.entities.get_detail(
                scope=scope,
                entity_id=entity_id,
                time_range=time_range,
                follow_merged=follow_merged,
            )
        self._telemetry.observe_query_latency("get_entity", time.perf_counter() - t0)
        return res

    def get_entity_relations(
        self,
        scope: AccessScope,
        entity_id: UUID,
        time_range: TimeRange,
        direction: Direction = Direction.BOTH,
        relation_types: Sequence[RelationType] | None = None,
        include_candidates: bool = False,
        page: PageSpec = PageSpec(limit=100),
    ) -> PageResult[Relation]:
        t0 = time.perf_counter()
        validated_page = page.validate(self._guards.max_page_limit)
        with self._uow_factory() as uow:
            res = uow.graph.get_entity_relations(
                scope=scope,
                entity_id=entity_id,
                time_range=time_range,
                direction=direction,
                relation_types=relation_types,
                include_candidates=include_candidates,
                page=validated_page,
            )
        self._telemetry.observe_query_latency("get_entity_relations", time.perf_counter() - t0)
        return res

    def traverse_graph(
        self,
        scope: AccessScope,
        time_range: TimeRange,
        spec: GraphTraversalSpec,
    ) -> SubgraphResult:
        t0 = time.perf_counter()
        validated = spec.validate(
            depth_cap=self._guards.max_graph_depth,
            nodes_cap=self._guards.max_graph_nodes,
            edges_cap=self._guards.max_graph_edges,
        )
        with self._uow_factory() as uow:
            res = uow.graph.traverse(scope=scope, time_range=time_range, spec=validated)
        self._telemetry.observe_query_latency("traverse_graph", time.perf_counter() - t0)
        return res

    def get_relation_evidence(
        self,
        scope: AccessScope,
        relation_id: UUID,
        time_range: TimeRange | None = None,
        page: PageSpec = PageSpec(limit=100),
    ) -> PageResult[RelationEvidenceDetail]:
        t0 = time.perf_counter()
        validated_page = page.validate(self._guards.max_page_limit)
        with self._uow_factory() as uow:
            res = uow.graph.get_relation_evidence(
                scope=scope,
                relation_id=relation_id,
                time_range=time_range,
                page=validated_page,
            )
        self._telemetry.observe_query_latency("get_relation_evidence", time.perf_counter() - t0)
        return res
