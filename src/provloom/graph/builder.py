from __future__ import annotations

from collections.abc import Sequence

from provloom.domain.graph_models import CandidateRelation, GraphBuildResult
from provloom.graph.interfaces import GraphBuilder
from provloom.observability.interfaces import PipelineTelemetry
from provloom.storage.interfaces import UnitOfWork


class DefaultGraphBuilder(GraphBuilder):
    def __init__(self, uow: UnitOfWork, telemetry: PipelineTelemetry) -> None:
        self._uow = uow
        self._telemetry = telemetry

    def apply_relations(self, relations: Sequence[CandidateRelation]) -> GraphBuildResult:
        if not relations:
            return GraphBuildResult(0, 0, 0)
        res = self._uow.graph.upsert_relations(relations)
        for rel in relations:
            self._telemetry.record_relation(rel.relation_type, rel.certainty)
        return res
