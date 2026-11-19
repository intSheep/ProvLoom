from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol

from provloom.domain.entity_models import EntityResolutionResult
from provloom.domain.graph_models import CandidateRelation, GraphBuildResult
from provloom.domain.ocsf_models import NormalizedEvent


class RelationExtractor(Protocol):
    def supports_class(self, class_uid: int) -> bool: ...
    def extract(
        self,
        event: NormalizedEvent,
        resolved: EntityResolutionResult,
    ) -> Sequence[CandidateRelation]: ...


class CrossSourceCorrelator(Protocol):
    """Links multi-source interactions (e.g. socket + firewall 5-tuple) without forced merges."""

    def correlate(
        self,
        event: NormalizedEvent,
        relations: Sequence[CandidateRelation],
    ) -> Sequence[CandidateRelation]: ...


class GraphBuilder(Protocol):
    def apply_relations(self, relations: Sequence[CandidateRelation]) -> GraphBuildResult: ...
