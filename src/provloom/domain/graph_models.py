from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from provloom.domain.entity_models import Entity
from provloom.domain.enums import Certainty, Direction, EntityType, RelationType
from provloom.domain.errors import QueryLimitExceededError


@dataclass(frozen=True)
class FiveTuple:
    src_ip: str
    src_port: int | None
    dst_ip: str
    dst_port: int | None
    protocol: str


@dataclass(frozen=True)
class CandidateRelation:
    """Pre-persistence relation traced back to its NormalizedEvent and RawEvent."""

    tenant_scope: str
    src_entity_id: UUID
    relation_type: RelationType
    dst_entity_id: UUID
    certainty: Certainty
    context_key: str
    correlation_rule_id: str
    observed_at: datetime
    event_id: UUID
    raw_event_id: UUID
    evidence_role: str
    correlation_basis: dict[str, Any] = field(default_factory=dict)
    five_tuple: FiveTuple | None = None


@dataclass(frozen=True)
class Relation:
    relation_id: UUID
    tenant_scope: str
    src_entity_id: UUID
    relation_type: RelationType
    dst_entity_id: UUID
    certainty: Certainty
    context_key: str
    correlation_rule_id: str
    first_seen_at: datetime
    last_seen_at: datetime
    evidence_count: int
    correlation_basis: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RelationEvidence:
    evidence_id: UUID
    relation_id: UUID
    event_id: UUID
    raw_event_id: UUID
    evidence_role: str
    observed_at: datetime
    match_detail: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RelationEvidenceDetail:
    evidence: RelationEvidence
    source_id: str
    ocsf_class_uid: int
    raw_payload: str


@dataclass(frozen=True)
class GraphTraversalSpec:
    seed_entity_id: UUID
    max_depth: int = 2
    direction: Direction = Direction.BOTH
    relation_types: tuple[RelationType, ...] | None = None
    include_candidates: bool = False  # Excludes CANDIDATE edges by default
    max_nodes: int = 200
    max_edges: int = 500

    def validate(self, depth_cap: int, nodes_cap: int, edges_cap: int) -> GraphTraversalSpec:
        if not (1 <= self.max_depth <= depth_cap):
            raise QueryLimitExceededError(f"max_depth must be between 1 and {depth_cap}")
        if not (1 <= self.max_nodes <= nodes_cap):
            raise QueryLimitExceededError(f"max_nodes must be between 1 and {nodes_cap}")
        if not (1 <= self.max_edges <= edges_cap):
            raise QueryLimitExceededError(f"max_edges must be between 1 and {edges_cap}")
        return self


@dataclass(frozen=True)
class SubgraphResult:
    seed_entity_id: UUID
    nodes: tuple[Entity, ...]
    edges: tuple[Relation, ...]
    truncated: bool = False


@dataclass(frozen=True)
class GraphBuildResult:
    created_relations: int
    updated_relations: int
    attached_evidences: int


NeighborhoodSortBy = Literal["rare", "last_seen", "evidence_count", "certainty"]


@dataclass(frozen=True)
class NeighborhoodItem:
    relation: Relation
    neighbor: Entity
    direction: Direction


@dataclass(frozen=True)
class NeighborhoodGroupSummary:
    relation_type: RelationType
    neighbor_entity_type: EntityType
    certainty: Certainty
    relation_count: int
    evidence_count: int
    sample_neighbor_labels: tuple[str, ...] = ()


@dataclass(frozen=True)
class EntityNeighborhoodResult:
    center_entity: Entity | None
    items: tuple[NeighborhoodItem, ...] = ()
    groups: tuple[NeighborhoodGroupSummary, ...] = ()
    total_relations_matched: int = 0
    next_cursor: str | None = None
    truncated: bool = False
