from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import UUID

from provloom.domain.enums import EntityType, ResolutionState


@dataclass(frozen=True)
class CandidateKey:
    namespace: str
    value: str
    is_authoritative: bool = False
    scope_role: str | None = None  # e.g. "host" when key requires host_entity_id scoping


@dataclass(frozen=True)
class EntityObservation:
    """Pre-resolution entity candidate extracted from a single NormalizedEvent."""

    role: str  # Semantic slot inside event, e.g. "actor_process", "dst_endpoint"
    entity_type: EntityType
    display_label: str
    observed_at: datetime
    candidate_keys: tuple[CandidateKey, ...]
    attributes: dict[str, Any] = field(default_factory=dict)
    lifecycle_start: datetime | None = None
    lifecycle_end: datetime | None = None


@dataclass(frozen=True)
class EntityIdentifier:
    identifier_id: UUID
    entity_id: UUID
    tenant_scope: str
    id_namespace: str
    id_value: str
    is_authoritative: bool
    first_seen_event_id: UUID
    scope_entity_id: UUID | None = None
    valid_from: datetime | None = None
    valid_to: datetime | None = None


@dataclass(frozen=True)
class Entity:
    entity_id: UUID
    tenant_scope: str
    entity_type: EntityType
    resolution_state: ResolutionState
    display_label: str
    canonical_key: str | None = None
    valid_from: datetime | None = None
    valid_to: datetime | None = None
    attributes: dict[str, Any] = field(default_factory=dict)
    merged_into_id: UUID | None = None


@dataclass(frozen=True)
class EntityMergeAudit:
    merge_id: UUID
    tenant_scope: str
    source_entity_id: UUID
    target_entity_id: UUID
    merge_rule_id: str
    match_basis: dict[str, Any]
    evidence_event_ids: tuple[UUID, ...]
    merged_at: datetime


@dataclass(frozen=True)
class EntityResolutionResult:
    by_role: dict[str, Entity]
    merges: tuple[EntityMergeAudit, ...] = ()


@dataclass(frozen=True)
class EntityDetail:
    entity: Entity
    identifiers: tuple[EntityIdentifier, ...]
    merges: tuple[EntityMergeAudit, ...]
