from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID

from provloom.detection.domain.rule import RuleSeverity
from provloom.detection.domain.rule_match import EvidenceReference
from provloom.domain.enums import Certainty, RelationType


class SignalStatus(str, Enum):
    """Tracks triage progress only; never asserts confirmed attack disposition."""

    NEW = "NEW"
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"
    SUPPRESSED = "SUPPRESSED"


@dataclass(frozen=True)
class Signal:
    signal_id: UUID
    tenant_scope: str
    dedup_key: str
    signal_type: str
    title: str
    severity: RuleSeverity
    status: SignalStatus
    primary_entity_id: UUID | None
    related_entity_ids: tuple[UUID, ...]
    rule_match_ids: tuple[UUID, ...]
    event_ids: tuple[UUID, ...]
    evidence_refs: tuple[EvidenceReference, ...]
    source_ids: tuple[str, ...]
    attack_tags: tuple[str, ...]
    first_seen_at: datetime
    last_seen_at: datetime
    occurrence_count: int
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True)
class SignalEvidenceDetail:
    event_id: UUID
    raw_event_id: UUID
    source_id: str
    ocsf_class_uid: int
    event_time: datetime
    original_event_uid: str | None
    ocsf_payload: dict[str, Any] = field(default_factory=dict)
    raw_payload: str = ""
    relation_id: UUID | None = None
    relation_type: RelationType | None = None
    certainty: Certainty | None = None
