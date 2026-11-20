from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import UUID

from provloom.detection.domain.rule import DetectionType, RuleSeverity


@dataclass(frozen=True)
class EvidenceReference:
    event_id: UUID | None
    raw_event_id: UUID | None
    relation_id: UUID | None = None
    source_id: str = ""
    original_event_uid: str | None = None
    observed_at: datetime | None = None


@dataclass(frozen=True)
class RuleMatch:
    """Immutable single rule firing record; never deleted when Signals aggregate."""

    match_id: UUID
    tenant_scope: str
    dedup_key: str
    rule_id: str
    rule_name: str
    rule_version: str
    severity: RuleSeverity
    detection_type: DetectionType
    primary_event_id: UUID | None
    matched_event_ids: tuple[UUID, ...]
    primary_entity_id: UUID | None
    related_entity_ids: tuple[UUID, ...]
    matched_fields: tuple[str, ...]
    matched_values: dict[str, Any] = field(default_factory=dict)
    evidence_references: tuple[EvidenceReference, ...] = ()
    source_ids: tuple[str, ...] = ()
    matched_at: datetime = field(default_factory=datetime.now)
    execution_id: UUID = field(default_factory=lambda: UUID(int=0))
