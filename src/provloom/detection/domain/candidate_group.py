from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import UUID

from provloom.detection.domain.rule_match import RuleMatch
from provloom.detection.domain.signal import Signal
from provloom.domain.enums import Certainty


@dataclass(frozen=True)
class CandidateGroupingConfig:
    enabled: bool = True
    max_time_gap_seconds: float = 3600.0
    group_by_shared_entity: bool = True
    group_by_direct_deterministic_relation: bool = True


@dataclass(frozen=True)
class CandidateGroup:
    """Deterministic pre-investigation clue cluster; does not assert a single attack campaign."""

    group_id: UUID
    tenant_scope: str
    group_key: str
    signal_ids: tuple[UUID, ...]
    rule_match_ids: tuple[UUID, ...]
    shared_entity_ids: tuple[UUID, ...]
    grouping_rule_id: str
    grouping_basis: dict[str, Any] = field(default_factory=dict)
    certainty: Certainty = Certainty.DETERMINISTIC
    unresolved_ambiguities: tuple[str, ...] = ()
    source_ids: tuple[str, ...] = ()
    first_seen_at: datetime = field(default_factory=datetime.now)
    last_seen_at: datetime = field(default_factory=datetime.now)
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)


@dataclass(frozen=True)
class CandidateGroupMembers:
    group: CandidateGroup
    signals: tuple[Signal, ...]
    rule_matches: tuple[RuleMatch, ...]
