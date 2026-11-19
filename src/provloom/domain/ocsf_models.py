from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import UUID

from provloom.domain.enums import NormalizationStatus
from provloom.domain.raw_models import RawEvent


@dataclass(frozen=True)
class NormalizedEvent:
    """OCSF-normalized event; unsupported events use class_uid=0 and UNSUPPORTED_PASSTHROUGH."""

    event_id: UUID
    raw_event_id: UUID
    tenant_scope: str
    source_id: str
    ocsf_version: str
    category_uid: int
    class_uid: int
    activity_id: int
    event_time: datetime
    normalization_status: NormalizationStatus
    mapping_rule_id: str
    original_event_uid: str | None = None
    ocsf_payload: dict[str, Any] = field(default_factory=dict)
    unmapped_fields: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class NormalizedEventSummary:
    event_id: UUID
    raw_event_id: UUID
    source_id: str
    ocsf_version: str
    category_uid: int
    class_uid: int
    activity_id: int
    event_time: datetime
    normalization_status: NormalizationStatus
    original_event_uid: str | None


@dataclass(frozen=True)
class EventWithRawDetail:
    normalized: NormalizedEvent
    raw: RawEvent | None = None
