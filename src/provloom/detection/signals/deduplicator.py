from __future__ import annotations

import hashlib
from uuid import UUID

from provloom.detection.domain.rule import DetectionType


def compute_match_dedup_key(
    tenant_scope: str,
    rule_id: str,
    rule_version: str,
    detection_type: DetectionType,
    anchor_id: UUID,
) -> str:
    payload = f"{tenant_scope}|{rule_id}|{rule_version}|{detection_type.value}|{anchor_id}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def compute_signal_dedup_key(
    tenant_scope: str,
    rule_id: str,
    primary_entity_id: UUID | None,
    primary_event_id: UUID | None,
) -> str:
    # Never aggregate across distinct entities; fall back to event anchor if entity is absent.
    anchor = (
        f"entity:{primary_entity_id}"
        if primary_entity_id is not None
        else f"event:{primary_event_id}"
    )
    payload = f"{tenant_scope}|rule:{rule_id}|{anchor}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
