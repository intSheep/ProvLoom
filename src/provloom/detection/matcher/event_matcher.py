from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any
from uuid import NAMESPACE_URL, UUID, uuid5

from provloom.detection.compiler.postgres_backend import CompiledEventQuery
from provloom.detection.domain.rule import DetectionRule, DetectionType
from provloom.detection.domain.rule_match import EvidenceReference, RuleMatch
from provloom.detection.signals.deduplicator import compute_match_dedup_key
from provloom.domain.common import AccessScope, TimeRange
from provloom.domain.ocsf_models import NormalizedEvent
from provloom.storage.interfaces import UnitOfWork
from provloom.storage.postgres.utils import extract_nested


def _extract_event_field_value(event: NormalizedEvent, field: str) -> Any:
    if field == "class_uid":
        return event.class_uid
    if field == "category_uid":
        return event.category_uid
    if field == "activity_id":
        return event.activity_id
    if field == "type_uid":
        return event.class_uid * 100 + event.activity_id
    if field == "source_id":
        return event.source_id
    if field == "ocsf_version":
        return event.ocsf_version
    if field == "original_event_uid":
        return event.original_event_uid
    return extract_nested(event.ocsf_payload, field)


class SingleEventMatcher:
    """Executes compiled parameterized OCSF SQL queries in Batch or Incremental mode."""

    def match_batch(
        self,
        uow: UnitOfWork,
        scope: AccessScope,
        time_range: TimeRange,
        rule: DetectionRule,
        query: CompiledEventQuery,
        execution_id: UUID,
        max_matches: int = 500,
    ) -> Sequence[RuleMatch]:
        events = uow.detection.execute_compiled_event_query(
            query=query,
            scope=scope,
            time_range=time_range,
            limit=max_matches,
        )
        return self._build_matches(uow, scope, rule, query, events, execution_id)

    def match_incremental(
        self,
        uow: UnitOfWork,
        scope: AccessScope,
        event_ids: Sequence[UUID],
        rule: DetectionRule,
        query: CompiledEventQuery,
        execution_id: UUID,
        max_matches: int = 500,
    ) -> Sequence[RuleMatch]:
        if not event_ids:
            return ()
        wide_range = TimeRange(
            start_time=datetime(1970, 1, 1, tzinfo=UTC),
            end_time=datetime(2100, 1, 1, tzinfo=UTC),
        )
        events = uow.detection.execute_compiled_event_query(
            query=query,
            scope=scope,
            time_range=wide_range,
            limit=max_matches,
            event_ids=event_ids,
        )
        return self._build_matches(uow, scope, rule, query, events, execution_id)

    def _build_matches(
        self,
        uow: UnitOfWork,
        scope: AccessScope,
        rule: DetectionRule,
        query: CompiledEventQuery,
        events: Sequence[NormalizedEvent],
        execution_id: UUID,
    ) -> Sequence[RuleMatch]:
        if not events:
            return ()
        entity_map = uow.detection.resolve_event_entities(
            tenant_scope=scope.tenant_id,
            event_ids=[e.event_id for e in events],
        )
        matches: list[RuleMatch] = []
        for ev in events:
            primary_ent, related_ents = entity_map.get(ev.event_id, (None, ()))
            matched_vals: dict[str, Any] = {}
            for mf in query.user_matched_fields:
                val = _extract_event_field_value(ev, mf)
                if val is not None:
                    matched_vals[mf] = val
            dedup_key = compute_match_dedup_key(
                tenant_scope=scope.tenant_id,
                rule_id=rule.rule_id,
                rule_version=rule.version,
                detection_type=DetectionType.EVENT,
                anchor_id=ev.event_id,
            )
            match_id = uuid5(NAMESPACE_URL, f"provloom:rulematch:{dedup_key}")
            ev_ref = EvidenceReference(
                event_id=ev.event_id,
                raw_event_id=ev.raw_event_id,
                source_id=ev.source_id,
                original_event_uid=ev.original_event_uid,
                observed_at=ev.event_time,
            )
            matches.append(
                RuleMatch(
                    match_id=match_id,
                    tenant_scope=scope.tenant_id,
                    dedup_key=dedup_key,
                    rule_id=rule.rule_id,
                    rule_name=rule.rule_name,
                    rule_version=rule.version,
                    severity=rule.severity,
                    detection_type=DetectionType.EVENT,
                    primary_event_id=ev.event_id,
                    matched_event_ids=(ev.event_id,),
                    primary_entity_id=primary_ent,
                    related_entity_ids=related_ents,
                    matched_fields=tuple(matched_vals.keys()) or query.user_matched_fields,
                    matched_values=matched_vals,
                    evidence_references=(ev_ref,),
                    source_ids=(ev.source_id,),
                    matched_at=ev.event_time,
                    execution_id=execution_id,
                )
            )
        return tuple(matches)
