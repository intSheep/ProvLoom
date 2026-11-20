from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import Connection, Executable, delete, insert, select, update

from provloom.detection.domain.candidate_group import CandidateGroup
from provloom.detection.domain.rule import (
    DetectionExecution,
    DetectionRule,
    DetectionType,
    ExecutionMode,
    ExecutionStatus,
    LogsourceSpec,
    RuleCompatibility,
    RuleExecutionFailure,
    RuleSeverity,
    RuleSource,
    RuleStatus,
)
from provloom.detection.domain.rule_match import EvidenceReference, RuleMatch
from provloom.detection.domain.signal import Signal, SignalEvidenceDetail, SignalStatus
from provloom.domain.common import AccessScope, PageResult, PageSpec, TimeRange
from provloom.domain.enums import Certainty, EntityType, NormalizationStatus, RelationType
from provloom.domain.ocsf_models import NormalizedEvent
from provloom.storage.interfaces import DetectionRepository, EventSqlSelector
from provloom.storage.postgres.tables import (
    detection_candidate_groups,
    detection_executions,
    detection_rule_matches,
    detection_rules,
    detection_signal_matches,
    detection_signals,
    entities,
    entity_identifiers,
    normalized_events,
    raw_events,
    relation_evidences,
    relations,
)
from provloom.storage.postgres.utils import (
    ensure_utc,
    next_offset_cursor,
    parse_offset,
    require_utc,
)

_ENTITY_TYPE_PRIORITY: dict[str, int] = {
    EntityType.PROCESS.value: 10,
    EntityType.USER.value: 9,
    EntityType.CONTAINER.value: 8,
    EntityType.SERVICE.value: 7,
    EntityType.FILE.value: 6,
    EntityType.NETWORK_ENDPOINT.value: 5,
    EntityType.HOST.value: 4,
}


def _scope_permits_sources(scope: AccessScope, source_ids: Sequence[str]) -> bool:
    if scope.allowed_sources is None:
        return True
    if not source_ids:
        return False
    return all(scope.permits_source(sid) for sid in source_ids)


def _serialize_evidence(ev: EvidenceReference) -> dict[str, Any]:
    return {
        "event_id": str(ev.event_id) if ev.event_id else None,
        "raw_event_id": str(ev.raw_event_id) if ev.raw_event_id else None,
        "relation_id": str(ev.relation_id) if ev.relation_id else None,
        "source_id": ev.source_id,
        "original_event_uid": ev.original_event_uid,
        "observed_at": ev.observed_at.isoformat() if ev.observed_at else None,
    }


def _deserialize_evidence(raw: dict[str, Any]) -> EvidenceReference:
    obs = raw.get("observed_at")
    return EvidenceReference(
        event_id=UUID(str(raw["event_id"])) if raw.get("event_id") else None,
        raw_event_id=UUID(str(raw["raw_event_id"])) if raw.get("raw_event_id") else None,
        relation_id=UUID(str(raw["relation_id"])) if raw.get("relation_id") else None,
        source_id=str(raw.get("source_id") or ""),
        original_event_uid=str(raw["original_event_uid"])
        if raw.get("original_event_uid") is not None
        else None,
        observed_at=require_utc(datetime.fromisoformat(str(obs))) if obs else None,
    )


def _serialize_compat(compat: RuleCompatibility) -> dict[str, Any]:
    return {
        "parse_success": compat.parse_success,
        "mapping_success": compat.mapping_success,
        "data_coverage": compat.data_coverage,
        "compile_success": compat.compile_success,
        "execution_success": compat.execution_success,
        "mapped_class_uids": list(compat.mapped_class_uids),
        "field_mappings": dict(compat.field_mappings),
        "uncovered_fields": list(compat.uncovered_fields),
        "unsupported_reasons": list(compat.unsupported_reasons),
    }


def _deserialize_compat(raw: dict[str, Any]) -> RuleCompatibility:
    return RuleCompatibility(
        parse_success=bool(raw.get("parse_success", False)),
        mapping_success=bool(raw.get("mapping_success", False)),
        data_coverage=bool(raw.get("data_coverage", False)),
        compile_success=bool(raw.get("compile_success", False)),
        execution_success=(
            bool(raw["execution_success"]) if raw.get("execution_success") is not None else None
        ),
        mapped_class_uids=tuple(int(x) for x in (raw.get("mapped_class_uids") or [])),
        field_mappings={str(k): str(v) for k, v in (raw.get("field_mappings") or {}).items()},
        uncovered_fields=tuple(str(x) for x in (raw.get("uncovered_fields") or [])),
        unsupported_reasons=tuple(str(x) for x in (raw.get("unsupported_reasons") or [])),
    )


class SqlDetectionRepository(DetectionRepository):
    def __init__(self, conn: Connection) -> None:
        self._conn = conn

    def upsert_rule(
        self, tenant_scope: str, rule: DetectionRule, preserve_status: bool = False
    ) -> DetectionRule:
        existing = self.get_rule(tenant_scope, rule.rule_id)
        final_status = rule.status
        created_at = rule.created_at
        if existing is not None:
            created_at = existing.created_at
            if (
                preserve_status
                and rule.compatibility.is_supported
                and existing.status in (RuleStatus.ENABLED, RuleStatus.DISABLED)
            ):
                final_status = existing.status

        vals = {
            "tenant_scope": tenant_scope,
            "rule_id": rule.rule_id,
            "rule_name": rule.rule_name,
            "source": rule.source.value,
            "source_reference": rule.source_reference,
            "version": rule.version,
            "description": rule.description,
            "severity": rule.severity.value,
            "attack_tags": list(rule.attack_tags),
            "logsource": {
                "category": rule.logsource.category,
                "product": rule.logsource.product,
                "service": rule.logsource.service,
            },
            "detection_type": rule.detection_type.value,
            "raw_content": rule.raw_content,
            "status": final_status.value,
            "compatibility": _serialize_compat(rule.compatibility),
            "created_at": created_at,
            "updated_at": rule.updated_at,
        }
        if existing is None:
            self._conn.execute(insert(detection_rules).values(**vals))
        else:
            self._conn.execute(
                update(detection_rules)
                .where(
                    detection_rules.c.tenant_scope == tenant_scope,
                    detection_rules.c.rule_id == rule.rule_id,
                )
                .values(**vals)
            )
        res = self.get_rule(tenant_scope, rule.rule_id)
        assert res is not None
        return res

    def get_rule(self, tenant_scope: str, rule_id: str) -> DetectionRule | None:
        row = (
            self._conn.execute(
                select(detection_rules).where(
                    detection_rules.c.tenant_scope == tenant_scope,
                    detection_rules.c.rule_id == rule_id,
                )
            )
            .mappings()
            .first()
        )
        return self._to_rule(row) if row is not None else None

    def list_all_rules(
        self, tenant_scope: str, status: RuleStatus | None = None
    ) -> Sequence[DetectionRule]:
        stmt = select(detection_rules).where(detection_rules.c.tenant_scope == tenant_scope)
        if status is not None:
            stmt = stmt.where(detection_rules.c.status == status.value)
        stmt = stmt.order_by(detection_rules.c.rule_id.asc())
        rows = self._conn.execute(stmt).mappings().all()
        return tuple(self._to_rule(r) for r in rows)

    def list_rules(
        self,
        tenant_scope: str,
        source: RuleSource | None,
        status: RuleStatus | None,
        severity: RuleSeverity | None,
        attack_tag: str | None,
        query_text: str | None,
        page: PageSpec,
    ) -> PageResult[DetectionRule]:
        offset = parse_offset(page.cursor)
        stmt = select(detection_rules).where(detection_rules.c.tenant_scope == tenant_scope)
        if source is not None:
            stmt = stmt.where(detection_rules.c.source == source.value)
        if status is not None:
            stmt = stmt.where(detection_rules.c.status == status.value)
        if severity is not None:
            stmt = stmt.where(detection_rules.c.severity == severity.value)
        stmt = stmt.order_by(detection_rules.c.rule_id.asc())

        rules = [self._to_rule(r) for r in self._conn.execute(stmt).mappings().all()]
        if attack_tag:
            tag_q = attack_tag.strip().lower()
            rules = [r for r in rules if any(tag_q in t.lower() for t in r.attack_tags)]
        if query_text:
            q = query_text.strip().lower()
            rules = [
                r
                for r in rules
                if q in r.rule_id.lower() or q in r.rule_name.lower() or q in r.description.lower()
            ]
        sliced = rules[offset : offset + page.limit + 1]
        cursor, has_more = next_offset_cursor(offset, page.limit, len(sliced))
        return PageResult(
            items=tuple(sliced[: page.limit]),
            next_cursor=cursor,
            truncated=has_more,
        )

    def update_rule_status(
        self,
        tenant_scope: str,
        rule_id: str,
        status: RuleStatus,
        updated_at: datetime,
    ) -> DetectionRule | None:
        existing = self.get_rule(tenant_scope, rule_id)
        if existing is None:
            return None
        self._conn.execute(
            update(detection_rules)
            .where(
                detection_rules.c.tenant_scope == tenant_scope,
                detection_rules.c.rule_id == rule_id,
            )
            .values(status=status.value, updated_at=updated_at)
        )
        return self.get_rule(tenant_scope, rule_id)

    def execute_compiled_event_query(
        self,
        query: EventSqlSelector,
        scope: AccessScope,
        time_range: TimeRange,
        limit: int,
        event_ids: Sequence[UUID] | None = None,
    ) -> Sequence[NormalizedEvent]:
        dialect_name = self._conn.dialect.name
        stmt = query.build_select(
            dialect_name=dialect_name,
            scope=scope,
            time_range=time_range,
            limit=limit,
            event_ids=event_ids,
        )
        assert isinstance(stmt, Executable)
        rows = self._conn.execute(stmt).mappings().all()
        return tuple(
            NormalizedEvent(
                event_id=r["event_id"],
                raw_event_id=r["raw_event_id"],
                tenant_scope=r["tenant_scope"],
                source_id=r["source_id"],
                ocsf_version=r["ocsf_version"],
                category_uid=int(r["category_uid"]),
                class_uid=int(r["class_uid"]),
                activity_id=int(r["activity_id"]),
                event_time=require_utc(r["event_time"]),
                normalization_status=NormalizationStatus(r["normalization_status"]),
                mapping_rule_id=r["mapping_rule_id"],
                original_event_uid=r["original_event_uid"],
                ocsf_payload=dict(r["ocsf_payload"] or {}),
                unmapped_fields=dict(r["unmapped_fields"] or {}),
            )
            for r in rows
        )

    def resolve_event_entities(
        self, tenant_scope: str, event_ids: Sequence[UUID]
    ) -> dict[UUID, tuple[UUID | None, tuple[UUID, ...]]]:
        if not event_ids:
            return {}

        ev_set = list(dict.fromkeys(event_ids))
        rel_rows = (
            self._conn.execute(
                select(
                    relation_evidences.c.event_id,
                    relations.c.relation_type,
                    relations.c.src_entity_id,
                    relations.c.dst_entity_id,
                )
                .select_from(
                    relation_evidences.join(
                        relations, relation_evidences.c.relation_id == relations.c.relation_id
                    )
                )
                .where(
                    relations.c.tenant_scope == tenant_scope,
                    relation_evidences.c.event_id.in_(ev_set),
                )
            )
            .mappings()
            .all()
        )
        id_rows = (
            self._conn.execute(
                select(
                    entity_identifiers.c.first_seen_event_id, entity_identifiers.c.entity_id
                ).where(
                    entity_identifiers.c.tenant_scope == tenant_scope,
                    entity_identifiers.c.first_seen_event_id.in_(ev_set),
                )
            )
            .mappings()
            .all()
        )

        candidate_ids: set[UUID] = set()
        for rr in rel_rows:
            candidate_ids.add(rr["src_entity_id"])
            candidate_ids.add(rr["dst_entity_id"])
        for ir in id_rows:
            candidate_ids.add(ir["entity_id"])

        ent_types: dict[UUID, str] = {}
        canonical_map: dict[UUID, UUID] = {}
        if candidate_ids:
            ent_rows = (
                self._conn.execute(
                    select(
                        entities.c.entity_id,
                        entities.c.entity_type,
                        entities.c.merged_into_id,
                    ).where(
                        entities.c.tenant_scope == tenant_scope,
                        entities.c.entity_id.in_(list(candidate_ids)),
                    )
                )
                .mappings()
                .all()
            )
            merged_targets = {
                r["merged_into_id"] for r in ent_rows if r["merged_into_id"] is not None
            }
            if merged_targets - candidate_ids:
                extra_rows = (
                    self._conn.execute(
                        select(
                            entities.c.entity_id,
                            entities.c.entity_type,
                            entities.c.merged_into_id,
                        ).where(
                            entities.c.tenant_scope == tenant_scope,
                            entities.c.entity_id.in_(list(merged_targets - candidate_ids)),
                        )
                    )
                    .mappings()
                    .all()
                )
                ent_rows = [*ent_rows, *extra_rows]
            for er in ent_rows:
                eid: UUID = er["entity_id"]
                target: UUID = er["merged_into_id"] or eid
                canonical_map[eid] = target
                ent_types[eid] = str(er["entity_type"])

        per_event_preferred: dict[UUID, list[UUID]] = {eid: [] for eid in ev_set}
        per_event_spawned_child: dict[UUID, UUID] = {}
        per_event_all: dict[UUID, list[UUID]] = {eid: [] for eid in ev_set}

        for rr in rel_rows:
            ev_id: UUID = rr["event_id"]
            src_id = canonical_map.get(rr["src_entity_id"], rr["src_entity_id"])
            dst_id = canonical_map.get(rr["dst_entity_id"], rr["dst_entity_id"])
            rtype = str(rr["relation_type"])
            if rtype == RelationType.SPAWNS.value:
                per_event_spawned_child[ev_id] = dst_id
                per_event_preferred[ev_id].append(dst_id)
                per_event_all[ev_id].extend([dst_id, src_id])
            elif rtype == RelationType.RUNS.value:
                per_event_preferred[ev_id].append(dst_id)
                per_event_all[ev_id].extend([dst_id, src_id])
            else:
                per_event_preferred[ev_id].append(src_id)
                per_event_all[ev_id].extend([src_id, dst_id])

        for ir in id_rows:
            ev_id = ir["first_seen_event_id"]
            ent_id = canonical_map.get(ir["entity_id"], ir["entity_id"])
            per_event_all[ev_id].append(ent_id)

        result: dict[UUID, tuple[UUID | None, tuple[UUID, ...]]] = {}
        for ev_id in ev_set:
            dedup_all = list(dict.fromkeys(per_event_all[ev_id]))
            if not dedup_all:
                result[ev_id] = (None, ())
                continue
            if ev_id in per_event_spawned_child:
                primary = per_event_spawned_child[ev_id]
            else:
                prefs = list(dict.fromkeys(per_event_preferred[ev_id]))
                pool = prefs if prefs else dedup_all
                primary = max(
                    pool,
                    key=lambda x: _ENTITY_TYPE_PRIORITY.get(ent_types.get(x, ""), 0),
                )
            related = tuple(x for x in dedup_all if x != primary)
            result[ev_id] = (primary, related)
        return result

    def save_execution(self, execution: DetectionExecution) -> None:
        vals = {
            "execution_id": execution.execution_id,
            "tenant_scope": execution.tenant_scope,
            "mode": execution.mode.value,
            "status": execution.status.value,
            "start_time": execution.time_range.start_time,
            "end_time": execution.time_range.end_time,
            "rule_ids": list(execution.rule_ids),
            "rules_evaluated": execution.rules_evaluated,
            "matches_created": execution.matches_created,
            "matches_deduplicated": execution.matches_deduplicated,
            "signals_created": execution.signals_created,
            "signals_updated": execution.signals_updated,
            "candidate_groups_created": execution.candidate_groups_created,
            "duration_ms": execution.duration_ms,
            "failures": [
                {"rule_id": f.rule_id, "stage": f.stage, "error_message": f.error_message}
                for f in execution.failures
            ],
            "started_at": execution.started_at,
            "completed_at": execution.completed_at,
        }
        existing = (
            self._conn.execute(
                select(detection_executions.c.execution_id).where(
                    detection_executions.c.execution_id == execution.execution_id
                )
            )
            .mappings()
            .first()
        )
        if existing is None:
            self._conn.execute(insert(detection_executions).values(**vals))
        else:
            self._conn.execute(
                update(detection_executions)
                .where(detection_executions.c.execution_id == execution.execution_id)
                .values(**vals)
            )

    def get_execution(self, scope: AccessScope, execution_id: UUID) -> DetectionExecution | None:
        row = (
            self._conn.execute(
                select(detection_executions).where(
                    detection_executions.c.execution_id == execution_id,
                    detection_executions.c.tenant_scope == scope.tenant_id,
                )
            )
            .mappings()
            .first()
        )
        return self._to_execution(row) if row is not None else None

    def list_executions(self, scope: AccessScope, page: PageSpec) -> PageResult[DetectionExecution]:
        offset = parse_offset(page.cursor)
        stmt = (
            select(detection_executions)
            .where(detection_executions.c.tenant_scope == scope.tenant_id)
            .order_by(detection_executions.c.started_at.desc())
            .offset(offset)
            .limit(page.limit + 1)
        )
        rows = self._conn.execute(stmt).mappings().all()
        cursor, has_more = next_offset_cursor(offset, page.limit, len(rows))
        return PageResult(
            items=tuple(self._to_execution(r) for r in rows[: page.limit]),
            next_cursor=cursor,
            truncated=has_more,
        )

    def insert_rule_match_if_absent(self, match: RuleMatch) -> tuple[RuleMatch, bool]:
        existing = (
            self._conn.execute(
                select(detection_rule_matches).where(
                    detection_rule_matches.c.tenant_scope == match.tenant_scope,
                    detection_rule_matches.c.dedup_key == match.dedup_key,
                )
            )
            .mappings()
            .first()
        )
        if existing is not None:
            return (self._to_rule_match(existing), False)

        self._conn.execute(
            insert(detection_rule_matches).values(
                match_id=match.match_id,
                tenant_scope=match.tenant_scope,
                dedup_key=match.dedup_key,
                rule_id=match.rule_id,
                rule_name=match.rule_name,
                rule_version=match.rule_version,
                severity=match.severity.value,
                detection_type=match.detection_type.value,
                primary_event_id=match.primary_event_id,
                matched_event_ids=[str(x) for x in match.matched_event_ids],
                primary_entity_id=match.primary_entity_id,
                related_entity_ids=[str(x) for x in match.related_entity_ids],
                matched_fields=list(match.matched_fields),
                matched_values=dict(match.matched_values),
                evidence_references=[_serialize_evidence(e) for e in match.evidence_references],
                source_ids=list(match.source_ids),
                matched_at=match.matched_at,
                execution_id=match.execution_id,
            )
        )
        return (match, True)

    def get_rule_match(self, scope: AccessScope, match_id: UUID) -> RuleMatch | None:
        row = (
            self._conn.execute(
                select(detection_rule_matches).where(
                    detection_rule_matches.c.match_id == match_id,
                    detection_rule_matches.c.tenant_scope == scope.tenant_id,
                )
            )
            .mappings()
            .first()
        )
        if row is None:
            return None
        m = self._to_rule_match(row)
        return m if _scope_permits_sources(scope, m.source_ids) else None

    def get_rule_matches_by_ids(
        self, scope: AccessScope, match_ids: Sequence[UUID]
    ) -> Sequence[RuleMatch]:
        if not match_ids:
            return ()
        rows = (
            self._conn.execute(
                select(detection_rule_matches)
                .where(
                    detection_rule_matches.c.tenant_scope == scope.tenant_id,
                    detection_rule_matches.c.match_id.in_(list(match_ids)),
                )
                .order_by(detection_rule_matches.c.matched_at.asc())
            )
            .mappings()
            .all()
        )
        items = [self._to_rule_match(r) for r in rows]
        return tuple(m for m in items if _scope_permits_sources(scope, m.source_ids))

    def search_rule_matches(
        self,
        scope: AccessScope,
        time_range: TimeRange,
        rule_id: str | None,
        detection_type: DetectionType | None,
        severity: RuleSeverity | None,
        entity_id: UUID | None,
        page: PageSpec,
    ) -> PageResult[RuleMatch]:
        offset = parse_offset(page.cursor)
        stmt = select(detection_rule_matches).where(
            detection_rule_matches.c.tenant_scope == scope.tenant_id,
            detection_rule_matches.c.matched_at >= time_range.start_time,
            detection_rule_matches.c.matched_at <= time_range.end_time,
        )
        if rule_id is not None:
            stmt = stmt.where(detection_rule_matches.c.rule_id == rule_id)
        if detection_type is not None:
            stmt = stmt.where(detection_rule_matches.c.detection_type == detection_type.value)
        if severity is not None:
            stmt = stmt.where(detection_rule_matches.c.severity == severity.value)
        stmt = stmt.order_by(
            detection_rule_matches.c.matched_at.desc(),
            detection_rule_matches.c.match_id.asc(),
        )

        all_matches = [self._to_rule_match(r) for r in self._conn.execute(stmt).mappings().all()]
        filtered = [m for m in all_matches if _scope_permits_sources(scope, m.source_ids)]
        if entity_id is not None:
            filtered = [
                m
                for m in filtered
                if m.primary_entity_id == entity_id or entity_id in m.related_entity_ids
            ]
        sliced = filtered[offset : offset + page.limit + 1]
        cursor, has_more = next_offset_cursor(offset, page.limit, len(sliced))
        return PageResult(
            items=tuple(sliced[: page.limit]),
            next_cursor=cursor,
            truncated=has_more,
        )

    def get_signal_by_dedup_key(self, tenant_scope: str, dedup_key: str) -> Signal | None:
        row = (
            self._conn.execute(
                select(detection_signals).where(
                    detection_signals.c.tenant_scope == tenant_scope,
                    detection_signals.c.dedup_key == dedup_key,
                )
            )
            .mappings()
            .first()
        )
        return self._to_signal(row) if row is not None else None

    def save_signal(self, signal: Signal) -> None:
        existing = (
            self._conn.execute(
                select(detection_signals.c.signal_id).where(
                    detection_signals.c.signal_id == signal.signal_id
                )
            )
            .mappings()
            .first()
        )
        vals = {
            "signal_id": signal.signal_id,
            "tenant_scope": signal.tenant_scope,
            "dedup_key": signal.dedup_key,
            "signal_type": signal.signal_type,
            "title": signal.title,
            "severity": signal.severity.value,
            "status": signal.status.value,
            "primary_entity_id": signal.primary_entity_id,
            "related_entity_ids": [str(x) for x in signal.related_entity_ids],
            "rule_match_ids": [str(x) for x in signal.rule_match_ids],
            "event_ids": [str(x) for x in signal.event_ids],
            "evidence_refs": [_serialize_evidence(e) for e in signal.evidence_refs],
            "source_ids": list(signal.source_ids),
            "attack_tags": list(signal.attack_tags),
            "first_seen_at": signal.first_seen_at,
            "last_seen_at": signal.last_seen_at,
            "occurrence_count": signal.occurrence_count,
            "created_at": signal.created_at,
            "updated_at": signal.updated_at,
        }
        if existing is None:
            self._conn.execute(insert(detection_signals).values(**vals))
        else:
            self._conn.execute(
                update(detection_signals)
                .where(detection_signals.c.signal_id == signal.signal_id)
                .values(**vals)
            )

        existing_links = {
            r["match_id"]
            for r in self._conn.execute(
                select(detection_signal_matches.c.match_id).where(
                    detection_signal_matches.c.signal_id == signal.signal_id
                )
            )
            .mappings()
            .all()
        }
        for mid in signal.rule_match_ids:
            if mid not in existing_links:
                self._conn.execute(
                    insert(detection_signal_matches).values(
                        signal_id=signal.signal_id, match_id=mid
                    )
                )

    def update_signal_status(
        self,
        scope: AccessScope,
        signal_id: UUID,
        status: SignalStatus,
        updated_at: datetime,
    ) -> Signal | None:
        sig = self.get_signal(scope, signal_id)
        if sig is None:
            return None
        self._conn.execute(
            update(detection_signals)
            .where(
                detection_signals.c.tenant_scope == scope.tenant_id,
                detection_signals.c.signal_id == signal_id,
            )
            .values(status=status.value, updated_at=updated_at)
        )
        return self.get_signal(scope, signal_id)

    def get_signal(self, scope: AccessScope, signal_id: UUID) -> Signal | None:
        row = (
            self._conn.execute(
                select(detection_signals).where(
                    detection_signals.c.signal_id == signal_id,
                    detection_signals.c.tenant_scope == scope.tenant_id,
                )
            )
            .mappings()
            .first()
        )
        if row is None:
            return None
        sig = self._to_signal(row)
        return sig if _scope_permits_sources(scope, sig.source_ids) else None

    def list_signals_in_window(self, scope: AccessScope, time_range: TimeRange) -> Sequence[Signal]:
        stmt = (
            select(detection_signals)
            .where(
                detection_signals.c.tenant_scope == scope.tenant_id,
                detection_signals.c.last_seen_at >= time_range.start_time,
                detection_signals.c.first_seen_at <= time_range.end_time,
            )
            .order_by(detection_signals.c.first_seen_at.asc())
        )
        sigs = [self._to_signal(r) for r in self._conn.execute(stmt).mappings().all()]
        return tuple(s for s in sigs if _scope_permits_sources(scope, s.source_ids))

    def search_signals(
        self,
        scope: AccessScope,
        time_range: TimeRange,
        status: SignalStatus | None,
        severity: RuleSeverity | None,
        entity_id: UUID | None,
        signal_type: str | None,
        page: PageSpec,
    ) -> PageResult[Signal]:
        offset = parse_offset(page.cursor)
        stmt = select(detection_signals).where(
            detection_signals.c.tenant_scope == scope.tenant_id,
            detection_signals.c.last_seen_at >= time_range.start_time,
            detection_signals.c.first_seen_at <= time_range.end_time,
        )
        if status is not None:
            stmt = stmt.where(detection_signals.c.status == status.value)
        if severity is not None:
            stmt = stmt.where(detection_signals.c.severity == severity.value)
        if signal_type is not None:
            stmt = stmt.where(detection_signals.c.signal_type == signal_type)
        stmt = stmt.order_by(
            detection_signals.c.last_seen_at.desc(),
            detection_signals.c.signal_id.asc(),
        )
        sigs = [self._to_signal(r) for r in self._conn.execute(stmt).mappings().all()]
        filtered = [s for s in sigs if _scope_permits_sources(scope, s.source_ids)]
        if entity_id is not None:
            filtered = [
                s
                for s in filtered
                if s.primary_entity_id == entity_id or entity_id in s.related_entity_ids
            ]
        sliced = filtered[offset : offset + page.limit + 1]
        cursor, has_more = next_offset_cursor(offset, page.limit, len(sliced))
        return PageResult(
            items=tuple(sliced[: page.limit]),
            next_cursor=cursor,
            truncated=has_more,
        )

    def get_signal_evidence(
        self, scope: AccessScope, signal_id: UUID
    ) -> Sequence[SignalEvidenceDetail]:
        sig = self.get_signal(scope, signal_id)
        if sig is None:
            return ()

        ev_to_rel: dict[UUID, UUID] = {}
        for ref in sig.evidence_refs:
            if ref.event_id is not None and ref.relation_id is not None:
                ev_to_rel[ref.event_id] = ref.relation_id

        target_event_ids = list(sig.event_ids)
        if not target_event_ids:
            return ()

        rel_lookup: dict[UUID, tuple[RelationType, Certainty]] = {}
        if ev_to_rel:
            rrows = (
                self._conn.execute(
                    select(
                        relations.c.relation_id,
                        relations.c.relation_type,
                        relations.c.certainty,
                    ).where(
                        relations.c.tenant_scope == scope.tenant_id,
                        relations.c.relation_id.in_(list(set(ev_to_rel.values()))),
                    )
                )
                .mappings()
                .all()
            )
            for rr in rrows:
                rel_lookup[rr["relation_id"]] = (
                    RelationType(rr["relation_type"]),
                    Certainty(rr["certainty"]),
                )

        stmt = (
            select(
                normalized_events.c.event_id,
                normalized_events.c.raw_event_id,
                normalized_events.c.source_id,
                normalized_events.c.class_uid,
                normalized_events.c.event_time,
                normalized_events.c.original_event_uid,
                normalized_events.c.ocsf_payload,
                raw_events.c.raw_payload,
            )
            .select_from(
                normalized_events.join(
                    raw_events, normalized_events.c.raw_event_id == raw_events.c.raw_event_id
                )
            )
            .where(
                normalized_events.c.tenant_scope == scope.tenant_id,
                normalized_events.c.event_id.in_(target_event_ids),
            )
            .order_by(normalized_events.c.event_time.asc())
        )
        if scope.allowed_sources is not None:
            stmt = stmt.where(normalized_events.c.source_id.in_(sorted(scope.allowed_sources)))

        rows = self._conn.execute(stmt).mappings().all()
        details: list[SignalEvidenceDetail] = []
        for r in rows:
            ev_id: UUID = r["event_id"]
            rid = ev_to_rel.get(ev_id)
            rtype_cert = rel_lookup.get(rid) if rid else None
            details.append(
                SignalEvidenceDetail(
                    event_id=ev_id,
                    raw_event_id=r["raw_event_id"],
                    source_id=str(r["source_id"]),
                    ocsf_class_uid=int(r["class_uid"]),
                    event_time=require_utc(r["event_time"]),
                    original_event_uid=r["original_event_uid"],
                    ocsf_payload=dict(r["ocsf_payload"] or {}),
                    raw_payload=str(r["raw_payload"]),
                    relation_id=rid,
                    relation_type=rtype_cert[0] if rtype_cert else None,
                    certainty=rtype_cert[1] if rtype_cert else None,
                )
            )
        return tuple(details)

    def upsert_candidate_group(self, group: CandidateGroup) -> bool:
        existing = (
            self._conn.execute(
                select(detection_candidate_groups).where(
                    detection_candidate_groups.c.tenant_scope == group.tenant_scope,
                    detection_candidate_groups.c.group_key == group.group_key,
                )
            )
            .mappings()
            .first()
        )
        vals = {
            "tenant_scope": group.tenant_scope,
            "group_key": group.group_key,
            "signal_ids": [str(x) for x in group.signal_ids],
            "rule_match_ids": [str(x) for x in group.rule_match_ids],
            "shared_entity_ids": [str(x) for x in group.shared_entity_ids],
            "grouping_rule_id": group.grouping_rule_id,
            "grouping_basis": dict(group.grouping_basis),
            "certainty": group.certainty.value,
            "unresolved_ambiguities": list(group.unresolved_ambiguities),
            "source_ids": list(group.source_ids),
            "first_seen_at": group.first_seen_at,
            "last_seen_at": group.last_seen_at,
            "updated_at": group.updated_at,
        }
        if existing is None:
            self._conn.execute(
                insert(detection_candidate_groups).values(
                    group_id=group.group_id,
                    created_at=group.created_at,
                    **vals,
                )
            )
            return True

        self._conn.execute(
            update(detection_candidate_groups)
            .where(detection_candidate_groups.c.group_id == existing["group_id"])
            .values(**vals)
        )
        return False

    def get_candidate_group(self, scope: AccessScope, group_id: UUID) -> CandidateGroup | None:
        row = (
            self._conn.execute(
                select(detection_candidate_groups).where(
                    detection_candidate_groups.c.group_id == group_id,
                    detection_candidate_groups.c.tenant_scope == scope.tenant_id,
                )
            )
            .mappings()
            .first()
        )
        if row is None:
            return None
        grp = self._to_candidate_group(row)
        return grp if _scope_permits_sources(scope, grp.source_ids) else None

    def search_candidate_groups(
        self,
        scope: AccessScope,
        time_range: TimeRange,
        entity_id: UUID | None,
        certainty: Certainty | None,
        page: PageSpec,
    ) -> PageResult[CandidateGroup]:
        offset = parse_offset(page.cursor)
        stmt = select(detection_candidate_groups).where(
            detection_candidate_groups.c.tenant_scope == scope.tenant_id,
            detection_candidate_groups.c.last_seen_at >= time_range.start_time,
            detection_candidate_groups.c.first_seen_at <= time_range.end_time,
        )
        if certainty is not None:
            stmt = stmt.where(detection_candidate_groups.c.certainty == certainty.value)
        stmt = stmt.order_by(
            detection_candidate_groups.c.last_seen_at.desc(),
            detection_candidate_groups.c.group_id.asc(),
        )
        groups = [self._to_candidate_group(r) for r in self._conn.execute(stmt).mappings().all()]
        filtered = [g for g in groups if _scope_permits_sources(scope, g.source_ids)]
        if entity_id is not None:
            filtered = [g for g in filtered if entity_id in g.shared_entity_ids]
        sliced = filtered[offset : offset + page.limit + 1]
        cursor, has_more = next_offset_cursor(offset, page.limit, len(sliced))
        return PageResult(
            items=tuple(sliced[: page.limit]),
            next_cursor=cursor,
            truncated=has_more,
        )

    def purge_tenant_detection_results(self, tenant_scope: str) -> None:
        sig_ids = select(detection_signals.c.signal_id).where(
            detection_signals.c.tenant_scope == tenant_scope
        )
        self._conn.execute(
            delete(detection_signal_matches).where(
                detection_signal_matches.c.signal_id.in_(sig_ids)
            )
        )
        self._conn.execute(
            delete(detection_candidate_groups).where(
                detection_candidate_groups.c.tenant_scope == tenant_scope
            )
        )
        self._conn.execute(
            delete(detection_signals).where(detection_signals.c.tenant_scope == tenant_scope)
        )
        self._conn.execute(
            delete(detection_rule_matches).where(
                detection_rule_matches.c.tenant_scope == tenant_scope
            )
        )
        self._conn.execute(
            delete(detection_executions).where(detection_executions.c.tenant_scope == tenant_scope)
        )

    @staticmethod
    def _to_rule(row: Any) -> DetectionRule:
        ls = dict(row["logsource"] or {})
        return DetectionRule(
            rule_id=str(row["rule_id"]),
            rule_name=str(row["rule_name"]),
            source=RuleSource(row["source"]),
            source_reference=str(row["source_reference"]),
            version=str(row["version"]),
            description=str(row["description"]),
            severity=RuleSeverity(row["severity"]),
            attack_tags=tuple(str(x) for x in (row["attack_tags"] or [])),
            logsource=LogsourceSpec(
                category=ls.get("category"),
                product=ls.get("product"),
                service=ls.get("service"),
            ),
            detection_type=DetectionType(row["detection_type"]),
            raw_content=str(row["raw_content"]),
            status=RuleStatus(row["status"]),
            compatibility=_deserialize_compat(dict(row["compatibility"] or {})),
            created_at=require_utc(row["created_at"]),
            updated_at=require_utc(row["updated_at"]),
        )

    @staticmethod
    def _to_execution(row: Any) -> DetectionExecution:
        return DetectionExecution(
            execution_id=row["execution_id"],
            tenant_scope=str(row["tenant_scope"]),
            mode=ExecutionMode(row["mode"]),
            status=ExecutionStatus(row["status"]),
            time_range=TimeRange(
                start_time=require_utc(row["start_time"]),
                end_time=require_utc(row["end_time"]),
            ),
            rule_ids=tuple(str(x) for x in (row["rule_ids"] or [])),
            rules_evaluated=int(row["rules_evaluated"]),
            matches_created=int(row["matches_created"]),
            matches_deduplicated=int(row["matches_deduplicated"]),
            signals_created=int(row["signals_created"]),
            signals_updated=int(row["signals_updated"]),
            candidate_groups_created=int(row["candidate_groups_created"]),
            duration_ms=float(row["duration_ms"]),
            failures=tuple(
                RuleExecutionFailure(
                    rule_id=str(f["rule_id"]),
                    stage=str(f["stage"]),
                    error_message=str(f["error_message"]),
                )
                for f in (row["failures"] or [])
            ),
            started_at=require_utc(row["started_at"]),
            completed_at=ensure_utc(row["completed_at"]),
        )

    @staticmethod
    def _to_rule_match(row: Any) -> RuleMatch:
        return RuleMatch(
            match_id=row["match_id"],
            tenant_scope=str(row["tenant_scope"]),
            dedup_key=str(row["dedup_key"]),
            rule_id=str(row["rule_id"]),
            rule_name=str(row["rule_name"]),
            rule_version=str(row["rule_version"]),
            severity=RuleSeverity(row["severity"]),
            detection_type=DetectionType(row["detection_type"]),
            primary_event_id=row["primary_event_id"],
            matched_event_ids=tuple(UUID(str(x)) for x in (row["matched_event_ids"] or [])),
            primary_entity_id=row["primary_entity_id"],
            related_entity_ids=tuple(UUID(str(x)) for x in (row["related_entity_ids"] or [])),
            matched_fields=tuple(str(x) for x in (row["matched_fields"] or [])),
            matched_values=dict(row["matched_values"] or {}),
            evidence_references=tuple(
                _deserialize_evidence(e) for e in (row["evidence_references"] or [])
            ),
            source_ids=tuple(str(x) for x in (row["source_ids"] or [])),
            matched_at=require_utc(row["matched_at"]),
            execution_id=row["execution_id"],
        )

    @staticmethod
    def _to_signal(row: Any) -> Signal:
        return Signal(
            signal_id=row["signal_id"],
            tenant_scope=str(row["tenant_scope"]),
            dedup_key=str(row["dedup_key"]),
            signal_type=str(row["signal_type"]),
            title=str(row["title"]),
            severity=RuleSeverity(row["severity"]),
            status=SignalStatus(row["status"]),
            primary_entity_id=row["primary_entity_id"],
            related_entity_ids=tuple(UUID(str(x)) for x in (row["related_entity_ids"] or [])),
            rule_match_ids=tuple(UUID(str(x)) for x in (row["rule_match_ids"] or [])),
            event_ids=tuple(UUID(str(x)) for x in (row["event_ids"] or [])),
            evidence_refs=tuple(_deserialize_evidence(e) for e in (row["evidence_refs"] or [])),
            source_ids=tuple(str(x) for x in (row["source_ids"] or [])),
            attack_tags=tuple(str(x) for x in (row["attack_tags"] or [])),
            first_seen_at=require_utc(row["first_seen_at"]),
            last_seen_at=require_utc(row["last_seen_at"]),
            occurrence_count=int(row["occurrence_count"]),
            created_at=require_utc(row["created_at"]),
            updated_at=require_utc(row["updated_at"]),
        )

    @staticmethod
    def _to_candidate_group(row: Any) -> CandidateGroup:
        return CandidateGroup(
            group_id=row["group_id"],
            tenant_scope=str(row["tenant_scope"]),
            group_key=str(row["group_key"]),
            signal_ids=tuple(UUID(str(x)) for x in (row["signal_ids"] or [])),
            rule_match_ids=tuple(UUID(str(x)) for x in (row["rule_match_ids"] or [])),
            shared_entity_ids=tuple(UUID(str(x)) for x in (row["shared_entity_ids"] or [])),
            grouping_rule_id=str(row["grouping_rule_id"]),
            grouping_basis=dict(row["grouping_basis"] or {}),
            certainty=Certainty(row["certainty"]),
            unresolved_ambiguities=tuple(str(x) for x in (row["unresolved_ambiguities"] or [])),
            source_ids=tuple(str(x) for x in (row["source_ids"] or [])),
            first_seen_at=require_utc(row["first_seen_at"]),
            last_seen_at=require_utc(row["last_seen_at"]),
            created_at=require_utc(row["created_at"]),
            updated_at=require_utc(row["updated_at"]),
        )
