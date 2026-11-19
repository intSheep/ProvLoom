from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import Connection, and_, delete, insert, or_, select, update

from provloom.domain.common import AccessScope, PageResult, PageSpec, TimeRange
from provloom.domain.entity_models import (
    Entity,
    EntityDetail,
    EntityIdentifier,
    EntityMergeAudit,
)
from provloom.domain.enums import EntityType, ResolutionState
from provloom.storage.interfaces import EntityRepository
from provloom.storage.postgres.tables import (
    entities,
    entity_identifiers,
    entity_merges,
    normalized_events,
    relation_evidences,
    relations,
)
from provloom.storage.postgres.utils import (
    ensure_utc,
    next_offset_cursor,
    parse_offset,
    require_utc,
)


class SqlEntityRepository(EntityRepository):
    def __init__(self, conn: Connection) -> None:
        self._conn = conn

    def find_by_identifier(
        self,
        tenant_scope: str,
        entity_type: EntityType,
        id_namespace: str,
        id_value: str,
        scope_entity_id: UUID | None = None,
        at_time: datetime | None = None,
    ) -> Entity | None:
        stmt = (
            select(entity_identifiers, entities)
            .join(entities, entity_identifiers.c.entity_id == entities.c.entity_id)
            .where(
                entity_identifiers.c.tenant_scope == tenant_scope,
                entity_identifiers.c.id_namespace == id_namespace,
                entity_identifiers.c.id_value == id_value,
                entity_identifiers.c.is_authoritative.is_(True),
                entities.c.entity_type == entity_type.value,
            )
        )
        if scope_entity_id is not None:
            stmt = stmt.where(entity_identifiers.c.scope_entity_id == scope_entity_id)
        else:
            stmt = stmt.where(entity_identifiers.c.scope_entity_id.is_(None))

        rows = self._conn.execute(stmt).mappings().all()
        check_ts = ensure_utc(at_time)
        for row in rows:
            vf = ensure_utc(row["valid_from"])
            vt = ensure_utc(row["valid_to"])
            if check_ts is not None:
                if vf is not None and check_ts < vf:
                    continue
                if vt is not None and check_ts >= vt:
                    continue
            ent = self._to_entity(row)
            return self._follow_merged(ent)
        return None

    def find_host_by_ip(self, tenant_scope: str, ip: str, at_time: datetime) -> Entity | None:
        return self.find_by_identifier(
            tenant_scope=tenant_scope,
            entity_type=EntityType.HOST,
            id_namespace="host_ip_lease",
            id_value=ip,
            scope_entity_id=None,
            at_time=at_time,
        )

    def save_entity(self, entity: Entity) -> None:
        existing = self._conn.execute(
            select(entities.c.entity_id).where(entities.c.entity_id == entity.entity_id)
        ).first()
        values = {
            "tenant_scope": entity.tenant_scope,
            "entity_type": entity.entity_type.value,
            "resolution_state": entity.resolution_state.value,
            "display_label": entity.display_label,
            "canonical_key": entity.canonical_key,
            "valid_from": entity.valid_from,
            "valid_to": entity.valid_to,
            "attributes": entity.attributes,
            "merged_into_id": entity.merged_into_id,
        }
        if existing is None:
            self._conn.execute(insert(entities).values(entity_id=entity.entity_id, **values))
        else:
            self._conn.execute(
                update(entities).where(entities.c.entity_id == entity.entity_id).values(**values)
            )

    def add_identifier(self, identifier: EntityIdentifier) -> None:
        conds = [
            entity_identifiers.c.entity_id == identifier.entity_id,
            entity_identifiers.c.id_namespace == identifier.id_namespace,
            entity_identifiers.c.id_value == identifier.id_value,
        ]
        if identifier.scope_entity_id is not None:
            conds.append(entity_identifiers.c.scope_entity_id == identifier.scope_entity_id)
        else:
            conds.append(entity_identifiers.c.scope_entity_id.is_(None))
        existing = (
            self._conn.execute(select(entity_identifiers).where(and_(*conds))).mappings().first()
        )
        if existing is not None:
            vt = ensure_utc(existing["valid_to"])
            check_vf = ensure_utc(identifier.valid_from)
            if vt is None or (check_vf is not None and check_vf < vt):
                new_vf = ensure_utc(existing["valid_from"])
                if identifier.valid_from is not None and (
                    new_vf is None or ensure_utc(identifier.valid_from) < new_vf  # type: ignore[operator]
                ):
                    new_vf = ensure_utc(identifier.valid_from)
                self._conn.execute(
                    update(entity_identifiers)
                    .where(entity_identifiers.c.identifier_id == existing["identifier_id"])
                    .values(
                        is_authoritative=bool(existing["is_authoritative"])
                        or identifier.is_authoritative,
                        valid_from=new_vf,
                        valid_to=identifier.valid_to or existing["valid_to"],
                    )
                )
                return

        self._conn.execute(
            insert(entity_identifiers).values(
                identifier_id=identifier.identifier_id,
                entity_id=identifier.entity_id,
                scope_entity_id=identifier.scope_entity_id,
                tenant_scope=identifier.tenant_scope,
                id_namespace=identifier.id_namespace,
                id_value=identifier.id_value,
                is_authoritative=identifier.is_authoritative,
                valid_from=identifier.valid_from,
                valid_to=identifier.valid_to,
                first_seen_event_id=identifier.first_seen_event_id,
            )
        )

    def close_active_identifiers(
        self,
        tenant_scope: str,
        id_namespace: str,
        id_value: str,
        scope_entity_id: UUID | None,
        valid_to: datetime,
    ) -> None:
        conds = [
            entity_identifiers.c.tenant_scope == tenant_scope,
            entity_identifiers.c.id_namespace == id_namespace,
            entity_identifiers.c.id_value == id_value,
            entity_identifiers.c.valid_to.is_(None),
        ]
        if scope_entity_id is not None:
            conds.append(entity_identifiers.c.scope_entity_id == scope_entity_id)
        else:
            conds.append(entity_identifiers.c.scope_entity_id.is_(None))

        active_rows = (
            self._conn.execute(select(entity_identifiers).where(and_(*conds))).mappings().all()
        )
        for row in active_rows:
            self._conn.execute(
                update(entity_identifiers)
                .where(entity_identifiers.c.identifier_id == row["identifier_id"])
                .values(valid_to=valid_to)
            )
            self._conn.execute(
                update(entities)
                .where(
                    entities.c.entity_id == row["entity_id"],
                    entities.c.valid_to.is_(None),
                )
                .values(valid_to=valid_to)
            )

    def merge_entities(self, merge: EntityMergeAudit) -> None:
        if merge.source_entity_id == merge.target_entity_id:
            return
        self._conn.execute(
            insert(entity_merges).values(
                merge_id=merge.merge_id,
                tenant_scope=merge.tenant_scope,
                source_entity_id=merge.source_entity_id,
                target_entity_id=merge.target_entity_id,
                merge_rule_id=merge.merge_rule_id,
                match_basis=merge.match_basis,
                evidence_event_ids=[str(eid) for eid in merge.evidence_event_ids],
                merged_at=merge.merged_at,
            )
        )
        self._conn.execute(
            update(entities)
            .where(entities.c.entity_id == merge.source_entity_id)
            .values(merged_into_id=merge.target_entity_id)
        )
        self._conn.execute(
            update(entity_identifiers)
            .where(entity_identifiers.c.entity_id == merge.source_entity_id)
            .values(entity_id=merge.target_entity_id)
        )
        self._conn.execute(
            update(entity_identifiers)
            .where(entity_identifiers.c.scope_entity_id == merge.source_entity_id)
            .values(scope_entity_id=merge.target_entity_id)
        )
        self._repoint_relations(merge.source_entity_id, merge.target_entity_id)

    def _repoint_relations(self, src_id: UUID, dst_id: UUID) -> None:
        affected = (
            self._conn.execute(
                select(relations).where(
                    or_(relations.c.src_entity_id == src_id, relations.c.dst_entity_id == src_id)
                )
            )
            .mappings()
            .all()
        )
        for rel in affected:
            new_src = dst_id if rel["src_entity_id"] == src_id else rel["src_entity_id"]
            new_dst = dst_id if rel["dst_entity_id"] == src_id else rel["dst_entity_id"]
            conflict = (
                self._conn.execute(
                    select(relations).where(
                        relations.c.tenant_scope == rel["tenant_scope"],
                        relations.c.src_entity_id == new_src,
                        relations.c.relation_type == rel["relation_type"],
                        relations.c.dst_entity_id == new_dst,
                        relations.c.certainty == rel["certainty"],
                        relations.c.context_key == rel["context_key"],
                        relations.c.relation_id != rel["relation_id"],
                    )
                )
                .mappings()
                .first()
            )
            if conflict is None:
                self._conn.execute(
                    update(relations)
                    .where(relations.c.relation_id == rel["relation_id"])
                    .values(src_entity_id=new_src, dst_entity_id=new_dst)
                )
            else:
                evs = (
                    self._conn.execute(
                        select(relation_evidences).where(
                            relation_evidences.c.relation_id == rel["relation_id"]
                        )
                    )
                    .mappings()
                    .all()
                )
                added = 0
                for ev in evs:
                    exists = self._conn.execute(
                        select(relation_evidences.c.evidence_id).where(
                            relation_evidences.c.relation_id == conflict["relation_id"],
                            relation_evidences.c.event_id == ev["event_id"],
                        )
                    ).first()
                    if exists is None:
                        self._conn.execute(
                            insert(relation_evidences).values(
                                evidence_id=uuid4(),
                                relation_id=conflict["relation_id"],
                                event_id=ev["event_id"],
                                raw_event_id=ev["raw_event_id"],
                                evidence_role=ev["evidence_role"],
                                observed_at=ev["observed_at"],
                                match_detail=ev["match_detail"],
                            )
                        )
                        added += 1
                self._conn.execute(
                    delete(relation_evidences).where(
                        relation_evidences.c.relation_id == rel["relation_id"]
                    )
                )
                self._conn.execute(
                    delete(relations).where(relations.c.relation_id == rel["relation_id"])
                )
                self._conn.execute(
                    update(relations)
                    .where(relations.c.relation_id == conflict["relation_id"])
                    .values(
                        first_seen_at=min(
                            require_utc(conflict["first_seen_at"]),
                            require_utc(rel["first_seen_at"]),
                        ),
                        last_seen_at=max(
                            require_utc(conflict["last_seen_at"]),
                            require_utc(rel["last_seen_at"]),
                        ),
                        evidence_count=int(conflict["evidence_count"]) + added,
                    )
                )

    def get_detail(
        self,
        scope: AccessScope,
        entity_id: UUID,
        time_range: TimeRange | None = None,
        follow_merged: bool = True,
    ) -> EntityDetail | None:
        row = (
            self._conn.execute(
                select(entities).where(
                    entities.c.entity_id == entity_id,
                    entities.c.tenant_scope == scope.tenant_id,
                )
            )
            .mappings()
            .first()
        )
        if row is None:
            return None
        ent = self._to_entity(row)
        if follow_merged and ent.merged_into_id is not None:
            ent = self._follow_merged(ent)
        if (
            time_range is not None
            and ent.valid_from is not None
            and ent.valid_to is not None
            and (ent.valid_to < time_range.start_time or ent.valid_from > time_range.end_time)
        ):
            return None
        if scope.allowed_sources is not None and not self._visible_in_sources(
            ent.entity_id, scope.allowed_sources
        ):
            return None

        id_rows = (
            self._conn.execute(
                select(entity_identifiers).where(entity_identifiers.c.entity_id == ent.entity_id)
            )
            .mappings()
            .all()
        )
        merge_rows = (
            self._conn.execute(
                select(entity_merges).where(
                    or_(
                        entity_merges.c.target_entity_id == ent.entity_id,
                        entity_merges.c.source_entity_id == ent.entity_id,
                    )
                )
            )
            .mappings()
            .all()
        )
        return EntityDetail(
            entity=ent,
            identifiers=tuple(self._to_identifier(r) for r in id_rows),
            merges=tuple(self._to_merge(r) for r in merge_rows),
        )

    def search(
        self,
        scope: AccessScope,
        time_range: TimeRange | None,
        entity_types: Sequence[EntityType] | None,
        resolution_states: Sequence[ResolutionState] | None,
        identifier_query: str | None,
        page: PageSpec,
    ) -> PageResult[Entity]:
        offset = parse_offset(page.cursor)
        stmt = select(entities).where(
            entities.c.tenant_scope == scope.tenant_id,
            entities.c.merged_into_id.is_(None),
        )
        if entity_types:
            stmt = stmt.where(entities.c.entity_type.in_([t.value for t in entity_types]))
        if resolution_states:
            stmt = stmt.where(entities.c.resolution_state.in_([s.value for s in resolution_states]))
        if identifier_query:
            q = f"%{identifier_query}%"
            matching_ids = select(entity_identifiers.c.entity_id).where(
                entity_identifiers.c.tenant_scope == scope.tenant_id,
                entity_identifiers.c.id_value.ilike(q),
            )
            stmt = stmt.where(
                or_(entities.c.display_label.ilike(q), entities.c.entity_id.in_(matching_ids))
            )
        stmt = stmt.order_by(entities.c.entity_type.asc(), entities.c.display_label.asc())
        rows = [self._to_entity(r) for r in self._conn.execute(stmt).mappings().all()]
        if time_range is not None:
            rows = [
                e
                for e in rows
                if not (
                    (e.valid_to is not None and e.valid_to < time_range.start_time)
                    or (e.valid_from is not None and e.valid_from > time_range.end_time)
                )
            ]
        if scope.allowed_sources is not None:
            rows = [e for e in rows if self._visible_in_sources(e.entity_id, scope.allowed_sources)]
        sliced = rows[offset : offset + page.limit + 1]
        cursor, has_more = next_offset_cursor(offset, page.limit, len(sliced))
        return PageResult(items=tuple(sliced[: page.limit]), next_cursor=cursor, truncated=has_more)

    def _visible_in_sources(self, entity_id: UUID, allowed_sources: frozenset[str]) -> bool:
        via_id = self._conn.execute(
            select(entity_identifiers.c.identifier_id)
            .join(
                normalized_events,
                entity_identifiers.c.first_seen_event_id == normalized_events.c.event_id,
            )
            .where(
                entity_identifiers.c.entity_id == entity_id,
                normalized_events.c.source_id.in_(allowed_sources),
            )
            .limit(1)
        ).first()
        if via_id is not None:
            return True
        via_rel = self._conn.execute(
            select(relations.c.relation_id)
            .join(relation_evidences, relations.c.relation_id == relation_evidences.c.relation_id)
            .join(normalized_events, relation_evidences.c.event_id == normalized_events.c.event_id)
            .where(
                or_(relations.c.src_entity_id == entity_id, relations.c.dst_entity_id == entity_id),
                normalized_events.c.source_id.in_(allowed_sources),
            )
            .limit(1)
        ).first()
        return via_rel is not None

    def _follow_merged(self, entity: Entity) -> Entity:
        cur = entity
        seen: set[UUID] = {cur.entity_id}
        while cur.merged_into_id is not None and cur.merged_into_id not in seen:
            seen.add(cur.merged_into_id)
            nxt = (
                self._conn.execute(
                    select(entities).where(entities.c.entity_id == cur.merged_into_id)
                )
                .mappings()
                .first()
            )
            if nxt is None:
                break
            cur = self._to_entity(nxt)
        return cur

    @staticmethod
    def _to_entity(row: Any) -> Entity:
        return Entity(
            entity_id=row["entity_id"],
            tenant_scope=row["tenant_scope"],
            entity_type=EntityType(row["entity_type"]),
            resolution_state=ResolutionState(row["resolution_state"]),
            display_label=row["display_label"],
            canonical_key=row["canonical_key"],
            valid_from=ensure_utc(row["valid_from"]),
            valid_to=ensure_utc(row["valid_to"]),
            attributes=dict(row["attributes"] or {}),
            merged_into_id=row["merged_into_id"],
        )

    @staticmethod
    def _to_identifier(row: Any) -> EntityIdentifier:
        return EntityIdentifier(
            identifier_id=row["identifier_id"],
            entity_id=row["entity_id"],
            scope_entity_id=row["scope_entity_id"],
            tenant_scope=row["tenant_scope"],
            id_namespace=row["id_namespace"],
            id_value=row["id_value"],
            is_authoritative=bool(row["is_authoritative"]),
            valid_from=ensure_utc(row["valid_from"]),
            valid_to=ensure_utc(row["valid_to"]),
            first_seen_event_id=row["first_seen_event_id"],
        )

    @staticmethod
    def _to_merge(row: Any) -> EntityMergeAudit:
        ev_ids = tuple(UUID(str(x)) for x in (row["evidence_event_ids"] or []))
        return EntityMergeAudit(
            merge_id=row["merge_id"],
            tenant_scope=row["tenant_scope"],
            source_entity_id=row["source_entity_id"],
            target_entity_id=row["target_entity_id"],
            merge_rule_id=row["merge_rule_id"],
            match_basis=dict(row["match_basis"] or {}),
            evidence_event_ids=ev_ids,
            merged_at=require_utc(row["merged_at"]),
        )
