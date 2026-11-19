from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timedelta
from typing import Any
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from sqlalchemy import Connection, delete, insert, literal, or_, select, update
from sqlalchemy.exc import IntegrityError

from provloom.domain.common import AccessScope, PageResult, PageSpec, TimeRange
from provloom.domain.entity_models import Entity
from provloom.domain.enums import Certainty, Direction, EntityType, RelationType, ResolutionState
from provloom.domain.graph_models import (
    CandidateRelation,
    GraphBuildResult,
    GraphTraversalSpec,
    Relation,
    RelationEvidence,
    RelationEvidenceDetail,
    SubgraphResult,
)
from provloom.storage.interfaces import GraphRepository
from provloom.storage.postgres.tables import (
    entities,
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


class SqlGraphRepository(GraphRepository):
    def __init__(self, conn: Connection) -> None:
        self._conn = conn

    def upsert_relations(self, candidates: Sequence[CandidateRelation]) -> GraphBuildResult:
        created = 0
        updated = 0
        attached = 0
        for cand in candidates:
            existing = (
                self._conn.execute(
                    select(relations).where(
                        relations.c.tenant_scope == cand.tenant_scope,
                        relations.c.src_entity_id == cand.src_entity_id,
                        relations.c.relation_type == cand.relation_type.value,
                        relations.c.dst_entity_id == cand.dst_entity_id,
                        relations.c.certainty == cand.certainty.value,
                        relations.c.context_key == cand.context_key,
                    )
                )
                .mappings()
                .first()
            )
            if existing is None:
                rel_id = uuid5(
                    NAMESPACE_URL,
                    f"provloom:rel:{cand.tenant_scope}:{cand.src_entity_id}:"
                    f"{cand.relation_type.value}:{cand.dst_entity_id}:"
                    f"{cand.certainty.value}:{cand.context_key}",
                )
                self._conn.execute(
                    insert(relations).values(
                        relation_id=rel_id,
                        tenant_scope=cand.tenant_scope,
                        src_entity_id=cand.src_entity_id,
                        relation_type=cand.relation_type.value,
                        dst_entity_id=cand.dst_entity_id,
                        certainty=cand.certainty.value,
                        context_key=cand.context_key,
                        correlation_rule_id=cand.correlation_rule_id,
                        correlation_basis=cand.correlation_basis,
                        first_seen_at=cand.observed_at,
                        last_seen_at=cand.observed_at,
                        evidence_count=0,
                    )
                )
                created += 1
                current_ev_count = 0
                first_seen = cand.observed_at
                last_seen = cand.observed_at
                merged_basis = dict(cand.correlation_basis)
            else:
                rel_id = existing["relation_id"]
                updated += 1
                current_ev_count = int(existing["evidence_count"])
                first_seen = min(require_utc(existing["first_seen_at"]), cand.observed_at)
                last_seen = max(require_utc(existing["last_seen_at"]), cand.observed_at)
                merged_basis = {
                    **dict(existing["correlation_basis"] or {}),
                    **cand.correlation_basis,
                }

            inserted_ev = self._insert_evidence_if_absent(
                relation_id=rel_id,
                event_id=cand.event_id,
                raw_event_id=cand.raw_event_id,
                evidence_role=cand.evidence_role,
                observed_at=cand.observed_at,
                match_detail=cand.correlation_basis,
            )
            if inserted_ev:
                current_ev_count += 1
                attached += 1

            self._conn.execute(
                update(relations)
                .where(relations.c.relation_id == rel_id)
                .values(
                    first_seen_at=first_seen,
                    last_seen_at=last_seen,
                    evidence_count=current_ev_count,
                    correlation_basis=merged_basis,
                )
            )
        return GraphBuildResult(
            created_relations=created,
            updated_relations=updated,
            attached_evidences=attached,
        )

    def _insert_evidence_if_absent(
        self,
        relation_id: UUID,
        event_id: UUID,
        raw_event_id: UUID,
        evidence_role: str,
        observed_at: datetime,
        match_detail: dict[str, Any],
    ) -> bool:
        try:
            with self._conn.begin_nested():
                self._conn.execute(
                    insert(relation_evidences).values(
                        evidence_id=uuid4(),
                        relation_id=relation_id,
                        event_id=event_id,
                        raw_event_id=raw_event_id,
                        evidence_role=evidence_role,
                        observed_at=observed_at,
                        match_detail=match_detail,
                    )
                )
            return True
        except IntegrityError:
            return False

    def find_network_relations_in_window(
        self,
        tenant_scope: str,
        dst_entity_id: UUID,
        around_time: datetime,
        skew_seconds: float,
    ) -> Sequence[Relation]:
        delta = timedelta(seconds=skew_seconds)
        stmt = select(relations).where(
            relations.c.tenant_scope == tenant_scope,
            relations.c.relation_type == RelationType.CONNECTS_TO.value,
            relations.c.dst_entity_id == dst_entity_id,
            relations.c.first_seen_at <= around_time + delta,
            relations.c.last_seen_at >= around_time - delta,
        )
        return [self._to_relation(r) for r in self._conn.execute(stmt).mappings().all()]

    def promote_sensor_relation_to_process(
        self,
        sensor_relation_id: UUID,
        process_relation: CandidateRelation,
    ) -> None:
        self.upsert_relations([process_relation])
        target = (
            self._conn.execute(
                select(relations).where(
                    relations.c.tenant_scope == process_relation.tenant_scope,
                    relations.c.src_entity_id == process_relation.src_entity_id,
                    relations.c.relation_type == process_relation.relation_type.value,
                    relations.c.dst_entity_id == process_relation.dst_entity_id,
                    relations.c.certainty == process_relation.certainty.value,
                    relations.c.context_key == process_relation.context_key,
                )
            )
            .mappings()
            .first()
        )
        if target is None or target["relation_id"] == sensor_relation_id:
            return
        evs = (
            self._conn.execute(
                select(relation_evidences).where(
                    relation_evidences.c.relation_id == sensor_relation_id
                )
            )
            .mappings()
            .all()
        )
        added = 0
        min_ts = require_utc(target["first_seen_at"])
        max_ts = require_utc(target["last_seen_at"])
        for ev in evs:
            obs = require_utc(ev["observed_at"])
            min_ts = min(min_ts, obs)
            max_ts = max(max_ts, obs)
            if self._insert_evidence_if_absent(
                relation_id=target["relation_id"],
                event_id=ev["event_id"],
                raw_event_id=ev["raw_event_id"],
                evidence_role=ev["evidence_role"],
                observed_at=obs,
                match_detail={
                    **dict(ev["match_detail"] or {}),
                    "correlated_by": "network_5tuple_v1",
                },
            ):
                added += 1
        self._conn.execute(
            delete(relation_evidences).where(relation_evidences.c.relation_id == sensor_relation_id)
        )
        self._conn.execute(delete(relations).where(relations.c.relation_id == sensor_relation_id))
        self._conn.execute(
            update(relations)
            .where(relations.c.relation_id == target["relation_id"])
            .values(
                first_seen_at=min_ts,
                last_seen_at=max_ts,
                evidence_count=int(target["evidence_count"]) + added,
            )
        )

    def get_entity_relations(
        self,
        scope: AccessScope,
        entity_id: UUID,
        time_range: TimeRange,
        direction: Direction,
        relation_types: Sequence[RelationType] | None,
        include_candidates: bool,
        page: PageSpec,
    ) -> PageResult[Relation]:
        offset = parse_offset(page.cursor)
        stmt = select(relations).where(
            relations.c.tenant_scope == scope.tenant_id,
            relations.c.first_seen_at <= time_range.end_time,
            relations.c.last_seen_at >= time_range.start_time,
        )
        if direction == Direction.OUTBOUND:
            stmt = stmt.where(relations.c.src_entity_id == entity_id)
        elif direction == Direction.INBOUND:
            stmt = stmt.where(relations.c.dst_entity_id == entity_id)
        else:
            stmt = stmt.where(
                or_(
                    relations.c.src_entity_id == entity_id,
                    relations.c.dst_entity_id == entity_id,
                )
            )
        if not include_candidates:
            stmt = stmt.where(relations.c.certainty == Certainty.DETERMINISTIC.value)
        if relation_types:
            stmt = stmt.where(relations.c.relation_type.in_([rt.value for rt in relation_types]))
        if scope.allowed_sources is not None:
            allowed_rel_ids = (
                select(relation_evidences.c.relation_id)
                .join(
                    normalized_events,
                    relation_evidences.c.event_id == normalized_events.c.event_id,
                )
                .where(normalized_events.c.source_id.in_(scope.allowed_sources))
            )
            stmt = stmt.where(relations.c.relation_id.in_(allowed_rel_ids))

        stmt = (
            stmt.order_by(relations.c.last_seen_at.desc(), relations.c.relation_id.asc())
            .offset(offset)
            .limit(page.limit + 1)
        )
        rows = self._conn.execute(stmt).mappings().all()
        cursor, has_more = next_offset_cursor(offset, page.limit, len(rows))
        return PageResult(
            items=tuple(self._to_relation(r) for r in rows[: page.limit]),
            next_cursor=cursor,
            truncated=has_more,
        )

    def traverse(
        self,
        scope: AccessScope,
        time_range: TimeRange,
        spec: GraphTraversalSpec,
    ) -> SubgraphResult:
        # Uses SQL WITH RECURSIVE for bounded hop discovery while preventing graph cycles.
        seed_row = (
            self._conn.execute(
                select(entities).where(
                    entities.c.entity_id == spec.seed_entity_id,
                    entities.c.tenant_scope == scope.tenant_id,
                )
            )
            .mappings()
            .first()
        )
        if seed_row is None:
            return SubgraphResult(seed_entity_id=spec.seed_entity_id, nodes=(), edges=())

        edge_filter = [
            relations.c.tenant_scope == scope.tenant_id,
            relations.c.first_seen_at <= time_range.end_time,
            relations.c.last_seen_at >= time_range.start_time,
        ]
        if not spec.include_candidates:
            edge_filter.append(relations.c.certainty == Certainty.DETERMINISTIC.value)
        if spec.relation_types:
            edge_filter.append(
                relations.c.relation_type.in_([rt.value for rt in spec.relation_types])
            )
        if scope.allowed_sources is not None:
            allowed_rel_ids = (
                select(relation_evidences.c.relation_id)
                .join(
                    normalized_events,
                    relation_evidences.c.event_id == normalized_events.c.event_id,
                )
                .where(normalized_events.c.source_id.in_(scope.allowed_sources))
            )
            edge_filter.append(relations.c.relation_id.in_(allowed_rel_ids))

        from sqlalchemy import String, cast

        valid_edges = select(relations).where(*edge_filter).cte("valid_edges")
        seed_str = str(spec.seed_entity_id)
        walk = select(
            literal(spec.seed_entity_id).label("node_id"),
            literal(None).cast(relations.c.relation_id.type).label("rel_id"),
            literal(0).label("depth"),
            literal(f"|{seed_str}|").cast(String).label("path"),
        ).cte(name="graph_walk", recursive=True)

        steps = []
        if spec.direction in (Direction.OUTBOUND, Direction.BOTH):
            dst_token = "|" + cast(valid_edges.c.dst_entity_id, String) + "|"
            steps.append(
                select(
                    valid_edges.c.dst_entity_id.label("node_id"),
                    valid_edges.c.relation_id.label("rel_id"),
                    (walk.c.depth + 1).label("depth"),
                    (walk.c.path + cast(valid_edges.c.dst_entity_id, String) + "|").label("path"),
                )
                .join(walk, valid_edges.c.src_entity_id == walk.c.node_id)
                .where(walk.c.depth < spec.max_depth, ~walk.c.path.contains(dst_token))
            )
        if spec.direction in (Direction.INBOUND, Direction.BOTH):
            src_token = "|" + cast(valid_edges.c.src_entity_id, String) + "|"
            steps.append(
                select(
                    valid_edges.c.src_entity_id.label("node_id"),
                    valid_edges.c.relation_id.label("rel_id"),
                    (walk.c.depth + 1).label("depth"),
                    (walk.c.path + cast(valid_edges.c.src_entity_id, String) + "|").label("path"),
                )
                .join(walk, valid_edges.c.dst_entity_id == walk.c.node_id)
                .where(walk.c.depth < spec.max_depth, ~walk.c.path.contains(src_token))
            )
        walk = walk.union_all(*steps)

        walk_rows = self._conn.execute(select(walk.c.node_id, walk.c.rel_id)).all()
        discovered_nodes: list[UUID] = [spec.seed_entity_id]
        traversed_rels: list[UUID] = []
        for nid, rid in walk_rows:
            uid = nid if isinstance(nid, UUID) else UUID(str(nid))
            if uid not in discovered_nodes:
                discovered_nodes.append(uid)
            if rid is not None:
                ruid = rid if isinstance(rid, UUID) else UUID(str(rid))
                if ruid not in traversed_rels:
                    traversed_rels.append(ruid)

        truncated = False
        if len(discovered_nodes) > spec.max_nodes:
            discovered_nodes = discovered_nodes[: spec.max_nodes]
            truncated = True
        if len(traversed_rels) > spec.max_edges:
            traversed_rels = traversed_rels[: spec.max_edges]
            truncated = True

        node_set = set(discovered_nodes)
        edge_rows = (
            self._conn.execute(
                select(valid_edges)
                .where(
                    valid_edges.c.relation_id.in_(traversed_rels)
                    if traversed_rels
                    else literal(False),
                    valid_edges.c.src_entity_id.in_(node_set),
                    valid_edges.c.dst_entity_id.in_(node_set),
                )
                .order_by(valid_edges.c.last_seen_at.desc())
            )
            .mappings()
            .all()
        )
        ent_rows = (
            self._conn.execute(select(entities).where(entities.c.entity_id.in_(node_set)))
            .mappings()
            .all()
        )
        return SubgraphResult(
            seed_entity_id=spec.seed_entity_id,
            nodes=tuple(self._to_entity(r) for r in ent_rows),
            edges=tuple(self._to_relation(r) for r in edge_rows),
            truncated=truncated,
        )

    def get_relation_evidence(
        self,
        scope: AccessScope,
        relation_id: UUID,
        time_range: TimeRange | None,
        page: PageSpec,
    ) -> PageResult[RelationEvidenceDetail]:
        rel_row = self._conn.execute(
            select(relations.c.relation_id).where(
                relations.c.relation_id == relation_id,
                relations.c.tenant_scope == scope.tenant_id,
            )
        ).first()
        if rel_row is None:
            return PageResult(items=())

        offset = parse_offset(page.cursor)
        stmt = (
            select(
                relation_evidences,
                normalized_events.c.source_id,
                normalized_events.c.class_uid,
                raw_events.c.raw_payload,
            )
            .join(normalized_events, relation_evidences.c.event_id == normalized_events.c.event_id)
            .join(raw_events, relation_evidences.c.raw_event_id == raw_events.c.raw_event_id)
            .where(relation_evidences.c.relation_id == relation_id)
        )
        if scope.allowed_sources is not None:
            stmt = stmt.where(normalized_events.c.source_id.in_(scope.allowed_sources))
        if time_range is not None:
            stmt = stmt.where(
                relation_evidences.c.observed_at >= time_range.start_time,
                relation_evidences.c.observed_at <= time_range.end_time,
            )
        stmt = (
            stmt.order_by(relation_evidences.c.observed_at.asc())
            .offset(offset)
            .limit(page.limit + 1)
        )
        rows = self._conn.execute(stmt).mappings().all()
        cursor, has_more = next_offset_cursor(offset, page.limit, len(rows))
        items = tuple(
            RelationEvidenceDetail(
                evidence=RelationEvidence(
                    evidence_id=r["evidence_id"],
                    relation_id=r["relation_id"],
                    event_id=r["event_id"],
                    raw_event_id=r["raw_event_id"],
                    evidence_role=r["evidence_role"],
                    observed_at=require_utc(r["observed_at"]),
                    match_detail=dict(r["match_detail"] or {}),
                ),
                source_id=r["source_id"],
                ocsf_class_uid=int(r["class_uid"]),
                raw_payload=r["raw_payload"],
            )
            for r in rows[: page.limit]
        )
        return PageResult(items=items, next_cursor=cursor, truncated=has_more)

    @staticmethod
    def _to_relation(row: Any) -> Relation:
        return Relation(
            relation_id=row["relation_id"],
            tenant_scope=row["tenant_scope"],
            src_entity_id=row["src_entity_id"],
            relation_type=RelationType(row["relation_type"]),
            dst_entity_id=row["dst_entity_id"],
            certainty=Certainty(row["certainty"]),
            context_key=row["context_key"],
            correlation_rule_id=row["correlation_rule_id"],
            correlation_basis=dict(row["correlation_basis"] or {}),
            first_seen_at=require_utc(row["first_seen_at"]),
            last_seen_at=require_utc(row["last_seen_at"]),
            evidence_count=int(row["evidence_count"]),
        )

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
