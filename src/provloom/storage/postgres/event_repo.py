from __future__ import annotations

from collections.abc import Sequence
from typing import Any
from uuid import UUID

from sqlalchemy import Connection, delete, func, insert, select

from provloom.domain.common import AccessScope, PageResult, PageSpec, TimeRange
from provloom.domain.enums import NormalizationStatus, RawProcessStatus
from provloom.domain.ocsf_models import (
    EventWithRawDetail,
    NormalizedEvent,
    NormalizedEventSummary,
)
from provloom.domain.raw_models import RawEvent
from provloom.storage.interfaces import NormalizedEventRepository
from provloom.storage.postgres.tables import normalized_events, raw_events
from provloom.storage.postgres.utils import (
    extract_nested,
    next_offset_cursor,
    parse_offset,
    require_utc,
)


class SqlNormalizedEventRepository(NormalizedEventRepository):
    def __init__(self, conn: Connection) -> None:
        self._conn = conn

    def upsert(self, event: NormalizedEvent) -> None:
        self._conn.execute(
            delete(normalized_events).where(normalized_events.c.raw_event_id == event.raw_event_id)
        )
        self._conn.execute(
            insert(normalized_events).values(
                event_id=event.event_id,
                raw_event_id=event.raw_event_id,
                tenant_scope=event.tenant_scope,
                source_id=event.source_id,
                ocsf_version=event.ocsf_version,
                category_uid=event.category_uid,
                class_uid=event.class_uid,
                activity_id=event.activity_id,
                event_time=event.event_time,
                normalization_status=event.normalization_status.value,
                mapping_rule_id=event.mapping_rule_id,
                original_event_uid=event.original_event_uid,
                ocsf_payload=event.ocsf_payload,
                unmapped_fields=event.unmapped_fields,
            )
        )

    def get_time_bounds(self, scope: AccessScope) -> TimeRange | None:
        stmt = select(
            func.min(normalized_events.c.event_time).label("min_t"),
            func.max(normalized_events.c.event_time).label("max_t"),
        ).where(normalized_events.c.tenant_scope == scope.tenant_id)
        if scope.allowed_sources is not None:
            stmt = stmt.where(normalized_events.c.source_id.in_(scope.allowed_sources))
        row = self._conn.execute(stmt).mappings().first()
        if not row or row["min_t"] is None or row["max_t"] is None:
            return None
        return TimeRange(start_time=require_utc(row["min_t"]), end_time=require_utc(row["max_t"]))

    def get_with_raw(
        self,
        scope: AccessScope,
        event_id: UUID,
        time_range: TimeRange | None = None,
        include_raw: bool = True,
    ) -> EventWithRawDetail | None:
        stmt = select(normalized_events).where(
            normalized_events.c.event_id == event_id,
            normalized_events.c.tenant_scope == scope.tenant_id,
        )
        if scope.allowed_sources is not None:
            stmt = stmt.where(normalized_events.c.source_id.in_(scope.allowed_sources))
        if time_range is not None:
            stmt = stmt.where(
                normalized_events.c.event_time >= time_range.start_time,
                normalized_events.c.event_time <= time_range.end_time,
            )
        nrow = self._conn.execute(stmt).mappings().first()
        if nrow is None:
            return None
        norm = self._to_event(nrow)
        raw_obj: RawEvent | None = None
        if include_raw:
            rrow = (
                self._conn.execute(
                    select(raw_events).where(raw_events.c.raw_event_id == norm.raw_event_id)
                )
                .mappings()
                .first()
            )
            if rrow is not None:
                raw_obj = RawEvent(
                    raw_event_id=rrow["raw_event_id"],
                    batch_id=rrow["batch_id"],
                    tenant_scope=rrow["tenant_scope"],
                    source_id=rrow["source_id"],
                    source_type=rrow["source_type"],
                    external_event_uid=rrow["external_event_uid"],
                    raw_fingerprint=rrow["raw_fingerprint"],
                    raw_payload=rrow["raw_payload"],
                    raw_metadata=dict(rrow["raw_metadata"] or {}),
                    ingested_at=require_utc(rrow["ingested_at"]),
                    process_status=RawProcessStatus(rrow["process_status"]),
                )
        return EventWithRawDetail(normalized=norm, raw=raw_obj)

    def search(
        self,
        scope: AccessScope,
        time_range: TimeRange,
        sources: Sequence[str] | None,
        class_uids: Sequence[int] | None,
        category_uids: Sequence[int] | None,
        field_equals: dict[str, str | int | bool] | None,
        include_fallback: bool,
        page: PageSpec,
    ) -> PageResult[NormalizedEventSummary]:
        offset = parse_offset(page.cursor)
        stmt = select(normalized_events).where(
            normalized_events.c.tenant_scope == scope.tenant_id,
            normalized_events.c.event_time >= time_range.start_time,
            normalized_events.c.event_time <= time_range.end_time,
        )
        if scope.allowed_sources is not None:
            stmt = stmt.where(normalized_events.c.source_id.in_(scope.allowed_sources))
        if sources:
            stmt = stmt.where(normalized_events.c.source_id.in_(sources))
        if class_uids:
            stmt = stmt.where(normalized_events.c.class_uid.in_(class_uids))
        if category_uids:
            stmt = stmt.where(normalized_events.c.category_uid.in_(category_uids))
        if not include_fallback:
            stmt = stmt.where(
                normalized_events.c.normalization_status == NormalizationStatus.MAPPED.value
            )
        stmt = stmt.order_by(
            normalized_events.c.event_time.desc(),
            normalized_events.c.event_id.asc(),
        )
        rows = self._conn.execute(stmt).mappings().all()
        if field_equals:
            rows = [
                r
                for r in rows
                if all(
                    extract_nested(dict(r["ocsf_payload"] or {}), k) == v
                    for k, v in field_equals.items()
                )
            ]
        sliced = rows[offset : offset + page.limit + 1]
        cursor, has_more = next_offset_cursor(offset, page.limit, len(sliced))
        return PageResult(
            items=tuple(self._to_summary(r) for r in sliced[: page.limit]),
            next_cursor=cursor,
            truncated=has_more,
        )

    @staticmethod
    def _to_event(row: Any) -> NormalizedEvent:
        return NormalizedEvent(
            event_id=row["event_id"],
            raw_event_id=row["raw_event_id"],
            tenant_scope=row["tenant_scope"],
            source_id=row["source_id"],
            ocsf_version=row["ocsf_version"],
            category_uid=int(row["category_uid"]),
            class_uid=int(row["class_uid"]),
            activity_id=int(row["activity_id"]),
            event_time=require_utc(row["event_time"]),
            normalization_status=NormalizationStatus(row["normalization_status"]),
            mapping_rule_id=row["mapping_rule_id"],
            original_event_uid=row["original_event_uid"],
            ocsf_payload=dict(row["ocsf_payload"] or {}),
            unmapped_fields=dict(row["unmapped_fields"] or {}),
        )

    @staticmethod
    def _to_summary(row: Any) -> NormalizedEventSummary:
        return NormalizedEventSummary(
            event_id=row["event_id"],
            raw_event_id=row["raw_event_id"],
            source_id=row["source_id"],
            ocsf_version=row["ocsf_version"],
            category_uid=int(row["category_uid"]),
            class_uid=int(row["class_uid"]),
            activity_id=int(row["activity_id"]),
            event_time=require_utc(row["event_time"]),
            normalization_status=NormalizationStatus(row["normalization_status"]),
            original_event_uid=row["original_event_uid"],
        )
