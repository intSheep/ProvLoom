from __future__ import annotations

from collections.abc import Sequence
from typing import Any
from uuid import UUID

from sqlalchemy import Connection, and_, delete, insert, select, update
from sqlalchemy.exc import IntegrityError

from provloom.domain.common import AccessScope, PageResult, PageSpec, TimeRange
from provloom.domain.enums import BatchStatus, PipelineStage, RawProcessStatus
from provloom.domain.raw_models import IngestBatch, PipelineFailure, RawEvent
from provloom.storage.interfaces import RawEventRepository
from provloom.storage.postgres.tables import ingest_batches, pipeline_failures, raw_events
from provloom.storage.postgres.utils import next_offset_cursor, parse_offset, require_utc


class SqlRawEventRepository(RawEventRepository):
    def __init__(self, conn: Connection) -> None:
        self._conn = conn

    def create_batch(self, batch: IngestBatch) -> None:
        self._conn.execute(
            insert(ingest_batches).values(
                batch_id=batch.batch_id,
                tenant_scope=batch.tenant_scope,
                source_id=batch.source_id,
                source_type=batch.source_type,
                adapter_type=batch.adapter_type,
                source_uri=batch.source_uri,
                total_count=batch.total_count,
                accepted_count=batch.accepted_count,
                duplicate_count=batch.duplicate_count,
                failed_count=batch.failed_count,
                received_at=batch.received_at,
                status=batch.status.value,
            )
        )

    def update_batch_counts(self, batch: IngestBatch) -> None:
        self._conn.execute(
            update(ingest_batches)
            .where(ingest_batches.c.batch_id == batch.batch_id)
            .values(
                total_count=batch.total_count,
                accepted_count=batch.accepted_count,
                duplicate_count=batch.duplicate_count,
                failed_count=batch.failed_count,
                status=batch.status.value,
            )
        )

    def get_batch(self, scope: AccessScope, batch_id: UUID) -> IngestBatch | None:
        stmt = select(ingest_batches).where(
            ingest_batches.c.batch_id == batch_id,
            ingest_batches.c.tenant_scope == scope.tenant_id,
        )
        if scope.allowed_sources is not None:
            stmt = stmt.where(ingest_batches.c.source_id.in_(scope.allowed_sources))
        row = self._conn.execute(stmt).mappings().first()
        return self._to_batch(row) if row else None

    def list_batches(self, scope: AccessScope, page: PageSpec) -> PageResult[IngestBatch]:
        offset = parse_offset(page.cursor)
        stmt = select(ingest_batches).where(ingest_batches.c.tenant_scope == scope.tenant_id)
        if scope.allowed_sources is not None:
            stmt = stmt.where(ingest_batches.c.source_id.in_(scope.allowed_sources))
        stmt = (
            stmt.order_by(ingest_batches.c.received_at.desc()).offset(offset).limit(page.limit + 1)
        )
        rows = self._conn.execute(stmt).mappings().all()
        cursor, has_more = next_offset_cursor(offset, page.limit, len(rows))
        return PageResult(
            items=tuple(self._to_batch(r) for r in rows[: page.limit]),
            next_cursor=cursor,
            truncated=has_more,
        )

    def insert_raw_if_absent(self, raw_event: RawEvent) -> bool:
        # Savepoint isolates unique-violation rollback inside an enclosing batch transaction.
        try:
            with self._conn.begin_nested():
                self._conn.execute(
                    insert(raw_events).values(
                        raw_event_id=raw_event.raw_event_id,
                        batch_id=raw_event.batch_id,
                        tenant_scope=raw_event.tenant_scope,
                        source_id=raw_event.source_id,
                        source_type=raw_event.source_type,
                        external_event_uid=raw_event.external_event_uid,
                        raw_fingerprint=raw_event.raw_fingerprint,
                        raw_payload=raw_event.raw_payload,
                        raw_metadata=raw_event.raw_metadata,
                        ingested_at=raw_event.ingested_at,
                        process_status=raw_event.process_status.value,
                    )
                )
            return True
        except IntegrityError:
            return False

    def update_status(self, raw_event_id: UUID, status: RawProcessStatus) -> None:
        self._conn.execute(
            update(raw_events)
            .where(raw_events.c.raw_event_id == raw_event_id)
            .values(process_status=status.value)
        )

    def iter_batch_events(self, batch_id: UUID, pending_only: bool = True) -> Sequence[RawEvent]:
        stmt = select(raw_events).where(raw_events.c.batch_id == batch_id)
        if pending_only:
            stmt = stmt.where(raw_events.c.process_status == RawProcessStatus.PENDING.value)
        stmt = stmt.order_by(raw_events.c.ingested_at.asc(), raw_events.c.raw_event_id.asc())
        return [self._to_raw(r) for r in self._conn.execute(stmt).mappings().all()]

    def iter_for_replay(
        self,
        scope: AccessScope,
        time_range: TimeRange | None = None,
        batch_ids: Sequence[UUID] | None = None,
    ) -> Sequence[RawEvent]:
        stmt = select(raw_events).where(raw_events.c.tenant_scope == scope.tenant_id)
        if scope.allowed_sources is not None:
            stmt = stmt.where(raw_events.c.source_id.in_(scope.allowed_sources))
        if time_range is not None:
            stmt = stmt.where(
                raw_events.c.ingested_at >= time_range.start_time,
                raw_events.c.ingested_at <= time_range.end_time,
            )
        if batch_ids:
            stmt = stmt.where(raw_events.c.batch_id.in_(batch_ids))
        stmt = stmt.order_by(raw_events.c.ingested_at.asc(), raw_events.c.raw_event_id.asc())
        return [self._to_raw(r) for r in self._conn.execute(stmt).mappings().all()]

    def record_failure(self, failure: PipelineFailure) -> None:
        self._conn.execute(
            insert(pipeline_failures).values(
                failure_id=failure.failure_id,
                batch_id=failure.batch_id,
                raw_event_id=failure.raw_event_id,
                tenant_scope=failure.tenant_scope,
                stage=failure.stage.value,
                error_code=failure.error_code,
                error_message=failure.error_message,
                raw_snippet=failure.raw_snippet,
                retryable=failure.retryable,
                retry_count=failure.retry_count,
                occurred_at=failure.occurred_at,
            )
        )

    def list_failures(
        self,
        scope: AccessScope,
        batch_id: UUID | None,
        stage: PipelineStage | None,
        page: PageSpec,
    ) -> PageResult[PipelineFailure]:
        offset = parse_offset(page.cursor)
        stmt = select(pipeline_failures).where(pipeline_failures.c.tenant_scope == scope.tenant_id)
        if batch_id is not None:
            stmt = stmt.where(pipeline_failures.c.batch_id == batch_id)
        if stage is not None:
            stmt = stmt.where(pipeline_failures.c.stage == stage.value)
        stmt = (
            stmt.order_by(pipeline_failures.c.occurred_at.desc())
            .offset(offset)
            .limit(page.limit + 1)
        )
        rows = self._conn.execute(stmt).mappings().all()
        cursor, has_more = next_offset_cursor(offset, page.limit, len(rows))
        return PageResult(
            items=tuple(self._to_failure(r) for r in rows[: page.limit]),
            next_cursor=cursor,
            truncated=has_more,
        )

    def iter_retryable_failures(
        self, scope: AccessScope, batch_id: UUID | None, limit: int
    ) -> Sequence[tuple[PipelineFailure, RawEvent]]:
        stmt = (
            select(pipeline_failures, raw_events)
            .join(raw_events, pipeline_failures.c.raw_event_id == raw_events.c.raw_event_id)
            .where(
                and_(
                    pipeline_failures.c.tenant_scope == scope.tenant_id,
                    pipeline_failures.c.retryable.is_(True),
                )
            )
        )
        if batch_id is not None:
            stmt = stmt.where(pipeline_failures.c.batch_id == batch_id)
        stmt = stmt.order_by(pipeline_failures.c.occurred_at.asc()).limit(limit)
        out: list[tuple[PipelineFailure, RawEvent]] = []
        for row in self._conn.execute(stmt).mappings().all():
            out.append((self._to_failure(row), self._to_raw(row)))
        return out

    def resolve_failure(self, failure_id: UUID) -> None:
        self._conn.execute(
            delete(pipeline_failures).where(pipeline_failures.c.failure_id == failure_id)
        )

    def increment_failure_retry(self, failure_id: UUID, error_message: str) -> None:
        self._conn.execute(
            update(pipeline_failures)
            .where(pipeline_failures.c.failure_id == failure_id)
            .values(
                retry_count=pipeline_failures.c.retry_count + 1,
                error_message=error_message,
            )
        )

    @staticmethod
    def _to_batch(row: Any) -> IngestBatch:
        return IngestBatch(
            batch_id=row["batch_id"],
            tenant_scope=row["tenant_scope"],
            source_id=row["source_id"],
            source_type=row["source_type"],
            adapter_type=row["adapter_type"],
            source_uri=row["source_uri"],
            received_at=require_utc(row["received_at"]),
            status=BatchStatus(row["status"]),
            total_count=row["total_count"],
            accepted_count=row["accepted_count"],
            duplicate_count=row["duplicate_count"],
            failed_count=row["failed_count"],
        )

    @staticmethod
    def _to_raw(row: Any) -> RawEvent:
        return RawEvent(
            raw_event_id=row["raw_event_id"],
            batch_id=row["batch_id"],
            tenant_scope=row["tenant_scope"],
            source_id=row["source_id"],
            source_type=row["source_type"],
            external_event_uid=row["external_event_uid"],
            raw_fingerprint=row["raw_fingerprint"],
            raw_payload=row["raw_payload"],
            raw_metadata=dict(row["raw_metadata"] or {}),
            ingested_at=require_utc(row["ingested_at"]),
            process_status=RawProcessStatus(row["process_status"]),
        )

    @staticmethod
    def _to_failure(row: Any) -> PipelineFailure:
        return PipelineFailure(
            failure_id=row["failure_id"],
            batch_id=row["batch_id"],
            raw_event_id=row["raw_event_id"],
            tenant_scope=row["tenant_scope"],
            stage=PipelineStage(row["stage"]),
            error_code=row["error_code"],
            error_message=row["error_message"],
            raw_snippet=row["raw_snippet"],
            retryable=bool(row["retryable"]),
            retry_count=int(row["retry_count"]),
            occurred_at=require_utc(row["occurred_at"]),
        )
