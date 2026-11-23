from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from contextlib import contextmanager

from sqlalchemy import Connection, Engine, create_engine, delete, event, select, update
from sqlalchemy.pool import StaticPool

from provloom.domain.enums import PipelineStage, RawProcessStatus
from provloom.storage.interfaces import UnitOfWork
from provloom.storage.postgres.detection_repo import SqlDetectionRepository
from provloom.storage.postgres.entity_repo import SqlEntityRepository
from provloom.storage.postgres.event_repo import SqlNormalizedEventRepository
from provloom.storage.postgres.graph_repo import SqlGraphRepository
from provloom.storage.postgres.raw_repo import SqlRawEventRepository
from provloom.storage.postgres.tables import (
    entities,
    entity_identifiers,
    entity_merges,
    metadata,
    normalized_events,
    pipeline_failures,
    raw_events,
    relation_evidences,
    relations,
)


def _sqlite_regexp(pattern: str | None, flags_str: str | None, value: str | None) -> int:
    if pattern is None or value is None:
        return 0
    flags = 0
    if flags_str:
        if "i" in flags_str:
            flags |= re.IGNORECASE
        if "m" in flags_str:
            flags |= re.MULTILINE
        if "s" in flags_str:
            flags |= re.DOTALL
    return 1 if re.search(pattern, str(value), flags) is not None else 0


def create_db_engine(database_url: str, echo: bool = False) -> Engine:
    kwargs: dict[str, object] = {"echo": echo}
    if database_url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
        if ":memory:" in database_url:
            kwargs["poolclass"] = StaticPool

    engine = create_engine(database_url, **kwargs)
    if database_url.startswith("sqlite"):

        @event.listens_for(engine, "connect")
        def _enable_sqlite_fk(dbapi_conn: object, _record: object) -> None:
            cursor = dbapi_conn.cursor()  # type: ignore[attr-defined]
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()
            dbapi_conn.create_function("provloom_regexp", 3, _sqlite_regexp)  # type: ignore[attr-defined]

    return engine


def init_schema(engine: Engine) -> None:
    metadata.create_all(engine)


class SqlUnitOfWork(UnitOfWork):
    def __init__(self, engine: Engine) -> None:
        self._engine = engine
        self._conn: Connection | None = None

    def __enter__(self) -> SqlUnitOfWork:
        self._conn = self._engine.connect()
        self._tx = self._conn.begin()
        self.raw_events = SqlRawEventRepository(self._conn)
        self.normalized_events = SqlNormalizedEventRepository(self._conn)
        self.entities = SqlEntityRepository(self._conn)
        self.graph = SqlGraphRepository(self._conn)
        self.detection = SqlDetectionRepository(self._conn)
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        if self._conn is None:
            return
        try:
            if exc_type is not None and self._tx.is_active:
                self._tx.rollback()
            elif self._tx.is_active:
                self._tx.commit()
        finally:
            self._conn.close()
            self._conn = None

    def commit(self) -> None:
        if self._conn is not None and self._tx.is_active:
            self._tx.commit()

    def rollback(self) -> None:
        if self._conn is not None and self._tx.is_active:
            self._tx.rollback()

    @contextmanager
    def savepoint(self) -> Iterator[None]:
        assert self._conn is not None
        with self._conn.begin_nested():
            yield

    def purge_derived_data(self, tenant_scope: str) -> None:
        assert self._conn is not None
        self.detection.purge_tenant_detection_results(tenant_scope)
        tenant_rel_ids = select(relations.c.relation_id).where(
            relations.c.tenant_scope == tenant_scope
        )
        self._conn.execute(
            delete(relation_evidences).where(relation_evidences.c.relation_id.in_(tenant_rel_ids))
        )
        self._conn.execute(delete(relations).where(relations.c.tenant_scope == tenant_scope))
        self._conn.execute(
            delete(entity_merges).where(entity_merges.c.tenant_scope == tenant_scope)
        )
        self._conn.execute(
            delete(entity_identifiers).where(entity_identifiers.c.tenant_scope == tenant_scope)
        )
        self._conn.execute(
            update(entities)
            .where(entities.c.tenant_scope == tenant_scope)
            .values(merged_into_id=None)
        )
        self._conn.execute(delete(entities).where(entities.c.tenant_scope == tenant_scope))
        self._conn.execute(
            delete(normalized_events).where(normalized_events.c.tenant_scope == tenant_scope)
        )
        self._conn.execute(
            delete(pipeline_failures).where(
                pipeline_failures.c.tenant_scope == tenant_scope,
                pipeline_failures.c.stage != PipelineStage.INGEST.value,
            )
        )
        self._conn.execute(
            update(raw_events)
            .where(raw_events.c.tenant_scope == tenant_scope)
            .values(process_status=RawProcessStatus.PENDING.value)
        )


UnitOfWorkFactory = Callable[[], UnitOfWork]


def make_uow_factory(engine: Engine) -> UnitOfWorkFactory:
    return lambda: SqlUnitOfWork(engine)
