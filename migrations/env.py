from __future__ import annotations

from alembic import context
from sqlalchemy import create_engine, pool

from provloom.config import AppConfig
from provloom.storage.postgres.tables import metadata

target_metadata = metadata


def run_migrations_offline() -> None:
    cfg = AppConfig.from_env()
    context.configure(
        url=cfg.database_url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    cfg = AppConfig.from_env()
    connectable = create_engine(cfg.database_url, poolclass=pool.NullPool)
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
