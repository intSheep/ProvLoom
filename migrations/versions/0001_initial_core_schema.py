"""Initial core schema for raw, normalized, entity, and provenance graph layers.

Revision ID: 0001_initial_core_schema
Revises:
Create Date: 2026-11-18
"""

from __future__ import annotations

from alembic import op

from provloom.storage.postgres.tables import metadata

revision = "0001_initial_core_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    metadata.create_all(bind=op.get_bind())


def downgrade() -> None:
    metadata.drop_all(bind=op.get_bind())
