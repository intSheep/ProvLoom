"""Add detection rules, executions, rule matches, signals, and candidate groups tables.

Revision ID: 0002_detection_layer_schema
Revises: 0001_initial_core_schema
Create Date: 2026-11-20
"""

from __future__ import annotations

from alembic import op

from provloom.storage.postgres.tables import (
    detection_candidate_groups,
    detection_executions,
    detection_rule_matches,
    detection_rules,
    detection_signal_matches,
    detection_signals,
    metadata,
)

revision = "0002_detection_layer_schema"
down_revision = "0001_initial_core_schema"
branch_labels = None
depends_on = None

_DETECTION_TABLES = [
    detection_rules,
    detection_executions,
    detection_rule_matches,
    detection_signals,
    detection_signal_matches,
    detection_candidate_groups,
]


def upgrade() -> None:
    metadata.create_all(bind=op.get_bind(), tables=_DETECTION_TABLES, checkfirst=True)


def downgrade() -> None:
    metadata.drop_all(bind=op.get_bind(), tables=_DETECTION_TABLES, checkfirst=True)
