from __future__ import annotations

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.dialects.postgresql import JSONB

metadata = MetaData()

# Renders native JSONB on PostgreSQL and JSON on SQLite for local dev/test parity.
JSON_DOC = JSON().with_variant(JSONB(), "postgresql")

ingest_batches = Table(
    "ingest_batches",
    metadata,
    Column("batch_id", Uuid, primary_key=True),
    Column("tenant_scope", String(64), nullable=False),
    Column("source_id", String(128), nullable=False),
    Column("source_type", String(64), nullable=False),
    Column("adapter_type", String(64), nullable=False),
    Column("source_uri", Text, nullable=False),
    Column("total_count", Integer, nullable=False, default=0),
    Column("accepted_count", Integer, nullable=False, default=0),
    Column("duplicate_count", Integer, nullable=False, default=0),
    Column("failed_count", Integer, nullable=False, default=0),
    Column("received_at", DateTime(timezone=True), nullable=False),
    Column("status", String(32), nullable=False),
    Index("ix_ingest_batches_tenant_received", "tenant_scope", "received_at"),
)

raw_events = Table(
    "raw_events",
    metadata,
    Column("raw_event_id", Uuid, primary_key=True),
    Column("batch_id", Uuid, ForeignKey("ingest_batches.batch_id"), nullable=False),
    Column("tenant_scope", String(64), nullable=False),
    Column("source_id", String(128), nullable=False),
    Column("source_type", String(64), nullable=False),
    Column("external_event_uid", String(256), nullable=True),
    Column("raw_fingerprint", String(64), nullable=False),
    Column("raw_payload", Text, nullable=False),
    Column("raw_metadata", JSON_DOC, nullable=False),
    Column("ingested_at", DateTime(timezone=True), nullable=False),
    Column("process_status", String(32), nullable=False),
    # Enforces idempotent ingestion per tenant + source (PRD AC-08).
    UniqueConstraint("tenant_scope", "source_id", "raw_fingerprint", name="uq_raw_events_dedup"),
    Index("ix_raw_events_batch_status", "batch_id", "process_status"),
)

pipeline_failures = Table(
    "pipeline_failures",
    metadata,
    Column("failure_id", Uuid, primary_key=True),
    Column("batch_id", Uuid, ForeignKey("ingest_batches.batch_id"), nullable=False),
    Column("raw_event_id", Uuid, ForeignKey("raw_events.raw_event_id"), nullable=True),
    Column("tenant_scope", String(64), nullable=False),
    Column("stage", String(32), nullable=False),
    Column("error_code", String(64), nullable=False),
    Column("error_message", Text, nullable=False),
    Column("raw_snippet", Text, nullable=True),
    Column("retryable", Boolean, nullable=False, default=True),
    Column("retry_count", Integer, nullable=False, default=0),
    Column("occurred_at", DateTime(timezone=True), nullable=False),
    Index("ix_pipeline_failures_tenant_stage", "tenant_scope", "stage", "occurred_at"),
)

normalized_events = Table(
    "normalized_events",
    metadata,
    Column("event_id", Uuid, primary_key=True),
    Column(
        "raw_event_id", Uuid, ForeignKey("raw_events.raw_event_id"), nullable=False, unique=True
    ),
    Column("tenant_scope", String(64), nullable=False),
    Column("source_id", String(128), nullable=False),
    Column("ocsf_version", String(16), nullable=False),
    Column("category_uid", Integer, nullable=False),
    Column("class_uid", Integer, nullable=False),
    Column("activity_id", Integer, nullable=False),
    Column("event_time", DateTime(timezone=True), nullable=False),
    Column("normalization_status", String(32), nullable=False),
    Column("mapping_rule_id", String(128), nullable=False),
    Column("original_event_uid", String(256), nullable=True),
    Column("ocsf_payload", JSON_DOC, nullable=False),
    Column("unmapped_fields", JSON_DOC, nullable=False),
    Index("ix_normalized_events_tenant_time", "tenant_scope", "event_time"),
    Index("ix_normalized_events_tenant_class_time", "tenant_scope", "class_uid", "event_time"),
    Index("ix_normalized_events_payload_gin", "ocsf_payload", postgresql_using="gin"),
)

entities = Table(
    "entities",
    metadata,
    Column("entity_id", Uuid, primary_key=True),
    Column("tenant_scope", String(64), nullable=False),
    Column("entity_type", String(32), nullable=False),
    Column("resolution_state", String(32), nullable=False),
    Column("display_label", String(512), nullable=False),
    Column("canonical_key", String(512), nullable=True),
    Column("valid_from", DateTime(timezone=True), nullable=True),
    Column("valid_to", DateTime(timezone=True), nullable=True),
    Column("attributes", JSON_DOC, nullable=False),
    Column("merged_into_id", Uuid, ForeignKey("entities.entity_id"), nullable=True),
    Index("ix_entities_tenant_type_state", "tenant_scope", "entity_type", "resolution_state"),
)

entity_identifiers = Table(
    "entity_identifiers",
    metadata,
    Column("identifier_id", Uuid, primary_key=True),
    Column("entity_id", Uuid, ForeignKey("entities.entity_id"), nullable=False),
    Column("scope_entity_id", Uuid, ForeignKey("entities.entity_id"), nullable=True),
    Column("tenant_scope", String(64), nullable=False),
    Column("id_namespace", String(64), nullable=False),
    Column("id_value", String(512), nullable=False),
    Column("is_authoritative", Boolean, nullable=False),
    Column("valid_from", DateTime(timezone=True), nullable=True),
    Column("valid_to", DateTime(timezone=True), nullable=True),
    Column("first_seen_event_id", Uuid, ForeignKey("normalized_events.event_id"), nullable=False),
    Index("ix_entity_identifiers_lookup", "tenant_scope", "id_namespace", "id_value"),
    Index("ix_entity_identifiers_entity", "entity_id"),
)

entity_merges = Table(
    "entity_merges",
    metadata,
    Column("merge_id", Uuid, primary_key=True),
    Column("tenant_scope", String(64), nullable=False),
    Column("source_entity_id", Uuid, ForeignKey("entities.entity_id"), nullable=False),
    Column("target_entity_id", Uuid, ForeignKey("entities.entity_id"), nullable=False),
    Column("merge_rule_id", String(128), nullable=False),
    Column("match_basis", JSON_DOC, nullable=False),
    Column("evidence_event_ids", JSON_DOC, nullable=False),
    Column("merged_at", DateTime(timezone=True), nullable=False),
    Index("ix_entity_merges_target", "target_entity_id"),
)

relations = Table(
    "relations",
    metadata,
    Column("relation_id", Uuid, primary_key=True),
    Column("tenant_scope", String(64), nullable=False),
    Column("src_entity_id", Uuid, ForeignKey("entities.entity_id"), nullable=False),
    Column("relation_type", String(32), nullable=False),
    Column("dst_entity_id", Uuid, ForeignKey("entities.entity_id"), nullable=False),
    Column("certainty", String(32), nullable=False),
    Column("context_key", String(256), nullable=False),
    Column("correlation_rule_id", String(128), nullable=False),
    Column("correlation_basis", JSON_DOC, nullable=False),
    Column("first_seen_at", DateTime(timezone=True), nullable=False),
    Column("last_seen_at", DateTime(timezone=True), nullable=False),
    Column("evidence_count", Integer, nullable=False, default=1),
    # Aggregates repeated observations while keeping DETERMINISTIC and CANDIDATE disjoint.
    UniqueConstraint(
        "tenant_scope",
        "src_entity_id",
        "relation_type",
        "dst_entity_id",
        "certainty",
        "context_key",
        name="uq_relations_logical_edge",
    ),
    Index("ix_relations_outbound", "tenant_scope", "src_entity_id", "certainty", "last_seen_at"),
    Index("ix_relations_inbound", "tenant_scope", "dst_entity_id", "certainty", "last_seen_at"),
)

relation_evidences = Table(
    "relation_evidences",
    metadata,
    Column("evidence_id", Uuid, primary_key=True),
    Column("relation_id", Uuid, ForeignKey("relations.relation_id"), nullable=False),
    Column("event_id", Uuid, ForeignKey("normalized_events.event_id"), nullable=False),
    Column("raw_event_id", Uuid, ForeignKey("raw_events.raw_event_id"), nullable=False),
    Column("evidence_role", String(64), nullable=False),
    Column("observed_at", DateTime(timezone=True), nullable=False),
    Column("match_detail", JSON_DOC, nullable=False),
    UniqueConstraint("relation_id", "event_id", name="uq_relation_evidences_event"),
    Index("ix_relation_evidences_relation", "relation_id", "observed_at"),
)
