from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from provloom.domain.enums import Certainty, EntityType, PipelineStage, RelationType


@dataclass(frozen=True)
class PipelineMetricsSnapshot:
    ingested_total: int
    duplicate_total: int
    ingest_failed_total: int
    parse_success_total: int
    parse_failed_total: int
    normalized_mapped_total: int
    normalized_fallback_total: int
    normalize_failed_total: int
    entity_merges_total: int
    deterministic_relations_total: int
    candidate_relations_total: int


class PipelineTelemetry(Protocol):
    """Records all 8 observability signals required by PRD Section 5."""

    def record_ingest(self, source_type: str, status: str, count: int = 1) -> None: ...
    def record_parse(self, parser_id: str, success: bool) -> None: ...
    def record_normalize(self, class_uid: int, status: str) -> None: ...
    def record_entity_merge(self, entity_type: EntityType, rule_id: str) -> None: ...
    def record_relation(self, relation_type: RelationType, certainty: Certainty) -> None: ...
    def observe_stage_latency(self, stage: PipelineStage, seconds: float) -> None: ...
    def observe_query_latency(self, operation: str, seconds: float) -> None: ...
