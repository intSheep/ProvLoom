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
    detection_rules_total: int = 0
    detection_rules_supported_total: int = 0
    detection_rules_unsupported_total: int = 0
    detection_executions_total: int = 0
    detection_matches_total: int = 0
    signals_created_total: int = 0
    signals_deduplicated_total: int = 0
    signals_aggregated_total: int = 0
    candidate_groups_created_total: int = 0


class PipelineTelemetry(Protocol):
    """Records pipeline and detection observability signals."""

    def record_ingest(self, source_type: str, status: str, count: int = 1) -> None: ...
    def record_parse(self, parser_id: str, success: bool) -> None: ...
    def record_normalize(self, class_uid: int, status: str) -> None: ...
    def record_entity_merge(self, entity_type: EntityType, rule_id: str) -> None: ...
    def record_relation(self, relation_type: RelationType, certainty: Certainty) -> None: ...
    def observe_stage_latency(self, stage: PipelineStage, seconds: float) -> None: ...
    def observe_query_latency(self, operation: str, seconds: float) -> None: ...
    def set_detection_rule_counts(self, total: int, supported: int, unsupported: int) -> None: ...
    def record_detection_execution(
        self,
        status: str,
        duration_seconds: float,
        matches_created: int,
        signals_created: int,
        signals_deduplicated: int,
        signals_aggregated: int,
        candidate_groups_created: int,
    ) -> None: ...
    def record_detection_failure(self, stage: str, count: int = 1) -> None: ...
