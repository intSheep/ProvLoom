from __future__ import annotations

from dataclasses import replace
from threading import Lock

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, generate_latest

from provloom.domain.enums import Certainty, EntityType, PipelineStage, RelationType
from provloom.observability.interfaces import PipelineMetricsSnapshot, PipelineTelemetry


class PrometheusTelemetry(PipelineTelemetry):
    def __init__(self, registry: CollectorRegistry | None = None) -> None:
        self.registry = registry or CollectorRegistry()
        self._lock = Lock()
        self._snap = PipelineMetricsSnapshot(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

        self._ingest = Counter(
            "provloom_ingest_records_total",
            "Ingested raw records by source_type and status",
            ["source_type", "status"],
            registry=self.registry,
        )
        self._parse = Counter(
            "provloom_parse_records_total",
            "Parsed records by parser_id and status",
            ["parser_id", "status"],
            registry=self.registry,
        )
        self._normalize = Counter(
            "provloom_normalize_records_total",
            "Normalized events by class_uid and status",
            ["class_uid", "status"],
            registry=self.registry,
        )
        self._merges = Counter(
            "provloom_entity_merges_total",
            "Deterministic entity merges by entity_type and rule_id",
            ["entity_type", "rule_id"],
            registry=self.registry,
        )
        self._relations = Counter(
            "provloom_relations_generated_total",
            "Generated or correlated relations by type and certainty",
            ["relation_type", "certainty"],
            registry=self.registry,
        )
        self._stage_latency = Histogram(
            "provloom_pipeline_stage_duration_seconds",
            "Pipeline stage processing latency",
            ["stage"],
            registry=self.registry,
        )
        self._query_latency = Histogram(
            "provloom_query_duration_seconds",
            "Read query service execution latency",
            ["operation"],
            registry=self.registry,
        )
        self._det_rules_total = Gauge(
            "detection_rules_total",
            "Total registered detection rules",
            registry=self.registry,
        )
        self._det_rules_supported = Gauge(
            "detection_rules_supported_total",
            "Total supported executable detection rules",
            registry=self.registry,
        )
        self._det_rules_unsupported = Gauge(
            "detection_rules_unsupported_total",
            "Total unsupported or errored detection rules",
            registry=self.registry,
        )
        self._det_executions = Counter(
            "detection_executions_total",
            "Total detection execution runs by status",
            ["status"],
            registry=self.registry,
        )
        self._det_matches = Counter(
            "detection_matches_total",
            "Total newly created RuleMatches",
            registry=self.registry,
        )
        self._det_exec_duration = Histogram(
            "detection_execution_duration_seconds",
            "Detection execution latency in seconds",
            registry=self.registry,
        )
        self._signals_created = Counter(
            "signals_created_total",
            "Total newly created Signals",
            registry=self.registry,
        )
        self._signals_deduplicated = Counter(
            "signals_deduplicated_total",
            "Total deduplicated Signal match attachments",
            registry=self.registry,
        )
        self._signals_aggregated = Counter(
            "signals_aggregated_total",
            "Total Signal aggregations across additional RuleMatches",
            registry=self.registry,
        )
        self._cand_groups_created = Counter(
            "candidate_groups_created_total",
            "Total newly created CandidateGroups",
            registry=self.registry,
        )
        self._det_failures = Counter(
            "detection_failures_total",
            "Total detection rule failures by stage (parse/mapping/compile/execution)",
            ["stage"],
            registry=self.registry,
        )

    def record_ingest(self, source_type: str, status: str, count: int = 1) -> None:
        self._ingest.labels(source_type=source_type, status=status).inc(count)
        with self._lock:
            if status == "accepted":
                self._snap = replace(self._snap, ingested_total=self._snap.ingested_total + count)
            elif status == "duplicate":
                self._snap = replace(self._snap, duplicate_total=self._snap.duplicate_total + count)
            elif status == "failed":
                self._snap = replace(
                    self._snap, ingest_failed_total=self._snap.ingest_failed_total + count
                )

    def record_parse(self, parser_id: str, success: bool) -> None:
        self._parse.labels(parser_id=parser_id, status="success" if success else "failed").inc()
        with self._lock:
            if success:
                self._snap = replace(
                    self._snap, parse_success_total=self._snap.parse_success_total + 1
                )
            else:
                self._snap = replace(
                    self._snap, parse_failed_total=self._snap.parse_failed_total + 1
                )

    def record_normalize(self, class_uid: int, status: str) -> None:
        self._normalize.labels(class_uid=str(class_uid), status=status).inc()
        with self._lock:
            if status == "mapped":
                self._snap = replace(
                    self._snap, normalized_mapped_total=self._snap.normalized_mapped_total + 1
                )
            elif status == "fallback":
                self._snap = replace(
                    self._snap, normalized_fallback_total=self._snap.normalized_fallback_total + 1
                )
            elif status == "failed":
                self._snap = replace(
                    self._snap, normalize_failed_total=self._snap.normalize_failed_total + 1
                )

    def record_entity_merge(self, entity_type: EntityType, rule_id: str) -> None:
        self._merges.labels(entity_type=entity_type.value, rule_id=rule_id).inc()
        with self._lock:
            self._snap = replace(self._snap, entity_merges_total=self._snap.entity_merges_total + 1)

    def record_relation(self, relation_type: RelationType, certainty: Certainty) -> None:
        self._relations.labels(relation_type=relation_type.value, certainty=certainty.value).inc()
        with self._lock:
            if certainty == Certainty.DETERMINISTIC:
                self._snap = replace(
                    self._snap,
                    deterministic_relations_total=self._snap.deterministic_relations_total + 1,
                )
            else:
                self._snap = replace(
                    self._snap,
                    candidate_relations_total=self._snap.candidate_relations_total + 1,
                )

    def observe_stage_latency(self, stage: PipelineStage, seconds: float) -> None:
        self._stage_latency.labels(stage=stage.value).observe(seconds)

    def observe_query_latency(self, operation: str, seconds: float) -> None:
        self._query_latency.labels(operation=operation).observe(seconds)

    def set_detection_rule_counts(self, total: int, supported: int, unsupported: int) -> None:
        self._det_rules_total.set(total)
        self._det_rules_supported.set(supported)
        self._det_rules_unsupported.set(unsupported)
        with self._lock:
            self._snap = replace(
                self._snap,
                detection_rules_total=total,
                detection_rules_supported_total=supported,
                detection_rules_unsupported_total=unsupported,
            )

    def record_detection_execution(
        self,
        status: str,
        duration_seconds: float,
        matches_created: int,
        signals_created: int,
        signals_deduplicated: int,
        signals_aggregated: int,
        candidate_groups_created: int,
    ) -> None:
        self._det_executions.labels(status=status).inc()
        self._det_exec_duration.observe(max(duration_seconds, 0.0))
        if matches_created > 0:
            self._det_matches.inc(matches_created)
        if signals_created > 0:
            self._signals_created.inc(signals_created)
        if signals_deduplicated > 0:
            self._signals_deduplicated.inc(signals_deduplicated)
        if signals_aggregated > 0:
            self._signals_aggregated.inc(signals_aggregated)
        if candidate_groups_created > 0:
            self._cand_groups_created.inc(candidate_groups_created)
        with self._lock:
            self._snap = replace(
                self._snap,
                detection_executions_total=self._snap.detection_executions_total + 1,
                detection_matches_total=self._snap.detection_matches_total + matches_created,
                signals_created_total=self._snap.signals_created_total + signals_created,
                signals_deduplicated_total=self._snap.signals_deduplicated_total
                + signals_deduplicated,
                signals_aggregated_total=self._snap.signals_aggregated_total + signals_aggregated,
                candidate_groups_created_total=self._snap.candidate_groups_created_total
                + candidate_groups_created,
            )

    def record_detection_failure(self, stage: str, count: int = 1) -> None:
        if count > 0:
            self._det_failures.labels(stage=stage).inc(count)

    def snapshot(self) -> PipelineMetricsSnapshot:
        with self._lock:
            return self._snap

    def render_prometheus(self) -> bytes:
        return generate_latest(self.registry)
