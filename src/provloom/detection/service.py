from __future__ import annotations

import time
from collections.abc import Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from provloom.config import DetectionConfig, QueryGuardConfig
from provloom.detection.compiler.postgres_backend import CompiledRuleArtifact
from provloom.detection.domain.candidate_group import (
    CandidateGroup,
    CandidateGroupingConfig,
    CandidateGroupMembers,
)
from provloom.detection.domain.rule import (
    DetectionExecution,
    DetectionRule,
    DetectionType,
    ExecutionMode,
    ExecutionStatus,
    RuleExecutionFailure,
    RuleSeverity,
    RuleSource,
    RuleStatus,
)
from provloom.detection.domain.rule_match import RuleMatch
from provloom.detection.domain.signal import Signal, SignalEvidenceDetail, SignalStatus
from provloom.detection.matcher.event_matcher import SingleEventMatcher
from provloom.detection.matcher.relation_matcher import GraphRelationMatcher
from provloom.detection.rules.registry import BuiltinRuleRegistry
from provloom.detection.signals.candidate_grouper import CandidateGrouper
from provloom.detection.signals.generator import SignalGenerator
from provloom.domain.common import AccessScope, PageResult, PageSpec, TimeRange
from provloom.domain.enums import Certainty
from provloom.domain.errors import (
    DetectionExecutionError,
    QueryLimitExceededError,
    RuleUnsupportedError,
    RuleValidationError,
)
from provloom.observability.interfaces import PipelineTelemetry
from provloom.storage.interfaces import UnitOfWork
from provloom.storage.postgres.uow import UnitOfWorkFactory


@dataclass(frozen=True)
class RuleDetailView:
    rule: DetectionRule
    compiled_sql: str | None
    parsed_summary: dict[str, Any] | None


@dataclass(frozen=True)
class RuleTestResult:
    rule: DetectionRule
    parsed_summary: dict[str, Any] | None
    field_mappings: dict[str, str]
    compiled_sql: str | None
    matches: tuple[RuleMatch, ...]
    failure_reason: str | None
    duration_ms: float


class DefaultDetectionService:
    def __init__(
        self,
        uow_factory: UnitOfWorkFactory,
        rule_registry: BuiltinRuleRegistry,
        telemetry: PipelineTelemetry,
        guards: QueryGuardConfig,
        detection_config: DetectionConfig | None = None,
    ) -> None:
        self._uow_factory = uow_factory
        self._registry = rule_registry
        self._telemetry = telemetry
        self._guards = guards
        self._cfg = detection_config or DetectionConfig()
        self._event_matcher = SingleEventMatcher()
        self._relation_matcher = GraphRelationMatcher()
        self._signal_gen = SignalGenerator()
        self._grouper = CandidateGrouper(
            CandidateGroupingConfig(
                enabled=True,
                max_time_gap_seconds=self._cfg.candidate_grouping_gap_seconds,
            )
        )
        self._seeded_tenants: set[str] = set()

    def _ensure_seeded(self, uow: UnitOfWork, tenant_scope: str) -> None:
        if tenant_scope in self._seeded_tenants:
            existing = uow.detection.list_all_rules(tenant_scope)
            if existing:
                return
        builtins = self._registry.load_builtins()
        for art in builtins:
            uow.detection.upsert_rule(tenant_scope, art.rule, preserve_status=True)
            if not art.rule.compatibility.parse_success:
                self._telemetry.record_detection_failure("parse")
            elif not art.rule.compatibility.mapping_success:
                self._telemetry.record_detection_failure("mapping")
            elif not art.rule.compatibility.compile_success:
                self._telemetry.record_detection_failure("compile")
        self._seeded_tenants.add(tenant_scope)
        self._refresh_rule_metrics(uow, tenant_scope)

    def _refresh_rule_metrics(self, uow: UnitOfWork, tenant_scope: str) -> None:
        all_rules = uow.detection.list_all_rules(tenant_scope)
        total = len(all_rules)
        supported = sum(1 for r in all_rules if r.compatibility.is_supported)
        self._telemetry.set_detection_rule_counts(
            total=total, supported=supported, unsupported=total - supported
        )

    def _record_artifact_failure_stage(self, art: CompiledRuleArtifact) -> None:
        c = art.rule.compatibility
        if not c.parse_success:
            self._telemetry.record_detection_failure("parse")
        elif not c.mapping_success:
            self._telemetry.record_detection_failure("mapping")
        elif not c.compile_success:
            self._telemetry.record_detection_failure("compile")

    def list_detection_rules(
        self,
        scope: AccessScope,
        source: RuleSource | None = None,
        status: RuleStatus | None = None,
        severity: RuleSeverity | None = None,
        attack_tag: str | None = None,
        query_text: str | None = None,
        page: PageSpec = PageSpec(limit=100),
    ) -> PageResult[DetectionRule]:
        validated = page.validate(self._guards.max_page_limit)
        t0 = time.perf_counter()
        with self._uow_factory() as uow:
            self._ensure_seeded(uow, scope.tenant_id)
            res = uow.detection.list_rules(
                tenant_scope=scope.tenant_id,
                source=source,
                status=status,
                severity=severity,
                attack_tag=attack_tag,
                query_text=query_text,
                page=validated,
            )
        self._telemetry.observe_query_latency("list_detection_rules", time.perf_counter() - t0)
        return res

    def get_detection_rule(self, scope: AccessScope, rule_id: str) -> RuleDetailView | None:
        with self._uow_factory() as uow:
            self._ensure_seeded(uow, scope.tenant_id)
            rule = uow.detection.get_rule(scope.tenant_id, rule_id)
            if rule is None:
                return None
        art = self._registry.compile(
            rule.raw_content,
            source_reference=rule.source_reference,
            source_hint=rule.source,
        )
        return RuleDetailView(
            rule=rule,
            compiled_sql=art.event_query.postgres_sql if art.event_query else None,
            parsed_summary=art.parsed_summary,
        )

    def validate_detection_rule(
        self,
        raw_yaml: str,
        source_hint: RuleSource | None = None,
    ) -> RuleDetailView:
        art = self._registry.compile(
            raw_yaml=raw_yaml,
            source_reference="validation-preview",
            source_hint=source_hint,
        )
        self._record_artifact_failure_stage(art)
        return RuleDetailView(
            rule=art.rule,
            compiled_sql=art.event_query.postgres_sql if art.event_query else None,
            parsed_summary=art.parsed_summary,
        )

    def import_detection_rule(
        self,
        scope: AccessScope,
        raw_yaml: str,
        source_reference: str = "api-import",
        source_hint: RuleSource | None = None,
    ) -> RuleDetailView:
        art = self._registry.compile(
            raw_yaml=raw_yaml,
            source_reference=source_reference,
            source_hint=source_hint,
        )
        self._record_artifact_failure_stage(art)
        if not art.rule.compatibility.parse_success:
            reasons = "; ".join(art.rule.compatibility.unsupported_reasons)
            raise RuleValidationError(reasons or "Rule failed YAML validation")

        with self._uow_factory() as uow:
            self._ensure_seeded(uow, scope.tenant_id)
            stored = uow.detection.upsert_rule(scope.tenant_id, art.rule, preserve_status=False)
            self._refresh_rule_metrics(uow, scope.tenant_id)
        return RuleDetailView(
            rule=stored,
            compiled_sql=art.event_query.postgres_sql if art.event_query else None,
            parsed_summary=art.parsed_summary,
        )

    def enable_detection_rule(self, scope: AccessScope, rule_id: str) -> DetectionRule | None:
        with self._uow_factory() as uow:
            self._ensure_seeded(uow, scope.tenant_id)
            existing = uow.detection.get_rule(scope.tenant_id, rule_id)
            if existing is None:
                return None
            if not existing.compatibility.is_supported:
                reasons = "; ".join(existing.compatibility.unsupported_reasons)
                raise RuleUnsupportedError(f"Cannot enable unsupported rule {rule_id!r}: {reasons}")
            updated = uow.detection.update_rule_status(
                scope.tenant_id, rule_id, RuleStatus.ENABLED, datetime.now(UTC)
            )
            self._refresh_rule_metrics(uow, scope.tenant_id)
            return updated

    def disable_detection_rule(self, scope: AccessScope, rule_id: str) -> DetectionRule | None:
        with self._uow_factory() as uow:
            self._ensure_seeded(uow, scope.tenant_id)
            existing = uow.detection.get_rule(scope.tenant_id, rule_id)
            if existing is None:
                return None
            if not existing.compatibility.is_supported:
                return existing
            updated = uow.detection.update_rule_status(
                scope.tenant_id, rule_id, RuleStatus.DISABLED, datetime.now(UTC)
            )
            self._refresh_rule_metrics(uow, scope.tenant_id)
            return updated

    def test_detection_rule(
        self,
        scope: AccessScope,
        time_range: TimeRange,
        raw_yaml: str | None = None,
        rule_id: str | None = None,
        max_matches: int = 100,
    ) -> RuleTestResult:
        if max_matches < 1 or max_matches > self._cfg.max_matches_per_rule:
            raise QueryLimitExceededError(
                f"max_matches must be between 1 and {self._cfg.max_matches_per_rule}"
            )
        t0 = time.perf_counter()
        with self._uow_factory() as uow:
            self._ensure_seeded(uow, scope.tenant_id)
            if raw_yaml and raw_yaml.strip():
                art = self._registry.compile(raw_yaml, source_reference="sandbox-test")
                target_rule = art.rule
            elif rule_id:
                stored = uow.detection.get_rule(scope.tenant_id, rule_id)
                if stored is None:
                    raise RuleValidationError(f"Rule not found: {rule_id}")
                art = self._registry.compile(
                    stored.raw_content,
                    source_reference=stored.source_reference,
                    source_hint=stored.source,
                )
                target_rule = stored
            else:
                raise RuleValidationError("Either raw_yaml or rule_id is required")

            if not art.rule.compatibility.is_supported:
                dur = (time.perf_counter() - t0) * 1000.0
                return RuleTestResult(
                    rule=target_rule,
                    parsed_summary=art.parsed_summary,
                    field_mappings=dict(art.rule.compatibility.field_mappings),
                    compiled_sql=art.event_query.postgres_sql if art.event_query else None,
                    matches=(),
                    failure_reason="; ".join(art.rule.compatibility.unsupported_reasons)
                    or "Rule is unsupported",
                    duration_ms=round(dur, 3),
                )

            sandbox_exec_id = uuid4()
            try:
                if art.rule.detection_type == DetectionType.EVENT and art.event_query is not None:
                    matches = tuple(
                        self._event_matcher.match_batch(
                            uow=uow,
                            scope=scope,
                            time_range=time_range,
                            rule=target_rule,
                            query=art.event_query,
                            execution_id=sandbox_exec_id,
                            max_matches=max_matches,
                        )
                    )
                elif (
                    art.rule.detection_type == DetectionType.RELATION
                    and art.relation_spec is not None
                ):
                    matches = tuple(
                        self._relation_matcher.match_batch(
                            uow=uow,
                            scope=scope,
                            time_range=time_range,
                            rule=target_rule,
                            spec=art.relation_spec,
                            execution_id=sandbox_exec_id,
                            max_matches=max_matches,
                        )
                    )
                else:
                    matches = ()
            except Exception as exc:
                self._telemetry.record_detection_failure("execution")
                err_rule = replace(
                    target_rule,
                    status=RuleStatus.ERROR,
                    compatibility=replace(target_rule.compatibility, execution_success=False),
                )
                dur = (time.perf_counter() - t0) * 1000.0
                return RuleTestResult(
                    rule=err_rule,
                    parsed_summary=art.parsed_summary,
                    field_mappings=dict(art.rule.compatibility.field_mappings),
                    compiled_sql=art.event_query.postgres_sql if art.event_query else None,
                    matches=(),
                    failure_reason=str(exc),
                    duration_ms=round(dur, 3),
                )

            checked_rule = replace(
                target_rule,
                compatibility=replace(target_rule.compatibility, execution_success=True),
            )
            dur = (time.perf_counter() - t0) * 1000.0
            return RuleTestResult(
                rule=checked_rule,
                parsed_summary=art.parsed_summary,
                field_mappings=dict(art.rule.compatibility.field_mappings),
                compiled_sql=art.event_query.postgres_sql if art.event_query else None,
                matches=matches,
                failure_reason=None,
                duration_ms=round(dur, 3),
            )

    def execute_rule(
        self,
        scope: AccessScope,
        rule_id: str,
        time_range: TimeRange,
        max_matches: int | None = None,
    ) -> DetectionExecution:
        return self.execute_rule_batch(
            scope=scope,
            time_range=time_range,
            rule_ids=(rule_id,),
            max_matches_per_rule=max_matches,
            require_explicit_supported=True,
        )

    def execute_rule_batch(
        self,
        scope: AccessScope,
        time_range: TimeRange,
        rule_ids: Sequence[str] | None = None,
        max_matches_per_rule: int | None = None,
        require_explicit_supported: bool = False,
    ) -> DetectionExecution:
        limit = max_matches_per_rule or self._cfg.max_matches_per_rule
        if limit < 1 or limit > self._cfg.max_matches_per_rule:
            raise QueryLimitExceededError(
                f"max_matches_per_rule must be between 1 and {self._cfg.max_matches_per_rule}"
            )

        started_at = datetime.now(UTC)
        t0 = time.perf_counter()
        deadline = t0 + self._cfg.max_execution_seconds
        exec_id = uuid4()

        with self._uow_factory() as uow:
            self._ensure_seeded(uow, scope.tenant_id)
            if rule_ids:
                selected: list[DetectionRule] = []
                for rid in rule_ids:
                    r = uow.detection.get_rule(scope.tenant_id, rid)
                    if r is None:
                        raise DetectionExecutionError(f"Detection rule not found: {rid}")
                    if require_explicit_supported and not r.compatibility.is_supported:
                        reasons = "; ".join(r.compatibility.unsupported_reasons)
                        raise RuleUnsupportedError(
                            f"Rule {rid!r} is unsupported and cannot execute: {reasons}"
                        )
                    selected.append(r)
            else:
                selected = list(
                    uow.detection.list_all_rules(scope.tenant_id, status=RuleStatus.ENABLED)
                )

            initial_exec = DetectionExecution(
                execution_id=exec_id,
                tenant_scope=scope.tenant_id,
                mode=ExecutionMode.BATCH,
                status=ExecutionStatus.RUNNING,
                time_range=time_range,
                rule_ids=tuple(r.rule_id for r in selected),
                rules_evaluated=0,
                matches_created=0,
                matches_deduplicated=0,
                signals_created=0,
                signals_updated=0,
                candidate_groups_created=0,
                duration_ms=0.0,
                failures=(),
                started_at=started_at,
                completed_at=None,
            )
            uow.detection.save_execution(initial_exec)

            rules_evaluated = 0
            matches_created = 0
            matches_dedup = 0
            sig_created = 0
            sig_aggregated = 0
            sig_dedup = 0
            failures: list[RuleExecutionFailure] = []

            for rule in selected:
                if time.perf_counter() > deadline:
                    failures.append(
                        RuleExecutionFailure(
                            rule_id=rule.rule_id,
                            stage="execution",
                            error_message=(
                                f"Time limit ({self._cfg.max_execution_seconds}s) exceeded"
                            ),
                        )
                    )
                    self._telemetry.record_detection_failure("execution")
                    break

                if not rule.compatibility.is_supported:
                    reasons = "; ".join(rule.compatibility.unsupported_reasons)
                    failures.append(
                        RuleExecutionFailure(
                            rule_id=rule.rule_id,
                            stage="compatibility",
                            error_message=reasons or "Unsupported rule",
                        )
                    )
                    self._telemetry.record_detection_failure("compile")
                    continue

                art = self._registry.compile(
                    rule.raw_content,
                    source_reference=rule.source_reference,
                    source_hint=rule.source,
                )
                try:
                    with uow.savepoint():
                        if (
                            rule.detection_type == DetectionType.EVENT
                            and art.event_query is not None
                        ):
                            raw_matches = self._event_matcher.match_batch(
                                uow=uow,
                                scope=scope,
                                time_range=time_range,
                                rule=rule,
                                query=art.event_query,
                                execution_id=exec_id,
                                max_matches=limit,
                            )
                        elif (
                            rule.detection_type == DetectionType.RELATION
                            and art.relation_spec is not None
                        ):
                            raw_matches = self._relation_matcher.match_batch(
                                uow=uow,
                                scope=scope,
                                time_range=time_range,
                                rule=rule,
                                spec=art.relation_spec,
                                execution_id=exec_id,
                                max_matches=limit,
                            )
                        else:
                            raise DetectionExecutionError("Rule missing compiled matcher target")

                        stored_matches: list[RuleMatch] = []
                        for m in raw_matches:
                            stored_m, was_created = uow.detection.insert_rule_match_if_absent(m)
                            stored_matches.append(stored_m)
                            if was_created:
                                matches_created += 1
                            else:
                                matches_dedup += 1

                        if stored_matches:
                            sig_stats = self._signal_gen.ingest_matches(
                                uow=uow, rule=rule, matches=stored_matches
                            )
                            sig_created += sig_stats.signals_created
                            sig_aggregated += sig_stats.signals_aggregated
                            sig_dedup += sig_stats.signals_deduplicated

                        if rule.compatibility.execution_success is not True:
                            uow.detection.upsert_rule(
                                scope.tenant_id,
                                replace(
                                    rule,
                                    compatibility=replace(
                                        rule.compatibility, execution_success=True
                                    ),
                                    updated_at=datetime.now(UTC),
                                ),
                                preserve_status=True,
                            )
                        rules_evaluated += 1
                except Exception as exc:
                    failures.append(
                        RuleExecutionFailure(
                            rule_id=rule.rule_id,
                            stage="execution",
                            error_message=str(exc),
                        )
                    )
                    self._telemetry.record_detection_failure("execution")
                    uow.detection.upsert_rule(
                        scope.tenant_id,
                        replace(
                            rule,
                            status=RuleStatus.ERROR,
                            compatibility=replace(rule.compatibility, execution_success=False),
                            updated_at=datetime.now(UTC),
                        ),
                        preserve_status=False,
                    )

            groups_created = self._grouper.build_groups(uow=uow, scope=scope, time_range=time_range)

            elapsed_s = time.perf_counter() - t0
            final_status = (
                ExecutionStatus.COMPLETED
                if not failures
                else (
                    ExecutionStatus.PARTIAL_FAILURE
                    if rules_evaluated > 0
                    else ExecutionStatus.FAILED
                )
            )
            final_exec = DetectionExecution(
                execution_id=exec_id,
                tenant_scope=scope.tenant_id,
                mode=ExecutionMode.BATCH,
                status=final_status,
                time_range=time_range,
                rule_ids=tuple(r.rule_id for r in selected),
                rules_evaluated=rules_evaluated,
                matches_created=matches_created,
                matches_deduplicated=matches_dedup,
                signals_created=sig_created,
                signals_updated=sig_aggregated,
                candidate_groups_created=groups_created,
                duration_ms=round(elapsed_s * 1000.0, 3),
                failures=tuple(failures),
                started_at=started_at,
                completed_at=datetime.now(UTC),
            )
            uow.detection.save_execution(final_exec)

        self._telemetry.record_detection_execution(
            status=final_exec.status.value,
            duration_seconds=elapsed_s,
            matches_created=matches_created,
            signals_created=sig_created,
            signals_deduplicated=sig_dedup,
            signals_aggregated=sig_aggregated,
            candidate_groups_created=groups_created,
        )
        return final_exec

    def execute_incremental(
        self,
        scope: AccessScope,
        event_ids: Sequence[UUID],
        time_range: TimeRange,
    ) -> DetectionExecution:
        started_at = datetime.now(UTC)
        t0 = time.perf_counter()
        exec_id = uuid4()

        with self._uow_factory() as uow:
            self._ensure_seeded(uow, scope.tenant_id)
            enabled = [
                r
                for r in uow.detection.list_all_rules(scope.tenant_id, status=RuleStatus.ENABLED)
                if r.detection_type == DetectionType.EVENT and r.compatibility.is_supported
            ]
            init_exec = DetectionExecution(
                execution_id=exec_id,
                tenant_scope=scope.tenant_id,
                mode=ExecutionMode.INCREMENTAL,
                status=ExecutionStatus.RUNNING,
                time_range=time_range,
                rule_ids=tuple(r.rule_id for r in enabled),
                rules_evaluated=0,
                matches_created=0,
                matches_deduplicated=0,
                signals_created=0,
                signals_updated=0,
                candidate_groups_created=0,
                duration_ms=0.0,
                failures=(),
                started_at=started_at,
            )
            uow.detection.save_execution(init_exec)

            matches_created = 0
            matches_dedup = 0
            sig_created = 0
            sig_aggregated = 0
            sig_dedup = 0
            for rule in enabled:
                art = self._registry.compile(
                    rule.raw_content,
                    source_reference=rule.source_reference,
                    source_hint=rule.source,
                )
                if art.event_query is None:
                    continue
                raw_matches = self._event_matcher.match_incremental(
                    uow=uow,
                    scope=scope,
                    event_ids=event_ids,
                    rule=rule,
                    query=art.event_query,
                    execution_id=exec_id,
                    max_matches=self._cfg.max_matches_per_rule,
                )
                stored_matches: list[RuleMatch] = []
                for m in raw_matches:
                    sm, created = uow.detection.insert_rule_match_if_absent(m)
                    stored_matches.append(sm)
                    if created:
                        matches_created += 1
                    else:
                        matches_dedup += 1
                if stored_matches:
                    st = self._signal_gen.ingest_matches(uow, rule, stored_matches)
                    sig_created += st.signals_created
                    sig_aggregated += st.signals_aggregated
                    sig_dedup += st.signals_deduplicated

            groups_created = self._grouper.build_groups(uow, scope, time_range)
            elapsed_s = time.perf_counter() - t0
            final_exec = DetectionExecution(
                execution_id=exec_id,
                tenant_scope=scope.tenant_id,
                mode=ExecutionMode.INCREMENTAL,
                status=ExecutionStatus.COMPLETED,
                time_range=time_range,
                rule_ids=tuple(r.rule_id for r in enabled),
                rules_evaluated=len(enabled),
                matches_created=matches_created,
                matches_deduplicated=matches_dedup,
                signals_created=sig_created,
                signals_updated=sig_aggregated,
                candidate_groups_created=groups_created,
                duration_ms=round(elapsed_s * 1000.0, 3),
                failures=(),
                started_at=started_at,
                completed_at=datetime.now(UTC),
            )
            uow.detection.save_execution(final_exec)

        self._telemetry.record_detection_execution(
            status=final_exec.status.value,
            duration_seconds=elapsed_s,
            matches_created=matches_created,
            signals_created=sig_created,
            signals_deduplicated=sig_dedup,
            signals_aggregated=sig_aggregated,
            candidate_groups_created=groups_created,
        )
        return final_exec

    def get_detection_execution(
        self, scope: AccessScope, execution_id: UUID
    ) -> DetectionExecution | None:
        with self._uow_factory() as uow:
            return uow.detection.get_execution(scope, execution_id)

    def list_detection_executions(
        self, scope: AccessScope, page: PageSpec = PageSpec(limit=50)
    ) -> PageResult[DetectionExecution]:
        validated = page.validate(self._guards.max_page_limit)
        with self._uow_factory() as uow:
            return uow.detection.list_executions(scope, validated)

    def search_rule_matches(
        self,
        scope: AccessScope,
        time_range: TimeRange,
        rule_id: str | None = None,
        detection_type: DetectionType | None = None,
        severity: RuleSeverity | None = None,
        entity_id: UUID | None = None,
        page: PageSpec = PageSpec(limit=100),
    ) -> PageResult[RuleMatch]:
        validated = page.validate(self._guards.max_page_limit)
        t0 = time.perf_counter()
        with self._uow_factory() as uow:
            res = uow.detection.search_rule_matches(
                scope=scope,
                time_range=time_range,
                rule_id=rule_id,
                detection_type=detection_type,
                severity=severity,
                entity_id=entity_id,
                page=validated,
            )
        self._telemetry.observe_query_latency("search_rule_matches", time.perf_counter() - t0)
        return res

    def get_rule_match(self, scope: AccessScope, match_id: UUID) -> RuleMatch | None:
        t0 = time.perf_counter()
        with self._uow_factory() as uow:
            res = uow.detection.get_rule_match(scope, match_id)
        self._telemetry.observe_query_latency("get_rule_match", time.perf_counter() - t0)
        return res

    def search_signals(
        self,
        scope: AccessScope,
        time_range: TimeRange,
        status: SignalStatus | None = None,
        severity: RuleSeverity | None = None,
        entity_id: UUID | None = None,
        signal_type: str | None = None,
        page: PageSpec = PageSpec(limit=100),
    ) -> PageResult[Signal]:
        validated = page.validate(self._guards.max_page_limit)
        t0 = time.perf_counter()
        with self._uow_factory() as uow:
            res = uow.detection.search_signals(
                scope=scope,
                time_range=time_range,
                status=status,
                severity=severity,
                entity_id=entity_id,
                signal_type=signal_type,
                page=validated,
            )
        self._telemetry.observe_query_latency("search_signals", time.perf_counter() - t0)
        return res

    def get_signal(self, scope: AccessScope, signal_id: UUID) -> Signal | None:
        t0 = time.perf_counter()
        with self._uow_factory() as uow:
            res = uow.detection.get_signal(scope, signal_id)
        self._telemetry.observe_query_latency("get_signal", time.perf_counter() - t0)
        return res

    def get_signal_matches(self, scope: AccessScope, signal_id: UUID) -> Sequence[RuleMatch] | None:
        t0 = time.perf_counter()
        with self._uow_factory() as uow:
            sig = uow.detection.get_signal(scope, signal_id)
            if sig is None:
                return None
            res = uow.detection.get_rule_matches_by_ids(scope, sig.rule_match_ids)
        self._telemetry.observe_query_latency("get_signal_matches", time.perf_counter() - t0)
        return res

    def get_signal_evidence(
        self, scope: AccessScope, signal_id: UUID
    ) -> Sequence[SignalEvidenceDetail] | None:
        t0 = time.perf_counter()
        with self._uow_factory() as uow:
            sig = uow.detection.get_signal(scope, signal_id)
            if sig is None:
                return None
            res = uow.detection.get_signal_evidence(scope, signal_id)
        self._telemetry.observe_query_latency("get_signal_evidence", time.perf_counter() - t0)
        return res

    def update_signal_status(
        self, scope: AccessScope, signal_id: UUID, status: SignalStatus
    ) -> Signal | None:
        with self._uow_factory() as uow:
            return uow.detection.update_signal_status(
                scope=scope,
                signal_id=signal_id,
                status=status,
                updated_at=datetime.now(UTC),
            )

    def search_candidate_groups(
        self,
        scope: AccessScope,
        time_range: TimeRange,
        entity_id: UUID | None = None,
        certainty: Certainty | None = None,
        page: PageSpec = PageSpec(limit=100),
    ) -> PageResult[CandidateGroup]:
        validated = page.validate(self._guards.max_page_limit)
        t0 = time.perf_counter()
        with self._uow_factory() as uow:
            res = uow.detection.search_candidate_groups(
                scope=scope,
                time_range=time_range,
                entity_id=entity_id,
                certainty=certainty,
                page=validated,
            )
        self._telemetry.observe_query_latency("search_candidate_groups", time.perf_counter() - t0)
        return res

    def get_candidate_group(self, scope: AccessScope, group_id: UUID) -> CandidateGroup | None:
        t0 = time.perf_counter()
        with self._uow_factory() as uow:
            res = uow.detection.get_candidate_group(scope, group_id)
        self._telemetry.observe_query_latency("get_candidate_group", time.perf_counter() - t0)
        return res

    def get_candidate_group_members(
        self, scope: AccessScope, group_id: UUID
    ) -> CandidateGroupMembers | None:
        t0 = time.perf_counter()
        with self._uow_factory() as uow:
            grp = uow.detection.get_candidate_group(scope, group_id)
            if grp is None:
                return None
            sigs = tuple(
                s
                for sid in grp.signal_ids
                if (s := uow.detection.get_signal(scope, sid)) is not None
            )
            matches = tuple(uow.detection.get_rule_matches_by_ids(scope, grp.rule_match_ids))
        self._telemetry.observe_query_latency(
            "get_candidate_group_members", time.perf_counter() - t0
        )
        return CandidateGroupMembers(group=grp, signals=sigs, rule_matches=matches)
