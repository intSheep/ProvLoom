from __future__ import annotations

import time
from collections.abc import Sequence
from datetime import datetime, timezone
from uuid import UUID, uuid4

from provloom.config import CorrelationConfig
from provloom.domain.common import AccessScope, PageSpec, TimeRange
from provloom.domain.enums import Direction, NormalizationStatus, PipelineStage, RawProcessStatus
from provloom.domain.errors import LogParseError, NormalizationError
from provloom.domain.raw_models import PipelineFailure, RawEvent
from provloom.entity.extractors.ocsf_extractor import OcsfEntityExtractor
from provloom.entity.interfaces import EntityExtractor
from provloom.entity.resolvers.identity_resolver import ScopedIdentityResolver
from provloom.graph.builder import DefaultGraphBuilder
from provloom.graph.correlators.network_correlator import NetworkFiveTupleCorrelator
from provloom.graph.extractors.ocsf_relations import OcsfRelationExtractor
from provloom.graph.interfaces import RelationExtractor
from provloom.normalization.interfaces import NormalizationService
from provloom.observability.interfaces import PipelineTelemetry
from provloom.parsing.interfaces import ParserRegistry
from provloom.pipeline.interfaces import (
    PipelineOrchestrator,
    ReplayReceipt,
    ReplayService,
    RetryReceipt,
)
from provloom.storage.interfaces import UnitOfWork
from provloom.storage.postgres.uow import UnitOfWorkFactory


class DefaultPipelineOrchestrator(PipelineOrchestrator):
    def __init__(
        self,
        uow_factory: UnitOfWorkFactory,
        parser_registry: ParserRegistry,
        normalizer: NormalizationService,
        telemetry: PipelineTelemetry,
        correlation_config: CorrelationConfig | None = None,
        entity_extractor: EntityExtractor | None = None,
        relation_extractor: RelationExtractor | None = None,
    ) -> None:
        self._uow_factory = uow_factory
        self._parsers = parser_registry
        self._normalizer = normalizer
        self._telemetry = telemetry
        self._corr_cfg = correlation_config or CorrelationConfig()
        self._ent_ext = entity_extractor or OcsfEntityExtractor()
        self._rel_ext = relation_extractor or OcsfRelationExtractor()

    def process_batch(self, batch_id: UUID) -> None:
        with self._uow_factory() as uow:
            raw_items = uow.raw_events.iter_batch_events(batch_id, pending_only=True)
            for raw_ev in raw_items:
                self.process_raw_event(uow, raw_ev, record_new_failure=True)
            uow.commit()

    def retry_failures(
        self, scope: AccessScope, batch_id: UUID | None = None, limit: int = 500
    ) -> RetryReceipt:
        attempted = 0
        succeeded = 0
        failed = 0
        with self._uow_factory() as uow:
            pairs = uow.raw_events.iter_retryable_failures(scope, batch_id, limit)
            for failure, raw_ev in pairs:
                attempted += 1
                ok, err = self.process_raw_event(uow, raw_ev, record_new_failure=False)
                if ok:
                    uow.raw_events.resolve_failure(failure.failure_id)
                    succeeded += 1
                else:
                    uow.raw_events.increment_failure_retry(
                        failure.failure_id, err or failure.error_message
                    )
                    failed += 1
            uow.commit()
        return RetryReceipt(attempted=attempted, succeeded=succeeded, failed=failed)

    def process_raw_event(
        self,
        uow: UnitOfWork,
        raw_ev: RawEvent,
        record_new_failure: bool = True,
    ) -> tuple[bool, str | None]:
        parser = self._parsers.resolve(raw_ev)
        t_parse = time.perf_counter()
        try:
            parsed = parser.parse(raw_ev)
            self._telemetry.record_parse(parser.parser_id, True)
            self._telemetry.observe_stage_latency(
                PipelineStage.PARSE, time.perf_counter() - t_parse
            )
        except LogParseError as exc:
            self._telemetry.record_parse(parser.parser_id, False)
            uow.raw_events.update_status(raw_ev.raw_event_id, RawProcessStatus.PARSE_FAILED)
            if record_new_failure:
                uow.raw_events.record_failure(
                    PipelineFailure(
                        failure_id=uuid4(),
                        batch_id=raw_ev.batch_id,
                        raw_event_id=raw_ev.raw_event_id,
                        tenant_scope=raw_ev.tenant_scope,
                        stage=PipelineStage.PARSE,
                        error_code="LOG_PARSE_ERROR",
                        error_message=str(exc),
                        raw_snippet=raw_ev.raw_payload[:500],
                        retryable=True,
                        occurred_at=datetime.now(timezone.utc),
                    )
                )
            return False, str(exc)

        t_norm = time.perf_counter()
        try:
            norm_ev = self._normalizer.normalize(parsed)
            uow.normalized_events.upsert(norm_ev)
            is_mapped = norm_ev.normalization_status == NormalizationStatus.MAPPED
            self._telemetry.record_normalize(
                norm_ev.class_uid, "mapped" if is_mapped else "fallback"
            )
            self._telemetry.observe_stage_latency(
                PipelineStage.NORMALIZE, time.perf_counter() - t_norm
            )
        except NormalizationError as exc:
            self._telemetry.record_normalize(-1, "failed")
            uow.raw_events.update_status(raw_ev.raw_event_id, RawProcessStatus.NORMALIZE_FAILED)
            if record_new_failure:
                uow.raw_events.record_failure(
                    PipelineFailure(
                        failure_id=uuid4(),
                        batch_id=raw_ev.batch_id,
                        raw_event_id=raw_ev.raw_event_id,
                        tenant_scope=raw_ev.tenant_scope,
                        stage=PipelineStage.NORMALIZE,
                        error_code="NORMALIZATION_ERROR",
                        error_message=str(exc),
                        raw_snippet=raw_ev.raw_payload[:500],
                        retryable=True,
                        occurred_at=datetime.now(timezone.utc),
                    )
                )
            return False, str(exc)

        if norm_ev.normalization_status == NormalizationStatus.MAPPED:
            t_ent = time.perf_counter()
            observations = (
                self._ent_ext.extract(norm_ev)
                if self._ent_ext.supports_class(norm_ev.class_uid)
                else ()
            )
            resolver = ScopedIdentityResolver(uow=uow, telemetry=self._telemetry)
            resolved = resolver.resolve(norm_ev, observations)
            self._telemetry.observe_stage_latency(PipelineStage.ENTITY, time.perf_counter() - t_ent)

            t_grp = time.perf_counter()
            if self._rel_ext.supports_class(norm_ev.class_uid):
                cand_rels = self._rel_ext.extract(norm_ev, resolved)
                correlator = NetworkFiveTupleCorrelator(uow=uow, config=self._corr_cfg)
                correlated = correlator.correlate(norm_ev, cand_rels)
                DefaultGraphBuilder(uow=uow, telemetry=self._telemetry).apply_relations(correlated)
            self._telemetry.observe_stage_latency(PipelineStage.GRAPH, time.perf_counter() - t_grp)
            uow.raw_events.update_status(raw_ev.raw_event_id, RawProcessStatus.NORMALIZED)
        else:
            uow.raw_events.update_status(raw_ev.raw_event_id, RawProcessStatus.NORMALIZED_FALLBACK)

        return True, None


class DefaultReplayService(ReplayService):
    def __init__(
        self,
        uow_factory: UnitOfWorkFactory,
        orchestrator: DefaultPipelineOrchestrator,
    ) -> None:
        self._uow_factory = uow_factory
        self._orchestrator = orchestrator

    def rebuild_from_raw(
        self,
        scope: AccessScope,
        time_range: TimeRange | None = None,
        batch_ids: Sequence[UUID] | None = None,
    ) -> ReplayReceipt:
        with self._uow_factory() as uow:
            raw_items = uow.raw_events.iter_for_replay(
                scope=scope, time_range=time_range, batch_ids=batch_ids
            )
            if time_range is None and not batch_ids and scope.allowed_sources is None:
                uow.purge_derived_data(scope.tenant_id)
            for raw_ev in raw_items:
                self._orchestrator.process_raw_event(uow, raw_ev, record_new_failure=True)

            ent_page = uow.entities.search(
                scope=scope,
                time_range=None,
                entity_types=None,
                resolution_states=None,
                identifier_query=None,
                page=PageSpec(limit=10000),
            )
            bounds = uow.normalized_events.get_time_bounds(scope)
            rel_total = 0
            if bounds is not None:
                seen_rels: set[UUID] = set()
                for ent in ent_page.items:
                    rels = uow.graph.get_entity_relations(
                        scope=scope,
                        entity_id=ent.entity_id,
                        time_range=bounds,
                        direction=Direction.BOTH,
                        relation_types=None,
                        include_candidates=True,
                        page=PageSpec(limit=10000),
                    )
                    for r in rels.items:
                        seen_rels.add(r.relation_id)
                rel_total = len(seen_rels)
            uow.commit()
            return ReplayReceipt(
                replayed_raw_events=len(raw_items),
                rebuilt_entities=len(ent_page.items),
                rebuilt_relations=rel_total,
            )
