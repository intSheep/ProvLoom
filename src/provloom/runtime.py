from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import Engine

from provloom.config import AppConfig
from provloom.detection.rules.registry import BuiltinRuleRegistry
from provloom.detection.service import DefaultDetectionService
from provloom.ingestion.gateway import DefaultIngestionGateway
from provloom.normalization.engine import DefaultMappingRegistry, DefaultNormalizationService
from provloom.observability.prometheus import PrometheusTelemetry
from provloom.parsing.registry import DefaultParserRegistry
from provloom.pipeline.orchestrator import DefaultPipelineOrchestrator, DefaultReplayService
from provloom.query.ops_service import DefaultOpsDebugService
from provloom.query.service import DefaultQueryService
from provloom.storage.postgres.uow import (
    UnitOfWorkFactory,
    create_db_engine,
    init_schema,
    make_uow_factory,
)


@dataclass
class ProvLoomRuntime:
    config: AppConfig
    engine: Engine
    uow_factory: UnitOfWorkFactory
    telemetry: PrometheusTelemetry
    ingestion_gateway: DefaultIngestionGateway
    orchestrator: DefaultPipelineOrchestrator
    replay_service: DefaultReplayService
    query_service: DefaultQueryService
    ops_service: DefaultOpsDebugService
    detection_service: DefaultDetectionService

    @classmethod
    def build(
        cls,
        config: AppConfig | None = None,
        auto_init_schema: bool = True,
        examples_dir: str | Path = "tests/fixtures/examples",
    ) -> ProvLoomRuntime:
        cfg = config or AppConfig.from_env()
        engine = create_db_engine(cfg.database_url)
        if auto_init_schema:
            init_schema(engine)

        uow_factory = make_uow_factory(engine)
        telemetry = PrometheusTelemetry()
        parsers = DefaultParserRegistry.with_defaults()
        mappings = DefaultMappingRegistry.from_yaml_dir(cfg.mappings_dir)
        normalizer = DefaultNormalizationService(registry=mappings, ocsf_version=cfg.ocsf_version)
        gateway = DefaultIngestionGateway(uow_factory=uow_factory, telemetry=telemetry)
        orchestrator = DefaultPipelineOrchestrator(
            uow_factory=uow_factory,
            parser_registry=parsers,
            normalizer=normalizer,
            telemetry=telemetry,
            correlation_config=cfg.correlation,
        )
        replay = DefaultReplayService(uow_factory=uow_factory, orchestrator=orchestrator)
        query_svc = DefaultQueryService(
            uow_factory=uow_factory, telemetry=telemetry, guards=cfg.query_guards
        )
        ops_svc = DefaultOpsDebugService(
            uow_factory=uow_factory,
            gateway=gateway,
            orchestrator=orchestrator,
            replay_service=replay,
            mapping_registry=mappings,
            telemetry=telemetry,
            guards=cfg.query_guards,
            examples_dir=examples_dir,
        )
        rule_registry = BuiltinRuleRegistry(
            mapping_specs=mappings.list_specs(),
            extra_rules_dir=cfg.detection.extra_rules_dir,
        )
        detection_svc = DefaultDetectionService(
            uow_factory=uow_factory,
            rule_registry=rule_registry,
            telemetry=telemetry,
            guards=cfg.query_guards,
            detection_config=cfg.detection,
        )
        return cls(
            config=cfg,
            engine=engine,
            uow_factory=uow_factory,
            telemetry=telemetry,
            ingestion_gateway=gateway,
            orchestrator=orchestrator,
            replay_service=replay,
            query_service=query_svc,
            ops_service=ops_svc,
            detection_service=detection_svc,
        )
