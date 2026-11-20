from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class QueryGuardConfig:
    default_page_limit: int = 100
    max_page_limit: int = 500
    max_graph_depth: int = 6
    max_graph_nodes: int = 250
    max_graph_edges: int = 600


@dataclass(frozen=True)
class CorrelationConfig:
    network_max_clock_skew_seconds: float = 5.0
    require_five_tuple_for_deterministic: bool = True


@dataclass(frozen=True)
class DetectionConfig:
    max_matches_per_rule: int = 500
    max_execution_seconds: float = 30.0
    candidate_grouping_gap_seconds: float = 3600.0
    extra_rules_dir: str | None = None
    execution_token: str | None = None


@dataclass(frozen=True)
class AppConfig:
    env: str = "development"
    database_url: str = "postgresql+psycopg://provloom:provloom@localhost:5432/provloom"
    ocsf_version: str = "1.3.0"
    mappings_dir: str = "configs/mappings"
    default_tenant: str = "default"
    query_guards: QueryGuardConfig = QueryGuardConfig()
    correlation: CorrelationConfig = CorrelationConfig()
    detection: DetectionConfig = DetectionConfig()

    @classmethod
    def from_env(cls) -> AppConfig:
        exec_token = os.getenv("PROVLOOM_DETECTION_EXEC_TOKEN") or None
        return cls(
            env=os.getenv("PROVLOOM_ENV", "development"),
            database_url=os.getenv("PROVLOOM_DATABASE_URL", "sqlite:///./.provloom_dev.db"),
            default_tenant=os.getenv("PROVLOOM_DEFAULT_TENANT", "default"),
            query_guards=QueryGuardConfig(
                max_page_limit=int(os.getenv("PROVLOOM_MAX_PAGE_LIMIT", "500")),
                max_graph_depth=int(os.getenv("PROVLOOM_MAX_GRAPH_DEPTH", "6")),
            ),
            detection=DetectionConfig(
                max_matches_per_rule=int(os.getenv("PROVLOOM_DETECTION_MAX_MATCHES", "500")),
                max_execution_seconds=float(os.getenv("PROVLOOM_DETECTION_MAX_SECONDS", "30.0")),
                extra_rules_dir=os.getenv("PROVLOOM_RULES_DIR") or None,
                execution_token=exec_token,
            ),
        )
