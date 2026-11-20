from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID

from provloom.domain.common import TimeRange
from provloom.domain.enums import EntityType, RelationType


class RuleSource(str, Enum):
    SIGMA = "SIGMA"
    CUSTOM = "CUSTOM"


class RuleStatus(str, Enum):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"
    UNSUPPORTED = "UNSUPPORTED"
    ERROR = "ERROR"


class RuleSeverity(str, Enum):
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


SEVERITY_RANK: dict[RuleSeverity, int] = {
    RuleSeverity.INFORMATIONAL: 1,
    RuleSeverity.LOW: 2,
    RuleSeverity.MEDIUM: 3,
    RuleSeverity.HIGH: 4,
    RuleSeverity.CRITICAL: 5,
}


def max_severity(a: RuleSeverity, b: RuleSeverity) -> RuleSeverity:
    return a if SEVERITY_RANK[a] >= SEVERITY_RANK[b] else b


class DetectionType(str, Enum):
    EVENT = "EVENT"
    RELATION = "RELATION"


class ExecutionMode(str, Enum):
    BATCH = "BATCH"
    INCREMENTAL = "INCREMENTAL"


class ExecutionStatus(str, Enum):
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    PARTIAL_FAILURE = "PARTIAL_FAILURE"
    FAILED = "FAILED"


class PredicateOperator(str, Enum):
    EQ = "eq"
    NEQ = "neq"
    CONTAINS = "contains"
    STARTSWITH = "startswith"
    ENDSWITH = "endswith"
    REGEX = "regex"
    GT = "gt"
    GTE = "gte"
    LT = "lt"
    LTE = "lte"
    IN = "in"
    EXISTS = "exists"


@dataclass(frozen=True)
class StructuredPredicate:
    field: str
    op: PredicateOperator
    value: Any = None
    case_sensitive: bool = False


@dataclass(frozen=True)
class CustomConditionNode:
    all_of: tuple[CustomConditionNode, ...] = ()
    any_of: tuple[CustomConditionNode, ...] = ()
    not_node: CustomConditionNode | None = None
    predicate: StructuredPredicate | None = None


@dataclass(frozen=True)
class CustomRelationSpec:
    relation_type: RelationType
    src_entity_type: EntityType | None = None
    dst_entity_type: EntityType | None = None
    # Epistemic invariant: never treat timestamp-only candidate edges as causal facts by default.
    deterministic_only: bool = True
    src_predicates: tuple[StructuredPredicate, ...] = ()
    dst_predicates: tuple[StructuredPredicate, ...] = ()
    min_evidence_count: int = 1


@dataclass(frozen=True)
class CustomEventSpec:
    target_class_uids: tuple[int, ...]
    condition: CustomConditionNode


@dataclass(frozen=True)
class LogsourceSpec:
    category: str | None = None
    product: str | None = None
    service: str | None = None


@dataclass(frozen=True)
class RuleCompatibility:
    parse_success: bool
    mapping_success: bool
    data_coverage: bool
    compile_success: bool
    execution_success: bool | None = None
    mapped_class_uids: tuple[int, ...] = ()
    field_mappings: dict[str, str] = field(default_factory=dict)
    uncovered_fields: tuple[str, ...] = ()
    unsupported_reasons: tuple[str, ...] = ()

    @property
    def is_supported(self) -> bool:
        return self.parse_success and self.mapping_success and self.compile_success


@dataclass(frozen=True)
class DetectionRule:
    rule_id: str
    rule_name: str
    source: RuleSource
    source_reference: str
    version: str
    description: str
    severity: RuleSeverity
    attack_tags: tuple[str, ...]
    logsource: LogsourceSpec
    detection_type: DetectionType
    raw_content: str
    status: RuleStatus
    compatibility: RuleCompatibility
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True)
class RuleExecutionFailure:
    rule_id: str
    stage: str
    error_message: str


@dataclass(frozen=True)
class DetectionExecution:
    execution_id: UUID
    tenant_scope: str
    mode: ExecutionMode
    status: ExecutionStatus
    time_range: TimeRange
    rule_ids: tuple[str, ...]
    rules_evaluated: int
    matches_created: int
    matches_deduplicated: int
    signals_created: int
    signals_updated: int
    candidate_groups_created: int
    duration_ms: float
    failures: tuple[RuleExecutionFailure, ...]
    started_at: datetime
    completed_at: datetime | None = None
