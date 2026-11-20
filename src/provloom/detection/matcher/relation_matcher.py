from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Any
from uuid import NAMESPACE_URL, UUID, uuid5

from provloom.detection.domain.rule import (
    CustomRelationSpec,
    DetectionRule,
    DetectionType,
    PredicateOperator,
    StructuredPredicate,
)
from provloom.detection.domain.rule_match import EvidenceReference, RuleMatch
from provloom.detection.signals.deduplicator import compute_match_dedup_key
from provloom.domain.common import AccessScope, PageSpec, TimeRange
from provloom.domain.entity_models import Entity
from provloom.domain.enums import Certainty, Direction
from provloom.storage.interfaces import UnitOfWork
from provloom.storage.postgres.utils import extract_nested


def _extract_entity_field(entity: Entity, field: str) -> Any:
    if field == "display_label":
        return entity.display_label
    if field == "canonical_key":
        return entity.canonical_key
    if field == "entity_type":
        return entity.entity_type.value
    if field == "resolution_state":
        return entity.resolution_state.value
    if field.startswith("attributes."):
        return extract_nested(entity.attributes, field.removeprefix("attributes."))
    return extract_nested(entity.attributes, field)


def _eval_predicate_on_entity(entity: Entity, pred: StructuredPredicate) -> bool:
    actual = _extract_entity_field(entity, pred.field)
    op = pred.op
    expected = pred.value

    if op == PredicateOperator.EXISTS:
        return (actual is not None) if bool(expected) else (actual is None)
    if actual is None:
        return op == PredicateOperator.NEQ

    if op in (
        PredicateOperator.GT,
        PredicateOperator.GTE,
        PredicateOperator.LT,
        PredicateOperator.LTE,
    ):
        try:
            num_a = float(actual)
            num_b = float(expected)
        except (TypeError, ValueError):
            return False
        if op == PredicateOperator.GT:
            return num_a > num_b
        if op == PredicateOperator.GTE:
            return num_a >= num_b
        if op == PredicateOperator.LT:
            return num_a < num_b
        return num_a <= num_b

    s_act = str(actual) if pred.case_sensitive else str(actual).lower()
    if op == PredicateOperator.IN:
        if not isinstance(expected, list):
            return False
        targets = [str(x) if pred.case_sensitive else str(x).lower() for x in expected]
        return s_act in targets

    s_exp = str(expected) if pred.case_sensitive else str(expected).lower()
    if op == PredicateOperator.EQ:
        if isinstance(actual, (int, float)) and isinstance(expected, (int, float)):
            return float(actual) == float(expected)
        return s_act == s_exp
    if op == PredicateOperator.NEQ:
        return s_act != s_exp
    if op == PredicateOperator.CONTAINS:
        return s_exp in s_act
    if op == PredicateOperator.STARTSWITH:
        return s_act.startswith(s_exp)
    if op == PredicateOperator.ENDSWITH:
        return s_act.endswith(s_exp)
    if op == PredicateOperator.REGEX:
        flags = 0 if pred.case_sensitive else re.IGNORECASE
        return re.search(str(expected), str(actual), flags) is not None
    return False


class GraphRelationMatcher:
    """Evaluates 1-hop entity relation rules via GraphRepository while preserving certainty."""

    def match_batch(
        self,
        uow: UnitOfWork,
        scope: AccessScope,
        time_range: TimeRange,
        rule: DetectionRule,
        spec: CustomRelationSpec,
        execution_id: UUID,
        max_matches: int = 500,
    ) -> Sequence[RuleMatch]:
        src_types = (spec.src_entity_type,) if spec.src_entity_type is not None else None
        seed_entities = uow.entities.search(
            scope=scope,
            time_range=time_range,
            entity_types=src_types,
            resolution_states=None,
            identifier_query=None,
            page=PageSpec(limit=500),
        ).items

        matches: list[RuleMatch] = []
        seen_relation_ids: set[UUID] = set()

        for src_ent in seed_entities:
            if src_ent.merged_into_id is not None:
                continue
            if not all(_eval_predicate_on_entity(src_ent, p) for p in spec.src_predicates):
                continue

            rels = uow.graph.get_entity_relations(
                scope=scope,
                entity_id=src_ent.entity_id,
                time_range=time_range,
                direction=Direction.OUTBOUND,
                relation_types=(spec.relation_type,),
                include_candidates=not spec.deterministic_only,
                page=PageSpec(limit=200),
            ).items

            for rel in rels:
                if rel.relation_id in seen_relation_ids:
                    continue
                if spec.deterministic_only and rel.certainty != Certainty.DETERMINISTIC:
                    continue
                if rel.evidence_count < spec.min_evidence_count:
                    continue

                dst_detail = uow.entities.get_detail(
                    scope=scope, entity_id=rel.dst_entity_id, follow_merged=True
                )
                if dst_detail is None:
                    continue
                dst_ent = dst_detail.entity
                if spec.dst_entity_type is not None and dst_ent.entity_type != spec.dst_entity_type:
                    continue
                if not all(_eval_predicate_on_entity(dst_ent, p) for p in spec.dst_predicates):
                    continue

                ev_page = uow.graph.get_relation_evidence(
                    scope=scope,
                    relation_id=rel.relation_id,
                    time_range=time_range,
                    page=PageSpec(limit=100),
                )
                if len(ev_page.items) < spec.min_evidence_count:
                    continue

                seen_relation_ids.add(rel.relation_id)
                ev_refs = tuple(
                    EvidenceReference(
                        event_id=e.evidence.event_id,
                        raw_event_id=e.evidence.raw_event_id,
                        relation_id=rel.relation_id,
                        source_id=e.source_id,
                        observed_at=e.evidence.observed_at,
                    )
                    for e in ev_page.items
                )
                ev_ids = tuple(dict.fromkeys(e.evidence.event_id for e in ev_page.items))
                src_ids = tuple(dict.fromkeys(e.source_id for e in ev_page.items))

                matched_vals: dict[str, Any] = {
                    "relation_type": rel.relation_type.value,
                    "certainty": rel.certainty.value,
                    "src_label": src_ent.display_label,
                    "dst_label": dst_ent.display_label,
                }
                for p in spec.src_predicates:
                    matched_vals[f"src.{p.field}"] = _extract_entity_field(src_ent, p.field)
                for p in spec.dst_predicates:
                    matched_vals[f"dst.{p.field}"] = _extract_entity_field(dst_ent, p.field)

                dedup_key = compute_match_dedup_key(
                    tenant_scope=scope.tenant_id,
                    rule_id=rule.rule_id,
                    rule_version=rule.version,
                    detection_type=DetectionType.RELATION,
                    anchor_id=rel.relation_id,
                )
                match_id = uuid5(NAMESPACE_URL, f"provloom:rulematch:{dedup_key}")
                matches.append(
                    RuleMatch(
                        match_id=match_id,
                        tenant_scope=scope.tenant_id,
                        dedup_key=dedup_key,
                        rule_id=rule.rule_id,
                        rule_name=rule.rule_name,
                        rule_version=rule.version,
                        severity=rule.severity,
                        detection_type=DetectionType.RELATION,
                        primary_event_id=ev_ids[0] if ev_ids else None,
                        matched_event_ids=ev_ids,
                        primary_entity_id=src_ent.entity_id,
                        related_entity_ids=(dst_ent.entity_id,),
                        matched_fields=tuple(matched_vals.keys()),
                        matched_values=matched_vals,
                        evidence_references=ev_refs,
                        source_ids=src_ids,
                        matched_at=rel.last_seen_at,
                        execution_id=execution_id,
                    )
                )
                if len(matches) >= max_matches:
                    return tuple(matches)

        return tuple(matches)
