from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import NAMESPACE_URL, uuid5

import yaml
from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule
from sigma.exceptions import SigmaError
from sigma.modifiers import (
    SigmaBase64OffsetModifier,
    SigmaCIDRModifier,
    SigmaExpandModifier,
    SigmaFieldReferenceModifier,
    SigmaModifier,
    SigmaTimestampModifier,
)
from sigma.rule import SigmaDetection, SigmaDetectionItem, SigmaRule

from provloom.detection.domain.rule import (
    CustomConditionNode,
    CustomEventSpec,
    CustomRelationSpec,
    DetectionType,
    LogsourceSpec,
    PredicateOperator,
    RuleSeverity,
    RuleSource,
    StructuredPredicate,
)
from provloom.domain.enums import EntityType, RelationType

_FORBIDDEN_CUSTOM_KEYS: frozenset[str] = frozenset(
    {"sql", "raw_sql", "query_sql", "python", "python_code", "code", "eval", "exec", "script"}
)

_FIELD_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")

_UNSUPPORTED_SIGMA_MODIFIERS: tuple[type[SigmaModifier[Any, Any]], ...] = (
    SigmaExpandModifier,
    SigmaFieldReferenceModifier,
    SigmaBase64OffsetModifier,
    SigmaCIDRModifier,
    SigmaTimestampModifier,
)

_SIGMA_LEVEL_MAP: dict[str, RuleSeverity] = {
    "informational": RuleSeverity.INFORMATIONAL,
    "low": RuleSeverity.LOW,
    "medium": RuleSeverity.MEDIUM,
    "high": RuleSeverity.HIGH,
    "critical": RuleSeverity.CRITICAL,
}


@dataclass(frozen=True)
class ParsedRuleEnvelope:
    parse_success: bool
    source: RuleSource
    detection_type: DetectionType
    rule_id: str
    rule_name: str
    version: str
    description: str
    severity: RuleSeverity
    attack_tags: tuple[str, ...]
    logsource: LogsourceSpec
    desired_enabled: bool
    sigma_rule: SigmaRule | None = None
    custom_event_spec: CustomEventSpec | None = None
    custom_relation_spec: CustomRelationSpec | None = None
    original_fields: tuple[str, ...] = ()
    semantic_errors: tuple[str, ...] = ()
    parse_errors: tuple[str, ...] = ()
    parsed_ast_preview: dict[str, Any] | None = None


def _contains_forbidden_keys(obj: Any) -> str | None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            key_str = str(k).lower()
            if key_str in _FORBIDDEN_CUSTOM_KEYS:
                return key_str
            nested = _contains_forbidden_keys(v)
            if nested is not None:
                return nested
    elif isinstance(obj, list):
        for item in obj:
            nested = _contains_forbidden_keys(item)
            if nested is not None:
                return nested
    return None


def _extract_attack_tags(raw_tags: list[Any]) -> tuple[str, ...]:
    tags: list[str] = []
    for t in raw_tags:
        s = str(t).strip()
        if s:
            tags.append(s)
    return tuple(dict.fromkeys(tags))


def _parse_severity(raw_level: Any) -> RuleSeverity:
    if raw_level is None:
        return RuleSeverity.MEDIUM
    val = str(raw_level).strip().lower()
    return _SIGMA_LEVEL_MAP.get(val, RuleSeverity.MEDIUM)


def _walk_sigma_detections(
    det: SigmaDetection,
    fields_out: list[str],
    semantic_errors: list[str],
) -> None:
    for item in det.detection_items:
        if isinstance(item, SigmaDetection):
            _walk_sigma_detections(item, fields_out, semantic_errors)
        elif isinstance(item, SigmaDetectionItem):
            if item.field is None:
                semantic_errors.append(
                    "Unbound keyword detection without field name is unsupported"
                )
            else:
                fields_out.append(item.field)
            for mod in item.modifiers:
                if issubclass(mod, _UNSUPPORTED_SIGMA_MODIFIERS):
                    semantic_errors.append(f"Unsupported Sigma modifier: {mod.__name__}")


def _parse_predicate(raw: Any, errors: list[str]) -> StructuredPredicate | None:
    if not isinstance(raw, dict):
        errors.append("Predicate must be a mapping")
        return None
    field_name = str(raw.get("field") or "").strip()
    if not field_name or not _FIELD_NAME_RE.match(field_name):
        errors.append(f"Invalid structured predicate field name: {field_name!r}")
        return None
    raw_op = str(raw.get("op") or "eq").strip().lower()
    try:
        op = PredicateOperator(raw_op)
    except ValueError:
        errors.append(f"Unsupported structured predicate operator: {raw_op!r}")
        return None
    if op != PredicateOperator.EXISTS and "value" not in raw:
        errors.append(f"Predicate on {field_name!r} with op {op.value!r} requires 'value'")
        return None
    val = raw.get("value", True if op == PredicateOperator.EXISTS else None)
    if op == PredicateOperator.REGEX and not isinstance(val, str):
        errors.append(f"Regex predicate on {field_name!r} requires string pattern")
        return None
    if op == PredicateOperator.REGEX and isinstance(val, str):
        try:
            re.compile(val)
        except re.error as exc:
            errors.append(f"Invalid regex pattern on {field_name!r}: {exc}")
            return None
    return StructuredPredicate(
        field=field_name,
        op=op,
        value=val,
        case_sensitive=bool(raw.get("case_sensitive", False)),
    )


def _parse_custom_condition(raw: Any, errors: list[str]) -> CustomConditionNode | None:
    if not isinstance(raw, dict):
        errors.append("Condition node must be a mapping")
        return None
    if "all" in raw:
        items = raw["all"]
        if not isinstance(items, list) or not items:
            errors.append("'all' condition requires a non-empty list")
            return None
        children = [_parse_custom_condition(c, errors) for c in items]
        if any(c is None for c in children):
            return None
        return CustomConditionNode(all_of=tuple(c for c in children if c is not None))
    if "any" in raw:
        items = raw["any"]
        if not isinstance(items, list) or not items:
            errors.append("'any' condition requires a non-empty list")
            return None
        children = [_parse_custom_condition(c, errors) for c in items]
        if any(c is None for c in children):
            return None
        return CustomConditionNode(any_of=tuple(c for c in children if c is not None))
    if "not" in raw:
        child = _parse_custom_condition(raw["not"], errors)
        if child is None:
            return None
        return CustomConditionNode(not_node=child)
    pred = _parse_predicate(raw, errors)
    if pred is None:
        return None
    return CustomConditionNode(predicate=pred)


def _collect_custom_fields(node: CustomConditionNode, out: list[str]) -> None:
    if node.predicate is not None:
        out.append(node.predicate.field)
    for c in node.all_of:
        _collect_custom_fields(c, out)
    for c in node.any_of:
        _collect_custom_fields(c, out)
    if node.not_node is not None:
        _collect_custom_fields(node.not_node, out)


def _is_custom_rule_doc(doc: dict[str, Any], source_hint: RuleSource | None) -> bool:
    if source_hint == RuleSource.CUSTOM:
        return True
    if str(doc.get("source") or "").upper() == "CUSTOM":
        return True
    if str(doc.get("rule_type") or "").lower() == "provloom_custom":
        return True
    return "relation_spec" in doc or "event_spec" in doc


def parse_rule_yaml(
    raw_yaml: str,
    source_hint: RuleSource | None = None,
) -> ParsedRuleEnvelope:
    fallback_id = str(uuid5(NAMESPACE_URL, f"provloom:rule:{raw_yaml.strip()}"))
    try:
        docs = [d for d in yaml.safe_load_all(raw_yaml) if d is not None]
    except yaml.YAMLError as exc:
        return ParsedRuleEnvelope(
            parse_success=False,
            source=source_hint or RuleSource.SIGMA,
            detection_type=DetectionType.EVENT,
            rule_id=fallback_id,
            rule_name="Malformed YAML Rule",
            version="1.0.0",
            description="",
            severity=RuleSeverity.MEDIUM,
            attack_tags=(),
            logsource=LogsourceSpec(),
            desired_enabled=False,
            parse_errors=(f"YAML syntax error: {exc}",),
        )

    if not docs or not isinstance(docs[0], dict):
        return ParsedRuleEnvelope(
            parse_success=False,
            source=source_hint or RuleSource.SIGMA,
            detection_type=DetectionType.EVENT,
            rule_id=fallback_id,
            rule_name="Empty or Non-Mapping Rule",
            version="1.0.0",
            description="",
            severity=RuleSeverity.MEDIUM,
            attack_tags=(),
            logsource=LogsourceSpec(),
            desired_enabled=False,
            parse_errors=("Rule YAML root must be a non-empty mapping",),
        )

    primary_doc = docs[0]
    forbidden = _contains_forbidden_keys(docs)
    if forbidden is not None:
        return ParsedRuleEnvelope(
            parse_success=False,
            source=RuleSource.CUSTOM
            if _is_custom_rule_doc(primary_doc, source_hint)
            else RuleSource.SIGMA,
            detection_type=DetectionType.EVENT,
            rule_id=str(primary_doc.get("id") or primary_doc.get("rule_id") or fallback_id),
            rule_name=str(
                primary_doc.get("title") or primary_doc.get("rule_name") or "Rejected Rule"
            ),
            version=str(primary_doc.get("version") or "1.0.0"),
            description=str(primary_doc.get("description") or ""),
            severity=_parse_severity(primary_doc.get("level") or primary_doc.get("severity")),
            attack_tags=(),
            logsource=LogsourceSpec(),
            desired_enabled=False,
            parse_errors=(
                f"Arbitrary SQL or code key '{forbidden}' is forbidden; rules must be structured",
            ),
        )

    if _is_custom_rule_doc(primary_doc, source_hint):
        return _parse_custom_doc(primary_doc, fallback_id)

    return _parse_sigma_yaml(raw_yaml, primary_doc, docs, fallback_id)


def _parse_custom_doc(doc: dict[str, Any], fallback_id: str) -> ParsedRuleEnvelope:
    rule_id = str(doc.get("rule_id") or doc.get("id") or fallback_id).strip()
    rule_name = str(doc.get("rule_name") or doc.get("title") or rule_id).strip()
    version = str(doc.get("version") or "1.0.0")
    description = str(doc.get("description") or "")
    severity = _parse_severity(doc.get("severity") or doc.get("level"))
    raw_tags_val = doc.get("attack_tags") or doc.get("tags")
    tags = _extract_attack_tags(list(raw_tags_val) if isinstance(raw_tags_val, list) else [])
    ls_obj = doc.get("logsource")
    ls_raw: dict[str, Any] = ls_obj if isinstance(ls_obj, dict) else {}
    logsource = LogsourceSpec(
        category=str(ls_raw["category"]) if ls_raw.get("category") else None,
        product=str(ls_raw["product"]) if ls_raw.get("product") else None,
        service=str(ls_raw["service"]) if ls_raw.get("service") else None,
    )
    enabled = str(doc.get("status") or "ENABLED").upper() != "DISABLED"

    raw_dtype = str(
        doc.get("detection_type") or ("RELATION" if "relation_spec" in doc else "EVENT")
    ).upper()
    try:
        dtype = DetectionType(raw_dtype)
    except ValueError:
        return ParsedRuleEnvelope(
            parse_success=False,
            source=RuleSource.CUSTOM,
            detection_type=DetectionType.EVENT,
            rule_id=rule_id,
            rule_name=rule_name,
            version=version,
            description=description,
            severity=severity,
            attack_tags=tags,
            logsource=logsource,
            desired_enabled=False,
            parse_errors=(f"Unsupported custom detection_type: {raw_dtype!r}",),
        )

    errors: list[str] = []
    if dtype == DetectionType.RELATION:
        spec_raw = doc.get("relation_spec")
        if not isinstance(spec_raw, dict):
            return ParsedRuleEnvelope(
                parse_success=False,
                source=RuleSource.CUSTOM,
                detection_type=DetectionType.RELATION,
                rule_id=rule_id,
                rule_name=rule_name,
                version=version,
                description=description,
                severity=severity,
                attack_tags=tags,
                logsource=logsource,
                desired_enabled=False,
                parse_errors=("RELATION custom rule requires 'relation_spec' mapping",),
            )
        if spec_raw.get("max_hops") not in (None, 1):
            return ParsedRuleEnvelope(
                parse_success=True,
                source=RuleSource.CUSTOM,
                detection_type=DetectionType.RELATION,
                rule_id=rule_id,
                rule_name=rule_name,
                version=version,
                description=description,
                severity=severity,
                attack_tags=tags,
                logsource=logsource,
                desired_enabled=enabled,
                semantic_errors=(
                    "Multi-hop graph pattern matching (max_hops > 1) is deferred in MVP",
                ),
            )
        try:
            rel_type = RelationType(str(spec_raw["relation_type"]).upper())
        except (KeyError, ValueError) as exc:
            errors.append(f"Invalid or missing relation_type in relation_spec: {exc}")
            rel_type = RelationType.CONNECTS_TO

        src_type: EntityType | None = None
        if spec_raw.get("src_entity_type") is not None:
            try:
                src_type = EntityType(str(spec_raw["src_entity_type"]).upper())
            except ValueError:
                errors.append(f"Invalid src_entity_type: {spec_raw['src_entity_type']!r}")

        dst_type: EntityType | None = None
        if spec_raw.get("dst_entity_type") is not None:
            try:
                dst_type = EntityType(str(spec_raw["dst_entity_type"]).upper())
            except ValueError:
                errors.append(f"Invalid dst_entity_type: {spec_raw['dst_entity_type']!r}")

        src_preds = [
            _parse_predicate(p, errors) for p in list(spec_raw.get("src_predicates") or [])
        ]
        dst_preds = [
            _parse_predicate(p, errors) for p in list(spec_raw.get("dst_predicates") or [])
        ]
        if errors:
            return ParsedRuleEnvelope(
                parse_success=False,
                source=RuleSource.CUSTOM,
                detection_type=DetectionType.RELATION,
                rule_id=rule_id,
                rule_name=rule_name,
                version=version,
                description=description,
                severity=severity,
                attack_tags=tags,
                logsource=logsource,
                desired_enabled=False,
                parse_errors=tuple(errors),
            )

        rel_spec = CustomRelationSpec(
            relation_type=rel_type,
            src_entity_type=src_type,
            dst_entity_type=dst_type,
            deterministic_only=bool(spec_raw.get("deterministic_only", True)),
            src_predicates=tuple(p for p in src_preds if p is not None),
            dst_predicates=tuple(p for p in dst_preds if p is not None),
            min_evidence_count=max(1, int(spec_raw.get("min_evidence_count", 1))),
        )
        ref_fields = [f"src.{p.field}" for p in rel_spec.src_predicates] + [
            f"dst.{p.field}" for p in rel_spec.dst_predicates
        ]
        return ParsedRuleEnvelope(
            parse_success=True,
            source=RuleSource.CUSTOM,
            detection_type=DetectionType.RELATION,
            rule_id=rule_id,
            rule_name=rule_name,
            version=version,
            description=description,
            severity=severity,
            attack_tags=tags,
            logsource=logsource,
            desired_enabled=enabled,
            custom_relation_spec=rel_spec,
            original_fields=tuple(ref_fields),
            parsed_ast_preview={
                "type": "custom_relation_1hop",
                "relation_type": rel_spec.relation_type.value,
                "src_entity_type": rel_spec.src_entity_type.value
                if rel_spec.src_entity_type
                else None,
                "dst_entity_type": rel_spec.dst_entity_type.value
                if rel_spec.dst_entity_type
                else None,
                "deterministic_only": rel_spec.deterministic_only,
            },
        )

    ev_raw = doc.get("event_spec")
    if not isinstance(ev_raw, dict):
        return ParsedRuleEnvelope(
            parse_success=False,
            source=RuleSource.CUSTOM,
            detection_type=DetectionType.EVENT,
            rule_id=rule_id,
            rule_name=rule_name,
            version=version,
            description=description,
            severity=severity,
            attack_tags=tags,
            logsource=logsource,
            desired_enabled=False,
            parse_errors=("EVENT custom rule requires 'event_spec' mapping",),
        )
    raw_classes = ev_raw.get("target_class_uids") or []
    if not isinstance(raw_classes, list) or not all(isinstance(x, int) for x in raw_classes):
        errors.append("'target_class_uids' must be a list of integer OCSF class_uids")
        class_uids: tuple[int, ...] = ()
    else:
        class_uids = tuple(int(x) for x in raw_classes)

    cond_node = _parse_custom_condition(ev_raw.get("condition"), errors)
    if errors or cond_node is None:
        return ParsedRuleEnvelope(
            parse_success=False,
            source=RuleSource.CUSTOM,
            detection_type=DetectionType.EVENT,
            rule_id=rule_id,
            rule_name=rule_name,
            version=version,
            description=description,
            severity=severity,
            attack_tags=tags,
            logsource=logsource,
            desired_enabled=False,
            parse_errors=tuple(errors or ["Invalid custom event condition"]),
        )

    fields_out: list[str] = []
    _collect_custom_fields(cond_node, fields_out)
    return ParsedRuleEnvelope(
        parse_success=True,
        source=RuleSource.CUSTOM,
        detection_type=DetectionType.EVENT,
        rule_id=rule_id,
        rule_name=rule_name,
        version=version,
        description=description,
        severity=severity,
        attack_tags=tags,
        logsource=logsource,
        desired_enabled=enabled,
        custom_event_spec=CustomEventSpec(target_class_uids=class_uids, condition=cond_node),
        original_fields=tuple(dict.fromkeys(fields_out)),
        parsed_ast_preview={
            "type": "custom_ocsf_event",
            "target_class_uids": list(class_uids),
            "fields": list(dict.fromkeys(fields_out)),
        },
    )


def _parse_sigma_yaml(
    raw_yaml: str,
    primary_doc: dict[str, Any],
    all_docs: list[Any],
    fallback_id: str,
) -> ParsedRuleEnvelope:
    doc_id = str(primary_doc.get("id") or fallback_id)
    doc_title = str(primary_doc.get("title") or doc_id)
    doc_ver = str(primary_doc.get("version") or primary_doc.get("date") or "1.0.0")
    doc_desc = str(primary_doc.get("description") or "")
    doc_sev = _parse_severity(primary_doc.get("level"))
    raw_tags_obj = primary_doc.get("tags")
    raw_tags: list[Any] = raw_tags_obj if isinstance(raw_tags_obj, list) else []
    attack_tags = _extract_attack_tags(raw_tags)
    ls_doc = primary_doc.get("logsource")
    ls_dict: dict[str, Any] = ls_doc if isinstance(ls_doc, dict) else {}
    logsource = LogsourceSpec(
        category=str(ls_dict["category"]) if ls_dict.get("category") else None,
        product=str(ls_dict["product"]) if ls_dict.get("product") else None,
        service=str(ls_dict["service"]) if ls_dict.get("service") else None,
    )
    enabled = str(primary_doc.get("provloom_status") or "ENABLED").upper() != "DISABLED"

    # Explicit detection of Sigma Correlation Rules before or during collection loading.
    if any(isinstance(d, dict) and "correlation" in d for d in all_docs):
        return ParsedRuleEnvelope(
            parse_success=True,
            source=RuleSource.SIGMA,
            detection_type=DetectionType.EVENT,
            rule_id=doc_id,
            rule_name=doc_title,
            version=doc_ver,
            description=doc_desc,
            severity=doc_sev,
            attack_tags=attack_tags,
            logsource=logsource,
            desired_enabled=enabled,
            semantic_errors=("Sigma correlation rules are deferred in MVP",),
            parsed_ast_preview={"type": "sigma_correlation", "supported": False},
        )

    det_block = primary_doc.get("detection")
    has_timeframe = isinstance(det_block, dict) and "timeframe" in det_block
    if "timeframe" in primary_doc:
        has_timeframe = True

    try:
        collection = SigmaCollection.from_yaml(raw_yaml)
    except SigmaError as exc:
        return ParsedRuleEnvelope(
            parse_success=False,
            source=RuleSource.SIGMA,
            detection_type=DetectionType.EVENT,
            rule_id=doc_id,
            rule_name=doc_title,
            version=doc_ver,
            description=doc_desc,
            severity=doc_sev,
            attack_tags=attack_tags,
            logsource=logsource,
            desired_enabled=False,
            parse_errors=(f"pySigma parse error: {exc}",),
        )

    if not collection.rules:
        return ParsedRuleEnvelope(
            parse_success=False,
            source=RuleSource.SIGMA,
            detection_type=DetectionType.EVENT,
            rule_id=doc_id,
            rule_name=doc_title,
            version=doc_ver,
            description=doc_desc,
            severity=doc_sev,
            attack_tags=attack_tags,
            logsource=logsource,
            desired_enabled=False,
            parse_errors=("No Sigma rule definitions found in YAML",),
        )

    first_rule = collection.rules[0]
    if isinstance(first_rule, SigmaCorrelationRule) or not isinstance(first_rule, SigmaRule):
        return ParsedRuleEnvelope(
            parse_success=True,
            source=RuleSource.SIGMA,
            detection_type=DetectionType.EVENT,
            rule_id=str(first_rule.id) if first_rule.id else doc_id,
            rule_name=first_rule.title or doc_title,
            version=doc_ver,
            description=first_rule.description or doc_desc,
            severity=doc_sev,
            attack_tags=attack_tags,
            logsource=logsource,
            desired_enabled=enabled,
            semantic_errors=("Sigma correlation rules are deferred in MVP",),
            parsed_ast_preview={"type": "sigma_correlation", "supported": False},
        )

    semantic_errors: list[str] = []
    if has_timeframe:
        semantic_errors.append("Temporal aggregation ('timeframe') is deferred in MVP")
    if len(collection.rules) > 1:
        semantic_errors.append(
            "Multi-document Sigma rule collections require individual rule import"
        )

    fields_out: list[str] = []
    for det in first_rule.detection.detections.values():
        _walk_sigma_detections(det, fields_out, semantic_errors)

    try:
        cond_strs = [str(c.condition) for c in first_rule.detection.parsed_condition]
        for c in first_rule.detection.parsed_condition:
            c.parse()
    except SigmaError as exc:
        semantic_errors.append(f"Unsupported Sigma condition expression: {exc}")
        cond_strs = list(first_rule.detection.condition)

    rule_id_str = str(first_rule.id) if first_rule.id else doc_id
    tags_tuple = tuple(str(t) for t in first_rule.tags) if first_rule.tags else attack_tags
    level_str = first_rule.level.name.lower() if first_rule.level else None
    resolved_sev = _SIGMA_LEVEL_MAP.get(level_str, doc_sev) if level_str else doc_sev
    resolved_ver = (
        str(primary_doc["version"])
        if primary_doc.get("version")
        else (str(first_rule.date) if first_rule.date else doc_ver)
    )

    return ParsedRuleEnvelope(
        parse_success=True,
        source=RuleSource.SIGMA,
        detection_type=DetectionType.EVENT,
        rule_id=rule_id_str,
        rule_name=first_rule.title or doc_title,
        version=resolved_ver,
        description=first_rule.description or doc_desc,
        severity=resolved_sev,
        attack_tags=tags_tuple,
        logsource=LogsourceSpec(
            category=first_rule.logsource.category,
            product=first_rule.logsource.product,
            service=first_rule.logsource.service,
        ),
        desired_enabled=enabled,
        sigma_rule=first_rule,
        original_fields=tuple(dict.fromkeys(fields_out)),
        semantic_errors=tuple(dict.fromkeys(semantic_errors)),
        parsed_ast_preview={
            "type": "sigma_rule",
            "id": rule_id_str,
            "title": first_rule.title,
            "logsource": {
                "category": first_rule.logsource.category,
                "product": first_rule.logsource.product,
                "service": first_rule.logsource.service,
            },
            "selections": list(first_rule.detection.detections.keys()),
            "conditions": cond_strs,
            "original_fields": list(dict.fromkeys(fields_out)),
            "parsed_at": datetime.now(UTC).isoformat(),
        },
    )
