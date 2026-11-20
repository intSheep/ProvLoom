from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.rule import SigmaRule
from sigma.types import (
    SigmaBool,
    SigmaCasedString,
    SigmaCompareExpression,
    SigmaExists,
    SigmaNull,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaRegularExpressionFlag,
    SigmaString,
    SigmaType,
    SpecialChars,
)
from sqlalchemy import (
    ColumnElement,
    Float,
    Numeric,
    Select,
    String,
    and_,
    bindparam,
    case,
    cast,
    exists,
    false,
    func,
    literal,
    not_,
    or_,
    select,
    true,
)
from sqlalchemy.dialects import postgresql
from sqlalchemy.dialects.postgresql import JSONB

from provloom.detection.compiler.ocsf_pipeline import (
    ARRAY_OCSF_FIELDS,
    KNOWN_OCSF_V13_FIELDS,
    apply_ocsf_pipeline,
    evaluate_data_coverage,
)
from provloom.detection.compiler.sigma_parser import ParsedRuleEnvelope, parse_rule_yaml
from provloom.detection.domain.rule import (
    CustomConditionNode,
    CustomEventSpec,
    CustomRelationSpec,
    DetectionRule,
    DetectionType,
    PredicateOperator,
    RuleCompatibility,
    RuleSource,
    RuleStatus,
    StructuredPredicate,
)
from provloom.domain.common import AccessScope, TimeRange
from provloom.domain.enums import NormalizationStatus
from provloom.normalization.interfaces import MappingSpecSummary
from provloom.storage.postgres.tables import normalized_events

_SAFE_OCSF_FIELD_RE = re.compile(r"^[A-Za-z0-9_]+(\.[A-Za-z0-9_]+)*$")
_ENVELOPE_SYNTHETIC_FIELDS: frozenset[str] = frozenset(
    {"class_uid", "category_uid", "activity_id", "type_uid"}
)


@dataclass(frozen=True)
class CompiledEventQuery:
    postgres_sql: str
    mapped_class_uids: tuple[int, ...]
    referenced_fields: tuple[str, ...]
    user_matched_fields: tuple[str, ...]
    _builder: Callable[[str], ColumnElement[bool]]

    def build_select(
        self,
        dialect_name: str,
        scope: AccessScope,
        time_range: TimeRange,
        limit: int,
        event_ids: Sequence[UUID] | None = None,
    ) -> Select[Any]:
        stmt = select(normalized_events).where(
            normalized_events.c.tenant_scope == bindparam("tenant_id", scope.tenant_id),
            normalized_events.c.event_time >= bindparam("start_time", time_range.start_time),
            normalized_events.c.event_time <= bindparam("end_time", time_range.end_time),
            normalized_events.c.normalization_status == NormalizationStatus.MAPPED.value,
        )
        if scope.allowed_sources is not None:
            if not scope.allowed_sources:
                stmt = stmt.where(false())
            else:
                stmt = stmt.where(normalized_events.c.source_id.in_(sorted(scope.allowed_sources)))
        if event_ids is not None:
            if not event_ids:
                stmt = stmt.where(false())
            else:
                stmt = stmt.where(normalized_events.c.event_id.in_(list(event_ids)))
        if self.mapped_class_uids:
            stmt = stmt.where(normalized_events.c.class_uid.in_(list(self.mapped_class_uids)))

        stmt = stmt.where(self._builder(dialect_name))
        stmt = stmt.order_by(
            normalized_events.c.event_time.asc(),
            normalized_events.c.event_id.asc(),
        ).limit(limit)
        return stmt


@dataclass(frozen=True)
class CompiledRuleArtifact:
    rule: DetectionRule
    event_query: CompiledEventQuery | None = None
    relation_spec: CustomRelationSpec | None = None
    parsed_summary: dict[str, Any] | None = None


class _ParamCounter:
    def __init__(self) -> None:
        self._n = 0

    def next_param(self, val: Any) -> Any:
        self._n += 1
        return bindparam(f"det_p_{self._n}", value=val)


def _validate_ocsf_field(field: str) -> None:
    if not _SAFE_OCSF_FIELD_RE.match(field):
        raise ValueError(f"Unsafe field identifier: {field!r}")
    if field not in KNOWN_OCSF_V13_FIELDS:
        raise ValueError(f"Unmapped or unsupported OCSF field: {field!r}")


def _extract_text_expr(field: str, dialect_name: str) -> ColumnElement[Any]:
    if field == "source_id":
        return normalized_events.c.source_id
    if field == "ocsf_version":
        return normalized_events.c.ocsf_version
    if field == "original_event_uid":
        return normalized_events.c.original_event_uid
    if field == "class_uid":
        return cast(normalized_events.c.class_uid, String)
    if field == "category_uid":
        return cast(normalized_events.c.category_uid, String)
    if field == "activity_id":
        return cast(normalized_events.c.activity_id, String)
    if field == "type_uid":
        return cast(normalized_events.c.class_uid * 100 + normalized_events.c.activity_id, String)

    parts = field.split(".")
    if dialect_name == "postgresql":
        return normalized_events.c.ocsf_payload.op("#>>")(postgresql.array(parts))
    json_path = "$." + ".".join(parts)
    return cast(func.json_extract(normalized_events.c.ocsf_payload, json_path), String)


def _extract_numeric_expr(field: str, dialect_name: str) -> ColumnElement[Any]:
    if field == "class_uid":
        return normalized_events.c.class_uid
    if field == "category_uid":
        return normalized_events.c.category_uid
    if field == "activity_id":
        return normalized_events.c.activity_id
    if field == "type_uid":
        return normalized_events.c.class_uid * 100 + normalized_events.c.activity_id

    parts = field.split(".")
    if dialect_name == "postgresql":
        txt = normalized_events.c.ocsf_payload.op("#>>")(postgresql.array(parts))
        return case(
            (txt.op("~")(r"^-?[0-9]+(\.[0-9]+)?$"), cast(txt, Numeric)),
            else_=None,
        )
    json_path = "$." + ".".join(parts)
    jtype = func.json_type(normalized_events.c.ocsf_payload, json_path)
    return case(
        (
            jtype.in_(["integer", "real"]),
            cast(func.json_extract(normalized_events.c.ocsf_payload, json_path), Float),
        ),
        else_=None,
    )


def _sigma_string_to_sql(
    col_expr: ColumnElement[Any],
    sigma_str: SigmaString | SigmaCasedString,
    case_sensitive: bool,
    dialect_name: str,
    counter: _ParamCounter,
) -> ColumnElement[bool]:
    has_wildcard = any(isinstance(p, SpecialChars) for p in sigma_str.s)
    if not has_wildcard:
        plain = "".join(str(p) for p in sigma_str.s)
        if case_sensitive:
            return and_(col_expr.is_not(None), col_expr == counter.next_param(plain))
        return and_(
            col_expr.is_not(None), func.lower(col_expr) == counter.next_param(plain.lower())
        )

    if case_sensitive and dialect_name != "postgresql":
        # SQLite LIKE is ASCII case-insensitive; use anchored exact-case regex for |cased wildcards.
        rx_parts: list[str] = ["^"]
        for p in sigma_str.s:
            if p == SpecialChars.WILDCARD_MULTI:
                rx_parts.append(".*")
            elif p == SpecialChars.WILDCARD_SINGLE:
                rx_parts.append(".")
            else:
                rx_parts.append(re.escape(str(p)))
        rx_parts.append("$")
        return and_(
            col_expr.is_not(None),
            func.provloom_regexp(
                counter.next_param("".join(rx_parts)),
                counter.next_param("s"),
                col_expr,
            )
            == 1,
        )

    like_parts: list[str] = []
    for p in sigma_str.s:
        if p == SpecialChars.WILDCARD_MULTI:
            like_parts.append("%")
        elif p == SpecialChars.WILDCARD_SINGLE:
            like_parts.append("_")
        else:
            escaped = str(p).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            like_parts.append(escaped)
    pattern = "".join(like_parts)
    if case_sensitive:
        return and_(
            col_expr.is_not(None),
            col_expr.like(counter.next_param(pattern), escape="\\"),
        )
    return and_(
        col_expr.is_not(None),
        func.lower(col_expr).like(counter.next_param(pattern.lower()), escape="\\"),
    )


def _regex_to_sql(
    col_expr: ColumnElement[Any],
    pattern: str,
    ignore_case: bool,
    multiline: bool,
    dotall: bool,
    dialect_name: str,
    counter: _ParamCounter,
) -> ColumnElement[bool]:
    if dialect_name == "postgresql":
        prefix = ""
        if multiline or dotall:
            flags = ("m" if multiline else "") + ("n" if not multiline and dotall else "")
            if dotall and multiline:
                prefix = "(?p)"
            elif dotall:
                prefix = "(?s)"
            elif multiline:
                prefix = "(?m)"
            _ = flags
        op = "~*" if ignore_case else "~"
        return and_(
            col_expr.is_not(None),
            col_expr.op(op)(counter.next_param(prefix + pattern)),
        )

    flag_str = ("i" if ignore_case else "") + ("m" if multiline else "") + ("s" if dotall else "")
    return and_(
        col_expr.is_not(None),
        func.provloom_regexp(
            counter.next_param(pattern),
            counter.next_param(flag_str),
            col_expr,
        )
        == 1,
    )


def _apply_scalar_or_array(
    field: str,
    dialect_name: str,
    elem_predicate_fn: Callable[[ColumnElement[Any]], ColumnElement[bool]],
) -> ColumnElement[bool]:
    scalar_col = _extract_text_expr(field, dialect_name)
    scalar_pred = elem_predicate_fn(scalar_col)
    if field not in ARRAY_OCSF_FIELDS:
        return scalar_pred

    parts = field.split(".")
    if dialect_name == "postgresql":
        pg_node = normalized_events.c.ocsf_payload.op("#>")(postgresql.array(parts))
        pg_arr = func.jsonb_array_elements_text(
            case(
                (func.jsonb_typeof(pg_node) == "array", pg_node),
                else_=cast(literal("[]"), JSONB),
            )
        ).table_valued("value")
        arr_pred = exists(
            select(literal(1)).select_from(pg_arr).where(elem_predicate_fn(pg_arr.c.value))
        )
        return or_(arr_pred, scalar_pred)

    json_path = "$." + ".".join(parts)
    sq_arr = func.json_each(
        case(
            (
                func.json_type(normalized_events.c.ocsf_payload, json_path) == "array",
                func.json_extract(normalized_events.c.ocsf_payload, json_path),
            ),
            else_=literal("[]"),
        )
    ).table_valued("value")
    arr_pred_sq = exists(
        select(literal(1))
        .select_from(sq_arr)
        .where(elem_predicate_fn(cast(sq_arr.c.value, String)))
    )
    return or_(arr_pred_sq, scalar_pred)


def _compile_sigma_field_value(
    field: str,
    val: SigmaType,
    dialect_name: str,
    counter: _ParamCounter,
) -> ColumnElement[bool]:
    _validate_ocsf_field(field)

    if isinstance(val, SigmaNull):
        col = _extract_text_expr(field, dialect_name)
        return col.is_(None)

    if isinstance(val, SigmaExists):
        col = _extract_text_expr(field, dialect_name)
        return col.is_not(None) if bool(val.exists) else col.is_(None)

    if isinstance(val, SigmaBool):
        bval = bool(val.boolean)
        if dialect_name != "postgresql" and "." in field:
            jpath = "$." + field
            jtype = func.json_type(normalized_events.c.ocsf_payload, jpath)
            return and_(jtype.is_not(None), jtype == ("true" if bval else "false"))
        col = _extract_text_expr(field, dialect_name)
        return and_(
            col.is_not(None),
            func.lower(col) == counter.next_param("true" if bval else "false"),
        )

    if isinstance(val, SigmaNumber):
        ncol = _extract_numeric_expr(field, dialect_name)
        return and_(ncol.is_not(None), ncol == counter.next_param(val.number))

    if isinstance(val, SigmaCompareExpression):
        ncol = _extract_numeric_expr(field, dialect_name)
        bound = counter.next_param(val.number.number)
        op = val.op
        if op == SigmaCompareExpression.CompareOperators.LT:
            return and_(ncol.is_not(None), ncol < bound)
        if op == SigmaCompareExpression.CompareOperators.LTE:
            return and_(ncol.is_not(None), ncol <= bound)
        if op == SigmaCompareExpression.CompareOperators.GT:
            return and_(ncol.is_not(None), ncol > bound)
        if op == SigmaCompareExpression.CompareOperators.GTE:
            return and_(ncol.is_not(None), ncol >= bound)
        raise ValueError(f"Unsupported numeric comparison operator: {op}")

    if isinstance(val, SigmaRegularExpression):
        rx_pattern = str(val.regexp)
        try:
            re.compile(rx_pattern)
        except re.error as exc:
            raise ValueError(f"Invalid regular expression {rx_pattern!r}: {exc}") from exc
        flags = val.flags or set()
        ic = SigmaRegularExpressionFlag.IGNORECASE in flags
        ml = SigmaRegularExpressionFlag.MULTILINE in flags
        da = SigmaRegularExpressionFlag.DOTALL in flags
        return _apply_scalar_or_array(
            field,
            dialect_name,
            lambda col_e: _regex_to_sql(col_e, rx_pattern, ic, ml, da, dialect_name, counter),
        )

    if isinstance(val, SigmaCasedString):
        return _apply_scalar_or_array(
            field,
            dialect_name,
            lambda col_e: _sigma_string_to_sql(col_e, val, True, dialect_name, counter),
        )

    if isinstance(val, SigmaString):
        return _apply_scalar_or_array(
            field,
            dialect_name,
            lambda col_e: _sigma_string_to_sql(col_e, val, False, dialect_name, counter),
        )

    raise ValueError(f"Unsupported Sigma value type on field {field!r}: {type(val).__name__}")


def _compile_sigma_node(
    node: object,
    dialect_name: str,
    counter: _ParamCounter,
) -> ColumnElement[bool]:
    if isinstance(node, ConditionAND):
        children = [_compile_sigma_node(arg, dialect_name, counter) for arg in node.args]
        return and_(*children) if children else true()
    if isinstance(node, ConditionOR):
        children = [_compile_sigma_node(arg, dialect_name, counter) for arg in node.args]
        return or_(*children) if children else false()
    if isinstance(node, ConditionNOT):
        if not node.args:
            return true()
        return not_(_compile_sigma_node(node.args[0], dialect_name, counter))
    if isinstance(node, ConditionFieldEqualsValueExpression):
        return _compile_sigma_field_value(node.field, node.value, dialect_name, counter)
    if isinstance(node, ConditionValueExpression):
        raise ValueError("Unbound keyword value expression without field is unsupported")
    raise ValueError(f"Unsupported Sigma condition AST node: {type(node).__name__}")


def _collect_sigma_ast_fields(
    node: object,
    fields_out: list[str],
    class_uids_out: list[int],
) -> None:
    if isinstance(node, (ConditionAND, ConditionOR, ConditionNOT)):
        for arg in node.args:
            _collect_sigma_ast_fields(arg, fields_out, class_uids_out)
    elif isinstance(node, ConditionFieldEqualsValueExpression):
        fields_out.append(node.field)
        if node.field == "class_uid" and isinstance(node.value, SigmaNumber):
            class_uids_out.append(int(node.value.number))
        elif node.field == "type_uid" and isinstance(node.value, SigmaNumber):
            class_uids_out.append(int(node.value.number) // 100)
    elif isinstance(node, ConditionValueExpression):
        raise ValueError("Unbound keyword value expression without field is unsupported")


def _compile_structured_predicate(
    pred: StructuredPredicate,
    dialect_name: str,
    counter: _ParamCounter,
) -> ColumnElement[bool]:
    _validate_ocsf_field(pred.field)
    op = pred.op
    val = pred.value

    if op == PredicateOperator.EXISTS:
        col = _extract_text_expr(pred.field, dialect_name)
        return col.is_not(None) if bool(val) else col.is_(None)

    if op in (
        PredicateOperator.GT,
        PredicateOperator.GTE,
        PredicateOperator.LT,
        PredicateOperator.LTE,
    ):
        ncol = _extract_numeric_expr(pred.field, dialect_name)
        bound = counter.next_param(float(val) if isinstance(val, float) else int(val))
        if op == PredicateOperator.GT:
            return and_(ncol.is_not(None), ncol > bound)
        if op == PredicateOperator.GTE:
            return and_(ncol.is_not(None), ncol >= bound)
        if op == PredicateOperator.LT:
            return and_(ncol.is_not(None), ncol < bound)
        return and_(ncol.is_not(None), ncol <= bound)

    if op == PredicateOperator.EQ:
        if isinstance(val, bool):
            return _compile_sigma_field_value(pred.field, SigmaBool(val), dialect_name, counter)
        if isinstance(val, (int, float)):
            return _compile_sigma_field_value(pred.field, SigmaNumber(val), dialect_name, counter)
        sval = SigmaCasedString(str(val)) if pred.case_sensitive else SigmaString(str(val))
        return _compile_sigma_field_value(pred.field, sval, dialect_name, counter)

    if op == PredicateOperator.NEQ:
        eq_expr = _compile_structured_predicate(
            StructuredPredicate(
                field=pred.field,
                op=PredicateOperator.EQ,
                value=val,
                case_sensitive=pred.case_sensitive,
            ),
            dialect_name,
            counter,
        )
        return not_(eq_expr)

    if op == PredicateOperator.IN:
        if not isinstance(val, list) or not val:
            raise ValueError(f"'in' operator on {pred.field!r} requires a non-empty list")
        sub_preds = [
            _compile_structured_predicate(
                StructuredPredicate(
                    field=pred.field,
                    op=PredicateOperator.EQ,
                    value=item,
                    case_sensitive=pred.case_sensitive,
                ),
                dialect_name,
                counter,
            )
            for item in val
        ]
        return or_(*sub_preds)

    raw_s = str(val)
    if op == PredicateOperator.CONTAINS:
        s_obj: SigmaString | SigmaCasedString = (
            SigmaCasedString.from_str(f"*{raw_s}*")
            if pred.case_sensitive
            else SigmaString(f"*{raw_s}*")
        )
        return _compile_sigma_field_value(pred.field, s_obj, dialect_name, counter)

    if op == PredicateOperator.STARTSWITH:
        s_obj = (
            SigmaCasedString.from_str(f"{raw_s}*")
            if pred.case_sensitive
            else SigmaString(f"{raw_s}*")
        )
        return _compile_sigma_field_value(pred.field, s_obj, dialect_name, counter)

    if op == PredicateOperator.ENDSWITH:
        s_obj = (
            SigmaCasedString.from_str(f"*{raw_s}")
            if pred.case_sensitive
            else SigmaString(f"*{raw_s}")
        )
        return _compile_sigma_field_value(pred.field, s_obj, dialect_name, counter)

    if op == PredicateOperator.REGEX:
        flags = set() if pred.case_sensitive else {SigmaRegularExpressionFlag.IGNORECASE}
        return _compile_sigma_field_value(
            pred.field,
            SigmaRegularExpression(raw_s, flags=flags),
            dialect_name,
            counter,
        )

    raise ValueError(f"Unsupported operator: {op}")


def _compile_custom_node(
    node: CustomConditionNode,
    dialect_name: str,
    counter: _ParamCounter,
) -> ColumnElement[bool]:
    if node.predicate is not None:
        return _compile_structured_predicate(node.predicate, dialect_name, counter)
    if node.all_of:
        return and_(*(_compile_custom_node(c, dialect_name, counter) for c in node.all_of))
    if node.any_of:
        return or_(*(_compile_custom_node(c, dialect_name, counter) for c in node.any_of))
    if node.not_node is not None:
        return not_(_compile_custom_node(node.not_node, dialect_name, counter))
    raise ValueError("Empty custom condition node")


def _render_postgres_preview(
    builder: Callable[[str], ColumnElement[bool]],
    mapped_class_uids: tuple[int, ...],
) -> str:
    preview_scope = AccessScope(tenant_id="default")
    preview_range = TimeRange(
        start_time=datetime(2026, 1, 1, tzinfo=UTC),
        end_time=datetime(2026, 1, 2, tzinfo=UTC),
    )
    q = CompiledEventQuery(
        postgres_sql="",
        mapped_class_uids=mapped_class_uids,
        referenced_fields=(),
        user_matched_fields=(),
        _builder=builder,
    )
    stmt = q.build_select(
        dialect_name="postgresql",
        scope=preview_scope,
        time_range=preview_range,
        limit=500,
    )
    pg_dialect = postgresql.dialect()  # type: ignore[no-untyped-call]
    return str(stmt.compile(dialect=pg_dialect))


def compile_sigma_event_query(
    transformed_rule: SigmaRule,
) -> CompiledEventQuery:
    parsed_asts: list[object] = [c.parse() for c in transformed_rule.detection.parsed_condition]
    all_fields: list[str] = []
    class_uids: list[int] = []
    for ast in parsed_asts:
        _collect_sigma_ast_fields(ast, all_fields, class_uids)

    unmapped = [f for f in dict.fromkeys(all_fields) if f not in KNOWN_OCSF_V13_FIELDS]
    if unmapped:
        raise ValueError(
            "Unmapped or unsupported OCSF field(s): " + ", ".join(repr(x) for x in unmapped)
        )

    dedup_fields = tuple(dict.fromkeys(all_fields))
    user_fields = tuple(f for f in dedup_fields if f not in _ENVELOPE_SYNTHETIC_FIELDS)
    dedup_classes = tuple(dict.fromkeys(class_uids))

    def _builder(dialect_name: str) -> ColumnElement[bool]:
        counter = _ParamCounter()
        exprs = [_compile_sigma_node(ast, dialect_name, counter) for ast in parsed_asts]
        return or_(*exprs) if len(exprs) > 1 else exprs[0]

    pg_sql = _render_postgres_preview(_builder, dedup_classes)
    # Also verify SQLite compilation upfront so parity errors surface at compile time.
    _builder("sqlite")

    return CompiledEventQuery(
        postgres_sql=pg_sql,
        mapped_class_uids=dedup_classes,
        referenced_fields=dedup_fields,
        user_matched_fields=user_fields or dedup_fields,
        _builder=_builder,
    )


def compile_custom_event_query(spec: CustomEventSpec) -> CompiledEventQuery:
    fields: list[str] = []

    def _gather(node: CustomConditionNode) -> None:
        if node.predicate is not None:
            fields.append(node.predicate.field)
        for c in node.all_of:
            _gather(c)
        for c in node.any_of:
            _gather(c)
        if node.not_node is not None:
            _gather(node.not_node)

    _gather(spec.condition)
    unmapped = [f for f in dict.fromkeys(fields) if f not in KNOWN_OCSF_V13_FIELDS]
    if unmapped:
        raise ValueError(
            "Unsupported OCSF field(s) in custom rule: " + ", ".join(repr(x) for x in unmapped)
        )

    dedup_fields = tuple(dict.fromkeys(fields))
    user_fields = tuple(f for f in dedup_fields if f not in _ENVELOPE_SYNTHETIC_FIELDS)

    def _builder(dialect_name: str) -> ColumnElement[bool]:
        counter = _ParamCounter()
        return _compile_custom_node(spec.condition, dialect_name, counter)

    pg_sql = _render_postgres_preview(_builder, spec.target_class_uids)
    _builder("sqlite")

    return CompiledEventQuery(
        postgres_sql=pg_sql,
        mapped_class_uids=spec.target_class_uids,
        referenced_fields=dedup_fields,
        user_matched_fields=user_fields or dedup_fields,
        _builder=_builder,
    )


def compile_rule_yaml(
    raw_yaml: str,
    source_reference: str = "inline",
    source_hint: RuleSource | None = None,
    mapping_specs: Sequence[MappingSpecSummary] | None = None,
    now: datetime | None = None,
) -> CompiledRuleArtifact:
    ts = now or datetime.now(UTC)
    parsed: ParsedRuleEnvelope = parse_rule_yaml(raw_yaml, source_hint=source_hint)

    if not parsed.parse_success:
        compat = RuleCompatibility(
            parse_success=False,
            mapping_success=False,
            data_coverage=False,
            compile_success=False,
            unsupported_reasons=parsed.parse_errors,
        )
        return CompiledRuleArtifact(
            rule=DetectionRule(
                rule_id=parsed.rule_id,
                rule_name=parsed.rule_name,
                source=parsed.source,
                source_reference=source_reference,
                version=parsed.version,
                description=parsed.description,
                severity=parsed.severity,
                attack_tags=parsed.attack_tags,
                logsource=parsed.logsource,
                detection_type=parsed.detection_type,
                raw_content=raw_yaml,
                status=RuleStatus.ERROR,
                compatibility=compat,
                created_at=ts,
                updated_at=ts,
            ),
            parsed_summary=parsed.parsed_ast_preview,
        )

    if parsed.semantic_errors:
        compat = RuleCompatibility(
            parse_success=True,
            mapping_success=False,
            data_coverage=False,
            compile_success=False,
            unsupported_reasons=parsed.semantic_errors,
        )
        return CompiledRuleArtifact(
            rule=DetectionRule(
                rule_id=parsed.rule_id,
                rule_name=parsed.rule_name,
                source=parsed.source,
                source_reference=source_reference,
                version=parsed.version,
                description=parsed.description,
                severity=parsed.severity,
                attack_tags=parsed.attack_tags,
                logsource=parsed.logsource,
                detection_type=parsed.detection_type,
                raw_content=raw_yaml,
                status=RuleStatus.UNSUPPORTED,
                compatibility=compat,
                created_at=ts,
                updated_at=ts,
            ),
            parsed_summary=parsed.parsed_ast_preview,
        )

    # Custom 1-hop Relation Rule
    if parsed.detection_type == DetectionType.RELATION and parsed.custom_relation_spec is not None:
        rel_spec = parsed.custom_relation_spec
        fmap = {f: f for f in parsed.original_fields}
        compat = RuleCompatibility(
            parse_success=True,
            mapping_success=True,
            data_coverage=True,
            compile_success=True,
            field_mappings=fmap,
        )
        return CompiledRuleArtifact(
            rule=DetectionRule(
                rule_id=parsed.rule_id,
                rule_name=parsed.rule_name,
                source=parsed.source,
                source_reference=source_reference,
                version=parsed.version,
                description=parsed.description,
                severity=parsed.severity,
                attack_tags=parsed.attack_tags,
                logsource=parsed.logsource,
                detection_type=DetectionType.RELATION,
                raw_content=raw_yaml,
                status=RuleStatus.ENABLED if parsed.desired_enabled else RuleStatus.DISABLED,
                compatibility=compat,
                created_at=ts,
                updated_at=ts,
            ),
            relation_spec=rel_spec,
            parsed_summary=parsed.parsed_ast_preview,
        )

    # Custom Event Rule
    if parsed.source == RuleSource.CUSTOM and parsed.custom_event_spec is not None:
        ev_spec = parsed.custom_event_spec
        fmap = {f: f for f in parsed.original_fields}
        unmapped_custom = [f for f in parsed.original_fields if f not in KNOWN_OCSF_V13_FIELDS]
        if unmapped_custom:
            compat = RuleCompatibility(
                parse_success=True,
                mapping_success=False,
                data_coverage=False,
                compile_success=False,
                mapped_class_uids=ev_spec.target_class_uids,
                field_mappings=fmap,
                unsupported_reasons=tuple(
                    f"Unsupported OCSF field in custom rule: {f!r}" for f in unmapped_custom
                ),
            )
            return CompiledRuleArtifact(
                rule=DetectionRule(
                    rule_id=parsed.rule_id,
                    rule_name=parsed.rule_name,
                    source=parsed.source,
                    source_reference=source_reference,
                    version=parsed.version,
                    description=parsed.description,
                    severity=parsed.severity,
                    attack_tags=parsed.attack_tags,
                    logsource=parsed.logsource,
                    detection_type=DetectionType.EVENT,
                    raw_content=raw_yaml,
                    status=RuleStatus.UNSUPPORTED,
                    compatibility=compat,
                    created_at=ts,
                    updated_at=ts,
                ),
                parsed_summary=parsed.parsed_ast_preview,
            )

        covered, uncovered = evaluate_data_coverage(
            ev_spec.target_class_uids, parsed.original_fields, mapping_specs
        )
        try:
            compiled_q = compile_custom_event_query(ev_spec)
        except ValueError as exc:
            compat = RuleCompatibility(
                parse_success=True,
                mapping_success=True,
                data_coverage=covered,
                compile_success=False,
                mapped_class_uids=ev_spec.target_class_uids,
                field_mappings=fmap,
                uncovered_fields=uncovered,
                unsupported_reasons=(str(exc),),
            )
            return CompiledRuleArtifact(
                rule=DetectionRule(
                    rule_id=parsed.rule_id,
                    rule_name=parsed.rule_name,
                    source=parsed.source,
                    source_reference=source_reference,
                    version=parsed.version,
                    description=parsed.description,
                    severity=parsed.severity,
                    attack_tags=parsed.attack_tags,
                    logsource=parsed.logsource,
                    detection_type=DetectionType.EVENT,
                    raw_content=raw_yaml,
                    status=RuleStatus.UNSUPPORTED,
                    compatibility=compat,
                    created_at=ts,
                    updated_at=ts,
                ),
                parsed_summary=parsed.parsed_ast_preview,
            )

        compat = RuleCompatibility(
            parse_success=True,
            mapping_success=True,
            data_coverage=covered,
            compile_success=True,
            mapped_class_uids=compiled_q.mapped_class_uids,
            field_mappings=fmap,
            uncovered_fields=uncovered,
        )
        return CompiledRuleArtifact(
            rule=DetectionRule(
                rule_id=parsed.rule_id,
                rule_name=parsed.rule_name,
                source=parsed.source,
                source_reference=source_reference,
                version=parsed.version,
                description=parsed.description,
                severity=parsed.severity,
                attack_tags=parsed.attack_tags,
                logsource=parsed.logsource,
                detection_type=DetectionType.EVENT,
                raw_content=raw_yaml,
                status=RuleStatus.ENABLED if parsed.desired_enabled else RuleStatus.DISABLED,
                compatibility=compat,
                created_at=ts,
                updated_at=ts,
            ),
            event_query=compiled_q,
            parsed_summary=parsed.parsed_ast_preview,
        )

    # Sigma Rule Pipeline + PostgreSQL Backend Compilation
    assert parsed.sigma_rule is not None
    transformed_sigma, field_mappings = apply_ocsf_pipeline(parsed.sigma_rule)
    for orig_f in parsed.original_fields:
        if orig_f not in field_mappings and orig_f in KNOWN_OCSF_V13_FIELDS:
            field_mappings[orig_f] = orig_f

    post_fields: list[str] = []
    post_classes: list[int] = []
    try:
        for cond_item in transformed_sigma.detection.parsed_condition:
            _collect_sigma_ast_fields(cond_item.parse(), post_fields, post_classes)
    except Exception as exc:
        compat = RuleCompatibility(
            parse_success=True,
            mapping_success=False,
            data_coverage=False,
            compile_success=False,
            field_mappings=field_mappings,
            unsupported_reasons=(f"OCSF pipeline AST error: {exc}",),
        )
        return CompiledRuleArtifact(
            rule=DetectionRule(
                rule_id=parsed.rule_id,
                rule_name=parsed.rule_name,
                source=RuleSource.SIGMA,
                source_reference=source_reference,
                version=parsed.version,
                description=parsed.description,
                severity=parsed.severity,
                attack_tags=parsed.attack_tags,
                logsource=parsed.logsource,
                detection_type=DetectionType.EVENT,
                raw_content=raw_yaml,
                status=RuleStatus.UNSUPPORTED,
                compatibility=compat,
                created_at=ts,
                updated_at=ts,
            ),
            parsed_summary=parsed.parsed_ast_preview,
        )

    unmapped_sigma = [f for f in dict.fromkeys(post_fields) if f not in KNOWN_OCSF_V13_FIELDS]
    mapping_reasons: list[str] = []
    if unmapped_sigma:
        mapping_reasons.extend(f"Unmapped Sigma field: {f!r}" for f in unmapped_sigma)
    if not post_classes and not any(f == "class_uid" for f in post_fields):
        # Allow explicit OCSF field rules only if logsource maps to a known OCSF class_uid.
        ls_desc = (
            f"category={parsed.logsource.category!r}, "
            f"product={parsed.logsource.product!r}, "
            f"service={parsed.logsource.service!r}"
        )
        mapping_reasons.append(
            f"Unsupported Sigma logsource without OCSF class mapping ({ls_desc})"
        )

    if mapping_reasons:
        compat = RuleCompatibility(
            parse_success=True,
            mapping_success=False,
            data_coverage=False,
            compile_success=False,
            mapped_class_uids=tuple(dict.fromkeys(post_classes)),
            field_mappings=field_mappings,
            unsupported_reasons=tuple(mapping_reasons),
        )
        return CompiledRuleArtifact(
            rule=DetectionRule(
                rule_id=parsed.rule_id,
                rule_name=parsed.rule_name,
                source=RuleSource.SIGMA,
                source_reference=source_reference,
                version=parsed.version,
                description=parsed.description,
                severity=parsed.severity,
                attack_tags=parsed.attack_tags,
                logsource=parsed.logsource,
                detection_type=DetectionType.EVENT,
                raw_content=raw_yaml,
                status=RuleStatus.UNSUPPORTED,
                compatibility=compat,
                created_at=ts,
                updated_at=ts,
            ),
            parsed_summary=parsed.parsed_ast_preview,
        )

    dedup_classes = tuple(dict.fromkeys(post_classes))
    covered, uncovered = evaluate_data_coverage(dedup_classes, post_fields, mapping_specs)

    try:
        compiled_sigma_q = compile_sigma_event_query(transformed_sigma)
    except ValueError as exc:
        compat = RuleCompatibility(
            parse_success=True,
            mapping_success=True,
            data_coverage=covered,
            compile_success=False,
            mapped_class_uids=dedup_classes,
            field_mappings=field_mappings,
            uncovered_fields=uncovered,
            unsupported_reasons=(str(exc),),
        )
        return CompiledRuleArtifact(
            rule=DetectionRule(
                rule_id=parsed.rule_id,
                rule_name=parsed.rule_name,
                source=RuleSource.SIGMA,
                source_reference=source_reference,
                version=parsed.version,
                description=parsed.description,
                severity=parsed.severity,
                attack_tags=parsed.attack_tags,
                logsource=parsed.logsource,
                detection_type=DetectionType.EVENT,
                raw_content=raw_yaml,
                status=RuleStatus.UNSUPPORTED,
                compatibility=compat,
                created_at=ts,
                updated_at=ts,
            ),
            parsed_summary=parsed.parsed_ast_preview,
        )

    compat = RuleCompatibility(
        parse_success=True,
        mapping_success=True,
        data_coverage=covered,
        compile_success=True,
        mapped_class_uids=compiled_sigma_q.mapped_class_uids,
        field_mappings=field_mappings,
        uncovered_fields=uncovered,
    )
    return CompiledRuleArtifact(
        rule=DetectionRule(
            rule_id=parsed.rule_id,
            rule_name=parsed.rule_name,
            source=RuleSource.SIGMA,
            source_reference=source_reference,
            version=parsed.version,
            description=parsed.description,
            severity=parsed.severity,
            attack_tags=parsed.attack_tags,
            logsource=parsed.logsource,
            detection_type=DetectionType.EVENT,
            raw_content=raw_yaml,
            status=RuleStatus.ENABLED if parsed.desired_enabled else RuleStatus.DISABLED,
            compatibility=compat,
            created_at=ts,
            updated_at=ts,
        ),
        event_query=compiled_sigma_q,
        parsed_summary=parsed.parsed_ast_preview,
    )
