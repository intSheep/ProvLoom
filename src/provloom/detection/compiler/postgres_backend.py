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
    SigmaExpansion,
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
    KNOWN_OCSF_V14_FIELDS,
    OBJECT_ARRAY_OCSF_FIELDS,
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
    if field not in KNOWN_OCSF_V14_FIELDS:
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
        return normalized_events.c.ocsf_payload.op("#>>", return_type=String)(
            postgresql.array(parts)
        )
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
        txt = normalized_events.c.ocsf_payload.op("#>>", return_type=String)(
            postgresql.array(parts)
        )
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


_LEADING_INLINE_FLAGS_RE = re.compile(r"^\(\?([iIms]+)\)")
_PG_SINGLE_ATOM_DUP_RE = re.compile(
    r"(\[(?:\^)?(?:\\.|[^\]\\])*\]|\\[A-Za-z0-9_.^$*+?()\[\]{}|\\-]|(?<!\\)\.|[A-Za-z0-9_/-])\{(\d+),(\d+)\}"
)
_PG_UNESCAPED_DUP_RE = re.compile(r"(?<!\\)\{(\d+)(?:,(\d*))?\}")


def _normalize_postgres_regex(
    pattern: str,
    ignore_case: bool,
    multiline: bool,
    dotall: bool,
) -> tuple[str, bool]:
    # Merge leading (?ims) flags so PostgreSQL POSIX ARE never sees two (?...) directors.
    while True:
        m = _LEADING_INLINE_FLAGS_RE.match(pattern)
        if m is None:
            break
        fl = m.group(1)
        if "i" in fl.lower():
            ignore_case = True
        if "m" in fl:
            multiline = True
        if "s" in fl:
            dotall = True
        pattern = pattern[m.end() :]

    # PostgreSQL POSIX ARE enforces DUPMAX=255 on {m,n}; decompose single-char/class atoms safely.
    def _split_dup(match: re.Match[str]) -> str:
        atom = match.group(1)
        lo = int(match.group(2))
        hi = int(match.group(3))
        if hi <= 255 or lo > hi or hi > 4096:
            return match.group(0)
        parts_out: list[str] = []
        qm, rm = divmod(lo, 255)
        parts_out.extend([f"{atom}{{255}}"] * qm)
        if rm > 0:
            parts_out.append(f"{atom}{{{rm}}}")
        qo, ro = divmod(hi - lo, 255)
        parts_out.extend([f"{atom}{{0,255}}"] * qo)
        if ro > 0:
            parts_out.append(f"{atom}{{0,{ro}}}")
        return "".join(parts_out) or f"{atom}{{0}}"

    pattern = _PG_SINGLE_ATOM_DUP_RE.sub(_split_dup, pattern)
    for dup_m in _PG_UNESCAPED_DUP_RE.finditer(pattern):
        b1 = int(dup_m.group(1))
        b2 = int(dup_m.group(2)) if dup_m.group(2) else 0
        if b1 > 255 or b2 > 255:
            raise ValueError(f"PostgreSQL POSIX regex repetition count exceeds 255 in {pattern!r}")

    prefix = ""
    if multiline and dotall:
        prefix = "(?p)"
    elif multiline:
        prefix = "(?m)"
    # Note: PostgreSQL ARE defaults to '.' matching newlines when (?m)/(?n) is absent.
    return (prefix + pattern, ignore_case)


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
        pg_pat, pg_ic = _normalize_postgres_regex(pattern, ignore_case, multiline, dotall)
        op = "~*" if pg_ic else "~"
        return and_(
            col_expr.is_not(None),
            col_expr.op(op)(counter.next_param(pg_pat)),
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


def _extract_elem_text_expr(
    elem_expr: ColumnElement[Any],
    elem_type_expr: ColumnElement[Any] | None,
    leaf_key: str,
    allow_legacy_str: bool,
    dialect_name: str,
) -> ColumnElement[Any]:
    if dialect_name == "postgresql":
        empty_text_arr = cast(
            postgresql.array([], type_=postgresql.TEXT), postgresql.ARRAY(postgresql.TEXT)
        )
        if allow_legacy_str:
            return case(
                (
                    func.jsonb_typeof(elem_expr) == "object",
                    elem_expr.op("->>", return_type=String)(leaf_key),
                ),
                (
                    func.jsonb_typeof(elem_expr) == "string",
                    elem_expr.op("#>>", return_type=String)(empty_text_arr),
                ),
                else_=None,
            )
        return case(
            (
                func.jsonb_typeof(elem_expr) == "object",
                elem_expr.op("->>", return_type=String)(leaf_key),
            ),
            else_=None,
        )

    assert elem_type_expr is not None
    leaf_jpath = "$." + leaf_key
    sq_obj_leaf_ok = and_(
        elem_type_expr == "object",
        func.json_type(elem_expr, leaf_jpath).in_(["text", "integer", "real"]),
    )
    if allow_legacy_str:
        return case(
            (sq_obj_leaf_ok, cast(func.json_extract(elem_expr, leaf_jpath), String)),
            (elem_type_expr == "text", cast(elem_expr, String)),
            else_=None,
        )
    return case(
        (sq_obj_leaf_ok, cast(func.json_extract(elem_expr, leaf_jpath), String)),
        else_=None,
    )


def _extract_elem_numeric_expr(
    elem_expr: ColumnElement[Any],
    elem_type_expr: ColumnElement[Any] | None,
    leaf_key: str,
    dialect_name: str,
) -> ColumnElement[Any]:
    if dialect_name == "postgresql":
        txt = elem_expr.op("->>", return_type=String)(leaf_key)
        return case(
            (
                and_(
                    func.jsonb_typeof(elem_expr) == "object",
                    txt.op("~")(r"^-?[0-9]+(\.[0-9]+)?$"),
                ),
                cast(txt, Numeric),
            ),
            else_=None,
        )
    assert elem_type_expr is not None
    leaf_jpath = "$." + leaf_key
    return case(
        (
            and_(
                elem_type_expr == "object",
                func.json_type(elem_expr, leaf_jpath).in_(["integer", "real"]),
            ),
            cast(func.json_extract(elem_expr, leaf_jpath), Float),
        ),
        else_=None,
    )


def _extract_elem_exists_expr(
    elem_expr: ColumnElement[Any],
    elem_type_expr: ColumnElement[Any] | None,
    leaf_key: str,
    allow_legacy_str: bool,
    dialect_name: str,
) -> ColumnElement[bool]:
    if dialect_name == "postgresql":
        obj_has_key = and_(
            func.jsonb_typeof(elem_expr) == "object",
            elem_expr.op("#>")(postgresql.array([leaf_key])).is_not(None),
        )
        if allow_legacy_str:
            return or_(obj_has_key, func.jsonb_typeof(elem_expr) == "string")
        return obj_has_key

    assert elem_type_expr is not None
    leaf_jpath = "$." + leaf_key
    obj_has_key = and_(
        elem_type_expr == "object",
        func.json_type(elem_expr, leaf_jpath).is_not(None),
    )
    if allow_legacy_str:
        return or_(obj_has_key, elem_type_expr == "text")
    return obj_has_key


def _extract_elem_bool_pred(
    elem_expr: ColumnElement[Any],
    elem_type_expr: ColumnElement[Any] | None,
    leaf_key: str,
    bval: bool,
    dialect_name: str,
    counter: _ParamCounter,
) -> ColumnElement[bool]:
    if dialect_name == "postgresql":
        leaf_node = elem_expr.op("#>")(postgresql.array([leaf_key]))
        return and_(
            func.jsonb_typeof(elem_expr) == "object",
            leaf_node.is_not(None),
            func.jsonb_typeof(leaf_node) == "boolean",
            elem_expr.op("->>", return_type=String)(leaf_key)
            == counter.next_param("true" if bval else "false"),
        )
    assert elem_type_expr is not None
    leaf_jpath = "$." + leaf_key
    return and_(
        elem_type_expr == "object",
        func.json_type(elem_expr, leaf_jpath) == ("true" if bval else "false"),
    )


def _compile_numeric_pred(
    ncol: ColumnElement[Any],
    val: SigmaNumber | SigmaCompareExpression,
    counter: _ParamCounter,
) -> ColumnElement[bool]:
    if isinstance(val, SigmaNumber):
        return and_(ncol.is_not(None), ncol == counter.next_param(val.number))
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
    if op == SigmaCompareExpression.CompareOperators.NEQ:
        return and_(ncol.is_not(None), ncol != bound)
    raise ValueError(f"Unsupported numeric comparison operator: {op}")


def _wrap_array_exists(
    arr_parts: tuple[str, ...],
    dialect_name: str,
    build_elem_pred_fn: Callable[
        [ColumnElement[Any], ColumnElement[Any] | None], ColumnElement[bool]
    ],
    legacy_scalar_pred_fn: Callable[[ColumnElement[Any]], ColumnElement[bool]] | None = None,
) -> ColumnElement[bool]:
    if dialect_name == "postgresql":
        pg_arr_node = normalized_events.c.ocsf_payload.op("#>")(postgresql.array(list(arr_parts)))
        is_pg_arr = and_(pg_arr_node.is_not(None), func.jsonb_typeof(pg_arr_node) == "array")
        pg_elems = func.jsonb_array_elements(
            case(
                (is_pg_arr, pg_arr_node),
                else_=cast(literal("[]"), JSONB),
            )
        ).table_valued("value")
        arr_pred: ColumnElement[bool] = exists(
            select(literal(1))
            .select_from(pg_elems)
            .where(build_elem_pred_fn(pg_elems.c.value, None))
        )
        if legacy_scalar_pred_fn is None:
            return arr_pred
        pg_legacy_scalar = normalized_events.c.ocsf_payload.op("#>>", return_type=String)(
            postgresql.array(list(arr_parts))
        )
        return or_(
            arr_pred,
            and_(
                pg_arr_node.is_not(None),
                func.jsonb_typeof(pg_arr_node) == "string",
                legacy_scalar_pred_fn(pg_legacy_scalar),
            ),
        )

    arr_jpath = "$." + ".".join(arr_parts)
    sq_jtype = func.json_type(normalized_events.c.ocsf_payload, arr_jpath)
    sq_elems = func.json_each(
        case(
            (
                and_(sq_jtype.is_not(None), sq_jtype == "array"),
                func.json_extract(normalized_events.c.ocsf_payload, arr_jpath),
            ),
            else_=literal("[]"),
        )
    ).table_valued("value", "type")
    arr_pred_sq: ColumnElement[bool] = exists(
        select(literal(1))
        .select_from(sq_elems)
        .where(build_elem_pred_fn(sq_elems.c.value, sq_elems.c.type))
    )
    if legacy_scalar_pred_fn is None:
        return arr_pred_sq
    sq_legacy_scalar = cast(func.json_extract(normalized_events.c.ocsf_payload, arr_jpath), String)
    return or_(
        arr_pred_sq,
        and_(
            sq_jtype.is_not(None),
            sq_jtype == "text",
            legacy_scalar_pred_fn(sq_legacy_scalar),
        ),
    )


def _apply_scalar_or_array(
    field: str,
    dialect_name: str,
    elem_predicate_fn: Callable[[ColumnElement[Any]], ColumnElement[bool]],
) -> ColumnElement[bool]:
    if field not in OBJECT_ARRAY_OCSF_FIELDS:
        scalar_col = _extract_text_expr(field, dialect_name)
        return elem_predicate_fn(scalar_col)

    arr_parts, leaf_key, allow_legacy_str = OBJECT_ARRAY_OCSF_FIELDS[field]
    return _wrap_array_exists(
        arr_parts,
        dialect_name,
        lambda ee, et: elem_predicate_fn(
            _extract_elem_text_expr(ee, et, leaf_key, allow_legacy_str, dialect_name)
        ),
        legacy_scalar_pred_fn=elem_predicate_fn if allow_legacy_str else None,
    )


def _compile_field_exists_expr(
    field: str,
    exists_flag: bool,
    dialect_name: str,
) -> ColumnElement[bool]:
    if field in {
        "source_id",
        "ocsf_version",
        "original_event_uid",
        "class_uid",
        "category_uid",
        "activity_id",
        "type_uid",
    }:
        col = _extract_text_expr(field, dialect_name)
        return col.is_not(None) if exists_flag else col.is_(None)

    if field in OBJECT_ARRAY_OCSF_FIELDS:
        arr_parts, leaf_key, allow_legacy_str = OBJECT_ARRAY_OCSF_FIELDS[field]
        if dialect_name == "postgresql":
            pg_arr_node = normalized_events.c.ocsf_payload.op("#>")(
                postgresql.array(list(arr_parts))
            )
            is_pg_arr = and_(pg_arr_node.is_not(None), func.jsonb_typeof(pg_arr_node) == "array")
            pg_elems = func.jsonb_array_elements(
                case((is_pg_arr, pg_arr_node), else_=cast(literal("[]"), JSONB))
            ).table_valued("value")
            elem_has_key = (
                or_(
                    and_(
                        func.jsonb_typeof(pg_elems.c.value) == "object",
                        pg_elems.c.value.op("#>")(postgresql.array([leaf_key])).is_not(None),
                    ),
                    func.jsonb_typeof(pg_elems.c.value) == "string",
                )
                if allow_legacy_str
                else and_(
                    func.jsonb_typeof(pg_elems.c.value) == "object",
                    pg_elems.c.value.op("#>")(postgresql.array([leaf_key])).is_not(None),
                )
            )
            present_expr: ColumnElement[bool] = exists(
                select(literal(1)).select_from(pg_elems).where(elem_has_key)
            )
            if allow_legacy_str:
                present_expr = or_(
                    present_expr,
                    and_(pg_arr_node.is_not(None), func.jsonb_typeof(pg_arr_node) == "string"),
                )
            return present_expr if exists_flag else not_(present_expr)

        arr_jpath = "$." + ".".join(arr_parts)
        leaf_jpath = "$." + leaf_key
        sq_jtype = func.json_type(normalized_events.c.ocsf_payload, arr_jpath)
        sq_elems = func.json_each(
            case(
                (
                    and_(sq_jtype.is_not(None), sq_jtype == "array"),
                    func.json_extract(normalized_events.c.ocsf_payload, arr_jpath),
                ),
                else_=literal("[]"),
            )
        ).table_valued("value", "type")
        sq_has_key = (
            or_(
                and_(
                    sq_elems.c.type == "object",
                    func.json_type(sq_elems.c.value, leaf_jpath).is_not(None),
                ),
                sq_elems.c.type == "text",
            )
            if allow_legacy_str
            else and_(
                sq_elems.c.type == "object",
                func.json_type(sq_elems.c.value, leaf_jpath).is_not(None),
            )
        )
        sq_present: ColumnElement[bool] = exists(
            select(literal(1)).select_from(sq_elems).where(sq_has_key)
        )
        if allow_legacy_str:
            sq_present = or_(sq_present, and_(sq_jtype.is_not(None), sq_jtype == "text"))
        return sq_present if exists_flag else not_(sq_present)

    # Sigma Spec: |exists checks field presence regardless of empty or JSON null value.
    parts = field.split(".")
    if dialect_name == "postgresql":
        pg_node = normalized_events.c.ocsf_payload.op("#>")(postgresql.array(parts))
        return pg_node.is_not(None) if exists_flag else pg_node.is_(None)
    jpath = "$." + ".".join(parts)
    jtype = func.json_type(normalized_events.c.ocsf_payload, jpath)
    return jtype.is_not(None) if exists_flag else jtype.is_(None)


def _compile_field_null_expr(field: str, dialect_name: str) -> ColumnElement[bool]:
    if field in OBJECT_ARRAY_OCSF_FIELDS:
        has_non_null = _apply_scalar_or_array(field, dialect_name, lambda col_e: col_e.is_not(None))
        return not_(has_non_null)
    col = _extract_text_expr(field, dialect_name)
    return col.is_(None)


def _compile_sigma_field_value(
    field: str,
    val: SigmaType,
    dialect_name: str,
    counter: _ParamCounter,
) -> ColumnElement[bool]:
    _validate_ocsf_field(field)

    if isinstance(val, SigmaNull):
        return _compile_field_null_expr(field, dialect_name)

    if isinstance(val, SigmaExists):
        return _compile_field_exists_expr(field, bool(val.exists), dialect_name)

    if isinstance(val, SigmaBool):
        bval = bool(val.boolean)
        if field in OBJECT_ARRAY_OCSF_FIELDS:
            arr_parts, leaf_key, _ = OBJECT_ARRAY_OCSF_FIELDS[field]
            return _wrap_array_exists(
                arr_parts,
                dialect_name,
                lambda ee, et: _extract_elem_bool_pred(
                    ee, et, leaf_key, bval, dialect_name, counter
                ),
            )
        if dialect_name != "postgresql" and "." in field:
            jpath = "$." + field
            jtype = func.json_type(normalized_events.c.ocsf_payload, jpath)
            return and_(jtype.is_not(None), jtype == ("true" if bval else "false"))
        col = _extract_text_expr(field, dialect_name)
        return and_(
            col.is_not(None),
            func.lower(col) == counter.next_param("true" if bval else "false"),
        )

    if isinstance(val, (SigmaNumber, SigmaCompareExpression)):
        if field in OBJECT_ARRAY_OCSF_FIELDS:
            arr_parts, leaf_key, _ = OBJECT_ARRAY_OCSF_FIELDS[field]
            return _wrap_array_exists(
                arr_parts,
                dialect_name,
                lambda ee, et: _compile_numeric_pred(
                    _extract_elem_numeric_expr(ee, et, leaf_key, dialect_name),
                    val,
                    counter,
                ),
            )
        return _compile_numeric_pred(_extract_numeric_expr(field, dialect_name), val, counter)

    if isinstance(val, SigmaExpansion):
        if not val.values:
            return false()
        return or_(
            *(
                _compile_sigma_field_value(field, sub_v, dialect_name, counter)
                for sub_v in val.values
            )
        )

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
        if dialect_name == "postgresql":
            _normalize_postgres_regex(rx_pattern, ic, ml, da)
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


def _is_fusible_sigma_value(val: SigmaType) -> bool:
    if isinstance(val, SigmaNull):
        return False
    if isinstance(val, SigmaExists):
        return bool(val.exists)
    if isinstance(val, SigmaExpansion):
        return all(_is_fusible_sigma_value(sub_v) for sub_v in val.values)
    return True


def _single_array_path_of_sigma_node(node: object) -> tuple[str, ...] | None:
    if isinstance(node, ConditionFieldEqualsValueExpression):
        if node.field not in OBJECT_ARRAY_OCSF_FIELDS:
            return None
        if not _is_fusible_sigma_value(node.value):
            return None
        return OBJECT_ARRAY_OCSF_FIELDS[node.field][0]
    if isinstance(node, (ConditionAND, ConditionOR)):
        if not node.args:
            return None
        paths = {_single_array_path_of_sigma_node(arg) for arg in node.args}
        if None in paths or len(paths) != 1:
            return None
        return next(iter(paths))
    return None


def _compile_array_elem_sigma_leaf(
    field: str,
    val: SigmaType,
    elem_expr: ColumnElement[Any],
    elem_type_expr: ColumnElement[Any] | None,
    dialect_name: str,
    counter: _ParamCounter,
) -> ColumnElement[bool]:
    _validate_ocsf_field(field)
    _, leaf_key, allow_legacy_str = OBJECT_ARRAY_OCSF_FIELDS[field]

    if isinstance(val, SigmaExists):
        if not bool(val.exists):
            raise ValueError(f"Cannot element-fuse negative exists on array field {field!r}")
        return _extract_elem_exists_expr(
            elem_expr, elem_type_expr, leaf_key, allow_legacy_str, dialect_name
        )

    if isinstance(val, SigmaBool):
        return _extract_elem_bool_pred(
            elem_expr, elem_type_expr, leaf_key, bool(val.boolean), dialect_name, counter
        )

    if isinstance(val, (SigmaNumber, SigmaCompareExpression)):
        return _compile_numeric_pred(
            _extract_elem_numeric_expr(elem_expr, elem_type_expr, leaf_key, dialect_name),
            val,
            counter,
        )

    if isinstance(val, SigmaExpansion):
        if not val.values:
            return false()
        return or_(
            *(
                _compile_array_elem_sigma_leaf(
                    field, sub_v, elem_expr, elem_type_expr, dialect_name, counter
                )
                for sub_v in val.values
            )
        )

    elem_text = _extract_elem_text_expr(
        elem_expr, elem_type_expr, leaf_key, allow_legacy_str, dialect_name
    )
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
        if dialect_name == "postgresql":
            _normalize_postgres_regex(rx_pattern, ic, ml, da)
        return _regex_to_sql(elem_text, rx_pattern, ic, ml, da, dialect_name, counter)

    if isinstance(val, SigmaCasedString):
        return _sigma_string_to_sql(elem_text, val, True, dialect_name, counter)

    if isinstance(val, SigmaString):
        return _sigma_string_to_sql(elem_text, val, False, dialect_name, counter)

    raise ValueError(f"Unsupported Sigma value type on array field {field!r}: {type(val).__name__}")


def _compile_array_elem_sigma_node(
    node: object,
    elem_expr: ColumnElement[Any],
    elem_type_expr: ColumnElement[Any] | None,
    dialect_name: str,
    counter: _ParamCounter,
) -> ColumnElement[bool]:
    if isinstance(node, ConditionAND):
        children = [
            _compile_array_elem_sigma_node(arg, elem_expr, elem_type_expr, dialect_name, counter)
            for arg in node.args
        ]
        return and_(*children) if children else true()
    if isinstance(node, ConditionOR):
        children = [
            _compile_array_elem_sigma_node(arg, elem_expr, elem_type_expr, dialect_name, counter)
            for arg in node.args
        ]
        return or_(*children) if children else false()
    if isinstance(node, ConditionFieldEqualsValueExpression):
        return _compile_array_elem_sigma_leaf(
            node.field, node.value, elem_expr, elem_type_expr, dialect_name, counter
        )
    raise ValueError(f"Unsupported AST node inside array element fusion: {type(node).__name__}")


def _compile_sigma_node(
    node: object,
    dialect_name: str,
    counter: _ParamCounter,
) -> ColumnElement[bool]:
    if isinstance(node, ConditionAND):
        fusible_groups: dict[tuple[str, ...], list[object]] = {}
        order_tokens: list[tuple[str, object]] = []
        for arg in node.args:
            arr_path = _single_array_path_of_sigma_node(arg)
            if arr_path is not None:
                if arr_path not in fusible_groups:
                    fusible_groups[arr_path] = []
                    order_tokens.append(("group", arr_path))
                fusible_groups[arr_path].append(arg)
            else:
                order_tokens.append(("single", arg))

        children: list[ColumnElement[bool]] = []
        for kind, payload in order_tokens:
            if kind == "single":
                children.append(_compile_sigma_node(payload, dialect_name, counter))
                continue
            assert isinstance(payload, tuple)
            group = fusible_groups[payload]
            if len(group) == 1:
                children.append(_compile_sigma_node(group[0], dialect_name, counter))
            else:

                def _build_fused(
                    ee: ColumnElement[Any],
                    et: ColumnElement[Any] | None,
                    g: list[object] = group,
                ) -> ColumnElement[bool]:
                    return and_(
                        *(
                            _compile_array_elem_sigma_node(sub, ee, et, dialect_name, counter)
                            for sub in g
                        )
                    )

                children.append(_wrap_array_exists(payload, dialect_name, _build_fused))
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


_CUSTOM_CMP_OP_MAP: dict[PredicateOperator, Any] = {
    PredicateOperator.LT: SigmaCompareExpression.CompareOperators.LT,
    PredicateOperator.LTE: SigmaCompareExpression.CompareOperators.LTE,
    PredicateOperator.GT: SigmaCompareExpression.CompareOperators.GT,
    PredicateOperator.GTE: SigmaCompareExpression.CompareOperators.GTE,
}


def _predicate_to_sigma_value(pred: StructuredPredicate) -> SigmaType:
    op = pred.op
    val = pred.value
    if op == PredicateOperator.EXISTS:
        return SigmaExists(bool(val))
    if op in _CUSTOM_CMP_OP_MAP:
        num = float(val) if isinstance(val, float) else int(val)
        return SigmaCompareExpression(SigmaNumber(num), _CUSTOM_CMP_OP_MAP[op])
    if op == PredicateOperator.EQ:
        if isinstance(val, bool):
            return SigmaBool(val)
        if isinstance(val, (int, float)):
            return SigmaNumber(val)
        return SigmaCasedString(str(val)) if pred.case_sensitive else SigmaString(str(val))
    raw_s = str(val)
    if op == PredicateOperator.CONTAINS:
        return (
            SigmaCasedString.from_str(f"*{raw_s}*")
            if pred.case_sensitive
            else SigmaString(f"*{raw_s}*")
        )
    if op == PredicateOperator.STARTSWITH:
        return (
            SigmaCasedString.from_str(f"{raw_s}*")
            if pred.case_sensitive
            else SigmaString(f"{raw_s}*")
        )
    if op == PredicateOperator.ENDSWITH:
        return (
            SigmaCasedString.from_str(f"*{raw_s}")
            if pred.case_sensitive
            else SigmaString(f"*{raw_s}")
        )
    if op == PredicateOperator.REGEX:
        flags = set() if pred.case_sensitive else {SigmaRegularExpressionFlag.IGNORECASE}
        return SigmaRegularExpression(raw_s, flags=flags)
    raise ValueError(f"Unsupported operator: {op}")


def _compile_structured_predicate(
    pred: StructuredPredicate,
    dialect_name: str,
    counter: _ParamCounter,
) -> ColumnElement[bool]:
    _validate_ocsf_field(pred.field)
    op = pred.op
    val = pred.value

    if op == PredicateOperator.EXISTS:
        return _compile_field_exists_expr(pred.field, bool(val), dialect_name)

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

    sigma_val = _predicate_to_sigma_value(pred)
    return _compile_sigma_field_value(pred.field, sigma_val, dialect_name, counter)


def _single_array_path_of_custom_node(node: CustomConditionNode) -> tuple[str, ...] | None:
    if node.predicate is not None:
        pred = node.predicate
        if pred.field not in OBJECT_ARRAY_OCSF_FIELDS:
            return None
        if pred.op == PredicateOperator.NEQ:
            return None
        if pred.op == PredicateOperator.EXISTS and not bool(pred.value):
            return None
        return OBJECT_ARRAY_OCSF_FIELDS[pred.field][0]
    if node.all_of:
        paths = {_single_array_path_of_custom_node(c) for c in node.all_of}
        if None in paths or len(paths) != 1:
            return None
        return next(iter(paths))
    if node.any_of:
        paths = {_single_array_path_of_custom_node(c) for c in node.any_of}
        if None in paths or len(paths) != 1:
            return None
        return next(iter(paths))
    return None


def _compile_array_elem_custom_node(
    node: CustomConditionNode,
    elem_expr: ColumnElement[Any],
    elem_type_expr: ColumnElement[Any] | None,
    dialect_name: str,
    counter: _ParamCounter,
) -> ColumnElement[bool]:
    if node.predicate is not None:
        pred = node.predicate
        _validate_ocsf_field(pred.field)
        if pred.op == PredicateOperator.IN:
            val = pred.value
            if not isinstance(val, list) or not val:
                raise ValueError(f"'in' operator on {pred.field!r} requires a non-empty list")
            return or_(
                *(
                    _compile_array_elem_custom_node(
                        CustomConditionNode(
                            predicate=StructuredPredicate(
                                field=pred.field,
                                op=PredicateOperator.EQ,
                                value=item,
                                case_sensitive=pred.case_sensitive,
                            )
                        ),
                        elem_expr,
                        elem_type_expr,
                        dialect_name,
                        counter,
                    )
                    for item in val
                )
            )
        sigma_val = _predicate_to_sigma_value(pred)
        return _compile_array_elem_sigma_leaf(
            pred.field, sigma_val, elem_expr, elem_type_expr, dialect_name, counter
        )
    if node.all_of:
        return and_(
            *(
                _compile_array_elem_custom_node(c, elem_expr, elem_type_expr, dialect_name, counter)
                for c in node.all_of
            )
        )
    if node.any_of:
        return or_(
            *(
                _compile_array_elem_custom_node(c, elem_expr, elem_type_expr, dialect_name, counter)
                for c in node.any_of
            )
        )
    raise ValueError("Unsupported custom node inside array element fusion")


def _compile_custom_node(
    node: CustomConditionNode,
    dialect_name: str,
    counter: _ParamCounter,
) -> ColumnElement[bool]:
    if node.predicate is not None:
        return _compile_structured_predicate(node.predicate, dialect_name, counter)
    if node.all_of:
        fusible_groups: dict[tuple[str, ...], list[CustomConditionNode]] = {}
        order_tokens: list[tuple[str, tuple[str, ...] | CustomConditionNode]] = []
        for child in node.all_of:
            arr_path = _single_array_path_of_custom_node(child)
            if arr_path is not None:
                if arr_path not in fusible_groups:
                    fusible_groups[arr_path] = []
                    order_tokens.append(("group", arr_path))
                fusible_groups[arr_path].append(child)
            else:
                order_tokens.append(("single", child))

        exprs: list[ColumnElement[bool]] = []
        for kind, payload in order_tokens:
            if kind == "single":
                assert isinstance(payload, CustomConditionNode)
                exprs.append(_compile_custom_node(payload, dialect_name, counter))
                continue
            assert isinstance(payload, tuple)
            group = fusible_groups[payload]
            if len(group) == 1:
                exprs.append(_compile_custom_node(group[0], dialect_name, counter))
            else:

                def _build_fused(
                    ee: ColumnElement[Any],
                    et: ColumnElement[Any] | None,
                    g: list[CustomConditionNode] = group,
                ) -> ColumnElement[bool]:
                    return and_(
                        *(
                            _compile_array_elem_custom_node(sub, ee, et, dialect_name, counter)
                            for sub in g
                        )
                    )

                exprs.append(_wrap_array_exists(payload, dialect_name, _build_fused))
        return and_(*exprs)
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

    unmapped = [f for f in dict.fromkeys(all_fields) if f not in KNOWN_OCSF_V14_FIELDS]
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
    unmapped = [f for f in dict.fromkeys(fields) if f not in KNOWN_OCSF_V14_FIELDS]
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
        unmapped_custom = [f for f in parsed.original_fields if f not in KNOWN_OCSF_V14_FIELDS]
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
        if orig_f not in field_mappings and orig_f in KNOWN_OCSF_V14_FIELDS:
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

    unmapped_sigma = [f for f in dict.fromkeys(post_fields) if f not in KNOWN_OCSF_V14_FIELDS]
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
