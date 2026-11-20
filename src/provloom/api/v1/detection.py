from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status

from provloom.api.dependencies import (
    get_access_scope,
    get_detection_service,
    require_detection_exec_permission,
)
from provloom.api.schemas import (
    CandidateGroupDto,
    CandidateGroupMembersDto,
    CandidateGroupSearchRequestDto,
    DetectionExecutionDto,
    DetectionRuleDetailDto,
    DetectionRuleDto,
    ExecuteRuleBatchRequestDto,
    ExecuteRuleRequestDto,
    ImportRuleRequestDto,
    PageResponse,
    RuleMatchDto,
    RuleMatchSearchRequestDto,
    RuleTestResponseDto,
    SignalDto,
    SignalEvidenceDetailDto,
    SignalSearchRequestDto,
    TestRuleRequestDto,
    UpdateSignalStatusRequestDto,
    ValidateRuleRequestDto,
)
from provloom.detection.domain.rule import RuleSeverity, RuleSource, RuleStatus
from provloom.detection.service import DefaultDetectionService
from provloom.domain.common import AccessScope, PageSpec, TimeRange

router = APIRouter(prefix="/detection", tags=["detection"])


@router.get("/rules", response_model=PageResponse[DetectionRuleDto])
def list_detection_rules(
    scope: Annotated[AccessScope, Depends(get_access_scope)],
    svc: Annotated[DefaultDetectionService, Depends(get_detection_service)],
    source: RuleSource | None = Query(default=None),
    rule_status: RuleStatus | None = Query(default=None, alias="status"),
    severity: RuleSeverity | None = Query(default=None),
    attack_tag: str | None = Query(default=None),
    q: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    cursor: str | None = Query(default=None),
) -> PageResponse[DetectionRuleDto]:
    res = svc.list_detection_rules(
        scope=scope,
        source=source,
        status=rule_status,
        severity=severity,
        attack_tag=attack_tag,
        query_text=q,
        page=PageSpec(limit=limit, cursor=cursor),
    )
    return PageResponse(
        items=[DetectionRuleDto.model_validate(r) for r in res.items],
        next_cursor=res.next_cursor,
        truncated=res.truncated,
    )


@router.get("/rules/{rule_id}", response_model=DetectionRuleDetailDto)
def get_detection_rule(
    rule_id: str,
    scope: Annotated[AccessScope, Depends(get_access_scope)],
    svc: Annotated[DefaultDetectionService, Depends(get_detection_service)],
) -> DetectionRuleDetailDto:
    view = svc.get_detection_rule(scope=scope, rule_id=rule_id)
    if view is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")
    return DetectionRuleDetailDto(
        rule=DetectionRuleDto.model_validate(view.rule),
        compiled_sql=view.compiled_sql,
        parsed_summary=view.parsed_summary,
    )


@router.post("/rules/validate", response_model=DetectionRuleDetailDto)
def validate_detection_rule(
    body: ValidateRuleRequestDto,
    svc: Annotated[DefaultDetectionService, Depends(get_detection_service)],
) -> DetectionRuleDetailDto:
    view = svc.validate_detection_rule(raw_yaml=body.raw_yaml, source_hint=body.source_hint)
    return DetectionRuleDetailDto(
        rule=DetectionRuleDto.model_validate(view.rule),
        compiled_sql=view.compiled_sql,
        parsed_summary=view.parsed_summary,
    )


@router.post(
    "/rules/import",
    response_model=DetectionRuleDetailDto,
    dependencies=[Depends(require_detection_exec_permission)],
)
def import_detection_rule(
    body: ImportRuleRequestDto,
    scope: Annotated[AccessScope, Depends(get_access_scope)],
    svc: Annotated[DefaultDetectionService, Depends(get_detection_service)],
) -> DetectionRuleDetailDto:
    view = svc.import_detection_rule(
        scope=scope,
        raw_yaml=body.raw_yaml,
        source_reference=body.source_reference,
        source_hint=body.source_hint,
    )
    return DetectionRuleDetailDto(
        rule=DetectionRuleDto.model_validate(view.rule),
        compiled_sql=view.compiled_sql,
        parsed_summary=view.parsed_summary,
    )


@router.post(
    "/rules/{rule_id}/enable",
    response_model=DetectionRuleDto,
    dependencies=[Depends(require_detection_exec_permission)],
)
def enable_detection_rule(
    rule_id: str,
    scope: Annotated[AccessScope, Depends(get_access_scope)],
    svc: Annotated[DefaultDetectionService, Depends(get_detection_service)],
) -> DetectionRuleDto:
    updated = svc.enable_detection_rule(scope=scope, rule_id=rule_id)
    if updated is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")
    return DetectionRuleDto.model_validate(updated)


@router.post(
    "/rules/{rule_id}/disable",
    response_model=DetectionRuleDto,
    dependencies=[Depends(require_detection_exec_permission)],
)
def disable_detection_rule(
    rule_id: str,
    scope: Annotated[AccessScope, Depends(get_access_scope)],
    svc: Annotated[DefaultDetectionService, Depends(get_detection_service)],
) -> DetectionRuleDto:
    updated = svc.disable_detection_rule(scope=scope, rule_id=rule_id)
    if updated is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")
    return DetectionRuleDto.model_validate(updated)


@router.post(
    "/rules/test",
    response_model=RuleTestResponseDto,
    dependencies=[Depends(require_detection_exec_permission)],
)
def test_detection_rule(
    body: TestRuleRequestDto,
    scope: Annotated[AccessScope, Depends(get_access_scope)],
    svc: Annotated[DefaultDetectionService, Depends(get_detection_service)],
) -> RuleTestResponseDto:
    tr = TimeRange(start_time=body.time_range.start_time, end_time=body.time_range.end_time)
    res = svc.test_detection_rule(
        scope=scope,
        time_range=tr,
        raw_yaml=body.raw_yaml,
        rule_id=body.rule_id,
        max_matches=body.max_matches,
    )
    return RuleTestResponseDto(
        rule=DetectionRuleDto.model_validate(res.rule),
        parsed_summary=res.parsed_summary,
        field_mappings=res.field_mappings,
        compiled_sql=res.compiled_sql,
        matches=[RuleMatchDto.model_validate(m) for m in res.matches],
        failure_reason=res.failure_reason,
        duration_ms=res.duration_ms,
    )


@router.post(
    "/execute/{rule_id}",
    response_model=DetectionExecutionDto,
    dependencies=[Depends(require_detection_exec_permission)],
)
def execute_rule(
    rule_id: str,
    body: ExecuteRuleRequestDto,
    scope: Annotated[AccessScope, Depends(get_access_scope)],
    svc: Annotated[DefaultDetectionService, Depends(get_detection_service)],
) -> DetectionExecutionDto:
    tr = TimeRange(start_time=body.time_range.start_time, end_time=body.time_range.end_time)
    ex = svc.execute_rule(scope=scope, rule_id=rule_id, time_range=tr, max_matches=body.max_matches)
    return DetectionExecutionDto.model_validate(ex)


@router.post(
    "/execute-batch",
    response_model=DetectionExecutionDto,
    dependencies=[Depends(require_detection_exec_permission)],
)
def execute_rule_batch(
    body: ExecuteRuleBatchRequestDto,
    scope: Annotated[AccessScope, Depends(get_access_scope)],
    svc: Annotated[DefaultDetectionService, Depends(get_detection_service)],
) -> DetectionExecutionDto:
    tr = TimeRange(start_time=body.time_range.start_time, end_time=body.time_range.end_time)
    ex = svc.execute_rule_batch(
        scope=scope,
        time_range=tr,
        rule_ids=body.rule_ids,
        max_matches_per_rule=body.max_matches_per_rule,
    )
    return DetectionExecutionDto.model_validate(ex)


@router.get("/executions", response_model=PageResponse[DetectionExecutionDto])
def list_detection_executions(
    scope: Annotated[AccessScope, Depends(get_access_scope)],
    svc: Annotated[DefaultDetectionService, Depends(get_detection_service)],
    limit: int = Query(default=50, ge=1, le=500),
    cursor: str | None = Query(default=None),
) -> PageResponse[DetectionExecutionDto]:
    res = svc.list_detection_executions(scope=scope, page=PageSpec(limit=limit, cursor=cursor))
    return PageResponse(
        items=[DetectionExecutionDto.model_validate(e) for e in res.items],
        next_cursor=res.next_cursor,
        truncated=res.truncated,
    )


@router.get("/executions/{execution_id}", response_model=DetectionExecutionDto)
def get_detection_execution(
    execution_id: UUID,
    scope: Annotated[AccessScope, Depends(get_access_scope)],
    svc: Annotated[DefaultDetectionService, Depends(get_detection_service)],
) -> DetectionExecutionDto:
    ex = svc.get_detection_execution(scope=scope, execution_id=execution_id)
    if ex is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Execution not found")
    return DetectionExecutionDto.model_validate(ex)


@router.post("/matches/search", response_model=PageResponse[RuleMatchDto])
def search_rule_matches(
    body: RuleMatchSearchRequestDto,
    scope: Annotated[AccessScope, Depends(get_access_scope)],
    svc: Annotated[DefaultDetectionService, Depends(get_detection_service)],
) -> PageResponse[RuleMatchDto]:
    tr = TimeRange(start_time=body.time_range.start_time, end_time=body.time_range.end_time)
    res = svc.search_rule_matches(
        scope=scope,
        time_range=tr,
        rule_id=body.rule_id,
        detection_type=body.detection_type,
        severity=body.severity,
        entity_id=body.entity_id,
        page=PageSpec(limit=body.limit, cursor=body.cursor),
    )
    return PageResponse(
        items=[RuleMatchDto.model_validate(m) for m in res.items],
        next_cursor=res.next_cursor,
        truncated=res.truncated,
    )


@router.get("/matches/{match_id}", response_model=RuleMatchDto)
def get_rule_match(
    match_id: UUID,
    scope: Annotated[AccessScope, Depends(get_access_scope)],
    svc: Annotated[DefaultDetectionService, Depends(get_detection_service)],
) -> RuleMatchDto:
    match = svc.get_rule_match(scope=scope, match_id=match_id)
    if match is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="RuleMatch not found")
    return RuleMatchDto.model_validate(match)


@router.post("/signals/search", response_model=PageResponse[SignalDto])
def search_signals(
    body: SignalSearchRequestDto,
    scope: Annotated[AccessScope, Depends(get_access_scope)],
    svc: Annotated[DefaultDetectionService, Depends(get_detection_service)],
) -> PageResponse[SignalDto]:
    tr = TimeRange(start_time=body.time_range.start_time, end_time=body.time_range.end_time)
    res = svc.search_signals(
        scope=scope,
        time_range=tr,
        status=body.status,
        severity=body.severity,
        entity_id=body.entity_id,
        signal_type=body.signal_type,
        page=PageSpec(limit=body.limit, cursor=body.cursor),
    )
    return PageResponse(
        items=[SignalDto.model_validate(s) for s in res.items],
        next_cursor=res.next_cursor,
        truncated=res.truncated,
    )


@router.get("/signals/{signal_id}", response_model=SignalDto)
def get_signal(
    signal_id: UUID,
    scope: Annotated[AccessScope, Depends(get_access_scope)],
    svc: Annotated[DefaultDetectionService, Depends(get_detection_service)],
) -> SignalDto:
    sig = svc.get_signal(scope=scope, signal_id=signal_id)
    if sig is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Signal not found")
    return SignalDto.model_validate(sig)


@router.get("/signals/{signal_id}/matches", response_model=list[RuleMatchDto])
def get_signal_matches(
    signal_id: UUID,
    scope: Annotated[AccessScope, Depends(get_access_scope)],
    svc: Annotated[DefaultDetectionService, Depends(get_detection_service)],
) -> list[RuleMatchDto]:
    matches = svc.get_signal_matches(scope=scope, signal_id=signal_id)
    if matches is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Signal not found")
    return [RuleMatchDto.model_validate(m) for m in matches]


@router.get("/signals/{signal_id}/evidence", response_model=list[SignalEvidenceDetailDto])
def get_signal_evidence(
    signal_id: UUID,
    scope: Annotated[AccessScope, Depends(get_access_scope)],
    svc: Annotated[DefaultDetectionService, Depends(get_detection_service)],
) -> list[SignalEvidenceDetailDto]:
    evidences = svc.get_signal_evidence(scope=scope, signal_id=signal_id)
    if evidences is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Signal not found")
    return [SignalEvidenceDetailDto.model_validate(e) for e in evidences]


@router.patch(
    "/signals/{signal_id}/status",
    response_model=SignalDto,
    dependencies=[Depends(require_detection_exec_permission)],
)
def update_signal_status(
    signal_id: UUID,
    body: UpdateSignalStatusRequestDto,
    scope: Annotated[AccessScope, Depends(get_access_scope)],
    svc: Annotated[DefaultDetectionService, Depends(get_detection_service)],
) -> SignalDto:
    updated = svc.update_signal_status(scope=scope, signal_id=signal_id, status=body.status)
    if updated is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Signal not found")
    return SignalDto.model_validate(updated)


@router.post("/candidate-groups/search", response_model=PageResponse[CandidateGroupDto])
def search_candidate_groups(
    body: CandidateGroupSearchRequestDto,
    scope: Annotated[AccessScope, Depends(get_access_scope)],
    svc: Annotated[DefaultDetectionService, Depends(get_detection_service)],
) -> PageResponse[CandidateGroupDto]:
    tr = TimeRange(start_time=body.time_range.start_time, end_time=body.time_range.end_time)
    res = svc.search_candidate_groups(
        scope=scope,
        time_range=tr,
        entity_id=body.entity_id,
        certainty=body.certainty,
        page=PageSpec(limit=body.limit, cursor=body.cursor),
    )
    return PageResponse(
        items=[CandidateGroupDto.model_validate(g) for g in res.items],
        next_cursor=res.next_cursor,
        truncated=res.truncated,
    )


@router.get("/candidate-groups/{group_id}", response_model=CandidateGroupDto)
def get_candidate_group(
    group_id: UUID,
    scope: Annotated[AccessScope, Depends(get_access_scope)],
    svc: Annotated[DefaultDetectionService, Depends(get_detection_service)],
) -> CandidateGroupDto:
    grp = svc.get_candidate_group(scope=scope, group_id=group_id)
    if grp is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="CandidateGroup not found"
        )
    return CandidateGroupDto.model_validate(grp)


@router.get(
    "/candidate-groups/{group_id}/members",
    response_model=CandidateGroupMembersDto,
)
def get_candidate_group_members(
    group_id: UUID,
    scope: Annotated[AccessScope, Depends(get_access_scope)],
    svc: Annotated[DefaultDetectionService, Depends(get_detection_service)],
) -> CandidateGroupMembersDto:
    members = svc.get_candidate_group_members(scope=scope, group_id=group_id)
    if members is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="CandidateGroup not found"
        )
    return CandidateGroupMembersDto(
        group=CandidateGroupDto.model_validate(members.group),
        signals=[SignalDto.model_validate(s) for s in members.signals],
        rule_matches=[RuleMatchDto.model_validate(m) for m in members.rule_matches],
    )
