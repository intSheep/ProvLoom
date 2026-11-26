from __future__ import annotations

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status

from provloom.api.dependencies import get_access_scope, get_query_service
from provloom.api.schemas import (
    EventDetailDto,
    EventSearchRequest,
    NormalizedEventSummaryDto,
    PageResponse,
    RawEventDto,
)
from provloom.domain.common import AccessScope, PageSpec, TimeRange
from provloom.query.interfaces import EventSearchFilter, QueryService

router = APIRouter(prefix="/events", tags=["events"])


@router.post("/search", response_model=PageResponse[NormalizedEventSummaryDto])
def search_events(
    body: EventSearchRequest,
    scope: Annotated[AccessScope, Depends(get_access_scope)],
    svc: Annotated[QueryService, Depends(get_query_service)],
) -> PageResponse[NormalizedEventSummaryDto]:
    result = svc.search_events(
        scope=scope,
        time_range=TimeRange(body.time_range.start_time, body.time_range.end_time),
        filters=EventSearchFilter(
            sources=tuple(body.sources) if body.sources else None,
            class_uids=tuple(body.class_uids) if body.class_uids else None,
            category_uids=tuple(body.category_uids) if body.category_uids else None,
            field_equals=body.field_equals,
            include_fallback=body.include_fallback,
            fields=tuple(body.fields) if body.fields else None,
        ),
        page=PageSpec(limit=body.limit, cursor=body.cursor),
    )
    return PageResponse(
        items=[NormalizedEventSummaryDto.model_validate(item) for item in result.items],
        next_cursor=result.next_cursor,
        truncated=result.truncated,
    )


@router.get("/{event_id}", response_model=EventDetailDto)
def get_event(
    event_id: UUID,
    scope: Annotated[AccessScope, Depends(get_access_scope)],
    svc: Annotated[QueryService, Depends(get_query_service)],
    start_time: datetime | None = Query(default=None),
    end_time: datetime | None = Query(default=None),
    include_raw: bool = Query(default=True),
) -> EventDetailDto:
    tr = TimeRange(start_time, end_time) if start_time and end_time else None
    detail = svc.get_event(scope=scope, event_id=event_id, time_range=tr, include_raw=include_raw)
    if detail is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not found")
    return EventDetailDto(
        **detail.normalized.__dict__,
        raw=RawEventDto.model_validate(detail.raw) if detail.raw is not None else None,
    )
