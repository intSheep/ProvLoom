from __future__ import annotations

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status

from provloom.api.dependencies import get_access_scope, get_query_service
from provloom.api.schemas import (
    EntityDetailDto,
    EntityDto,
    EntitySearchRequest,
    PageResponse,
    RelationDto,
)
from provloom.domain.common import AccessScope, PageSpec, TimeRange
from provloom.domain.enums import Direction, RelationType
from provloom.query.interfaces import EntitySearchFilter, QueryService

router = APIRouter(prefix="/entities", tags=["entities"])


@router.post("/search", response_model=PageResponse[EntityDto])
def search_entities(
    body: EntitySearchRequest,
    scope: Annotated[AccessScope, Depends(get_access_scope)],
    svc: Annotated[QueryService, Depends(get_query_service)],
) -> PageResponse[EntityDto]:
    tr = (
        TimeRange(body.time_range.start_time, body.time_range.end_time) if body.time_range else None
    )
    result = svc.search_entities(
        scope=scope,
        time_range=tr,
        filters=EntitySearchFilter(
            entity_types=tuple(body.entity_types) if body.entity_types else None,
            resolution_states=tuple(body.resolution_states) if body.resolution_states else None,
            identifier_query=body.identifier_query,
        ),
        page=PageSpec(limit=body.limit, cursor=body.cursor),
    )
    return PageResponse(
        items=[EntityDto.model_validate(item) for item in result.items],
        next_cursor=result.next_cursor,
        truncated=result.truncated,
    )


@router.get("/{entity_id}", response_model=EntityDetailDto)
def get_entity(
    entity_id: UUID,
    scope: Annotated[AccessScope, Depends(get_access_scope)],
    svc: Annotated[QueryService, Depends(get_query_service)],
    start_time: datetime | None = Query(default=None),
    end_time: datetime | None = Query(default=None),
    follow_merged: bool = Query(default=True),
) -> EntityDetailDto:
    tr = TimeRange(start_time, end_time) if start_time and end_time else None
    detail = svc.get_entity(
        scope=scope, entity_id=entity_id, time_range=tr, follow_merged=follow_merged
    )
    if detail is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Entity not found")
    return EntityDetailDto.model_validate(detail)


@router.get("/{entity_id}/relations", response_model=PageResponse[RelationDto])
def get_entity_relations(
    entity_id: UUID,
    start_time: datetime,
    end_time: datetime,
    scope: Annotated[AccessScope, Depends(get_access_scope)],
    svc: Annotated[QueryService, Depends(get_query_service)],
    direction: Direction = Query(default=Direction.BOTH),
    relation_types: Annotated[list[RelationType] | None, Query()] = None,
    include_candidates: bool = Query(default=False),
    limit: int = Query(default=100, ge=1, le=500),
    cursor: str | None = Query(default=None),
) -> PageResponse[RelationDto]:
    result = svc.get_entity_relations(
        scope=scope,
        entity_id=entity_id,
        time_range=TimeRange(start_time, end_time),
        direction=direction,
        relation_types=relation_types,
        include_candidates=include_candidates,
        page=PageSpec(limit=limit, cursor=cursor),
    )
    return PageResponse(
        items=[RelationDto.model_validate(item) for item in result.items],
        next_cursor=result.next_cursor,
        truncated=result.truncated,
    )
