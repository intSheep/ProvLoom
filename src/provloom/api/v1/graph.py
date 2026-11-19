from __future__ import annotations

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query

from provloom.api.dependencies import get_access_scope, get_query_service
from provloom.api.schemas import (
    EntityDto,
    GraphTraverseRequest,
    PageResponse,
    RelationDto,
    RelationEvidenceDetailDto,
    SubgraphResponse,
)
from provloom.domain.common import AccessScope, PageSpec, TimeRange
from provloom.domain.graph_models import GraphTraversalSpec
from provloom.query.interfaces import QueryService

router = APIRouter(tags=["graph"])


@router.post("/graph/traverse", response_model=SubgraphResponse)
def traverse_graph(
    body: GraphTraverseRequest,
    scope: Annotated[AccessScope, Depends(get_access_scope)],
    svc: Annotated[QueryService, Depends(get_query_service)],
) -> SubgraphResponse:
    subgraph = svc.traverse_graph(
        scope=scope,
        time_range=TimeRange(body.time_range.start_time, body.time_range.end_time),
        spec=GraphTraversalSpec(
            seed_entity_id=body.seed_entity_id,
            max_depth=body.max_depth,
            direction=body.direction,
            relation_types=tuple(body.relation_types) if body.relation_types else None,
            include_candidates=body.include_candidates,
            max_nodes=body.max_nodes,
            max_edges=body.max_edges,
        ),
    )
    return SubgraphResponse(
        seed_entity_id=subgraph.seed_entity_id,
        nodes=[EntityDto.model_validate(n) for n in subgraph.nodes],
        edges=[RelationDto.model_validate(e) for e in subgraph.edges],
        truncated=subgraph.truncated,
    )


@router.get(
    "/relations/{relation_id}/evidence", response_model=PageResponse[RelationEvidenceDetailDto]
)
def get_relation_evidence(
    relation_id: UUID,
    scope: Annotated[AccessScope, Depends(get_access_scope)],
    svc: Annotated[QueryService, Depends(get_query_service)],
    start_time: datetime | None = Query(default=None),
    end_time: datetime | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    cursor: str | None = Query(default=None),
) -> PageResponse[RelationEvidenceDetailDto]:
    tr = TimeRange(start_time, end_time) if start_time and end_time else None
    result = svc.get_relation_evidence(
        scope=scope,
        relation_id=relation_id,
        time_range=tr,
        page=PageSpec(limit=limit, cursor=cursor),
    )
    return PageResponse(
        items=[
            RelationEvidenceDetailDto(
                evidence_id=item.evidence.evidence_id,
                relation_id=item.evidence.relation_id,
                event_id=item.evidence.event_id,
                raw_event_id=item.evidence.raw_event_id,
                evidence_role=item.evidence.evidence_role,
                observed_at=item.evidence.observed_at,
                match_detail=item.evidence.match_detail,
                source_id=item.source_id,
                ocsf_class_uid=item.ocsf_class_uid,
                raw_payload=item.raw_payload,
            )
            for item in result.items
        ],
        next_cursor=result.next_cursor,
        truncated=result.truncated,
    )
