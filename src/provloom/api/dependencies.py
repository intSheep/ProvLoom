from __future__ import annotations

from fastapi import Header, HTTPException, Request, status

from provloom.domain.common import AccessScope
from provloom.query.interfaces import QueryService
from provloom.query.ops_interfaces import OpsDebugService


def get_access_scope(
    x_tenant_id: str = Header(default="default"),
    x_allowed_sources: str | None = Header(default=None),
) -> AccessScope:
    sources = (
        frozenset(s.strip() for s in x_allowed_sources.split(",") if s.strip())
        if x_allowed_sources
        else None
    )
    return AccessScope(tenant_id=x_tenant_id, allowed_sources=sources)


def get_query_service(request: Request) -> QueryService:
    svc: QueryService | None = getattr(request.app.state, "query_service", None)
    if svc is None:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="QueryService is not wired yet (scheduled for M6).",
        )
    return svc


def get_ops_service(request: Request) -> OpsDebugService:
    svc: OpsDebugService | None = getattr(request.app.state, "ops_service", None)
    if svc is None:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="OpsDebugService is not wired yet (scheduled for M2-M6).",
        )
    return svc
