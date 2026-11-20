from __future__ import annotations

import hmac

from fastapi import Header, HTTPException, Request, status

from provloom.detection.service import DefaultDetectionService
from provloom.domain.common import AccessScope
from provloom.domain.errors import DetectionPermissionError
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


def get_detection_service(request: Request) -> DefaultDetectionService:
    svc: DefaultDetectionService | None = getattr(request.app.state, "detection_service", None)
    if svc is None:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="DetectionService is not wired.",
        )
    return svc


def require_detection_exec_permission(
    request: Request,
    x_detection_exec_token: str | None = Header(default=None),
    x_ops_token: str | None = Header(default=None),
    x_detection_role: str | None = Header(default=None),
) -> None:
    if x_detection_role and x_detection_role.strip().lower() in {"readonly", "viewer", "guest"}:
        raise DetectionPermissionError(
            "Read-only caller is not permitted to mutate or execute detection rules"
        )
    rt = getattr(request.app.state, "runtime", None)
    expected: str | None = rt.config.detection.execution_token if rt is not None else None
    if expected is not None:
        provided = x_detection_exec_token or x_ops_token or ""
        if not hmac.compare_digest(provided, expected):
            raise DetectionPermissionError(
                "Missing or invalid X-Detection-Exec-Token for detection execution"
            )
