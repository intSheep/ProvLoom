from __future__ import annotations

import os
from datetime import timedelta
from pathlib import Path
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status

from provloom.api.dependencies import get_access_scope, get_ops_service
from provloom.api.schemas import (
    IngestBatchDto,
    PageResponse,
    PipelineFailureDto,
    RawPasteImportDto,
    ReplayRequestDto,
    SampleImportDto,
    TimeRangeDto,
)
from provloom.domain.common import AccessScope, PageSpec, TimeRange
from provloom.domain.enums import PipelineStage
from provloom.query.ops_interfaces import OpsDebugService, ReplayRequest, SampleImportRequest

router = APIRouter(prefix="/ops", tags=["ops-debug"])


@router.post("/batches/import")
def import_sample(
    body: SampleImportDto,
    scope: Annotated[AccessScope, Depends(get_access_scope)],
    ops: Annotated[OpsDebugService, Depends(get_ops_service)],
) -> dict[str, Any]:
    allowed_root = Path(os.getenv("PROVLOOM_INGEST_ROOT", ".")).resolve()
    target_path = Path(body.source_uri).resolve()
    if not target_path.is_relative_to(allowed_root):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="source_uri must reside within PROVLOOM_INGEST_ROOT",
        )
    receipt = ops.submit_import(
        SampleImportRequest(
            tenant_scope=scope.tenant_id,
            source_id=body.source_id,
            source_type=body.source_type,
            adapter_type=body.adapter_type,
            source_uri=body.source_uri,
        )
    )
    return receipt.__dict__


@router.post("/batches/raw")
def import_raw_text(
    body: RawPasteImportDto,
    scope: Annotated[AccessScope, Depends(get_access_scope)],
    ops: Annotated[OpsDebugService, Depends(get_ops_service)],
) -> dict[str, Any]:
    receipt = ops.import_raw_content(
        tenant_scope=scope.tenant_id,
        source_id=body.source_id,
        source_type=body.source_type,
        adapter_type=body.adapter_type,
        raw_text=body.raw_text,
    )
    return receipt.__dict__


@router.post("/batches/examples")
def load_examples(
    scope: Annotated[AccessScope, Depends(get_access_scope)],
    ops: Annotated[OpsDebugService, Depends(get_ops_service)],
) -> dict[str, Any]:
    receipts = ops.load_builtin_examples(tenant_scope=scope.tenant_id)
    return {
        "batches_loaded": len(receipts),
        "accepted_total": sum(r.accepted_count for r in receipts),
        "duplicate_total": sum(r.duplicate_count for r in receipts),
        "failed_total": sum(r.failed_count for r in receipts),
    }


@router.get("/time-bounds")
def get_time_bounds(
    scope: Annotated[AccessScope, Depends(get_access_scope)],
    ops: Annotated[OpsDebugService, Depends(get_ops_service)],
) -> TimeRangeDto | None:
    bounds = ops.get_dataset_time_bounds(scope)
    if bounds is None:
        return None
    return TimeRangeDto(
        start_time=bounds.start_time - timedelta(minutes=1),
        end_time=bounds.end_time + timedelta(minutes=1),
    )


@router.get("/batches", response_model=PageResponse[IngestBatchDto])
def list_batches(
    scope: Annotated[AccessScope, Depends(get_access_scope)],
    ops: Annotated[OpsDebugService, Depends(get_ops_service)],
    limit: int = Query(default=50, ge=1, le=500),
    cursor: str | None = Query(default=None),
) -> PageResponse[IngestBatchDto]:
    res = ops.list_batches(scope=scope, page=PageSpec(limit=limit, cursor=cursor))
    return PageResponse(
        items=[IngestBatchDto.model_validate(b) for b in res.items],
        next_cursor=res.next_cursor,
        truncated=res.truncated,
    )


@router.get("/batches/{batch_id}", response_model=IngestBatchDto)
def get_batch(
    batch_id: UUID,
    scope: Annotated[AccessScope, Depends(get_access_scope)],
    ops: Annotated[OpsDebugService, Depends(get_ops_service)],
) -> IngestBatchDto:
    batch = ops.get_batch(scope=scope, batch_id=batch_id)
    if batch is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Batch not found")
    return IngestBatchDto.model_validate(batch)


@router.get("/failures", response_model=PageResponse[PipelineFailureDto])
def list_failures(
    scope: Annotated[AccessScope, Depends(get_access_scope)],
    ops: Annotated[OpsDebugService, Depends(get_ops_service)],
    batch_id: UUID | None = Query(default=None),
    stage: PipelineStage | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    cursor: str | None = Query(default=None),
) -> PageResponse[PipelineFailureDto]:
    res = ops.list_failures(
        scope=scope, batch_id=batch_id, stage=stage, page=PageSpec(limit=limit, cursor=cursor)
    )
    return PageResponse(
        items=[PipelineFailureDto.model_validate(f) for f in res.items],
        next_cursor=res.next_cursor,
        truncated=res.truncated,
    )


@router.post("/retry")
def trigger_retry(
    scope: Annotated[AccessScope, Depends(get_access_scope)],
    ops: Annotated[OpsDebugService, Depends(get_ops_service)],
    batch_id: UUID | None = Query(default=None),
) -> dict[str, int]:
    return ops.trigger_retry(scope=scope, batch_id=batch_id).__dict__


@router.post("/replay")
def trigger_replay(
    body: ReplayRequestDto,
    scope: Annotated[AccessScope, Depends(get_access_scope)],
    ops: Annotated[OpsDebugService, Depends(get_ops_service)],
) -> dict[str, int]:
    tr = (
        TimeRange(body.time_range.start_time, body.time_range.end_time) if body.time_range else None
    )
    receipt = ops.trigger_replay(
        scope=scope,
        req=ReplayRequest(
            time_range=tr,
            batch_ids=tuple(body.batch_ids) if body.batch_ids else None,
        ),
    )
    return receipt.__dict__


@router.get("/metrics/summary")
def get_metrics_summary(
    scope: Annotated[AccessScope, Depends(get_access_scope)],
    ops: Annotated[OpsDebugService, Depends(get_ops_service)],
) -> dict[str, int]:
    return ops.get_metrics_snapshot(scope=scope).__dict__


@router.get("/mappings")
def list_mappings(
    ops: Annotated[OpsDebugService, Depends(get_ops_service)],
) -> list[dict[str, Any]]:
    return [spec.__dict__ for spec in ops.list_mapping_specs()]
