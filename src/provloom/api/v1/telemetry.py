from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query

from provloom.api.dependencies import get_access_scope, get_query_service
from provloom.api.schemas import (
    IngestBatchDto,
    PipelineFailureDto,
    TelemetryCoverageDto,
    TimeRangeDto,
)
from provloom.domain.common import AccessScope, TimeRange
from provloom.query.interfaces import QueryService

router = APIRouter(prefix="/telemetry", tags=["telemetry"])


@router.get("/coverage", response_model=TelemetryCoverageDto)
def get_telemetry_coverage(
    start_time: datetime,
    end_time: datetime,
    scope: Annotated[AccessScope, Depends(get_access_scope)],
    svc: Annotated[QueryService, Depends(get_query_service)],
    include_batches: bool = Query(default=True),
    include_failures: bool = Query(default=True),
) -> TelemetryCoverageDto:
    cov = svc.get_telemetry_coverage(
        scope=scope,
        time_range=TimeRange(start_time, end_time),
        include_batches=include_batches,
        include_failures=include_failures,
    )
    return TelemetryCoverageDto(
        time_range=TimeRangeDto.model_validate(cov.time_range),
        dataset_time_bounds=(
            TimeRangeDto.model_validate(cov.dataset_time_bounds)
            if cov.dataset_time_bounds is not None
            else None
        ),
        total_events=cov.total_events,
        by_source=cov.by_source,
        by_class_uid=cov.by_class_uid,
        by_normalization_status=cov.by_normalization_status,
        ingest_batches=[IngestBatchDto.model_validate(b) for b in cov.ingest_batches],
        failures_total=cov.failures_total,
        failures_by_stage_code=cov.failures_by_stage_code,
        sample_failures=[PipelineFailureDto.model_validate(f) for f in cov.sample_failures],
    )
