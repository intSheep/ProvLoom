from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from provloom import __version__
from provloom.api.v1 import entities, events, graph, ops
from provloom.config import AppConfig
from provloom.domain.errors import (
    AdapterReadError,
    InvalidTimeRangeError,
    QueryLimitExceededError,
    ScopeViolationError,
)
from provloom.runtime import ProvLoomRuntime


def create_app(runtime: ProvLoomRuntime | None = None) -> FastAPI:
    rt = runtime or ProvLoomRuntime.build(AppConfig.from_env())
    app = FastAPI(
        title="ProvLoom API",
        version=__version__,
        description="Unified OCSF security fact and provenance graph query service",
    )
    app.state.runtime = rt
    app.state.query_service = rt.query_service
    app.state.ops_service = rt.ops_service

    @app.exception_handler(InvalidTimeRangeError)
    def _handle_time_err(_req: Request, exc: InvalidTimeRangeError) -> JSONResponse:
        return JSONResponse(status_code=400, content={"detail": str(exc)})

    @app.exception_handler(AdapterReadError)
    def _handle_adapter_err(_req: Request, exc: AdapterReadError) -> JSONResponse:
        return JSONResponse(status_code=400, content={"detail": str(exc)})

    @app.exception_handler(QueryLimitExceededError)
    def _handle_limit_err(_req: Request, exc: QueryLimitExceededError) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(ScopeViolationError)
    def _handle_scope_err(_req: Request, exc: ScopeViolationError) -> JSONResponse:
        return JSONResponse(status_code=403, content={"detail": str(exc)})

    @app.get("/healthz", tags=["system"])
    def healthz() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.get("/metrics", tags=["system"])
    def prometheus_metrics() -> Response:
        return Response(
            content=rt.telemetry.render_prometheus(),
            media_type="text/plain; version=0.0.4; charset=utf-8",
        )

    app.include_router(events.router, prefix="/api/v1")
    app.include_router(entities.router, prefix="/api/v1")
    app.include_router(graph.router, prefix="/api/v1")
    app.include_router(ops.router, prefix="/api/v1")

    static_dir = Path(__file__).resolve().parent / "static"
    web_dist = Path("web/dist")
    ui_root = web_dist if web_dist.is_dir() else static_dir
    if ui_root.is_dir():
        app.mount("/assets", StaticFiles(directory=str(ui_root)), name="ui-assets")

        @app.get("/", include_in_schema=False)
        def serve_console() -> FileResponse:
            return FileResponse(ui_root / "index.html")

    return app
