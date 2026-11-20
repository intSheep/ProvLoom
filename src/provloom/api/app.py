from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from provloom import __version__
from provloom.api.v1 import detection, entities, events, graph, ops
from provloom.config import AppConfig
from provloom.domain.errors import (
    AdapterReadError,
    DetectionExecutionError,
    DetectionPermissionError,
    InvalidTimeRangeError,
    QueryLimitExceededError,
    RuleUnsupportedError,
    RuleValidationError,
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
    app.state.detection_service = rt.detection_service

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

    @app.exception_handler(DetectionPermissionError)
    def _handle_det_perm_err(_req: Request, exc: DetectionPermissionError) -> JSONResponse:
        return JSONResponse(status_code=403, content={"detail": str(exc)})

    @app.exception_handler(RuleValidationError)
    def _handle_rule_val_err(_req: Request, exc: RuleValidationError) -> JSONResponse:
        return JSONResponse(status_code=400, content={"detail": str(exc)})

    @app.exception_handler(RuleUnsupportedError)
    def _handle_rule_unsup_err(_req: Request, exc: RuleUnsupportedError) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(DetectionExecutionError)
    def _handle_det_exec_err(_req: Request, exc: DetectionExecutionError) -> JSONResponse:
        code = 404 if "not found" in str(exc).lower() else 400
        return JSONResponse(status_code=code, content={"detail": str(exc)})

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
    app.include_router(detection.router, prefix="/api/v1")
    app.include_router(ops.router, prefix="/api/v1")

    static_dir = Path(__file__).resolve().parent / "static"
    repo_web_dist = Path(__file__).resolve().parents[3] / "web" / "dist"
    cwd_web_dist = Path("web/dist")
    web_dist = cwd_web_dist if cwd_web_dist.is_dir() else repo_web_dist

    if web_dist.is_dir():
        assets_dir = web_dist / "assets"
        if assets_dir.is_dir():
            app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="ui-assets")

        @app.get("/{full_path:path}", include_in_schema=False)
        def serve_spa(full_path: str) -> Response:
            if full_path.startswith(("api/", "assets/")) or full_path in {"api", "assets"}:
                return JSONResponse(status_code=404, content={"detail": "Not Found"})
            candidate = (web_dist / full_path).resolve()
            if full_path and candidate.is_file() and candidate.is_relative_to(web_dist.resolve()):
                return FileResponse(candidate)
            return FileResponse(web_dist / "index.html")
    elif static_dir.is_dir():
        app.mount("/assets", StaticFiles(directory=str(static_dir)), name="ui-assets")

        @app.get("/", include_in_schema=False)
        def serve_console() -> FileResponse:
            return FileResponse(static_dir / "index.html")

    return app
