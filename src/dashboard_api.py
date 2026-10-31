"""Aplicação FastAPI do Marco 12."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse

from src.dashboard_service import DashboardRequest, DashboardService
from src.monitoring_repository import (
    PredictionRepository,
    RepositoryUnavailable,
    create_mongo_repository,
)
from src.runtime_config import (
    ActiveModelIdentity,
    RuntimeSettings,
    load_active_model_identity,
)


def _request(
    start: Annotated[datetime | None, Query(description="Início inclusivo com fuso")] = None,
    end: Annotated[datetime | None, Query(description="Fim exclusivo com fuso")] = None,
    source: Annotated[str | None, Query(min_length=1, max_length=200)] = None,
    protocol: Annotated[str | None, Query(min_length=1, max_length=200)] = None,
    bucket_minutes: Annotated[int, Query(ge=1, le=1440)] = 5,
    top_n: Annotated[int, Query(ge=1, le=100)] = 10,
    limit: Annotated[int, Query(ge=1, le=1000)] = 20,
) -> DashboardRequest:
    return DashboardRequest(
        start=start,
        end=end,
        source=source,
        protocol=protocol,
        bucket_minutes=bucket_minutes,
        top_n=top_n,
        recent_limit=limit,
    )


def create_app(
    *,
    repository: PredictionRepository | None = None,
    settings: RuntimeSettings | None = None,
    model: ActiveModelIdentity | None = None,
) -> FastAPI:
    """Cria a aplicação com injeção de dependência para testes sem MongoDB."""
    settings = settings or RuntimeSettings.from_env()
    model = model or load_active_model_identity(project_root=settings.project_root)
    repository = repository or create_mongo_repository(settings)
    service = DashboardService(repository, model, settings)
    app = FastAPI(
        title="TCC Network Anomaly Dashboard API",
        version="12.0.0",
        description=(
            "API somente leitura para o dashboard do replay experimental. "
            "O anomaly_score não é probabilidade."
        ),
    )
    app.state.dashboard_service = service

    @app.exception_handler(RepositoryUnavailable)
    async def repository_unavailable_handler(_request, exc: RepositoryUnavailable):
        return JSONResponse(
            status_code=503,
            content={
                "detail": "Repositório de monitoramento indisponível.",
                "error_type": "repository_unavailable",
            },
        )

    def execute(action):
        try:
            return action()
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.get("/health/live", tags=["health"])
    def health_live():
        return {"status": "alive"}

    @app.get("/health/ready", tags=["health"])
    def health_ready():
        try:
            reachable = repository.ping()
        except RepositoryUnavailable as exc:
            raise HTTPException(
                status_code=503, detail="MongoDB indisponível."
            ) from exc
        if not reachable:
            raise HTTPException(status_code=503, detail="MongoDB indisponível.")
        return {"status": "ready", "repository": "reachable"}

    @app.get("/api/v1/dashboard/overview", tags=["dashboard"])
    def overview(request: Annotated[DashboardRequest, Depends(_request)]):
        return execute(lambda: service.overview(request))

    @app.get("/api/v1/dashboard/timeseries", tags=["dashboard"])
    def timeseries(request: Annotated[DashboardRequest, Depends(_request)]):
        return execute(lambda: service.timeseries(request))

    @app.get("/api/v1/dashboard/breakdowns", tags=["dashboard"])
    def breakdowns(request: Annotated[DashboardRequest, Depends(_request)]):
        return execute(lambda: service.breakdowns(request))

    @app.get("/api/v1/anomalies/recent", tags=["anomalies"])
    def recent_anomalies(request: Annotated[DashboardRequest, Depends(_request)]):
        return execute(lambda: service.recent_anomalies(request))

    @app.get("/api/v1/model/status", tags=["model"])
    def model_status():
        return service.model_status()

    return app
