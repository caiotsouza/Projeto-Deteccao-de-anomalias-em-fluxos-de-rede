"""Casos de uso do dashboard, independentes do framework HTTP."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from src.dashboard_reporting import build_dashboard_snapshot
from src.monitoring_repository import (
    PredictionRepository,
    QueryFilters,
    QueryResult,
)
from src.runtime_config import ActiveModelIdentity, RuntimeSettings


UNAVAILABLE_VALUES = {
    "",
    "none",
    "null",
    "unknown",
    "not_available",
    "not_available_in_processed_cicids",
}


def _utc(value: datetime, field: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field} deve informar fuso horário.")
    return value.astimezone(timezone.utc)


@dataclass(frozen=True)
class DashboardRequest:
    """Parâmetros comuns às consultas, com intervalo [start, end)."""

    start: datetime | None = None
    end: datetime | None = None
    source: str | None = None
    protocol: str | None = None
    bucket_minutes: int = 5
    top_n: int = 10
    recent_limit: int = 20


class DashboardService:
    """Produz respostas reconciliadas para FastAPI e Grafana."""

    def __init__(
        self,
        repository: PredictionRepository,
        model: ActiveModelIdentity,
        settings: RuntimeSettings,
    ) -> None:
        self.repository = repository
        self.model = model
        self.settings = settings

    def _normalize_request(
        self, request: DashboardRequest
    ) -> tuple[DashboardRequest, datetime, datetime]:
        end = _utc(request.end, "end") if request.end else datetime.now(timezone.utc)
        start = (
            _utc(request.start, "start")
            if request.start
            else end - timedelta(hours=self.settings.dashboard_window_hours)
        )
        if start >= end:
            raise ValueError("A janela deve obedecer start < end.")
        if end - start > timedelta(days=self.settings.dashboard_max_window_days):
            raise ValueError(
                "A janela excede o máximo de "
                f"{self.settings.dashboard_max_window_days} dias."
            )
        if not 1 <= request.bucket_minutes <= 1_440:
            raise ValueError("bucket_minutes deve estar entre 1 e 1440.")
        if not 1 <= request.top_n <= 100:
            raise ValueError("top_n deve estar entre 1 e 100.")
        if not 1 <= request.recent_limit <= 1_000:
            raise ValueError("recent_limit deve estar entre 1 e 1000.")
        for field, value in (("source", request.source), ("protocol", request.protocol)):
            if value is not None and (not value.strip() or len(value) > 200):
                raise ValueError(f"{field} deve possuir entre 1 e 200 caracteres.")
        return request, start, end

    def _query(
        self,
        request: DashboardRequest,
        *,
        anomalies_only: bool = False,
        newest_first: bool = False,
        limit: int | None = None,
    ) -> tuple[QueryResult, datetime, datetime]:
        request, start, end = self._normalize_request(request)
        effective_limit = min(
            limit or self.settings.dashboard_max_records,
            self.settings.dashboard_max_records,
        )
        result = self.repository.query(
            QueryFilters(
                start=start,
                end=end,
                model=self.model,
                source=request.source,
                protocol=request.protocol,
                anomalies_only=anomalies_only,
                newest_first=newest_first,
                limit=effective_limit,
            )
        )
        return result, start, end

    def _query_metadata(
        self,
        request: DashboardRequest,
        start: datetime,
        end: datetime,
        result: QueryResult,
    ) -> dict[str, Any]:
        return {
            "start": start.isoformat(),
            "end": end.isoformat(),
            "interval_semantics": "start_inclusive_end_exclusive",
            "source": request.source,
            "protocol": request.protocol,
            "matched_records": result.matched_count,
            "returned_records": result.returned_count,
            "truncated": result.truncated,
            "maximum_records": self.settings.dashboard_max_records,
        }

    def _empty_snapshot(
        self, start: datetime, end: datetime, bucket_minutes: int
    ) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "window": {
                "start": start.isoformat(),
                "end": end.isoformat(),
                "bucket_minutes": bucket_minutes,
            },
            "data_extent": {"start": None, "end": None},
            "model_filter": self.model.as_filter(),
            "totals": {"flows": 0, "normal": 0, "anomalies": 0, "anomaly_rate": 0.0},
            "scores": {
                "minimum": None,
                "mean": None,
                "p95": None,
                "maximum": None,
                "is_probability": False,
                "comparability_note": (
                    "Compare scores only inside the same model SHA and operating point."
                ),
            },
            "timeline": [],
            "distributions": {"protocol": [], "source": []},
            "top_anomalous_sources": [],
            "top_anomalous_destinations": [],
            "top_anomalous_destination_ports": [],
            "recent_anomalies": [],
        }

    def snapshot(
        self, request: DashboardRequest
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        result, start, end = self._query(request)
        if result.truncated:
            raise ValueError(
                "A consulta excedeu o limite seguro de "
                f"{self.settings.dashboard_max_records} registros. "
                "Reduza a janela ou aplique um filtro; métricas parciais não são publicadas."
            )
        if result.documents:
            snapshot = build_dashboard_snapshot(
                result.documents,
                bucket_minutes=request.bucket_minutes,
                top_n=request.top_n,
                recent_limit=request.recent_limit,
            )
            snapshot["model_filter"] = self.model.as_filter()
            snapshot["data_extent"] = {
                "start": snapshot["window"]["start"],
                "end": snapshot["window"]["end"],
            }
            snapshot["window"] = {
                "start": start.isoformat(),
                "end": end.isoformat(),
                "bucket_minutes": request.bucket_minutes,
            }
        else:
            snapshot = self._empty_snapshot(start, end, request.bucket_minutes)
        metadata = self._query_metadata(request, start, end, result)
        return snapshot, metadata

    def overview(self, request: DashboardRequest) -> dict[str, Any]:
        snapshot, query = self.snapshot(request)
        totals = snapshot["totals"]
        scores = snapshot["scores"]
        return {
            "schema_version": 1,
            "generated_at_utc": snapshot["generated_at_utc"],
            "mode": "offline_replay",
            "query": query,
            "window": snapshot["window"],
            "data_extent": snapshot["data_extent"],
            "model_filter": snapshot["model_filter"],
            "totals": totals,
            "scores": scores,
            "rows": [
                {
                    "flows": totals["flows"],
                    "normal": totals["normal"],
                    "anomalies": totals["anomalies"],
                    "anomaly_rate": totals["anomaly_rate"],
                    "score_p95": scores["p95"],
                }
            ],
        }

    def timeseries(self, request: DashboardRequest) -> dict[str, Any]:
        snapshot, query = self.snapshot(request)
        return {
            "schema_version": 1,
            "generated_at_utc": snapshot["generated_at_utc"],
            "mode": "offline_replay",
            "query": query,
            "window": snapshot["window"],
            "data_extent": snapshot["data_extent"],
            "model_filter": snapshot["model_filter"],
            "timeline": snapshot["timeline"],
            "items": snapshot["timeline"],
        }

    def breakdowns(self, request: DashboardRequest) -> dict[str, Any]:
        snapshot, query = self.snapshot(request)

        def values_available(rows: list[dict[str, Any]]) -> bool:
            return any(
                str(row.get("value", "")).strip().lower() not in UNAVAILABLE_VALUES
                for row in rows
            )

        availability = {
            "protocol": values_available(snapshot["distributions"]["protocol"]),
            "src_ip": values_available(snapshot["top_anomalous_sources"]),
            "dst_ip": values_available(snapshot["top_anomalous_destinations"]),
            "dst_port": values_available(
                snapshot["top_anomalous_destination_ports"]
            ),
            "note": (
                "O replay CICIDS processado não contém IPs ou protocolo; "
                "essas dimensões não são fabricadas."
            ),
        }
        return {
            "schema_version": 1,
            "generated_at_utc": snapshot["generated_at_utc"],
            "mode": "offline_replay",
            "query": query,
            "model_filter": snapshot["model_filter"],
            "dimension_availability": availability,
            "distributions": snapshot["distributions"],
            "top_anomalous_sources": (
                snapshot["top_anomalous_sources"] if availability["src_ip"] else []
            ),
            "top_anomalous_destinations": (
                snapshot["top_anomalous_destinations"] if availability["dst_ip"] else []
            ),
            "top_anomalous_destination_ports": snapshot[
                "top_anomalous_destination_ports"
            ],
            "protocols": (
                snapshot["distributions"]["protocol"]
                if availability["protocol"]
                else []
            ),
            "sources": snapshot["distributions"]["source"],
            "destination_ports": snapshot["top_anomalous_destination_ports"],
        }

    def recent_anomalies(self, request: DashboardRequest) -> dict[str, Any]:
        result, start, end = self._query(
            request,
            anomalies_only=True,
            newest_first=True,
            limit=request.recent_limit,
        )
        items = []
        for document in result.documents:
            classification = document["classification"]
            context = document.get("context", {})
            items.append(
                {
                    "event_id": document["event_id"],
                    "observed_at": document["observed_at"],
                    "anomaly_score": classification["anomaly_score"],
                    "threshold_distance": classification["threshold_distance"],
                    "dst_port": context.get("dst_port"),
                    "dataset_provenance_ref": context.get(
                        "dataset_provenance_ref"
                    ),
                    "src_ip": context.get("src_ip"),
                    "dst_ip": context.get("dst_ip"),
                    "protocol": context.get("protocol"),
                }
            )
        return {
            "schema_version": 1,
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "mode": "offline_replay",
            "query": self._query_metadata(request, start, end, result),
            "model_filter": self.model.as_filter(),
            "recent_anomalies": items,
            "items": items,
        }

    def model_status(self) -> dict[str, Any]:
        repository_status = self.repository.status(self.model)
        row = {
            "experiment": self.model.experiment,
            "model": self.model.key,
            "display_name": self.model.display_name,
            "model_sha256": self.model.sha256,
            "operating_point": self.model.operating_point,
            "threshold": self.model.threshold,
            "target_false_positive_rate": self.model.target_false_positive_rate,
            "production_approved": self.model.production_approved,
            "mode": "offline_replay",
            "stored_documents": repository_status["documents"],
        }
        return {
            "schema_version": 1,
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "status": "ready" if repository_status["reachable"] else "unavailable",
            "mode": "offline_replay",
            "experimental_warning": (
                "Replay balanceado e tempo simulado; não representa prevalência "
                "nem comportamento temporal da rede real."
            ),
            "score_warning": "anomaly_score não é probabilidade.",
            "model_filter": self.model.as_filter(),
            "model": row,
            "repository": repository_status,
            "rows": [row],
        }
