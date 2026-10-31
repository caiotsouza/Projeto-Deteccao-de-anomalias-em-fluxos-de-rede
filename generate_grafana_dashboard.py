"""Gera o dashboard Grafana provisionado do Marco 12.

O arquivo JSON resultante e este gerador ficam versionáveis. Assim, nenhuma
configuração essencial depende de cliques manuais na interface do Grafana.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parent
OUTPUT_PATH = PROJECT_ROOT / "infra" / "grafana" / "dashboards" / "tcc-network-anomaly.json"
DATASOURCE = {
    "type": "yesoreyeram-infinity-datasource",
    "uid": "tcc-fastapi",
}
API_BASE = "http://api:8000"
TIME_QUERY = "start=${__from:date:iso}&end=${__to:date:iso}"


def infinity_target(
    endpoint: str,
    root_selector: str,
    columns: list[tuple[str, str, str]],
    *,
    ref_id: str = "A",
    format_: str = "table",
    include_time: bool = True,
) -> dict[str, Any]:
    """Monta uma consulta JSON/URL do Infinity usando o parser backend."""
    separator = "&" if "?" in endpoint else "?"
    url = (
        f"{API_BASE}{endpoint}{separator}{TIME_QUERY}"
        if include_time
        else f"{API_BASE}{endpoint}"
    )
    return {
        "columns": [
            {"selector": selector, "text": text, "type": type_}
            for selector, text, type_ in columns
        ],
        "filters": [],
        "format": format_,
        "parser": "backend",
        "refId": ref_id,
        "root_selector": root_selector,
        "source": "url",
        "type": "json",
        "url": url,
        "url_options": {"data": "", "method": "GET"},
    }


def panel(
    panel_id: int,
    title: str,
    type_: str,
    grid: tuple[int, int, int, int],
    targets: list[dict[str, Any]],
    *,
    description: str,
    unit: str = "short",
    decimals: int | None = None,
    options: dict[str, Any] | None = None,
    overrides: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    x, y, w, h = grid
    defaults: dict[str, Any] = {
        "color": {"mode": "palette-classic"},
        "custom": {},
        "mappings": [],
        "thresholds": {
            "mode": "absolute",
            "steps": [
                {"color": "green", "value": None},
                {"color": "red", "value": 1},
            ],
        },
        "unit": unit,
    }
    if decimals is not None:
        defaults["decimals"] = decimals
    return {
        "datasource": DATASOURCE,
        "description": description,
        "fieldConfig": {
            "defaults": defaults,
            "overrides": overrides or [],
        },
        "gridPos": {"h": h, "w": w, "x": x, "y": y},
        "id": panel_id,
        "options": options or {},
        "pluginVersion": "12.2.5",
        "targets": targets,
        "title": title,
        "type": type_,
    }


def build_dashboard() -> dict[str, Any]:
    """Constrói o dashboard com 11 painéis e avisos experimentais explícitos."""
    overview = "/api/v1/dashboard/overview"
    timeseries = "/api/v1/dashboard/timeseries?bucket_minutes=5"
    breakdowns = "/api/v1/dashboard/breakdowns?top_n=10"
    recent = "/api/v1/anomalies/recent?limit=20"
    status = "/api/v1/model/status"

    stat_options = {
        "colorMode": "value",
        "graphMode": "area",
        "justifyMode": "auto",
        "orientation": "auto",
        "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
        "showPercentChange": False,
        "textMode": "auto",
        "wideLayout": True,
    }
    bar_options = {
        "barRadius": 0,
        "barWidth": 0.8,
        "fullHighlight": False,
        "groupWidth": 0.7,
        "legend": {"displayMode": "list", "placement": "bottom", "showLegend": False},
        "orientation": "horizontal",
        "showValue": "always",
        "stacking": "none",
        "tooltip": {"mode": "single", "sort": "none"},
        "xTickLabelRotation": 0,
        "xTickLabelSpacing": 0,
    }
    time_options = {
        "legend": {"calcs": [], "displayMode": "list", "placement": "bottom", "showLegend": True},
        "tooltip": {"hideZeros": False, "mode": "multi", "sort": "none"},
    }

    panels = [
        panel(
            1,
            "Fluxos analisados",
            "stat",
            (0, 0, 6, 4),
            [infinity_target(overview, "$.rows", [("flows", "Fluxos", "number")])],
            description="Quantidade de previsões do modelo ativo no intervalo [início, fim).",
            options=stat_options,
        ),
        panel(
            2,
            "Anomalias sinalizadas",
            "stat",
            (6, 0, 6, 4),
            [infinity_target(overview, "$.rows", [("anomalies", "Anomalias", "number")])],
            description="Decisões cujo anomaly_score atingiu ou superou o limiar operacional ativo.",
            options=stat_options,
        ),
        panel(
            3,
            "Taxa de anomalias",
            "stat",
            (12, 0, 6, 4),
            [infinity_target(overview, "$.rows", [("anomaly_rate", "Taxa", "number")])],
            description="Fração de previsões sinalizadas. No replay balanceado, não estima a prevalência de uma rede real.",
            unit="percentunit",
            decimals=2,
            options=stat_options,
        ),
        panel(
            4,
            "Anomaly score — P95",
            "stat",
            (18, 0, 6, 4),
            [infinity_target(overview, "$.rows", [("score_p95", "P95", "number")])],
            description="Percentil 95 do anomaly_score. Esse escore não é probabilidade e só é comparável na mesma versão e ponto operacional.",
            decimals=4,
            options=stat_options,
        ),
        panel(
            5,
            "Fluxos normais e anomalias ao longo do replay",
            "timeseries",
            (0, 4, 16, 8),
            [
                infinity_target(
                    timeseries,
                    "$.items",
                    [
                        ("bucket_start", "Tempo", "timestamp"),
                        ("normal_total", "Normais", "number"),
                        ("anomalies_total", "Anomalias", "number"),
                    ],
                    format_="timeseries",
                )
            ],
            description="Contagens em janelas de 5 minutos. Os horários são simulados e preservam apenas a sequência do replay.",
            options=time_options,
        ),
        panel(
            6,
            "Taxa de anomalias ao longo do replay",
            "timeseries",
            (16, 4, 8, 8),
            [
                infinity_target(
                    timeseries,
                    "$.items",
                    [
                        ("bucket_start", "Tempo", "timestamp"),
                        ("anomaly_rate", "Taxa de anomalias", "number"),
                    ],
                    format_="timeseries",
                )
            ],
            description="Fração sinalizada por janela. Não interpretar como taxa natural de ataques por causa do teste balanceado.",
            unit="percentunit",
            decimals=2,
            options=time_options,
        ),
        panel(
            7,
            "Protocolos observados no replay",
            "barchart",
            (0, 12, 8, 7),
            [
                infinity_target(
                    breakdowns,
                    "$.protocols",
                    [("value", "Protocolo", "string"), ("count", "Fluxos", "number")],
                )
            ],
            description=(
                "Protocolos do GeneratedLabelledFlows, associados somente após a "
                "validação das features contra X_test. Sem contexto validado, a "
                "API retorna uma série vazia em vez de fabricar valores."
            ),
            options=bar_options,
        ),
        panel(
            8,
            "IPs de origem das anomalias",
            "barchart",
            (8, 12, 8, 7),
            [
                infinity_target(
                    breakdowns,
                    "$.top_anomalous_sources",
                    [("value", "IP de origem", "string"), ("count", "Anomalias", "number")],
                )
            ],
            description=(
                "IPs de origem do GeneratedLabelledFlows, associados somente após "
                "a validação das features contra X_test. O ranking inclui apenas "
                "fluxos sinalizados como anomalia pelo modelo."
            ),
            options=bar_options,
        ),
        panel(
            9,
            "Portas de destino mais frequentes nas anomalias",
            "barchart",
            (16, 12, 8, 7),
            [
                infinity_target(
                    breakdowns,
                    "$.destination_ports",
                    [("value", "Porta", "string"), ("count", "Anomalias", "number")],
                )
            ],
            description="Ranking baseado em destination_port, que existe no conjunto de features selecionadas.",
            options=bar_options,
        ),
        panel(
            10,
            "Anomalias recentes",
            "table",
            (0, 19, 16, 9),
            [
                infinity_target(
                    recent,
                    "$.items",
                    [
                        ("observed_at", "Observado em", "timestamp"),
                        ("event_id", "Evento", "string"),
                        ("anomaly_score", "Anomaly score", "number"),
                        ("threshold_distance", "Distância do limiar", "number"),
                        ("dst_port", "Porta de destino", "number"),
                        ("dataset_provenance_ref", "Referência de proveniência", "string"),
                    ],
                )
            ],
            description="Últimas decisões positivas no intervalo. Exibe previsões, não rótulos verdadeiros do teste.",
            decimals=4,
            options={"cellHeight": "sm", "showHeader": True},
        ),
        panel(
            11,
            "Identidade operacional e estado do repositório",
            "table",
            (16, 19, 8, 9),
            [
                infinity_target(
                    status,
                    "$.rows",
                    [
                        ("display_name", "Modelo", "string"),
                        ("experiment", "Experimento", "string"),
                        ("operating_point", "Ponto operacional", "string"),
                        ("threshold", "Limiar", "number"),
                        ("model_sha256", "SHA-256", "string"),
                        ("stored_documents", "Documentos", "number"),
                        ("mode", "Modo", "string"),
                    ],
                    include_time=False,
                )
            ],
            description="Fixação completa do modelo, limiar e ponto operacional usada em todas as consultas.",
            options={"cellHeight": "sm", "showHeader": True},
        ),
    ]
    if len(panels) != 11 or len({item["id"] for item in panels}) != 11:
        raise RuntimeError("O dashboard deve possuir exatamente 11 painéis únicos.")

    return {
        "annotations": {"list": []},
        "description": (
            "MARCO 12 — VISUALIZAÇÃO EXPERIMENTAL. Dados provenientes de replay offline "
            "do teste CIC-IDS2017 balanceado, com timestamps simulados. Não representa "
            "prevalência ou cronologia de uma rede real. IPs e protocolos só são exibidos "
            "quando validados contra GeneratedLabelledFlows; nunca são fabricados. "
            "anomaly_score não é probabilidade."
        ),
        "editable": False,
        "fiscalYearStartMonth": 0,
        "graphTooltip": 1,
        "id": None,
        "links": [],
        "panels": panels,
        "refresh": "30s",
        "schemaVersion": 41,
        "tags": ["tcc", "cibersegurança", "anomalias", "offline-replay", "experimental"],
        "templating": {"list": []},
        "time": {"from": "2026-01-01T00:00:00Z", "to": "2026-01-02T04:00:00Z"},
        "timepicker": {"refresh_intervals": ["30s", "1m", "5m", "15m"]},
        "timezone": "utc",
        "title": "TCC — Detecção de Anomalias de Rede (Replay Experimental)",
        "uid": "tcc-network-anomaly",
        "version": 1,
        "weekStart": "monday",
    }


def write_dashboard(path: Path = OUTPUT_PATH) -> Path:
    """Grava de forma atômica para evitar JSON parcial."""
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("w", encoding="utf-8") as file:
        json.dump(build_dashboard(), file, ensure_ascii=False, indent=2)
        file.write("\n")
    os.replace(temporary, path)
    return path


if __name__ == "__main__":
    generated = write_dashboard()
    print(f"Dashboard gerado: {generated}")
