"""Contratos de integração para MongoDB, FastAPI e Grafana no Marco 11."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.config import PROJECT_ROOT
from src.inference_service import (
    DEFAULT_EXPERIMENT,
    DEFAULT_MODEL,
    DEFAULT_OPERATING_POINT,
    ModelSelection,
    SUPPORTED_OPERATING_POINTS,
    default_registry_path,
)


OUTPUT_FILENAMES = {
    "request_schema": "inference_request.schema.json",
    "response_schema": "inference_response.schema.json",
    "mongodb_schema": "mongodb_prediction.schema.json",
    "grafana_spec": "grafana_dashboard_spec.json",
    "summary": "MARCO_11_SUMMARY.md",
    "manifest": "marco_11_manifest.json",
}
CONTEXT_PROPERTIES = {
    "src_ip": {"type": "string"},
    "dst_ip": {"type": "string"},
    "src_port": {"type": "integer", "minimum": 0, "maximum": 65535},
    "dst_port": {"type": "integer", "minimum": 0, "maximum": 65535},
    "protocol": {"type": ["string", "integer"]},
    "interface": {"type": "string"},
    "direction": {"type": "string"},
    "device_id": {"type": "string"},
    "flow_id": {"type": "string"},
}


def _utc_now() -> str:
    """Retorna o instante UTC atual no formato ISO 8601."""
    return datetime.now(timezone.utc).isoformat()


def _load_json(path: Path) -> dict[str, Any]:
    """Carrega um objeto JSON obrigatório."""
    if not path.is_file():
        raise FileNotFoundError(f"JSON obrigatório não encontrado: {path}")
    with path.open("r", encoding="utf-8") as file:
        data = json.load(file)
    if not isinstance(data, dict):
        raise ValueError(f"Objeto JSON inválido: {path}")
    return data


def _sha256_file(path: Path) -> str:
    """Calcula SHA-256 em blocos."""
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for block in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _safe_project_path(project_root: Path, relative_path: str) -> Path:
    """Resolve referências do registro somente dentro do projeto."""
    candidate = (project_root / relative_path).resolve()
    try:
        candidate.relative_to(project_root.resolve())
    except ValueError as exc:
        raise ValueError(f"Caminho fora do projeto: {relative_path}") from exc
    return candidate


def _relative(path: Path, project_root: Path) -> str:
    """Produz caminho relativo portátil."""
    try:
        return path.resolve().relative_to(project_root.resolve()).as_posix()
    except ValueError as exc:
        raise ValueError(f"Caminho fora do projeto: {path}") from exc


def _source_digest(sources: list[dict[str, Any]]) -> str:
    """Resume caminhos e hashes das fontes do contrato."""
    digest = hashlib.sha256()
    for source in sorted(sources, key=lambda item: item["relative_path"]):
        digest.update(source["relative_path"].encode("utf-8"))
        digest.update(b"\0")
        digest.update(source["sha256"].encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def build_inference_request_schema(feature_columns: list[str]) -> dict[str, Any]:
    """Define o JSON aceito futuramente por uma rota de inferência."""
    if len(feature_columns) != 60 or len(set(feature_columns)) != 60:
        raise ValueError("O contrato requer exatamente 60 features únicas.")
    feature_properties = {
        feature: {
            "type": "number",
            "description": "Finite numeric flow statistic.",
        }
        for feature in feature_columns
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "urn:tcc-network-anomaly:inference-request:v1",
        "title": "Network anomaly inference request",
        "type": "object",
        "additionalProperties": False,
        "required": ["observed_at", "source", "features"],
        "properties": {
            "event_id": {
                "type": "string",
                "minLength": 1,
                "description": "Stable collector identifier for idempotency.",
            },
            "observed_at": {
                "type": "string",
                "format": "date-time",
                "description": "Flow observation time with timezone.",
            },
            "source": {
                "type": "string",
                "minLength": 1,
                "description": "Collector origin, for example pfsense or squid.",
            },
            "features": {
                "type": "object",
                "additionalProperties": False,
                "required": feature_columns,
                "properties": feature_properties,
            },
            "context": {
                "type": "object",
                "propertyNames": {
                    "not": {"pattern": "(^\\$)|\\."}
                },
                "additionalProperties": {
                    "type": ["string", "number", "integer", "boolean", "null"]
                },
                "properties": CONTEXT_PROPERTIES,
                "description": (
                    "Fields used for investigation and dashboard filters; they are "
                    "never sent to the model."
                ),
            },
        },
    }


def build_inference_response_schema() -> dict[str, Any]:
    """Define a resposta estável da futura API."""
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "urn:tcc-network-anomaly:inference-response:v1",
        "title": "Network anomaly inference response",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "event_id",
            "event_id_generated",
            "observed_at",
            "processed_at_utc",
            "source",
            "model",
            "prediction",
            "context",
        ],
        "properties": {
            "schema_version": {"const": 1},
            "event_id": {"type": "string"},
            "event_id_generated": {"type": "boolean"},
            "observed_at": {"type": "string", "format": "date-time"},
            "processed_at_utc": {"type": "string", "format": "date-time"},
            "source": {"type": "string"},
            "context": {"type": "object"},
            "model": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "experiment",
                    "key",
                    "display_name",
                    "sha256",
                    "operating_point",
                    "threshold",
                    "positive_rule",
                ],
                "properties": {
                    "experiment": {"type": "string"},
                    "key": {"enum": ["isolation_forest", "lof"]},
                    "display_name": {"type": "string"},
                    "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                    "operating_point": {
                        "enum": list(SUPPORTED_OPERATING_POINTS)
                    },
                    "threshold": {"type": "number"},
                    "positive_rule": {"type": "string"},
                },
            },
            "prediction": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "label",
                    "predicted_anomaly",
                    "native_predicted_anomaly",
                    "sklearn_native_prediction",
                    "anomaly_score",
                    "score_samples",
                    "decision_function",
                    "threshold_distance",
                    "anomaly_score_is_probability",
                ],
                "properties": {
                    "label": {"enum": ["normal", "anomaly"]},
                    "predicted_anomaly": {"enum": [0, 1]},
                    "native_predicted_anomaly": {"enum": [0, 1]},
                    "sklearn_native_prediction": {"enum": [-1, 1]},
                    "anomaly_score": {"type": "number"},
                    "score_samples": {"type": "number"},
                    "decision_function": {"type": "number"},
                    "threshold_distance": {"type": "number"},
                    "anomaly_score_is_probability": {"const": False},
                },
            },
        },
    }


def build_mongodb_prediction_schema() -> dict[str, Any]:
    """Define uma validação conceitual para a coleção de predições."""
    return {
        "schema_version": 1,
        "collection": "network_flow_predictions",
        "validation_level": "strict",
        "validator": {
            "$jsonSchema": {
                "bsonType": "object",
                "required": [
                    "schema_version",
                    "event_id",
                    "observed_at",
                    "processed_at_utc",
                    "source",
                    "model",
                    "classification",
                    "context",
                ],
                "properties": {
                    "schema_version": {"bsonType": "int"},
                    "event_id": {"bsonType": "string", "minLength": 1},
                    "observed_at": {
                        "bsonType": "date",
                        "description": (
                            "Persist as BSON Date in MongoDB. ISO strings exist only "
                            "at the application boundary."
                        ),
                    },
                    "processed_at_utc": {"bsonType": "date"},
                    "source": {"bsonType": "string"},
                    "model": {
                        "bsonType": "object",
                        "required": [
                            "experiment",
                            "key",
                            "display_name",
                            "sha256",
                            "operating_point",
                            "threshold",
                            "positive_rule",
                        ],
                        "additionalProperties": False,
                        "properties": {
                            "experiment": {"bsonType": "string"},
                            "key": {"bsonType": "string"},
                            "display_name": {"bsonType": "string"},
                            "sha256": {
                                "bsonType": "string",
                                "pattern": "^[0-9a-f]{64}$",
                            },
                            "operating_point": {"bsonType": "string"},
                            "threshold": {"bsonType": "double"},
                            "positive_rule": {"bsonType": "string"},
                        },
                    },
                    "classification": {
                        "bsonType": "object",
                        "required": [
                            "status",
                            "is_anomaly",
                            "predicted_anomaly",
                            "native_predicted_anomaly",
                            "sklearn_native_prediction",
                            "anomaly_score",
                            "score_samples",
                            "decision_function",
                            "threshold_distance",
                            "anomaly_score_is_probability",
                        ],
                        "additionalProperties": False,
                        "properties": {
                            "status": {"enum": ["normal", "anomaly"]},
                            "is_anomaly": {"bsonType": "bool"},
                            "predicted_anomaly": {"enum": [0, 1]},
                            "native_predicted_anomaly": {"enum": [0, 1]},
                            "sklearn_native_prediction": {"enum": [-1, 1]},
                            "anomaly_score": {"bsonType": "double"},
                            "score_samples": {"bsonType": "double"},
                            "decision_function": {"bsonType": "double"},
                            "threshold_distance": {"bsonType": "double"},
                            "anomaly_score_is_probability": {"enum": [False]},
                        },
                    },
                    "context": {
                        "bsonType": "object",
                        "additionalProperties": False,
                        "properties": {
                            "dataset": {"bsonType": "string"},
                            "dataset_split": {"bsonType": "string"},
                            "dataset_provenance_ref": {"bsonType": "string"},
                            "dataset_source_row": {"bsonType": ["int", "long"]},
                            "dataset_record_hash": {"bsonType": "string"},
                            "replay_namespace": {"bsonType": "string"},
                            "replay_sequence": {"bsonType": ["int", "long"]},
                            "timestamp_origin": {"bsonType": "string"},
                            "context_origin": {"bsonType": "string"},
                            "dataset_balance_warning": {"bsonType": "string"},
                            "src_ip": {"bsonType": "string"},
                            "dst_ip": {"bsonType": "string"},
                            "protocol": {"bsonType": "string"},
                            "dst_port": {"bsonType": ["int", "long"]},
                            "flow_duration": {"bsonType": ["int", "long", "double"]},
                            "total_fwd_packets": {"bsonType": ["int", "long", "double"]},
                            "total_backward_packets": {"bsonType": ["int", "long", "double"]},
                            "total_fwd_bytes": {"bsonType": ["int", "long", "double"]},
                            "total_backward_bytes": {"bsonType": ["int", "long", "double"]},
                        },
                    },
                },
            }
        },
        "recommended_indexes": [
            {
                "keys": {"event_id": 1},
                "unique": True,
                "purpose": "Idempotent ingestion",
            },
            {
                "keys": {"observed_at": -1},
                "purpose": "Grafana time-range filtering",
            },
            {
                "keys": {"classification.is_anomaly": 1, "observed_at": -1},
                "purpose": "Recent anomaly panels",
            },
            {
                "keys": {"context.src_ip": 1, "observed_at": -1},
                "purpose": "Top anomalous source investigation",
            },
            {
                "keys": {"context.dst_port": 1, "observed_at": -1},
                "purpose": "Destination port analysis",
            },
        ],
        "retention": {
            "ttl_enabled_by_default": False,
            "note": "Define retention with the TCC data-governance policy first.",
        },
    }


def build_grafana_dashboard_spec(
    selection: ModelSelection,
    model_entry: dict[str, Any],
) -> dict[str, Any]:
    """Descreve os painéis e campos antes de acoplar uma fonte de dados."""
    threshold = model_entry["thresholds"][selection.operating_point]
    threshold_value = (
        threshold["equivalent_anomaly_score_threshold"]
        if selection.operating_point == "native"
        else threshold["threshold"]
    )
    return {
        "schema_version": 1,
        "title": "Monitoramento de anomalias no fluxo da rede",
        "status": "design_contract_not_provisioned",
        "purpose": (
            "Specify the first Grafana page and its backend payloads before "
            "choosing a concrete data-source adapter."
        ),
        "default_model_filter": {
            "experiment": selection.experiment,
            "model": selection.model,
            "operating_point": selection.operating_point,
            "model_sha256": model_entry["model_artifact"]["sha256"],
            "threshold": float(threshold_value),
            "experimental_warning": (
                "The default candidate uses a laboratory FPR budget but has not "
                "been temporally validated on traffic from the target network."
            ),
        },
        "data_contract": {
            "transport": "JSON over future FastAPI endpoints",
            "storage_candidate": "MongoDB collection network_flow_predictions",
            "grafana_data_source": "to_be_selected_in_dashboard_implementation",
            "time_field": "observed_at",
            "required_model_filter": [
                "model.sha256",
                "model.operating_point",
                "model.experiment",
            ],
            "score_warning": (
                "anomaly_score is not a probability and raw score scales from "
                "different algorithms must not be mixed."
            ),
        },
        "future_endpoints": [
            {
                "method": "GET",
                "path": "/api/v1/dashboard/overview",
                "returns": "totals, anomaly rate and score summary",
            },
            {
                "method": "GET",
                "path": "/api/v1/dashboard/timeseries",
                "returns": "bucketed flow and anomaly time series",
            },
            {
                "method": "GET",
                "path": "/api/v1/dashboard/breakdowns",
                "returns": "protocol, source, destination and port rankings",
            },
            {
                "method": "GET",
                "path": "/api/v1/anomalies/recent",
                "returns": "recent anomaly investigation rows",
            },
            {
                "method": "GET",
                "path": "/api/v1/model/status",
                "returns": "active model, hash, threshold and health",
            },
        ],
        "dashboard_variables": [
            {"name": "model_sha256", "required": True},
            {"name": "operating_point", "required": True},
            {"name": "source", "required": False},
            {"name": "protocol", "required": False},
            {"name": "src_ip", "required": False},
            {"name": "dst_ip", "required": False},
        ],
        "panels": [
            {
                "id": "total_flows",
                "title": "Fluxos analisados",
                "visualization": "stat",
                "field": "totals.flows",
                "priority": 1,
            },
            {
                "id": "total_anomalies",
                "title": "Anomalias detectadas",
                "visualization": "stat",
                "field": "totals.anomalies",
                "priority": 1,
            },
            {
                "id": "anomaly_rate",
                "title": "Taxa de anomalias",
                "visualization": "gauge",
                "field": "totals.anomaly_rate",
                "priority": 1,
            },
            {
                "id": "score_p95",
                "title": "P95 do anomaly score",
                "visualization": "stat",
                "field": "scores.p95",
                "priority": 2,
                "note": "Score, not probability; keep the model filter fixed.",
            },
            {
                "id": "flow_timeline",
                "title": "Fluxos normais e anômalos ao longo do tempo",
                "visualization": "time_series",
                "fields": [
                    "timeline.bucket_start",
                    "timeline.normal_total",
                    "timeline.anomalies_total",
                ],
                "priority": 1,
            },
            {
                "id": "anomaly_rate_timeline",
                "title": "Evolução da taxa de anomalias",
                "visualization": "time_series",
                "fields": ["timeline.bucket_start", "timeline.anomaly_rate"],
                "priority": 1,
            },
            {
                "id": "protocol_distribution",
                "title": "Distribuição por protocolo",
                "visualization": "bar_chart",
                "field": "distributions.protocol",
                "priority": 2,
            },
            {
                "id": "top_anomalous_sources",
                "title": "Principais IPs de origem com anomalias",
                "visualization": "bar_chart",
                "field": "top_anomalous_sources",
                "priority": 1,
            },
            {
                "id": "top_destination_ports",
                "title": "Portas de destino mais frequentes nas anomalias",
                "visualization": "bar_chart",
                "field": "top_anomalous_destination_ports",
                "priority": 1,
            },
            {
                "id": "recent_anomalies",
                "title": "Anomalias recentes",
                "visualization": "table",
                "field": "recent_anomalies",
                "priority": 1,
            },
            {
                "id": "model_status",
                "title": "Modelo ativo e limiar",
                "visualization": "table",
                "field": "model_filter",
                "priority": 2,
            },
        ],
        "intentionally_absent_panels": [
            {
                "metric": "live_false_positive_rate",
                "reason": (
                    "A live flow has no immediate ground-truth label; presenting "
                    "false positives would be methodologically misleading."
                ),
            },
            {
                "metric": "attack_category",
                "reason": (
                    "The unsupervised model predicts anomaly, not a specific attack "
                    "family."
                ),
            },
        ],
        "privacy": {
            "sensitive_fields": ["context.src_ip", "context.dst_ip"],
            "recommendation": (
                "Restrict dashboard access and define masking/retention before "
                "production use."
            ),
        },
    }


def _write_text_atomic(path: Path, text: str) -> None:
    """Grava um arquivo por substituição atômica."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(text, encoding="utf-8")
    os.replace(temporary, path)


def _write_json_atomic(path: Path, data: dict[str, Any]) -> None:
    """Grava JSON UTF-8 com indentação legível."""
    _write_text_atomic(
        path,
        json.dumps(data, ensure_ascii=False, indent=2) + "\n",
    )


def _summary_markdown(
    selection: ModelSelection,
    feature_count: int,
    dashboard_spec: dict[str, Any],
) -> str:
    """Explica os contratos gerados em linguagem de apresentação."""
    return "\n".join(
        [
            "# Marco 11 — preparação para integração e Grafana",
            "",
            "Status: **contratos preparados; serviços externos ainda não iniciados**.",
            "",
            (
                "A inferência agora pode receber objetos estruturados em memória, "
                "sem depender de CSV. O MongoDB, a API FastAPI e o Grafana ainda "
                "não são iniciados por este marco."
            ),
            "",
            "## Configuração de referência",
            "",
            f"- Experimento: `{selection.experiment}`",
            f"- Modelo: `{selection.model}`",
            f"- Ponto operacional: `{selection.operating_point}`",
            f"- Features obrigatórias: {feature_count}",
            "- `anomaly_score` é um escore, não uma probabilidade.",
            "",
            "## Fluxo planejado",
            "",
            "```text",
            "pfSense/Squid -> extrator das 60 features -> serviço de inferência",
            "-> documento de monitoramento -> MongoDB -> FastAPI -> Grafana",
            "```",
            "",
            "O extrator das 60 estatísticas de fluxo ainda deverá ser implementado. "
            "Logs brutos de pfSense ou Squid não podem ser enviados diretamente ao "
            "modelo treinado no CIC-IDS2017.",
            "",
            "## Primeira página do Grafana",
            "",
            f"A especificação contém {len(dashboard_spec['panels'])} painéis: volume "
            "de fluxos, anomalias, taxa de anomalias, P95 do escore, séries "
            "temporais, protocolos, principais origens, portas de destino, "
            "anomalias recentes e estado do modelo.",
            "",
            "Falsos positivos e famílias de ataque não aparecem como métricas ao "
            "vivo porque não existe rótulo verdadeiro imediato e o modelo não faz "
            "classificação supervisionada de ataques.",
            "",
            "## Arquivos",
            "",
            "- `inference_request.schema.json`: entrada esperada pela futura API.",
            "- `inference_response.schema.json`: resposta estável da inferência.",
            "- `mongodb_prediction.schema.json`: documento e índices recomendados.",
            "- `grafana_dashboard_spec.json`: painéis, filtros e endpoints futuros.",
            "- `marco_11_manifest.json`: integridade das fontes e das saídas.",
            "",
        ]
    )


def run_marco11_preparation(
    *,
    project_root: Path = PROJECT_ROOT,
    output_dir: Path | None = None,
    selection: ModelSelection | None = None,
    overwrite: bool = False,
) -> dict[str, Any]:
    """Gera contratos sem carregar modelos ou acessar serviços externos."""
    project_root = project_root.resolve()
    output_dir = (
        output_dir or project_root / "reports" / "integration"
    ).resolve()
    try:
        output_dir.relative_to(project_root)
    except ValueError as exc:
        raise ValueError("O destino deve permanecer dentro do projeto.") from exc
    if output_dir.is_relative_to(project_root / "models"):
        raise ValueError("O destino não pode ficar dentro da pasta de modelos.")
    paths = {key: output_dir / name for key, name in OUTPUT_FILENAMES.items()}
    existing = [path for path in paths.values() if path.exists()]
    if existing and not overwrite:
        raise FileExistsError(
            "O Marco 11 já possui contratos; use --overwrite para substituir: "
            + ", ".join(str(path) for path in existing)
        )
    selection = selection or ModelSelection(
        experiment=DEFAULT_EXPERIMENT,
        model=DEFAULT_MODEL,
        operating_point=DEFAULT_OPERATING_POINT,
    )
    registry_path = default_registry_path(project_root)
    protected_directories = (
        project_root / "models",
        project_root / "reports" / "final",
        project_root / "experiments" / "scale_100k" / "models",
    )
    if any(
        output_dir == directory.resolve()
        or output_dir.is_relative_to(directory.resolve())
        for directory in protected_directories
    ):
        raise ValueError(
            "O destino dos contratos não pode ficar dentro de uma pasta de "
            "modelos ou do registro final."
        )
    registry = _load_json(registry_path)
    if registry.get("status") != "completed":
        raise ValueError("O registro do Marco 10 não está concluído.")
    try:
        model_entry = registry["experiments"][selection.experiment]["models"][
            selection.model
        ]
        threshold_entry = model_entry["thresholds"][selection.operating_point]
    except KeyError as exc:
        raise ValueError(f"Seleção não registrada: {selection}") from exc
    if (
        selection.operating_point != "native"
        and threshold_entry.get("test_labels_used") is not False
    ):
        raise ValueError("O contrato selecionado utiliza um limiar baseado no teste.")
    metadata_path = _safe_project_path(
        project_root, model_entry["metadata_artifact"]["relative_path"]
    )
    model_path = _safe_project_path(
        project_root, model_entry["model_artifact"]["relative_path"]
    )
    metadata = _load_json(metadata_path)
    feature_columns = [str(name) for name in metadata["feature_columns"]]
    if feature_columns != list(dict.fromkeys(feature_columns)):
        raise ValueError("Metadados contêm features duplicadas.")
    if len(feature_columns) != int(model_entry["feature_count"]):
        raise ValueError("Quantidade de features diverge do registro do modelo.")
    if metadata["model_input_schema_sha256"] != model_entry[
        "model_input_schema_sha256"
    ]:
        raise ValueError("Fingerprint de features diverge do registro do modelo.")
    if _sha256_file(model_path) != model_entry["model_artifact"]["sha256"]:
        raise ValueError("Hash do modelo diverge do registro do Marco 10.")

    sources = [
        {
            "relative_path": _relative(path, project_root),
            "sha256": _sha256_file(path),
            "size_bytes": path.stat().st_size,
        }
        for path in (registry_path, metadata_path, model_path)
    ]
    digest_before = _source_digest(sources)
    request_schema = build_inference_request_schema(feature_columns)
    response_schema = build_inference_response_schema()
    mongodb_schema = build_mongodb_prediction_schema()
    grafana_spec = build_grafana_dashboard_spec(selection, model_entry)
    sources_after = [
        {
            **source,
            "sha256": _sha256_file(project_root / source["relative_path"]),
        }
        for source in sources
    ]
    digest_after = _source_digest(sources_after)
    if digest_before != digest_after:
        raise RuntimeError("Uma fonte mudou durante a criação dos contratos.")

    _write_json_atomic(paths["request_schema"], request_schema)
    _write_json_atomic(paths["response_schema"], response_schema)
    _write_json_atomic(paths["mongodb_schema"], mongodb_schema)
    _write_json_atomic(paths["grafana_spec"], grafana_spec)
    _write_text_atomic(
        paths["summary"],
        _summary_markdown(selection, len(feature_columns), grafana_spec),
    )
    outputs = {
        key: {
            "relative_path": _relative(path, project_root),
            "sha256": _sha256_file(path),
            "size_bytes": path.stat().st_size,
        }
        for key, path in paths.items()
        if key != "manifest"
    }
    manifest = {
        "schema_version": 1,
        "stage": "integration_and_dashboard_preparation_marco_11",
        "created_at_utc": _utc_now(),
        "status": "completed",
        "scope": {
            "structured_inference_layer": "implemented",
            "monitoring_document_builder": "implemented",
            "dashboard_aggregation_builder": "implemented",
            "mongodb_connection": "not_implemented",
            "fastapi_server": "not_implemented",
            "grafana_provisioning": "not_implemented",
            "pfsense_squid_feature_extractor": "not_implemented",
        },
        "selection": {
            "experiment": selection.experiment,
            "model": selection.model,
            "operating_point": selection.operating_point,
            "production_approved": False,
        },
        "methodology": {
            "model_loaded_during_contract_generation": False,
            "model_modified": False,
            "threshold_modified": False,
            "source_artifacts_modified": False,
            "anomaly_score_treated_as_probability": False,
            "live_ground_truth_assumed": False,
        },
        "source_integrity": {
            "sources": sources,
            "aggregate_sha256_before": digest_before,
            "aggregate_sha256_after": digest_after,
            "unchanged": digest_before == digest_after,
        },
        "validation": {
            "feature_count": len(feature_columns),
            "request_requires_all_features": True,
            "labels_forbidden_from_model_input": True,
            "calibrated_threshold_independent_from_test": True,
            "dashboard_panel_count": len(grafana_spec["panels"]),
            "status": "passed",
        },
        "outputs": outputs,
    }
    _write_json_atomic(paths["manifest"], manifest)
    return manifest


def format_marco11_summary(manifest: dict[str, Any]) -> str:
    """Resume a geração dos contratos no terminal."""
    selection = manifest["selection"]
    scope = manifest["scope"]
    return "\n".join(
        [
            "Marco 11 preparado.",
            (
                "Modelo de referência: "
                f"{selection['experiment']}/{selection['model']}/"
                f"{selection['operating_point']}"
            ),
            f"Features exigidas: {manifest['validation']['feature_count']}",
            (
                "Painéis especificados para Grafana: "
                f"{manifest['validation']['dashboard_panel_count']}"
            ),
            f"Fontes inalteradas: {manifest['source_integrity']['unchanged']}",
            f"Inferência estruturada: {scope['structured_inference_layer']}",
            "MongoDB/FastAPI/Grafana iniciados: não",
            f"Validação: {manifest['validation']['status']}",
        ]
    )
