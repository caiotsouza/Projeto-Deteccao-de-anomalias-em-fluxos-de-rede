"""Replay idempotente das previsões congeladas para o Marco 12."""

from __future__ import annotations

import hashlib
import json
import math
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

import numpy as np
import pandas as pd

from src.config import (
    DEFAULT_REPLAY_BATCH_SIZE,
    DEFAULT_REPLAY_INTERVAL_MILLISECONDS,
    DEFAULT_REPLAY_LIMIT,
    DEFAULT_REPLAY_NAMESPACE,
    DEFAULT_REPLAY_START_ISO,
    PROJECT_ROOT,
)
from src.dashboard_reporting import build_monitoring_document
from src.generated_flow_context import (
    FlowNetworkContext,
    GeneratedFlowContextResolver,
)
from src.monitoring_repository import PredictionRepository, UpsertSummary
from src.runtime_config import ActiveModelIdentity, load_active_model_identity


PREDICTION_COLUMNS = (
    "row_position",
    "record_hash",
    "sklearn_prediction",
    "predicted_anomaly",
    "score_samples",
    "decision_function",
    "anomaly_score",
)
PROVENANCE_COLUMNS = ("source_file", "source_row", "record_hash")
CONTEXT_FEATURES = (
    "destination_port",
    "flow_duration",
    "total_fwd_packets",
    "total_backward_packets",
    "total_length_of_fwd_packets",
    "total_length_of_bwd_packets",
)


@dataclass(frozen=True)
class ReplayConfig:
    """Configuração reproduzível do replay offline."""

    limit: int = DEFAULT_REPLAY_LIMIT
    offset: int = 0
    batch_size: int = DEFAULT_REPLAY_BATCH_SIZE
    interval_milliseconds: int = DEFAULT_REPLAY_INTERVAL_MILLISECONDS
    start_time: datetime | None = None
    namespace: str | None = None
    network_context_dir: Path | None = None
    dry_run: bool = False

    def normalized(self, available_records: int) -> "ReplayConfig":
        if self.limit <= 0:
            raise ValueError("limit deve ser positivo.")
        if self.offset < 0:
            raise ValueError("offset não pode ser negativo.")
        if self.offset >= available_records:
            raise ValueError("offset está fora dos dados disponíveis.")
        if self.offset + self.limit > available_records:
            raise ValueError(
                "offset + limit excede os registros disponíveis: "
                f"{self.offset + self.limit} > {available_records}."
            )
        if not 1 <= self.batch_size <= 1_000:
            raise ValueError("batch_size deve estar entre 1 e 1000.")
        if not 1 <= self.interval_milliseconds <= 3_600_000:
            raise ValueError(
                "interval_milliseconds deve estar entre 1 e 3600000."
            )
        if self.start_time is None:
            start = datetime.fromisoformat(DEFAULT_REPLAY_START_ISO)
        else:
            start = self.start_time
            if start.tzinfo is None or start.utcoffset() is None:
                raise ValueError("start_time deve informar fuso horário.")
            start = start.astimezone(timezone.utc)
        # BSON Date possui precisão de milissegundos. Normalizar aqui impede que
        # um replay idêntico conflite depois do round-trip pelo MongoDB.
        start = start.replace(microsecond=(start.microsecond // 1_000) * 1_000)
        namespace = (self.namespace or DEFAULT_REPLAY_NAMESPACE).strip()
        if not namespace or len(namespace) > 120:
            raise ValueError("namespace deve possuir entre 1 e 120 caracteres.")
        return ReplayConfig(
            limit=self.limit,
            offset=self.offset,
            batch_size=self.batch_size,
            interval_milliseconds=self.interval_milliseconds,
            start_time=start,
            namespace=namespace,
            network_context_dir=self.network_context_dir,
            dry_run=self.dry_run,
        )


@dataclass(frozen=True)
class ReplayArtifacts:
    features_path: Path
    predictions_path: Path
    provenance_path: Path


def default_replay_artifacts(
    project_root: Path,
    model_key: str,
) -> ReplayArtifacts:
    base = project_root / "experiments" / "scale_100k" / "data"
    return ReplayArtifacts(
        features_path=base / "splits" / "X_test.parquet",
        predictions_path=(
            base / "predictions" / f"{model_key}_test_predictions.parquet"
        ),
        provenance_path=base / "splits" / "y_test.parquet",
    )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for block in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _event_id(namespace: str, record_hash: str, model: ActiveModelIdentity) -> str:
    material = "\0".join(
        (namespace, record_hash, model.sha256, model.operating_point)
    ).encode("utf-8")
    return "replay-" + hashlib.sha256(material).hexdigest()


def _python_scalar(value: object) -> int | float:
    if isinstance(value, (np.integer, int)) and not isinstance(value, bool):
        return int(value)
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("O contexto do replay contém valor não finito.")
    return number


def _validate_aligned_inputs(
    features: pd.DataFrame,
    predictions: pd.DataFrame,
    provenance: pd.DataFrame,
) -> None:
    if not len(features) == len(predictions) == len(provenance):
        raise ValueError(
            "Features, previsões e proveniência possuem tamanhos diferentes."
        )
    if not len(features):
        raise ValueError("O replay não pode usar entradas vazias.")
    if list(predictions.columns) != list(PREDICTION_COLUMNS):
        raise ValueError("As previsões não obedecem ao contrato congelado.")
    if list(provenance.columns) != list(PROVENANCE_COLUMNS):
        raise ValueError("A proveniência contém colunas inesperadas.")
    missing_context = [name for name in CONTEXT_FEATURES if name not in features]
    if missing_context:
        raise ValueError(f"Features contextuais ausentes: {missing_context}")
    positions = predictions["row_position"].to_numpy(dtype=np.int64)
    if not np.array_equal(positions, np.arange(len(predictions), dtype=np.int64)):
        raise ValueError("row_position das previsões não corresponde à ordem do split.")
    prediction_hashes = predictions["record_hash"].astype("string")
    provenance_hashes = provenance["record_hash"].astype("string")
    if prediction_hashes.isna().any() or prediction_hashes.duplicated().any():
        raise ValueError("As previsões possuem record_hash ausente ou duplicado.")
    if not prediction_hashes.reset_index(drop=True).equals(
        provenance_hashes.reset_index(drop=True)
    ):
        raise ValueError("record_hash diverge entre previsão e proveniência.")
    feature_hashes = pd.Series(
        (
            f"{int(value):016x}"
            for value in pd.util.hash_pandas_object(
                features, index=False
            ).to_numpy(dtype=np.uint64)
        ),
        dtype="string",
    )
    if not prediction_hashes.reset_index(drop=True).equals(feature_hashes):
        raise ValueError(
            "record_hash das previsões não corresponde às features do X_test."
        )
    sklearn_prediction = predictions["sklearn_prediction"].to_numpy()
    predicted_anomaly = predictions["predicted_anomaly"].to_numpy()
    if not np.isin(sklearn_prediction, (-1, 1)).all():
        raise ValueError("sklearn_prediction deve conter somente -1 ou 1.")
    if not np.isin(predicted_anomaly, (0, 1)).all():
        raise ValueError("predicted_anomaly deve conter somente 0 ou 1.")
    if not np.array_equal(
        predicted_anomaly.astype(np.int8),
        (sklearn_prediction == -1).astype(np.int8),
    ):
        raise ValueError("predicted_anomaly diverge de sklearn_prediction.")
    if not np.array_equal(
        sklearn_prediction.astype(np.int8),
        np.where(
            predictions["decision_function"].to_numpy(dtype=np.float64) < 0.0,
            -1,
            1,
        ).astype(np.int8),
    ):
        raise ValueError("sklearn_prediction diverge de decision_function.")
    numeric = predictions.loc[
        :, ("score_samples", "decision_function", "anomaly_score")
    ].to_numpy(dtype=np.float64)
    if not np.isfinite(numeric).all():
        raise ValueError("As previsões congeladas contêm escores não finitos.")
    if not np.allclose(
        predictions["anomaly_score"].to_numpy(dtype=np.float64),
        -predictions["score_samples"].to_numpy(dtype=np.float64),
        rtol=0.0,
        atol=1e-12,
    ):
        raise ValueError("A orientação de anomaly_score está inconsistente.")


def build_replay_documents(
    features: pd.DataFrame,
    predictions: pd.DataFrame,
    provenance: pd.DataFrame,
    model: ActiveModelIdentity,
    config: ReplayConfig,
    network_context_by_position: Mapping[int, FlowNetworkContext] | None = None,
) -> list[dict[str, Any]]:
    """Monta documentos sem carregar rótulos ou executar novamente o modelo."""
    _validate_aligned_inputs(features, predictions, provenance)
    config = config.normalized(len(features))
    start_index = config.offset
    end_index = config.offset + config.limit
    interval = timedelta(milliseconds=config.interval_milliseconds)
    documents: list[dict[str, Any]] = []
    for row_index in range(start_index, end_index):
        feature_row = features.iloc[row_index]
        prediction_row = predictions.iloc[row_index]
        provenance_row = provenance.iloc[row_index]
        observed_at = config.start_time + row_index * interval
        anomaly_score = float(prediction_row["anomaly_score"])
        native_anomaly = int(prediction_row["predicted_anomaly"])
        selected_anomaly = (
            native_anomaly
            if model.operating_point == "native"
            else int(anomaly_score >= model.threshold)
        )
        raw_destination_port = _python_scalar(feature_row["destination_port"])
        destination_port = int(raw_destination_port)
        if float(raw_destination_port) != float(destination_port):
            raise ValueError(
                f"destination_port deve ser inteira na linha {row_index}."
            )
        if not 0 <= destination_port <= 65_535:
            raise ValueError(f"destination_port inválida na linha {row_index}.")
        context = {
            "dataset": "CIC-IDS2017",
            "dataset_split": "test",
            "dataset_provenance_ref": hashlib.sha256(
                str(provenance_row["source_file"]).encode("utf-8")
            ).hexdigest()[:16],
            "dataset_source_row": int(provenance_row["source_row"]),
            "dataset_record_hash": str(provenance_row["record_hash"]),
            "replay_namespace": str(config.namespace),
            "replay_sequence": row_index,
            "timestamp_origin": "simulated_sequence",
            "context_origin": "processed_cicids_features",
            "dataset_balance_warning": "experimental_balanced_50_50",
            "dst_port": destination_port,
            "flow_duration": _python_scalar(feature_row["flow_duration"]),
            "total_fwd_packets": _python_scalar(
                feature_row["total_fwd_packets"]
            ),
            "total_backward_packets": _python_scalar(
                feature_row["total_backward_packets"]
            ),
            "total_fwd_bytes": _python_scalar(
                feature_row["total_length_of_fwd_packets"]
            ),
            "total_backward_bytes": _python_scalar(
                feature_row["total_length_of_bwd_packets"]
            ),
        }
        if network_context_by_position is not None:
            try:
                network_context = network_context_by_position[row_index]
            except KeyError as exc:
                raise ValueError(
                    f"Contexto de rede ausente para a posição do replay {row_index}."
                ) from exc
            context.update(
                {
                    "src_ip": network_context.src_ip,
                    "dst_ip": network_context.dst_ip,
                    "protocol": network_context.protocol,
                    "context_origin": (
                        "processed_cicids_features+generated_labelled_flows_validated"
                    ),
                }
            )
        inference_result = {
            "schema_version": 1,
            "event_id": _event_id(
                str(config.namespace), str(prediction_row["record_hash"]), model
            ),
            "event_id_generated": False,
            "observed_at": observed_at.isoformat(),
            "processed_at_utc": observed_at.isoformat(),
            "source": "offline_replay",
            "model": {
                "experiment": model.experiment,
                "key": model.key,
                "display_name": model.display_name,
                "sha256": model.sha256,
                "operating_point": model.operating_point,
                "threshold": model.threshold,
                "positive_rule": model.positive_rule,
            },
            "prediction": {
                "label": "anomaly" if selected_anomaly else "normal",
                "predicted_anomaly": selected_anomaly,
                "native_predicted_anomaly": native_anomaly,
                "sklearn_native_prediction": int(
                    prediction_row["sklearn_prediction"]
                ),
                "anomaly_score": anomaly_score,
                "score_samples": float(prediction_row["score_samples"]),
                "decision_function": float(prediction_row["decision_function"]),
                "threshold_distance": anomaly_score - model.threshold,
                "anomaly_score_is_probability": False,
            },
            "context": context,
        }
        documents.append(build_monitoring_document(inference_result))
    return documents


def _load_replay_frames(
    artifacts: ReplayArtifacts,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    for path in (
        artifacts.features_path,
        artifacts.predictions_path,
        artifacts.provenance_path,
    ):
        if not path.is_file():
            raise FileNotFoundError(f"Artefato de replay não encontrado: {path}")
    # As 60 features são lidas para recomputar record_hash e provar que X_test,
    # previsões e proveniência continuam na mesma ordem. Somente seis features
    # contextuais são levadas aos documentos persistidos.
    features = pd.read_parquet(artifacts.features_path)
    predictions = pd.read_parquet(
        artifacts.predictions_path, columns=list(PREDICTION_COLUMNS)
    )
    # Projeção deliberada: Label e binary_label existem no Parquet, mas não são
    # lidos nem usados pelo replay operacional.
    provenance = pd.read_parquet(
        artifacts.provenance_path, columns=list(PROVENANCE_COLUMNS)
    )
    return features, predictions, provenance


def _write_json_atomic(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("w", encoding="utf-8") as file:
        json.dump(data, file, ensure_ascii=False, indent=2)
        file.write("\n")
    os.replace(temporary, path)


def run_replay(
    repository: PredictionRepository,
    *,
    project_root: Path = PROJECT_ROOT,
    model: ActiveModelIdentity | None = None,
    config: ReplayConfig | None = None,
    artifacts: ReplayArtifacts | None = None,
    initialize_repository: bool = True,
    report_path: Path | None = None,
    overwrite_report: bool = False,
) -> dict[str, Any]:
    """Executa o replay em lotes e reconcilia todas as contagens."""
    project_root = project_root.resolve()
    model = model or load_active_model_identity(project_root=project_root)
    config = config or ReplayConfig()
    artifacts = artifacts or default_replay_artifacts(project_root, model.key)
    normalized_report_path: Path | None = None
    if report_path is not None:
        normalized_report_path = report_path.resolve()
        try:
            normalized_report_path.relative_to(project_root)
        except ValueError as exc:
            raise ValueError("report_path deve permanecer dentro do projeto.") from exc
        # Este preflight precede qualquer initialize/upsert. Assim, a proteção
        # contra sobrescrita nunca falha depois de já alterar o MongoDB.
        if normalized_report_path.exists() and not overwrite_report:
            raise FileExistsError(
                f"Relatório já existe: {normalized_report_path}. "
                "Use --overwrite-report."
            )
    source_paths = {
        "features": artifacts.features_path,
        "predictions": artifacts.predictions_path,
        "provenance": artifacts.provenance_path,
        "registry": model.registry_path,
        "model": model.model_path,
    }
    hashes_before = {name: _sha256_file(path) for name, path in source_paths.items()}
    features, predictions, provenance = _load_replay_frames(artifacts)
    normalized_config = config.normalized(len(features))
    network_context = None
    context_source_paths: tuple[Path, ...] = ()
    if normalized_config.network_context_dir is not None:
        context_dir = normalized_config.network_context_dir
        if not context_dir.is_absolute():
            context_dir = project_root / context_dir
        resolver = GeneratedFlowContextResolver(context_dir, features.columns)
        positions = range(
            normalized_config.offset,
            normalized_config.offset + normalized_config.limit,
        )
        context_source_paths = resolver.source_paths_for(provenance, positions)
        for index, path in enumerate(context_source_paths):
            source_paths[f"network_context_{index}"] = path
            hashes_before[f"network_context_{index}"] = _sha256_file(path)
        network_context = resolver.resolve(features, provenance, positions)
    documents = build_replay_documents(
        features,
        predictions,
        provenance,
        model,
        normalized_config,
        network_context.by_position if network_context is not None else None,
    )
    initialization = None
    inserted = duplicates = conflicts = 0
    if not normalized_config.dry_run:
        if initialize_repository:
            initialization = repository.initialize()
        for start in range(0, len(documents), normalized_config.batch_size):
            summary: UpsertSummary = repository.upsert_many(
                documents[start : start + normalized_config.batch_size]
            )
            inserted += summary.inserted
            duplicates += summary.duplicates
            conflicts += summary.conflicts
    hashes_after = {name: _sha256_file(path) for name, path in source_paths.items()}
    if hashes_before != hashes_after:
        raise RuntimeError("Uma fonte foi alterada durante o replay.")
    attempted = len(documents)
    if not normalized_config.dry_run and attempted != inserted + duplicates + conflicts:
        raise RuntimeError("As contagens do replay não reconciliam.")
    report = {
        "schema_version": 1,
        "stage": "offline_prediction_replay_marco_12",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "dry_run" if normalized_config.dry_run else "completed",
        "mode": "offline_replay",
        "configuration": {
            "limit": normalized_config.limit,
            "offset": normalized_config.offset,
            "batch_size": normalized_config.batch_size,
            "interval_milliseconds": normalized_config.interval_milliseconds,
            "start_time": normalized_config.start_time.isoformat(),
            "namespace": normalized_config.namespace,
            "network_context_dir": (
                str(normalized_config.network_context_dir)
                if normalized_config.network_context_dir is not None
                else None
            ),
            "dry_run": normalized_config.dry_run,
        },
        "model": model.as_filter(),
        "methodology": {
            "frozen_predictions_used": True,
            "model_deserialized": False,
            "predictions_recomputed": False,
            "labels_loaded": False,
            "binary_labels_loaded": False,
            "test_truth_persisted": False,
            "timestamps_simulated": True,
            "ips_or_protocol_fabricated": False,
            "network_context_enriched_from_generated_labelled_flows": (
                network_context is not None
            ),
            "network_context_records_validated": (
                network_context.records_validated if network_context is not None else 0
            ),
            "network_context_source_file_count": len(context_source_paths),
            "destination_port_from_selected_feature": True,
            "balanced_test_set_warning": True,
        },
        "counts": {
            "attempted": attempted,
            "inserted": inserted,
            "duplicates": duplicates,
            "conflicts": conflicts,
            "would_insert_in_dry_run": attempted if normalized_config.dry_run else 0,
        },
        "repository_initialization": initialization,
        "source_sha256_before": hashes_before,
        "source_sha256_after": hashes_after,
        "source_integrity_unchanged": True,
        "preview": documents[:3],
    }
    if normalized_report_path is not None:
        _write_json_atomic(normalized_report_path, report)
    return report
