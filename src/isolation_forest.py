"""Treinamento e inferencia sem rotulos do Isolation Forest (Marco 6)."""

from __future__ import annotations

import hashlib
import json
import logging
import platform
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import IsolationForest

from src.config import (
    DEFAULT_IFOREST_CONTAMINATION,
    DEFAULT_IFOREST_MAX_FEATURES,
    DEFAULT_IFOREST_MAX_SAMPLES,
    DEFAULT_IFOREST_N_ESTIMATORS,
    DEFAULT_RANDOM_STATE,
)
from src.utils import save_json


LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class IsolationForestConfig:
    """Hiperparametros reproduziveis do primeiro modelo de anomalias."""

    n_estimators: int = DEFAULT_IFOREST_N_ESTIMATORS
    max_samples: int = DEFAULT_IFOREST_MAX_SAMPLES
    contamination: str | float = DEFAULT_IFOREST_CONTAMINATION
    max_features: float = DEFAULT_IFOREST_MAX_FEATURES
    bootstrap: bool = False
    random_state: int = DEFAULT_RANDOM_STATE
    n_jobs: int = -1

    def __post_init__(self) -> None:
        if self.n_estimators <= 0:
            raise ValueError("n_estimators deve ser maior que zero.")
        if self.max_samples <= 0:
            raise ValueError("max_samples deve ser maior que zero.")
        if self.contamination != "auto":
            try:
                contamination = float(self.contamination)
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    "contamination deve ser 'auto' ou um numero no intervalo (0, 0.5]."
                ) from exc
            if not 0.0 < contamination <= 0.5:
                raise ValueError("contamination numerico deve estar no intervalo (0, 0.5].")
        if not 0.0 < self.max_features <= 1.0:
            raise ValueError("max_features deve estar no intervalo (0, 1].")
        if self.n_jobs == 0:
            raise ValueError("n_jobs nao pode ser zero.")

    def sklearn_parameters(self) -> dict[str, Any]:
        """Converte a configuracao para argumentos aceitos pelo scikit-learn."""
        contamination: str | float = self.contamination
        if contamination != "auto":
            contamination = float(contamination)
        return {
            "n_estimators": self.n_estimators,
            "max_samples": self.max_samples,
            "contamination": contamination,
            "max_features": self.max_features,
            "bootstrap": self.bootstrap,
            "random_state": self.random_state,
            "n_jobs": self.n_jobs,
        }


@dataclass
class IsolationForestResult:
    """Modelo, previsoes sem rotulos e documentos de auditoria."""

    model: IsolationForest
    bundle: dict[str, Any]
    predictions: dict[str, pd.DataFrame]
    metadata: dict[str, Any]
    report: dict[str, Any]


def load_split_manifest(path: Path) -> dict[str, Any]:
    """Carrega e valida os campos de esquema produzidos no Marco 5."""
    if not path.is_file():
        raise FileNotFoundError(f"Manifesto de divisao nao encontrado: {path}")
    with path.open("r", encoding="utf-8") as file:
        manifest = json.load(file)
    required = ("feature_columns", "feature_count", "model_input_schema_sha256")
    missing = [field for field in required if field not in manifest]
    if missing:
        raise ValueError(f"Manifesto de divisao incompleto; campos ausentes: {missing}")
    if len(manifest["feature_columns"]) != int(manifest["feature_count"]):
        raise ValueError("feature_count diverge da lista feature_columns no manifesto.")
    return manifest


def schema_fingerprint(features: pd.DataFrame) -> str:
    """Calcula o SHA-256 de nomes, ordem e tipos das features."""
    schema = "\n".join(
        f"{column}:{features[column].dtype}" for column in features.columns
    )
    return hashlib.sha256(schema.encode("utf-8")).hexdigest()


def validate_feature_frame(
    features: pd.DataFrame,
    split_name: str,
    expected_columns: list[str],
    expected_schema_sha256: str,
) -> str:
    """Impede inferencia com esquema trocado, texto, ausentes ou infinitos."""
    if features.empty:
        raise ValueError(f"{split_name} esta vazio.")
    actual_columns = features.columns.tolist()
    if actual_columns != expected_columns:
        missing = [column for column in expected_columns if column not in actual_columns]
        extra = [column for column in actual_columns if column not in expected_columns]
        order_changed = not missing and not extra
        raise ValueError(
            f"Esquema de {split_name} diverge do manifesto: "
            f"ausentes={missing}, extras={extra}, ordem_alterada={order_changed}."
        )
    non_numeric = [
        column
        for column in actual_columns
        if not pd.api.types.is_numeric_dtype(features[column])
    ]
    if non_numeric:
        raise ValueError(f"{split_name} contem features nao numericas: {non_numeric}")
    if features.isna().any().any():
        columns = features.columns[features.isna().any()].tolist()
        raise ValueError(f"{split_name} contem NaN nas features: {columns}")
    values = features.to_numpy(dtype=np.float64, copy=False)
    if not np.isfinite(values).all():
        invalid_columns = features.columns[~np.isfinite(values).all(axis=0)].tolist()
        raise ValueError(f"{split_name} contem infinito: {invalid_columns}")
    fingerprint = schema_fingerprint(features)
    if fingerprint != expected_schema_sha256:
        raise ValueError(
            f"Fingerprint de {split_name} divergente: esperado={expected_schema_sha256}, "
            f"obtido={fingerprint}."
        )
    return fingerprint


def _record_hashes(features: pd.DataFrame) -> pd.Series:
    """Reconstrói a chave hexadecimal usada para unir previsoes e rotulos depois."""
    values = pd.util.hash_pandas_object(features, index=False).to_numpy(dtype=np.uint64)
    return pd.Series((f"{int(value):016x}" for value in values), dtype="string")


def _score_statistics(values: np.ndarray) -> dict[str, float]:
    """Resume um vetor de escores sem consultar a classe verdadeira."""
    quantiles = np.quantile(values, [0.01, 0.05, 0.25, 0.50, 0.75, 0.95, 0.99])
    return {
        "minimum": float(np.min(values)),
        "p01": float(quantiles[0]),
        "p05": float(quantiles[1]),
        "p25": float(quantiles[2]),
        "median": float(quantiles[3]),
        "p75": float(quantiles[4]),
        "p95": float(quantiles[5]),
        "p99": float(quantiles[6]),
        "maximum": float(np.max(values)),
        "mean": float(np.mean(values)),
        "standard_deviation": float(np.std(values)),
    }


def predict_without_labels(
    model: IsolationForest,
    features: pd.DataFrame,
) -> tuple[pd.DataFrame, dict[str, Any], float]:
    """Produz previsoes e escores mantendo a convencao explicita no artefato."""
    started = time.perf_counter()
    score_samples = model.score_samples(features)
    decision_function = score_samples - float(model.offset_)
    sklearn_prediction = np.where(decision_function < 0.0, -1, 1).astype(np.int8)
    predicted_anomaly = (sklearn_prediction == -1).astype(np.int8)
    anomaly_score = -score_samples
    elapsed = time.perf_counter() - started

    predictions = pd.DataFrame(
        {
            "row_position": np.arange(len(features), dtype=np.int64),
            "record_hash": _record_hashes(features),
            "sklearn_prediction": sklearn_prediction,
            "predicted_anomaly": predicted_anomaly,
            "score_samples": score_samples.astype(np.float64),
            "decision_function": decision_function.astype(np.float64),
            "anomaly_score": anomaly_score.astype(np.float64),
        }
    )
    normal_count = int((predicted_anomaly == 0).sum())
    anomaly_count = int((predicted_anomaly == 1).sum())
    summary = {
        "records": int(len(predictions)),
        "predicted_normal": normal_count,
        "predicted_anomaly": anomaly_count,
        "predicted_anomaly_rate": float(anomaly_count / len(predictions)),
        "score_statistics": {
            "score_samples_lower_is_more_abnormal": _score_statistics(score_samples),
            "decision_function_negative_is_anomaly": _score_statistics(decision_function),
            "anomaly_score_higher_is_more_abnormal": _score_statistics(anomaly_score),
        },
        "inference_seconds": float(elapsed),
    }
    return predictions, summary, elapsed


def train_and_score(
    split_frames: dict[str, pd.DataFrame],
    split_paths: dict[str, Path],
    manifest: dict[str, Any],
    manifest_path: Path,
    config: IsolationForestConfig | None = None,
) -> IsolationForestResult:
    """Valida os tres X, ajusta somente no treino e infere sem abrir y."""
    config = config or IsolationForestConfig()
    expected_splits = ("train", "validation", "test")
    missing_splits = [name for name in expected_splits if name not in split_frames]
    if missing_splits:
        raise ValueError(f"Conjuntos de features ausentes: {missing_splits}")

    expected_columns = list(manifest["feature_columns"])
    expected_schema = str(manifest["model_input_schema_sha256"])
    observed_schemas: dict[str, str] = {}
    for name in expected_splits:
        observed_schemas[name] = validate_feature_frame(
            split_frames[name], name, expected_columns, expected_schema
        )

    model = IsolationForest(**config.sklearn_parameters())
    LOGGER.info(
        "Treinando Isolation Forest com %s registros e %s features.",
        f"{len(split_frames['train']):,}",
        len(expected_columns),
    )
    training_started = time.perf_counter()
    model.fit(split_frames["train"])
    training_seconds = time.perf_counter() - training_started

    predictions: dict[str, pd.DataFrame] = {}
    split_summaries: dict[str, Any] = {}
    total_inference_seconds = 0.0
    for name in expected_splits:
        prediction, summary, elapsed = predict_without_labels(
            model, split_frames[name]
        )
        predictions[name] = prediction
        split_summaries[name] = summary
        total_inference_seconds += elapsed
        LOGGER.info(
            "%s: normais=%s, anomalias=%s.",
            name,
            f"{summary['predicted_normal']:,}",
            f"{summary['predicted_anomaly']:,}",
        )

    created_at = datetime.now(timezone.utc).isoformat()
    parameters = config.sklearn_parameters()
    effective_max_samples = int(model.max_samples_)
    bundle = {
        "schema_version": 1,
        "artifact_type": "sklearn_isolation_forest_bundle",
        "stage": "isolation_forest_training_marco_6",
        "created_at_utc": created_at,
        "model": model,
        "feature_columns": expected_columns,
        "model_input_schema_sha256": expected_schema,
        "configuration": parameters,
        "effective_max_samples": effective_max_samples,
        "score_semantics": {
            "sklearn_prediction": "1=normal, -1=anomaly",
            "predicted_anomaly": "0=normal, 1=anomaly",
            "score_samples": "lower values indicate more abnormal observations",
            "decision_function": "negative values are predicted as anomalies",
            "anomaly_score": "-score_samples; higher values indicate more abnormal observations",
        },
    }
    metadata: dict[str, Any] = {
        "schema_version": 1,
        "stage": "isolation_forest_training_marco_6",
        "created_at_utc": created_at,
        "algorithm": "IsolationForest",
        "configuration": parameters,
        "effective_max_samples": effective_max_samples,
        "learned_offset": float(model.offset_),
        "feature_count": len(expected_columns),
        "feature_columns": expected_columns,
        "model_input_schema_sha256": expected_schema,
        "source_split_manifest": str(manifest_path.resolve()),
        "training_records": int(len(split_frames["train"])),
        "libraries": {
            "python": platform.python_version(),
            "numpy": np.__version__,
            "pandas": pd.__version__,
            "scikit_learn": sklearn.__version__,
            "joblib": joblib.__version__,
        },
        "methodology": {
            "training_input": "X_train only",
            "labels_loaded": False,
            "labels_used": False,
            "scaler_used": False,
            "validation_and_test_used_for_fit": False,
            "threshold_source": "IsolationForest contamination parameter and learned offset_",
        },
        "score_semantics": bundle["score_semantics"],
    }
    report: dict[str, Any] = {
        "schema_version": 1,
        "stage": "isolation_forest_training_marco_6",
        "created_at_utc": created_at,
        "status": "completed_without_labels",
        "configuration": parameters,
        "effective_max_samples": effective_max_samples,
        "learned_offset": float(model.offset_),
        "inputs": {
            name: {
                "path": str(split_paths[name].resolve()),
                "records": int(len(split_frames[name])),
                "features": int(len(split_frames[name].columns)),
                "schema_sha256": observed_schemas[name],
            }
            for name in expected_splits
        },
        "input_validation": {
            "expected_schema_sha256": expected_schema,
            "all_schemas_match": len(set(observed_schemas.values())) == 1,
            "all_features_numeric": True,
            "nan_count": 0,
            "infinity_count": 0,
            "label_columns_loaded": False,
            "status": "passed",
        },
        "methodology": metadata["methodology"],
        "score_semantics": bundle["score_semantics"],
        "timing_seconds": {
            "training": float(training_seconds),
            "inference_total": float(total_inference_seconds),
            "training_and_inference": float(training_seconds + total_inference_seconds),
        },
        "predictions_without_ground_truth": split_summaries,
        "evaluation_deferred_to_marco_7": True,
        "metrics_not_calculated": [
            "confusion_matrix",
            "precision",
            "recall",
            "f1_score",
            "false_positive_rate",
            "roc_auc",
            "pr_auc",
        ],
        "libraries": metadata["libraries"],
    }
    return IsolationForestResult(
        model=model,
        bundle=bundle,
        predictions=predictions,
        metadata=metadata,
        report=report,
    )


def load_feature_splits(
    split_paths: dict[str, Path],
) -> dict[str, pd.DataFrame]:
    """Carrega exclusivamente arquivos X; nenhum caminho y e aceito aqui."""
    expected = ("train", "validation", "test")
    missing_keys = [name for name in expected if name not in split_paths]
    if missing_keys:
        raise ValueError(f"Caminhos X ausentes: {missing_keys}")
    missing_files = [split_paths[name] for name in expected if not split_paths[name].is_file()]
    if missing_files:
        raise FileNotFoundError(f"Arquivos X nao encontrados: {missing_files}")
    return {name: pd.read_parquet(split_paths[name]) for name in expected}


def _sha256_file(path: Path) -> str:
    """Calcula a assinatura do modelo serializado para verificar integridade."""
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for block in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _artifact_paths(
    model_path: Path,
    metadata_path: Path,
    predictions_dir: Path,
    report_path: Path,
) -> dict[str, Path]:
    """Centraliza os destinos para verificacao e persistencia consistentes."""
    paths = {
        "model": model_path,
        "metadata": metadata_path,
        "report": report_path,
    }
    for name in ("train", "validation", "test"):
        paths[f"predictions_{name}"] = (
            predictions_dir / f"isolation_forest_{name}_predictions.parquet"
        )
    return paths


def save_isolation_forest_artifacts(
    result: IsolationForestResult,
    model_path: Path,
    metadata_path: Path,
    predictions_dir: Path,
    report_path: Path,
    overwrite: bool = False,
) -> dict[str, Path]:
    """Salva modelo, metadados, tres previsoes e relatorio auditavel."""
    paths = _artifact_paths(model_path, metadata_path, predictions_dir, report_path)
    existing = [path for path in paths.values() if path.exists()]
    if existing and not overwrite:
        raise FileExistsError(
            "Artefato(s) ja existente(s); use --overwrite para substituir: "
            + ", ".join(str(path) for path in existing)
        )
    for path in paths.values():
        path.parent.mkdir(parents=True, exist_ok=True)

    joblib.dump(result.bundle, model_path, compress=3)
    model_sha256 = _sha256_file(model_path)
    for name, frame in result.predictions.items():
        frame.to_parquet(
            paths[f"predictions_{name}"], index=False, compression="snappy"
        )

    artifact_paths = {name: str(path.resolve()) for name, path in paths.items()}
    result.metadata["model_sha256"] = model_sha256
    result.metadata["artifacts"] = artifact_paths
    result.report["model_sha256"] = model_sha256
    result.report["artifacts"] = artifact_paths
    result.report["prediction_columns"] = result.predictions["train"].columns.tolist()
    save_json(result.metadata, metadata_path)
    save_json(result.report, report_path)
    return paths


def run_isolation_forest_training(
    split_paths: dict[str, Path],
    manifest_path: Path,
    model_path: Path,
    metadata_path: Path,
    predictions_dir: Path,
    report_path: Path,
    config: IsolationForestConfig | None = None,
    overwrite: bool = False,
) -> IsolationForestResult:
    """Executa o Marco 6 completo, da leitura de X ate a persistencia."""
    paths = _artifact_paths(model_path, metadata_path, predictions_dir, report_path)
    existing = [path for path in paths.values() if path.exists()]
    if existing and not overwrite:
        raise FileExistsError(
            "Artefato(s) ja existente(s); use --overwrite para substituir: "
            + ", ".join(str(path) for path in existing)
        )
    manifest = load_split_manifest(manifest_path)
    split_frames = load_feature_splits(split_paths)
    result = train_and_score(
        split_frames=split_frames,
        split_paths=split_paths,
        manifest=manifest,
        manifest_path=manifest_path,
        config=config,
    )
    save_isolation_forest_artifacts(
        result=result,
        model_path=model_path,
        metadata_path=metadata_path,
        predictions_dir=predictions_dir,
        report_path=report_path,
        overwrite=overwrite,
    )
    return result


def format_training_summary(report: dict[str, Any]) -> str:
    """Exibe o resultado descritivo, sem confundi-lo com avaliacao rotulada."""
    lines = [
        "\n=== ISOLATION FOREST — MARCO 6 ===",
        f"Arvores: {report['configuration']['n_estimators']}",
        f"Amostras por arvore: {report['effective_max_samples']}",
        f"Features: {report['inputs']['train']['features']}",
        f"Registros de treino normal: {report['inputs']['train']['records']:,}",
        f"Tempo de treino: {report['timing_seconds']['training']:.3f} s",
    ]
    for name, label in (("train", "Treino"), ("validation", "Validacao"), ("test", "Teste")):
        summary = report["predictions_without_ground_truth"][name]
        lines.append(
            f"{label}: normais previstos={summary['predicted_normal']:,}, "
            f"anomalias previstas={summary['predicted_anomaly']:,} "
            f"({summary['predicted_anomaly_rate']:.2%})"
        )
    lines.extend(
        [
            "Rotulos carregados: nao",
            "Metricas supervisionadas: adiadas para o Marco 7",
        ]
    )
    return "\n".join(lines)
