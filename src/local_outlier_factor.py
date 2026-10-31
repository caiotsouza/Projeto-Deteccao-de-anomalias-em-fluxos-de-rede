"""Treinamento e inferencia sem rotulos do LOF em novelty mode (Marco 8)."""

from __future__ import annotations

import hashlib
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
from sklearn.neighbors import LocalOutlierFactor
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from src.config import (
    DEFAULT_LOF_ALGORITHM,
    DEFAULT_LOF_CONTAMINATION,
    DEFAULT_LOF_LEAF_SIZE,
    DEFAULT_LOF_METRIC,
    DEFAULT_LOF_N_NEIGHBORS,
    DEFAULT_LOF_P,
)
from src.isolation_forest import (
    load_feature_splits,
    load_split_manifest,
    validate_feature_frame,
)
from src.utils import save_json


LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class LOFConfig:
    """Hiperparametros centralizados do baseline Local Outlier Factor."""

    n_neighbors: int = DEFAULT_LOF_N_NEIGHBORS
    contamination: str | float = DEFAULT_LOF_CONTAMINATION
    algorithm: str = DEFAULT_LOF_ALGORITHM
    leaf_size: int = DEFAULT_LOF_LEAF_SIZE
    metric: str = DEFAULT_LOF_METRIC
    p: int = DEFAULT_LOF_P
    n_jobs: int = -1

    def __post_init__(self) -> None:
        if self.n_neighbors < 2:
            raise ValueError("n_neighbors deve ser pelo menos 2.")
        if self.contamination != "auto":
            try:
                contamination = float(self.contamination)
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    "contamination deve ser 'auto' ou um numero no intervalo (0, 0.5]."
                ) from exc
            if not 0.0 < contamination <= 0.5:
                raise ValueError("contamination numerico deve estar no intervalo (0, 0.5].")
        if self.algorithm not in {"auto", "ball_tree", "kd_tree", "brute"}:
            raise ValueError("algorithm deve ser auto, ball_tree, kd_tree ou brute.")
        if self.leaf_size <= 0:
            raise ValueError("leaf_size deve ser maior que zero.")
        if not self.metric.strip():
            raise ValueError("metric nao pode ser vazio.")
        if self.p <= 0:
            raise ValueError("p deve ser maior que zero.")
        if self.n_jobs == 0:
            raise ValueError("n_jobs nao pode ser zero.")

    def sklearn_parameters(self) -> dict[str, Any]:
        """Converte a configuracao para os argumentos do estimador."""
        contamination: str | float = self.contamination
        if contamination != "auto":
            contamination = float(contamination)
        return {
            "n_neighbors": self.n_neighbors,
            "contamination": contamination,
            "novelty": True,
            "algorithm": self.algorithm,
            "leaf_size": self.leaf_size,
            "metric": self.metric,
            "p": self.p,
            "n_jobs": self.n_jobs,
        }


@dataclass
class LOFTrainingResult:
    """Pipeline, diagnostico de treino, previsoes e documentos de auditoria."""

    pipeline: Pipeline
    bundle: dict[str, Any]
    train_diagnostics: pd.DataFrame
    predictions: dict[str, pd.DataFrame]
    metadata: dict[str, Any]
    report: dict[str, Any]


def build_lof_pipeline(config: LOFConfig | None = None) -> Pipeline:
    """Encapsula escala e detector para impedir inferencia sem transformacao."""
    config = config or LOFConfig()
    return Pipeline(
        steps=[
            ("scaler", StandardScaler()),
            ("lof", LocalOutlierFactor(**config.sklearn_parameters())),
        ]
    )


def _record_hashes(features: pd.DataFrame) -> pd.Series:
    """Reconstroi a chave hexadecimal usada nos demais marcos."""
    values = pd.util.hash_pandas_object(features, index=False).to_numpy(dtype=np.uint64)
    return pd.Series((f"{int(value):016x}" for value in values), dtype="string")


def _score_statistics(values: np.ndarray) -> dict[str, float]:
    """Resume escores sem consultar a classe verdadeira."""
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


def _build_train_diagnostics(
    lof: LocalOutlierFactor,
    features: pd.DataFrame,
) -> tuple[pd.DataFrame, dict[str, Any]]:
    """Usa somente o atributo de treino permitido pela API de novelty."""
    negative_outlier_factor = np.asarray(
        lof.negative_outlier_factor_, dtype=np.float64
    )
    diagnostic_prediction = np.where(
        negative_outlier_factor < float(lof.offset_), -1, 1
    ).astype(np.int8)
    diagnostic_anomaly = (diagnostic_prediction == -1).astype(np.int8)
    anomaly_score = -negative_outlier_factor
    frame = pd.DataFrame(
        {
            "row_position": np.arange(len(features), dtype=np.int64),
            "record_hash": _record_hashes(features),
            "negative_outlier_factor": negative_outlier_factor,
            "training_anomaly_score": anomaly_score,
            "diagnostic_sklearn_prediction": diagnostic_prediction,
            "diagnostic_predicted_anomaly": diagnostic_anomaly,
        }
    )
    anomaly_count = int(diagnostic_anomaly.sum())
    summary = {
        "records": int(len(frame)),
        "diagnostic_normal": int(len(frame) - anomaly_count),
        "diagnostic_anomaly": anomaly_count,
        "diagnostic_anomaly_rate": float(anomaly_count / len(frame)),
        "negative_outlier_factor_lower_is_more_abnormal": _score_statistics(
            negative_outlier_factor
        ),
        "training_anomaly_score_higher_is_more_abnormal": _score_statistics(
            anomaly_score
        ),
        "novelty_predict_called_on_training": False,
        "novelty_decision_function_called_on_training": False,
        "novelty_score_samples_called_on_training": False,
        "diagnostic_source": "negative_outlier_factor_ training attribute",
    }
    return frame, summary


def predict_unseen(
    pipeline: Pipeline,
    features: pd.DataFrame,
) -> tuple[pd.DataFrame, dict[str, Any], float]:
    """Transforma e pontua novos registros com uma unica busca de vizinhos."""
    started = time.perf_counter()
    scaler: StandardScaler = pipeline.named_steps["scaler"]
    lof: LocalOutlierFactor = pipeline.named_steps["lof"]
    scaled = scaler.transform(features)
    score_samples = lof.score_samples(scaled)
    decision_function = score_samples - float(lof.offset_)
    sklearn_prediction = np.where(decision_function < 0.0, -1, 1).astype(np.int8)
    predicted_anomaly = (sklearn_prediction == -1).astype(np.int8)
    anomaly_score = -score_samples
    elapsed = time.perf_counter() - started

    frame = pd.DataFrame(
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
    anomaly_count = int(predicted_anomaly.sum())
    summary = {
        "records": int(len(frame)),
        "predicted_normal": int(len(frame) - anomaly_count),
        "predicted_anomaly": anomaly_count,
        "predicted_anomaly_rate": float(anomaly_count / len(frame)),
        "score_statistics": {
            "score_samples_lower_is_more_abnormal": _score_statistics(score_samples),
            "decision_function_negative_is_anomaly": _score_statistics(
                decision_function
            ),
            "anomaly_score_higher_is_more_abnormal": _score_statistics(anomaly_score),
        },
        "inference_seconds": float(elapsed),
        "neighbor_searches_performed": 1,
        "prediction_derived_from": "score_samples - offset_",
    }
    return frame, summary, elapsed


def _scaler_audit(
    scaler: StandardScaler,
    scaled_train: np.ndarray,
    feature_columns: list[str],
) -> dict[str, Any]:
    """Registra os parametros ajustados exclusivamente no treino."""
    variances = np.asarray(scaler.var_, dtype=np.float64)
    nonzero_variance = variances > 0.0
    scaled_std = np.std(scaled_train, axis=0)
    return {
        "fitted_on": "X_train only",
        "with_mean": bool(scaler.with_mean),
        "with_std": bool(scaler.with_std),
        "feature_count": int(scaler.n_features_in_),
        "zero_variance_features": [
            feature_columns[index]
            for index in np.flatnonzero(~nonzero_variance).tolist()
        ],
        "maximum_absolute_scaled_train_mean": float(
            np.max(np.abs(np.mean(scaled_train, axis=0)))
        ),
        "maximum_scaled_train_std_deviation_from_one_nonzero_features": float(
            np.max(np.abs(scaled_std[nonzero_variance] - 1.0))
            if nonzero_variance.any()
            else 0.0
        ),
        "statistics_by_feature": {
            feature: {
                "mean": float(scaler.mean_[index]),
                "variance": float(scaler.var_[index]),
                "scale": float(scaler.scale_[index]),
            }
            for index, feature in enumerate(feature_columns)
        },
    }


def train_and_score_lof(
    split_frames: dict[str, pd.DataFrame],
    split_paths: dict[str, Path],
    manifest: dict[str, Any],
    manifest_path: Path,
    config: LOFConfig | None = None,
) -> LOFTrainingResult:
    """Ajusta scaler/LOF no treino e pontua somente conjuntos nao vistos."""
    config = config or LOFConfig()
    expected_splits = ("train", "validation", "test")
    missing_splits = [name for name in expected_splits if name not in split_frames]
    if missing_splits:
        raise ValueError(f"Conjuntos de features ausentes: {missing_splits}")
    if config.n_neighbors >= len(split_frames["train"]):
        raise ValueError("n_neighbors deve ser menor que a quantidade de treino.")

    expected_columns = list(manifest["feature_columns"])
    expected_schema = str(manifest["model_input_schema_sha256"])
    observed_schemas: dict[str, str] = {}
    record_hash_sets: dict[str, set[str]] = {}
    for name in expected_splits:
        observed_schemas[name] = validate_feature_frame(
            split_frames[name], name, expected_columns, expected_schema
        )
        record_hash_sets[name] = set(_record_hashes(split_frames[name]).tolist())
    overlaps = {
        "train_validation": len(record_hash_sets["train"] & record_hash_sets["validation"]),
        "train_test": len(record_hash_sets["train"] & record_hash_sets["test"]),
        "validation_test": len(record_hash_sets["validation"] & record_hash_sets["test"]),
    }
    if any(overlaps.values()):
        raise ValueError(f"LOF recebeu registros repetidos entre splits: {overlaps}")

    pipeline = build_lof_pipeline(config)
    LOGGER.info(
        "Treinando StandardScaler + LOF com %s registros, %s features e k=%s.",
        f"{len(split_frames['train']):,}",
        len(expected_columns),
        config.n_neighbors,
    )
    training_started = time.perf_counter()
    pipeline.fit(split_frames["train"])
    training_seconds = time.perf_counter() - training_started
    scaler: StandardScaler = pipeline.named_steps["scaler"]
    lof: LocalOutlierFactor = pipeline.named_steps["lof"]
    scaled_train = scaler.transform(split_frames["train"])
    scaler_report = _scaler_audit(scaler, scaled_train, expected_columns)
    train_diagnostics, train_summary = _build_train_diagnostics(
        lof, split_frames["train"]
    )

    predictions: dict[str, pd.DataFrame] = {}
    split_summaries: dict[str, Any] = {}
    total_inference_seconds = 0.0
    for name in ("validation", "test"):
        prediction, summary, elapsed = predict_unseen(
            pipeline, split_frames[name]
        )
        predictions[name] = prediction
        split_summaries[name] = summary
        total_inference_seconds += elapsed
        LOGGER.info(
            "%s: normais=%s, anomalias=%s, tempo=%.3f s.",
            name,
            f"{summary['predicted_normal']:,}",
            f"{summary['predicted_anomaly']:,}",
            elapsed,
        )

    created_at = datetime.now(timezone.utc).isoformat()
    parameters = config.sklearn_parameters()
    score_semantics = {
        "sklearn_prediction": "1=normal, -1=anomaly",
        "predicted_anomaly": "0=normal, 1=anomaly",
        "score_samples": "opposite LOF; lower values indicate more abnormal observations",
        "decision_function": "score_samples - offset_; negative values are anomalies",
        "anomaly_score": "-score_samples; higher values indicate more abnormal observations",
        "training_negative_outlier_factor": (
            "training-only attribute; lower values indicate more abnormal observations"
        ),
    }
    bundle = {
        "schema_version": 1,
        "artifact_type": "sklearn_standard_scaler_lof_pipeline_bundle",
        "stage": "lof_training_marco_8",
        "created_at_utc": created_at,
        "pipeline": pipeline,
        "feature_columns": expected_columns,
        "model_input_schema_sha256": expected_schema,
        "configuration": parameters,
        "score_semantics": score_semantics,
    }
    libraries = {
        "python": platform.python_version(),
        "numpy": np.__version__,
        "pandas": pd.__version__,
        "scikit_learn": sklearn.__version__,
        "joblib": joblib.__version__,
    }
    methodology = {
        "training_input": "X_train only",
        "labels_loaded": False,
        "labels_used": False,
        "scaler_fitted_on": "X_train only",
        "validation_and_test_used_for_fit": False,
        "novelty": True,
        "novelty_methods_called_on_training": False,
        "training_diagnostic_source": "negative_outlier_factor_",
        "validation_and_test_confirmed_unseen_by_record_hash": True,
        "random_state": "not applicable; LOF and StandardScaler are deterministic",
    }
    metadata: dict[str, Any] = {
        "schema_version": 1,
        "stage": "lof_training_marco_8",
        "created_at_utc": created_at,
        "algorithm": "LocalOutlierFactor",
        "pipeline_steps": ["StandardScaler", "LocalOutlierFactor"],
        "configuration": parameters,
        "effective_n_neighbors": int(lof.n_neighbors_),
        "effective_metric": str(lof.effective_metric_),
        "learned_offset": float(lof.offset_),
        "training_records": int(len(split_frames["train"])),
        "feature_count": len(expected_columns),
        "feature_columns": expected_columns,
        "model_input_schema_sha256": expected_schema,
        "source_split_manifest": str(manifest_path.resolve()),
        "scaler": scaler_report,
        "methodology": methodology,
        "score_semantics": score_semantics,
        "libraries": libraries,
    }
    report: dict[str, Any] = {
        "schema_version": 1,
        "stage": "lof_training_marco_8",
        "created_at_utc": created_at,
        "status": "completed_without_labels",
        "configuration": parameters,
        "effective_n_neighbors": int(lof.n_neighbors_),
        "effective_metric": str(lof.effective_metric_),
        "learned_offset": float(lof.offset_),
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
            "all_schemas_match": len(set(observed_schemas.values())) == 1,
            "hash_overlaps": overlaps,
            "all_evaluation_records_unseen_during_fit": not any(overlaps.values()),
            "all_features_numeric": True,
            "nan_count": 0,
            "infinity_count": 0,
            "label_columns_loaded": False,
            "status": "passed",
        },
        "methodology": methodology,
        "scaler": scaler_report,
        "score_semantics": score_semantics,
        "training_diagnostics": train_summary,
        "predictions_without_ground_truth": split_summaries,
        "timing_seconds": {
            "pipeline_fit": float(training_seconds),
            "inference_validation_and_test": float(total_inference_seconds),
            "fit_and_inference": float(training_seconds + total_inference_seconds),
        },
        "evaluation_deferred_to_marco_9": True,
        "libraries": libraries,
    }
    return LOFTrainingResult(
        pipeline=pipeline,
        bundle=bundle,
        train_diagnostics=train_diagnostics,
        predictions=predictions,
        metadata=metadata,
        report=report,
    )


def _sha256_file(path: Path) -> str:
    """Calcula a assinatura do pipeline serializado."""
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
    """Centraliza os destinos oficiais do Marco 8."""
    return {
        "model": model_path,
        "metadata": metadata_path,
        "train_diagnostics": predictions_dir / "lof_train_diagnostics.parquet",
        "predictions_validation": predictions_dir / "lof_validation_predictions.parquet",
        "predictions_test": predictions_dir / "lof_test_predictions.parquet",
        "report": report_path,
    }


def save_lof_artifacts(
    result: LOFTrainingResult,
    model_path: Path,
    metadata_path: Path,
    predictions_dir: Path,
    report_path: Path,
    overwrite: bool = False,
) -> dict[str, Path]:
    """Salva pipeline, diagnostico, previsoes e documentos de auditoria."""
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
    result.train_diagnostics.to_parquet(
        paths["train_diagnostics"], index=False, compression="snappy"
    )
    result.predictions["validation"].to_parquet(
        paths["predictions_validation"], index=False, compression="snappy"
    )
    result.predictions["test"].to_parquet(
        paths["predictions_test"], index=False, compression="snappy"
    )
    pipeline_sha256 = _sha256_file(model_path)
    artifact_paths = {name: str(path.resolve()) for name, path in paths.items()}
    result.metadata["pipeline_sha256"] = pipeline_sha256
    result.metadata["artifacts"] = artifact_paths
    result.report["pipeline_sha256"] = pipeline_sha256
    result.report["artifacts"] = artifact_paths
    result.report["prediction_columns"] = result.predictions["validation"].columns.tolist()
    result.report["train_diagnostic_columns"] = result.train_diagnostics.columns.tolist()
    save_json(result.metadata, metadata_path)
    save_json(result.report, report_path)
    return paths


def run_lof_training(
    split_paths: dict[str, Path],
    manifest_path: Path,
    model_path: Path,
    metadata_path: Path,
    predictions_dir: Path,
    report_path: Path,
    config: LOFConfig | None = None,
    overwrite: bool = False,
) -> LOFTrainingResult:
    """Executa o Marco 8 completo sem receber qualquer caminho y."""
    paths = _artifact_paths(model_path, metadata_path, predictions_dir, report_path)
    existing = [path for path in paths.values() if path.exists()]
    if existing and not overwrite:
        raise FileExistsError(
            "Artefato(s) ja existente(s); use --overwrite para substituir: "
            + ", ".join(str(path) for path in existing)
        )
    manifest = load_split_manifest(manifest_path)
    split_frames = load_feature_splits(split_paths)
    result = train_and_score_lof(
        split_frames=split_frames,
        split_paths=split_paths,
        manifest=manifest,
        manifest_path=manifest_path,
        config=config,
    )
    save_lof_artifacts(
        result=result,
        model_path=model_path,
        metadata_path=metadata_path,
        predictions_dir=predictions_dir,
        report_path=report_path,
        overwrite=overwrite,
    )
    return result


def format_lof_summary(report: dict[str, Any]) -> str:
    """Apresenta os resultados descritivos sem antecipar a avaliacao."""
    lines = [
        "\n=== LOCAL OUTLIER FACTOR — MARCO 8 ===",
        f"Vizinhos: {report['effective_n_neighbors']}",
        f"Metrica efetiva: {report['effective_metric']}",
        f"Features: {report['inputs']['train']['features']}",
        f"Registros de treino normal: {report['inputs']['train']['records']:,}",
        f"Tempo de ajuste do pipeline: {report['timing_seconds']['pipeline_fit']:.3f} s",
        (
            "Treino: apenas negative_outlier_factor_; "
            "predict/decision_function/score_samples nao foram chamados"
        ),
    ]
    for name, label in (("validation", "Validacao"), ("test", "Teste")):
        summary = report["predictions_without_ground_truth"][name]
        lines.append(
            f"{label}: normais previstos={summary['predicted_normal']:,}, "
            f"anomalias previstas={summary['predicted_anomaly']:,} "
            f"({summary['predicted_anomaly_rate']:.2%}), "
            f"inferencia={summary['inference_seconds']:.3f} s"
        )
    lines.extend(
        [
            "Rotulos carregados: nao",
            "Avaliacao e comparacao: adiadas para o Marco 9",
        ]
    )
    return "\n".join(lines)
