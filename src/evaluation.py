"""Avaliacao pos-predicao do Isolation Forest usando rotulos (Marco 7)."""

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

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import sklearn
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)

from src.utils import save_json


LOGGER = logging.getLogger(__name__)
logging.getLogger("matplotlib").setLevel(logging.WARNING)
BENIGN_LABEL = "BENIGN"
PREDICTION_REQUIRED_COLUMNS = (
    "row_position",
    "record_hash",
    "sklearn_prediction",
    "predicted_anomaly",
    "score_samples",
    "decision_function",
    "anomaly_score",
)
LABEL_REQUIRED_COLUMNS = (
    "label",
    "binary_label",
    "source_file",
    "source_row",
    "record_hash",
)


@dataclass
class EvaluationResult:
    """Dados associados e relatorio completo dos dois pontos operacionais."""

    evaluated_frames: dict[str, pd.DataFrame]
    report: dict[str, Any]


def _load_json(path: Path) -> dict[str, Any]:
    """Carrega um JSON obrigatorio com mensagem de erro contextual."""
    if not path.is_file():
        raise FileNotFoundError(f"Arquivo JSON nao encontrado: {path}")
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def _sha256_file(path: Path) -> str:
    """Calcula a assinatura de um artefato sem interpretar seu conteudo."""
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for block in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _require_columns(frame: pd.DataFrame, required: tuple[str, ...], name: str) -> None:
    """Interrompe a avaliacao quando uma coluna contratual esta ausente."""
    missing = [column for column in required if column not in frame.columns]
    if missing:
        raise ValueError(f"{name} nao possui as colunas obrigatorias: {missing}")


def join_predictions_and_labels(
    predictions: pd.DataFrame,
    labels: pd.DataFrame,
    split_name: str,
) -> tuple[pd.DataFrame, dict[str, Any]]:
    """Associa previsao e verdade por hash, validando todas as convencoes."""
    _require_columns(predictions, PREDICTION_REQUIRED_COLUMNS, f"previsoes/{split_name}")
    _require_columns(labels, LABEL_REQUIRED_COLUMNS, f"rotulos/{split_name}")
    if predictions.empty or labels.empty:
        raise ValueError(f"{split_name} possui previsoes ou rotulos vazios.")
    if len(predictions) != len(labels):
        raise ValueError(
            f"Quantidade divergente em {split_name}: "
            f"previsoes={len(predictions)}, rotulos={len(labels)}."
        )

    predictions = predictions.loc[:, PREDICTION_REQUIRED_COLUMNS].copy()
    labels = labels.loc[:, LABEL_REQUIRED_COLUMNS].copy()
    predictions["record_hash"] = predictions["record_hash"].astype("string")
    labels["record_hash"] = labels["record_hash"].astype("string")
    if predictions["record_hash"].isna().any() or labels["record_hash"].isna().any():
        raise ValueError(f"{split_name} possui record_hash ausente.")
    duplicate_predictions = int(predictions["record_hash"].duplicated().sum())
    duplicate_labels = int(labels["record_hash"].duplicated().sum())
    if duplicate_predictions or duplicate_labels:
        raise ValueError(
            f"Hashes duplicados em {split_name}: previsoes={duplicate_predictions}, "
            f"rotulos={duplicate_labels}."
        )

    expected_positions = np.arange(len(predictions), dtype=np.int64)
    actual_positions = predictions["row_position"].to_numpy(dtype=np.int64)
    if not np.array_equal(actual_positions, expected_positions):
        raise ValueError(f"row_position de {split_name} nao e uma sequencia de 0 a N-1.")

    prediction_hashes = set(predictions["record_hash"].tolist())
    label_hashes = set(labels["record_hash"].tolist())
    missing_in_labels = prediction_hashes - label_hashes
    missing_in_predictions = label_hashes - prediction_hashes
    if missing_in_labels or missing_in_predictions:
        raise ValueError(
            f"Conjuntos de record_hash divergentes em {split_name}: "
            f"sem_rotulo={len(missing_in_labels)}, sem_previsao={len(missing_in_predictions)}."
        )

    numeric_score_columns = ("score_samples", "decision_function", "anomaly_score")
    score_values = predictions.loc[:, numeric_score_columns].to_numpy(dtype=np.float64)
    if not np.isfinite(score_values).all():
        raise ValueError(f"{split_name} possui escore ausente ou infinito.")
    if not np.allclose(
        predictions["anomaly_score"].to_numpy(dtype=np.float64),
        -predictions["score_samples"].to_numpy(dtype=np.float64),
        rtol=0.0,
        atol=1e-12,
    ):
        raise ValueError(f"Orientacao do anomaly_score inconsistente em {split_name}.")

    sklearn_prediction = predictions["sklearn_prediction"].to_numpy(dtype=np.int8)
    predicted_anomaly = predictions["predicted_anomaly"].to_numpy(dtype=np.int8)
    decision_function = predictions["decision_function"].to_numpy(dtype=np.float64)
    if set(np.unique(sklearn_prediction)) - {-1, 1}:
        raise ValueError(f"sklearn_prediction invalida em {split_name}.")
    if set(np.unique(predicted_anomaly)) - {0, 1}:
        raise ValueError(f"predicted_anomaly invalida em {split_name}.")
    if not np.array_equal(predicted_anomaly, (sklearn_prediction == -1).astype(np.int8)):
        raise ValueError(f"Conversao -1/1 para 0/1 inconsistente em {split_name}.")
    if not np.array_equal(predicted_anomaly, (decision_function < 0.0).astype(np.int8)):
        raise ValueError(f"Limiar original inconsistente em {split_name}.")

    if labels["label"].isna().any() or labels["binary_label"].isna().any():
        raise ValueError(f"{split_name} possui rotulo ausente.")
    labels["label"] = labels["label"].astype("string")
    labels["binary_label"] = labels["binary_label"].astype("int8")
    if set(labels["binary_label"].unique()) != {0, 1}:
        raise ValueError(f"{split_name} deve conter as classes binarias 0 e 1.")
    expected_binary = labels["label"].str.strip().ne(BENIGN_LABEL).astype("int8")
    if not np.array_equal(labels["binary_label"].to_numpy(), expected_binary.to_numpy()):
        raise ValueError(f"Mapeamento BENIGN=0/ataque=1 inconsistente em {split_name}.")

    hashes_already_aligned = bool(
        predictions["record_hash"].reset_index(drop=True).equals(
            labels["record_hash"].reset_index(drop=True)
        )
    )
    joined = predictions.merge(
        labels,
        on="record_hash",
        how="inner",
        validate="one_to_one",
        sort=False,
    ).sort_values("row_position", kind="mergesort")
    joined.reset_index(drop=True, inplace=True)
    if len(joined) != len(predictions):
        raise ValueError(f"Associacao incompleta em {split_name}.")

    columns = [
        "row_position",
        "record_hash",
        "label",
        "binary_label",
        "source_file",
        "source_row",
        "sklearn_prediction",
        "predicted_anomaly",
        "score_samples",
        "decision_function",
        "anomaly_score",
    ]
    audit = {
        "prediction_records": int(len(predictions)),
        "label_records": int(len(labels)),
        "joined_records": int(len(joined)),
        "unique_prediction_hashes": int(predictions["record_hash"].nunique()),
        "unique_label_hashes": int(labels["record_hash"].nunique()),
        "hash_sets_identical": True,
        "hash_order_already_identical": hashes_already_aligned,
        "missing_predictions": 0,
        "missing_labels": 0,
        "score_orientation_valid": True,
        "binary_mapping_valid": True,
        "status": "passed",
    }
    return joined.loc[:, columns].copy(), audit


def select_f1_threshold(y_true: np.ndarray, anomaly_score: np.ndarray) -> dict[str, Any]:
    """Escolhe na validacao o limiar de maior F1 com desempate explicito."""
    precision, recall, thresholds = precision_recall_curve(
        y_true, anomaly_score, pos_label=1
    )
    if len(thresholds) == 0:
        raise ValueError("Nao ha limiares candidatos para calibracao.")
    precision_at_threshold = precision[:-1]
    recall_at_threshold = recall[:-1]
    denominator = precision_at_threshold + recall_at_threshold
    f1_values = np.divide(
        2.0 * precision_at_threshold * recall_at_threshold,
        denominator,
        out=np.zeros_like(denominator),
        where=denominator > 0.0,
    )
    maximum = float(np.max(f1_values))
    candidates = np.flatnonzero(np.isclose(f1_values, maximum, rtol=0.0, atol=1e-12))
    best_index = max(
        candidates.tolist(),
        key=lambda index: (
            float(precision_at_threshold[index]),
            float(recall_at_threshold[index]),
            float(thresholds[index]),
        ),
    )
    return {
        "objective": "maximize_f1",
        "score": "anomaly_score",
        "positive_rule": "anomaly_score >= threshold",
        "threshold": float(thresholds[best_index]),
        "validation_f1_at_selection": float(f1_values[best_index]),
        "validation_precision_at_selection": float(precision_at_threshold[best_index]),
        "validation_recall_at_selection": float(recall_at_threshold[best_index]),
        "candidate_threshold_count": int(len(thresholds)),
        "tied_maximum_count": int(len(candidates)),
        "tie_breaking": "higher precision, then higher recall, then higher threshold",
        "test_labels_used": False,
    }


def _safe_ratio(numerator: int, denominator: int) -> float:
    """Evita divisao por zero mantendo o valor JSON numerico."""
    return float(numerator / denominator) if denominator else 0.0


def calculate_classification_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
) -> dict[str, Any]:
    """Calcula metricas dependentes do ponto operacional."""
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    tn, fp, fn, tp = (int(tn), int(fp), int(fn), int(tp))
    return {
        "confusion_matrix": [[tn, fp], [fn, tp]],
        "true_negative": tn,
        "false_positive": fp,
        "false_negative": fn,
        "true_positive": tp,
        "normal_support": int(tn + fp),
        "attack_support": int(tp + fn),
        "predicted_normal": int(tn + fn),
        "predicted_anomaly": int(tp + fp),
        "predicted_anomaly_rate": _safe_ratio(tp + fp, len(y_true)),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "balanced_accuracy": float(balanced_accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall_tpr": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1_score": float(f1_score(y_true, y_pred, zero_division=0)),
        "specificity_tnr": _safe_ratio(tn, tn + fp),
        "false_positive_rate": _safe_ratio(fp, fp + tn),
        "false_negative_rate": _safe_ratio(fn, fn + tp),
    }


def _score_statistics(series: pd.Series) -> dict[str, float]:
    """Resume anomaly_score para uma classe verdadeira."""
    values = series.to_numpy(dtype=np.float64)
    return {
        "minimum": float(np.min(values)),
        "p05": float(np.quantile(values, 0.05)),
        "median": float(np.median(values)),
        "p95": float(np.quantile(values, 0.95)),
        "maximum": float(np.max(values)),
        "mean": float(np.mean(values)),
        "standard_deviation": float(np.std(values)),
    }


def _attack_category_metrics(frame: pd.DataFrame) -> dict[str, dict[str, Any]]:
    """Detalha quais categorias de ataque foram detectadas ou perdidas."""
    attacks = frame.loc[frame["binary_label"].eq(1)]
    result: dict[str, dict[str, Any]] = {}
    for label, group in attacks.groupby("label", sort=True):
        support = int(len(group))
        default_detected = int(group["predicted_anomaly"].sum())
        calibrated_detected = int(group["predicted_anomaly_calibrated_f1"].sum())
        result[str(label)] = {
            "support": support,
            "default_detected": default_detected,
            "default_detection_rate": _safe_ratio(default_detected, support),
            "calibrated_f1_detected": calibrated_detected,
            "calibrated_f1_detection_rate": _safe_ratio(calibrated_detected, support),
            "anomaly_score_mean": float(group["anomaly_score"].mean()),
            "anomaly_score_median": float(group["anomaly_score"].median()),
        }
    return result


def _evaluate_split(frame: pd.DataFrame) -> dict[str, Any]:
    """Avalia classificacao, ranking, classes e distribuicao de escores."""
    y_true = frame["binary_label"].to_numpy(dtype=np.int8)
    anomaly_score = frame["anomaly_score"].to_numpy(dtype=np.float64)
    default_prediction = frame["predicted_anomaly"].to_numpy(dtype=np.int8)
    calibrated_prediction = frame["predicted_anomaly_calibrated_f1"].to_numpy(
        dtype=np.int8
    )
    return {
        "records": int(len(frame)),
        "true_distribution": {
            "normal": int((y_true == 0).sum()),
            "attack": int((y_true == 1).sum()),
        },
        "ranking_metrics": {
            "roc_auc": float(roc_auc_score(y_true, anomaly_score)),
            "average_precision": float(average_precision_score(y_true, anomaly_score)),
            "average_precision_note": (
                "weighted precision gain across recall; not trapezoidal PR interpolation"
            ),
        },
        "operating_points": {
            "isolation_forest_default": calculate_classification_metrics(
                y_true, default_prediction
            ),
            "validation_f1_calibrated": calculate_classification_metrics(
                y_true, calibrated_prediction
            ),
        },
        "anomaly_score_by_true_class": {
            "normal": _score_statistics(frame.loc[frame["binary_label"].eq(0), "anomaly_score"]),
            "attack": _score_statistics(frame.loc[frame["binary_label"].eq(1), "anomaly_score"]),
        },
        "attack_categories": _attack_category_metrics(frame),
    }


def evaluate_joined_splits(
    validation: pd.DataFrame,
    test: pd.DataFrame,
    learned_offset: float,
    threshold_selection: dict[str, Any] | None = None,
) -> EvaluationResult:
    """Calibra em validacao e usa o teste somente para avaliacao final."""
    validation = validation.copy()
    test = test.copy()
    selection = threshold_selection or select_f1_threshold(
        validation["binary_label"].to_numpy(dtype=np.int8),
        validation["anomaly_score"].to_numpy(dtype=np.float64),
    )
    threshold = float(selection["threshold"])
    for frame in (validation, test):
        frame["predicted_anomaly_calibrated_f1"] = (
            frame["anomaly_score"].ge(threshold).astype("int8")
        )

    report = {
        "thresholds": {
            "isolation_forest_default": {
                "decision_rule": "decision_function < 0",
                "equivalent_anomaly_score_rule": "anomaly_score > -learned_offset",
                "learned_offset": float(learned_offset),
                "equivalent_anomaly_score_threshold": float(-learned_offset),
                "source": "frozen Marco 6 predictions",
            },
            "validation_f1_calibrated": selection,
        },
        "splits": {
            "validation": _evaluate_split(validation),
            "test": _evaluate_split(test),
        },
    }
    return EvaluationResult(
        evaluated_frames={"validation": validation, "test": test},
        report=report,
    )


def _plot_confusion_matrices(result: EvaluationResult, output_path: Path) -> None:
    """Gera quatro matrizes para comparar limiar original e calibrado."""
    figure, axes = plt.subplots(2, 2, figsize=(10, 9))
    split_labels = {"validation": "Validação", "test": "Teste"}
    for row, split in enumerate(("validation", "test")):
        for column, (point, title) in enumerate(
            (
                ("isolation_forest_default", "Limiar original"),
                ("validation_f1_calibrated", "Limiar calibrado por F1"),
            )
        ):
            matrix = np.asarray(
                result.report["splits"][split]["operating_points"][point][
                    "confusion_matrix"
                ]
            )
            axis = axes[row, column]
            image = axis.imshow(matrix, cmap="Blues", vmin=0)
            for i in range(2):
                for j in range(2):
                    axis.text(
                        j,
                        i,
                        f"{matrix[i, j]:,}".replace(",", "."),
                        ha="center",
                        va="center",
                        color="white" if matrix[i, j] > matrix.max() / 2 else "black",
                        fontsize=11,
                    )
            axis.set_xticks([0, 1], labels=["Normal", "Anomalia"])
            axis.set_yticks([0, 1], labels=["Normal", "Ataque"])
            axis.set_xlabel("Predição")
            axis.set_ylabel("Classe verdadeira")
            axis.set_title(f"{split_labels[split]} — {title}")
            figure.colorbar(image, ax=axis, fraction=0.046, pad=0.04)
    figure.suptitle("Isolation Forest — matrizes de confusão", fontsize=14)
    figure.tight_layout()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(output_path, dpi=160, bbox_inches="tight")
    plt.close(figure)


def _plot_roc_pr_curves(result: EvaluationResult, output_path: Path) -> None:
    """Gera curvas independentes de limiar para validacao e teste."""
    figure, (roc_axis, pr_axis) = plt.subplots(1, 2, figsize=(13, 5.5))
    colors = {"validation": "#1f77b4", "test": "#d62728"}
    labels = {"validation": "Validação", "test": "Teste"}
    for split, frame in result.evaluated_frames.items():
        y_true = frame["binary_label"].to_numpy(dtype=np.int8)
        scores = frame["anomaly_score"].to_numpy(dtype=np.float64)
        ranking = result.report["splits"][split]["ranking_metrics"]
        fpr, tpr, _ = roc_curve(y_true, scores, pos_label=1)
        precision, recall, _ = precision_recall_curve(y_true, scores, pos_label=1)
        roc_axis.plot(
            fpr,
            tpr,
            color=colors[split],
            label=f"{labels[split]} (AUC={ranking['roc_auc']:.3f})",
        )
        pr_axis.plot(
            recall,
            precision,
            color=colors[split],
            label=f"{labels[split]} (AP={ranking['average_precision']:.3f})",
        )
    roc_axis.plot([0, 1], [0, 1], linestyle="--", color="gray", label="Aleatório")
    roc_axis.set(xlabel="False Positive Rate", ylabel="True Positive Rate", xlim=(0, 1), ylim=(0, 1.02))
    roc_axis.set_title("Curva ROC")
    roc_axis.grid(alpha=0.25)
    roc_axis.legend(loc="lower right")

    prevalence = float(result.evaluated_frames["test"]["binary_label"].mean())
    pr_axis.axhline(prevalence, linestyle="--", color="gray", label=f"Prevalência={prevalence:.2f}")
    pr_axis.set(xlabel="Recall", ylabel="Precision", xlim=(0, 1), ylim=(0, 1.02))
    pr_axis.set_title("Curva Precision–Recall")
    pr_axis.grid(alpha=0.25)
    pr_axis.legend(loc="lower left")
    figure.suptitle("Isolation Forest — desempenho de ranking", fontsize=14)
    figure.tight_layout()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(output_path, dpi=160, bbox_inches="tight")
    plt.close(figure)


def _plot_score_distributions(result: EvaluationResult, output_path: Path) -> None:
    """Compara os escores verdadeiros e mostra ambos os limiares."""
    figure, axes = plt.subplots(1, 2, figsize=(13, 5.5), sharey=True)
    split_labels = {"validation": "Validação", "test": "Teste"}
    calibrated_threshold = result.report["thresholds"]["validation_f1_calibrated"][
        "threshold"
    ]
    default_threshold = result.report["thresholds"]["isolation_forest_default"][
        "equivalent_anomaly_score_threshold"
    ]
    for axis, split in zip(axes, ("validation", "test")):
        frame = result.evaluated_frames[split]
        normal = frame.loc[frame["binary_label"].eq(0), "anomaly_score"]
        attacks = frame.loc[frame["binary_label"].eq(1), "anomaly_score"]
        lower = float(min(normal.min(), attacks.min()))
        upper = float(max(normal.max(), attacks.max()))
        bins = np.linspace(lower, upper, 61)
        axis.hist(normal, bins=bins, density=True, alpha=0.60, label="Normal", color="#1f77b4")
        axis.hist(attacks, bins=bins, density=True, alpha=0.55, label="Ataque", color="#d62728")
        axis.axvline(default_threshold, color="black", linestyle="--", label="Limiar original")
        axis.axvline(calibrated_threshold, color="#2ca02c", linestyle="-.", label="Limiar calibrado")
        axis.set_title(split_labels[split])
        axis.set_xlabel("Anomaly score (maior = mais anômalo)")
        axis.grid(alpha=0.20)
    axes[0].set_ylabel("Densidade")
    axes[1].legend(loc="upper right")
    figure.suptitle("Isolation Forest — distribuição dos escores por classe", fontsize=14)
    figure.tight_layout()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(output_path, dpi=160, bbox_inches="tight")
    plt.close(figure)


def _artifact_paths(
    evaluation_data_dir: Path,
    report_path: Path,
    figures_dir: Path,
) -> dict[str, Path]:
    """Centraliza todos os destinos gerados no Marco 7."""
    return {
        "evaluated_validation": evaluation_data_dir / "isolation_forest_validation_evaluated.parquet",
        "evaluated_test": evaluation_data_dir / "isolation_forest_test_evaluated.parquet",
        "report": report_path,
        "confusion_matrices_figure": figures_dir / "isolation_forest_confusion_matrices.png",
        "roc_pr_curves_figure": figures_dir / "isolation_forest_roc_pr_curves.png",
        "score_distributions_figure": figures_dir / "isolation_forest_score_distributions.png",
    }


def save_evaluation_artifacts(
    result: EvaluationResult,
    evaluation_data_dir: Path,
    report_path: Path,
    figures_dir: Path,
    overwrite: bool = False,
) -> dict[str, Path]:
    """Persiste dados associados, relatorio e figuras cientificas."""
    paths = _artifact_paths(evaluation_data_dir, report_path, figures_dir)
    existing = [path for path in paths.values() if path.exists()]
    if existing and not overwrite:
        raise FileExistsError(
            "Artefato(s) ja existente(s); use --overwrite para substituir: "
            + ", ".join(str(path) for path in existing)
        )
    for path in paths.values():
        path.parent.mkdir(parents=True, exist_ok=True)

    result.evaluated_frames["validation"].to_parquet(
        paths["evaluated_validation"], index=False, compression="snappy"
    )
    result.evaluated_frames["test"].to_parquet(
        paths["evaluated_test"], index=False, compression="snappy"
    )
    _plot_confusion_matrices(result, paths["confusion_matrices_figure"])
    _plot_roc_pr_curves(result, paths["roc_pr_curves_figure"])
    _plot_score_distributions(result, paths["score_distributions_figure"])
    result.report["artifacts"] = {
        name: str(path.resolve()) for name, path in paths.items()
    }
    save_json(result.report, report_path)
    return paths


def run_isolation_forest_evaluation(
    prediction_paths: dict[str, Path],
    label_paths: dict[str, Path],
    training_report_path: Path,
    evaluation_data_dir: Path,
    report_path: Path,
    figures_dir: Path,
    overwrite: bool = False,
) -> EvaluationResult:
    """Executa o Marco 7 sem carregar ou modificar o modelo treinado."""
    paths = _artifact_paths(evaluation_data_dir, report_path, figures_dir)
    existing = [path for path in paths.values() if path.exists()]
    if existing and not overwrite:
        raise FileExistsError(
            "Artefato(s) ja existente(s); use --overwrite para substituir: "
            + ", ".join(str(path) for path in existing)
        )
    for name in ("validation", "test"):
        if name not in prediction_paths or name not in label_paths:
            raise ValueError(f"Caminhos de previsao/rotulo ausentes para {name}.")
        if not prediction_paths[name].is_file():
            raise FileNotFoundError(f"Previsao nao encontrada: {prediction_paths[name]}")
        if not label_paths[name].is_file():
            raise FileNotFoundError(f"Rotulo nao encontrado: {label_paths[name]}")

    training_report = _load_json(training_report_path)
    if training_report.get("stage") != "isolation_forest_training_marco_6":
        raise ValueError("O relatorio informado nao pertence ao Marco 6.")
    if not training_report.get("evaluation_deferred_to_marco_7"):
        raise ValueError("O relatorio de treino nao reservou a avaliacao para o Marco 7.")
    learned_offset = float(training_report["learned_offset"])

    model_path = Path(training_report["artifacts"]["model"])
    if not model_path.is_file():
        raise FileNotFoundError(f"Modelo referenciado nao encontrado: {model_path}")
    expected_model_sha256 = str(training_report["model_sha256"])
    actual_model_sha256 = _sha256_file(model_path)
    if actual_model_sha256 != expected_model_sha256:
        raise ValueError("SHA-256 do modelo diverge do relatorio do Marco 6.")

    joined_frames: dict[str, pd.DataFrame] = {}
    join_audits: dict[str, Any] = {}
    evaluation_started = time.perf_counter()

    # O limiar e decidido e congelado antes de o rotulo de teste ser aberto.
    validation_predictions = pd.read_parquet(prediction_paths["validation"])
    validation_labels = pd.read_parquet(label_paths["validation"])
    joined_frames["validation"], join_audits["validation"] = (
        join_predictions_and_labels(
            validation_predictions, validation_labels, "validation"
        )
    )
    LOGGER.info(
        "validation: %s previsoes associadas aos rotulos.",
        f"{len(validation_labels):,}",
    )
    threshold_selection = select_f1_threshold(
        joined_frames["validation"]["binary_label"].to_numpy(dtype=np.int8),
        joined_frames["validation"]["anomaly_score"].to_numpy(dtype=np.float64),
    )
    LOGGER.info(
        "Limiar de F1 congelado antes da abertura de y_test: %.6f.",
        threshold_selection["threshold"],
    )

    test_predictions = pd.read_parquet(prediction_paths["test"])
    test_labels = pd.read_parquet(label_paths["test"])
    joined_frames["test"], join_audits["test"] = join_predictions_and_labels(
        test_predictions, test_labels, "test"
    )
    LOGGER.info(
        "test: %s previsoes associadas aos rotulos apos congelar o limiar.",
        f"{len(test_labels):,}",
    )

    result = evaluate_joined_splits(
        validation=joined_frames["validation"],
        test=joined_frames["test"],
        learned_offset=learned_offset,
        threshold_selection=threshold_selection,
    )
    elapsed = time.perf_counter() - evaluation_started
    created_at = datetime.now(timezone.utc).isoformat()
    result.report.update(
        {
            "schema_version": 1,
            "stage": "isolation_forest_evaluation_marco_7",
            "created_at_utc": created_at,
            "status": "completed_with_labels_after_frozen_predictions",
            "methodology": {
                "predictions_generated_before_labels_loaded": True,
                "model_loaded": False,
                "model_refitted_or_modified": False,
                "labels_used_for_model_fit": False,
                "validation_labels_used_for_threshold_selection": True,
                "test_labels_used_for_threshold_selection": False,
                "test_labels_loaded_after_threshold_selection": True,
                "test_labels_used_for_final_evaluation_only": True,
                "primary_baseline": "frozen Isolation Forest default predictions",
                "secondary_operating_point": "validation F1-calibrated threshold",
                "positive_class": "attack=1",
                "score_direction": "higher anomaly_score means more anomalous",
                "balanced_split_warning": (
                    "validation and test are 50/50 controlled samples; precision and "
                    "accuracy do not estimate production prevalence"
                ),
            },
            "integrity": {
                "model_sha256_expected": expected_model_sha256,
                "model_sha256_observed": actual_model_sha256,
                "model_sha256_verified": True,
                "joins": join_audits,
                "status": "passed",
            },
            "inputs": {
                "training_report": {
                    "path": str(training_report_path.resolve()),
                    "sha256": _sha256_file(training_report_path),
                },
                "model": {
                    "path": str(model_path.resolve()),
                    "sha256": actual_model_sha256,
                },
                **{
                    f"{kind}_{split}": {
                        "path": str(paths_by_split[split].resolve()),
                        "sha256": _sha256_file(paths_by_split[split]),
                    }
                    for kind, paths_by_split in (
                        ("predictions", prediction_paths),
                        ("labels", label_paths),
                    )
                    for split in ("validation", "test")
                },
            },
            "evaluation_seconds_excluding_artifact_writes": float(elapsed),
            "model_timing_seconds_from_marco_6": {
                "training": float(training_report["timing_seconds"]["training"]),
                "inference_validation": float(
                    training_report["predictions_without_ground_truth"]["validation"][
                        "inference_seconds"
                    ]
                ),
                "inference_test": float(
                    training_report["predictions_without_ground_truth"]["test"][
                        "inference_seconds"
                    ]
                ),
                "inference_all_splits": float(
                    training_report["timing_seconds"]["inference_total"]
                ),
            },
            "libraries": {
                "python": platform.python_version(),
                "numpy": np.__version__,
                "pandas": pd.__version__,
                "scikit_learn": sklearn.__version__,
                "matplotlib": matplotlib.__version__,
            },
        }
    )
    # Reordena os campos de cabecalho antes dos resultados para leitura humana.
    header_order = (
        "schema_version",
        "stage",
        "created_at_utc",
        "status",
        "methodology",
        "integrity",
        "inputs",
        "thresholds",
        "splits",
        "model_timing_seconds_from_marco_6",
        "evaluation_seconds_excluding_artifact_writes",
        "libraries",
    )
    result.report = {key: result.report[key] for key in header_order}
    save_evaluation_artifacts(
        result,
        evaluation_data_dir=evaluation_data_dir,
        report_path=report_path,
        figures_dir=figures_dir,
        overwrite=overwrite,
    )
    return result


def format_evaluation_summary(report: dict[str, Any]) -> str:
    """Apresenta as metricas centrais sem esconder os dois limiares."""
    threshold = report["thresholds"]["validation_f1_calibrated"]["threshold"]
    lines = [
        "\n=== AVALIACAO DO ISOLATION FOREST — MARCO 7 ===",
        f"Limiar calibrado na validacao (anomaly_score >=): {threshold:.6f}",
    ]
    for split, split_label in (("validation", "Validacao"), ("test", "Teste")):
        ranking = report["splits"][split]["ranking_metrics"]
        lines.append(f"\n{split_label} — ROC-AUC={ranking['roc_auc']:.4f}, AP={ranking['average_precision']:.4f}")
        for point, point_label in (
            ("isolation_forest_default", "original"),
            ("validation_f1_calibrated", "calibrado"),
        ):
            metrics = report["splits"][split]["operating_points"][point]
            lines.append(
                f"  {point_label}: precision={metrics['precision']:.4f}, "
                f"recall={metrics['recall_tpr']:.4f}, F1={metrics['f1_score']:.4f}, "
                f"FPR={metrics['false_positive_rate']:.4f}, "
                f"FP={metrics['false_positive']:,}, FN={metrics['false_negative']:,}"
            )
    lines.extend(
        [
            "\nModelo retreinado: nao",
            "Teste usado para escolher o limiar: nao",
        ]
    )
    return "\n".join(lines)
