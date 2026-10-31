"""Avaliacao do LOF e comparacao justa com Isolation Forest (Marco 9)."""

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
    average_precision_score,
    precision_recall_curve,
    roc_auc_score,
    roc_curve,
)

from src.evaluation import (
    calculate_classification_metrics,
    join_predictions_and_labels,
    select_f1_threshold,
)
from src.utils import save_json


LOGGER = logging.getLogger(__name__)
logging.getLogger("matplotlib").setLevel(logging.WARNING)

MODEL_KEYS = ("isolation_forest", "lof")
MODEL_LABELS = {
    "isolation_forest": "Isolation Forest",
    "lof": "Local Outlier Factor",
}
MODEL_COLORS = {
    "isolation_forest": "#1f77b4",
    "lof": "#d62728",
}
OPERATING_POINTS = ("native", "validation_f1_calibrated")
OPERATING_POINT_LABELS = {
    "native": "Limiar nativo",
    "validation_f1_calibrated": "Calibrado por F1",
}


@dataclass
class ModelEvaluation:
    """Frames avaliados e metricas de um modelo."""

    evaluated_frames: dict[str, pd.DataFrame]
    thresholds: dict[str, Any]
    splits: dict[str, Any]


@dataclass
class Marco9Result:
    """Resultado completo da avaliacao e comparacao do Marco 9."""

    model_evaluations: dict[str, ModelEvaluation]
    paired_frames: dict[str, pd.DataFrame]
    comparison_report: dict[str, Any]
    lof_report: dict[str, Any]
    summary_table: pd.DataFrame
    attack_table: pd.DataFrame


def _load_json(path: Path) -> dict[str, Any]:
    """Carrega um JSON obrigatorio com erro contextual."""
    if not path.is_file():
        raise FileNotFoundError(f"Arquivo JSON nao encontrado: {path}")
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def _sha256_file(path: Path) -> str:
    """Calcula SHA-256 sem interpretar o artefato."""
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for block in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _safe_ratio(numerator: float, denominator: float) -> float | None:
    """Calcula razao ou retorna None quando o denominador e zero."""
    if denominator == 0:
        return None
    return float(numerator / denominator)


def _score_statistics(series: pd.Series) -> dict[str, float]:
    """Resume um escore continuo sem alterar sua orientacao."""
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
    """Mede a deteccao por familia de ataque nos dois pontos operacionais."""
    attacks = frame.loc[frame["binary_label"].eq(1)]
    result: dict[str, dict[str, Any]] = {}
    for label, group in attacks.groupby("label", sort=True):
        support = int(len(group))
        native_detected = int(group["predicted_anomaly"].sum())
        calibrated_detected = int(group["predicted_anomaly_calibrated_f1"].sum())
        result[str(label)] = {
            "support": support,
            "native_detected": native_detected,
            "native_detection_rate": float(native_detected / support),
            "calibrated_f1_detected": calibrated_detected,
            "calibrated_f1_detection_rate": float(calibrated_detected / support),
            "anomaly_score_mean": float(group["anomaly_score"].mean()),
            "anomaly_score_median": float(group["anomaly_score"].median()),
        }
    return result


def _evaluate_split(frame: pd.DataFrame) -> dict[str, Any]:
    """Calcula ranking, classificacao, distribuicoes e categorias."""
    y_true = frame["binary_label"].to_numpy(dtype=np.int8)
    scores = frame["anomaly_score"].to_numpy(dtype=np.float64)
    native = frame["predicted_anomaly"].to_numpy(dtype=np.int8)
    calibrated = frame["predicted_anomaly_calibrated_f1"].to_numpy(dtype=np.int8)
    return {
        "records": int(len(frame)),
        "true_distribution": {
            "normal": int((y_true == 0).sum()),
            "attack": int((y_true == 1).sum()),
        },
        "ranking_metrics": {
            "roc_auc": float(roc_auc_score(y_true, scores)),
            "average_precision": float(average_precision_score(y_true, scores)),
            "average_precision_note": (
                "weighted precision gain across recall; not trapezoidal PR interpolation"
            ),
        },
        "operating_points": {
            "native": calculate_classification_metrics(y_true, native),
            "validation_f1_calibrated": calculate_classification_metrics(
                y_true, calibrated
            ),
        },
        "anomaly_score_by_true_class": {
            "normal": _score_statistics(
                frame.loc[frame["binary_label"].eq(0), "anomaly_score"]
            ),
            "attack": _score_statistics(
                frame.loc[frame["binary_label"].eq(1), "anomaly_score"]
            ),
        },
        "attack_categories": _attack_category_metrics(frame),
    }


def evaluate_model_splits(
    validation: pd.DataFrame,
    test: pd.DataFrame,
    learned_offset: float,
    threshold_selection: dict[str, Any] | None = None,
) -> ModelEvaluation:
    """Aplica um limiar escolhido na validacao aos dois splits."""
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
    thresholds = {
        "native": {
            "decision_rule": "decision_function < 0",
            "equivalent_anomaly_score_rule": "anomaly_score > -learned_offset",
            "learned_offset": float(learned_offset),
            "equivalent_anomaly_score_threshold": float(-learned_offset),
            "source": "frozen predictions generated before labels were loaded",
        },
        "validation_f1_calibrated": selection,
    }
    return ModelEvaluation(
        evaluated_frames={"validation": validation, "test": test},
        thresholds=thresholds,
        splits={
            "validation": _evaluate_split(validation),
            "test": _evaluate_split(test),
        },
    )


def _assert_model_frames_aligned(
    isolation_forest: pd.DataFrame,
    lof: pd.DataFrame,
    split: str,
) -> None:
    """Garante comparacao pareada dos mesmos registros e rotulos."""
    if len(isolation_forest) != len(lof):
        raise ValueError(f"Modelos possuem quantidades diferentes em {split}.")
    for column in ("row_position", "record_hash", "label", "binary_label"):
        left = isolation_forest[column].reset_index(drop=True)
        right = lof[column].reset_index(drop=True)
        if not left.equals(right):
            raise ValueError(
                f"Modelos nao estao alinhados pela coluna {column} em {split}."
            )


def build_paired_frame(
    isolation_forest: pd.DataFrame,
    lof: pd.DataFrame,
    split: str,
) -> pd.DataFrame:
    """Cria tabela por registro com resultados lado a lado."""
    _assert_model_frames_aligned(isolation_forest, lof, split)
    paired = isolation_forest.loc[
        :, [
            "row_position",
            "record_hash",
            "label",
            "binary_label",
            "source_file",
            "source_row",
        ]
    ].copy()
    model_columns = (
        "predicted_anomaly",
        "predicted_anomaly_calibrated_f1",
        "score_samples",
        "decision_function",
        "anomaly_score",
    )
    for model_key, frame in (
        ("isolation_forest", isolation_forest),
        ("lof", lof),
    ):
        for column in model_columns:
            paired[f"{model_key}_{column}"] = frame[column].to_numpy()
        for point, column in (
            ("native", "predicted_anomaly"),
            ("validation_f1_calibrated", "predicted_anomaly_calibrated_f1"),
        ):
            paired[f"{model_key}_{point}_correct"] = (
                frame[column].to_numpy(dtype=np.int8)
                == frame["binary_label"].to_numpy(dtype=np.int8)
            )
    return paired


def _paired_outcomes(paired: pd.DataFrame, point: str) -> dict[str, Any]:
    """Conta concordancias e acertos exclusivos dos modelos."""
    if_correct = paired[f"isolation_forest_{point}_correct"].to_numpy(dtype=bool)
    lof_correct = paired[f"lof_{point}_correct"].to_numpy(dtype=bool)
    if_pred = paired[
        "isolation_forest_predicted_anomaly"
        if point == "native"
        else "isolation_forest_predicted_anomaly_calibrated_f1"
    ].to_numpy(dtype=np.int8)
    lof_pred = paired[
        "lof_predicted_anomaly"
        if point == "native"
        else "lof_predicted_anomaly_calibrated_f1"
    ].to_numpy(dtype=np.int8)
    return {
        "records": int(len(paired)),
        "same_prediction": int((if_pred == lof_pred).sum()),
        "different_prediction": int((if_pred != lof_pred).sum()),
        "both_correct": int((if_correct & lof_correct).sum()),
        "both_wrong": int((~if_correct & ~lof_correct).sum()),
        "isolation_forest_only_correct": int((if_correct & ~lof_correct).sum()),
        "lof_only_correct": int((~if_correct & lof_correct).sum()),
    }


def _winner(
    if_value: float,
    lof_value: float,
    higher_is_better: bool = True,
) -> str:
    """Escolhe vencedor com tolerancia numerica e regra de direcao explicita."""
    if np.isclose(if_value, lof_value, rtol=0.0, atol=1e-12):
        return "tie"
    if higher_is_better:
        return "isolation_forest" if if_value > lof_value else "lof"
    return "isolation_forest" if if_value < lof_value else "lof"


def compare_model_evaluations(
    evaluations: dict[str, ModelEvaluation],
    paired_frames: dict[str, pd.DataFrame],
) -> dict[str, Any]:
    """Compara ranking e pontos operacionais sem misturar escalas de score."""
    result: dict[str, Any] = {}
    metric_directions = {
        "accuracy": True,
        "balanced_accuracy": True,
        "precision": True,
        "recall_tpr": True,
        "f1_score": True,
        "specificity_tnr": True,
        "false_positive_rate": False,
        "false_negative_rate": False,
    }
    for split in ("validation", "test"):
        if_split = evaluations["isolation_forest"].splits[split]
        lof_split = evaluations["lof"].splits[split]
        ranking = {}
        for metric in ("roc_auc", "average_precision"):
            if_value = float(if_split["ranking_metrics"][metric])
            lof_value = float(lof_split["ranking_metrics"][metric])
            ranking[metric] = {
                "isolation_forest": if_value,
                "lof": lof_value,
                "delta_lof_minus_isolation_forest": float(lof_value - if_value),
                "winner": _winner(if_value, lof_value),
            }
        operating_points = {}
        for point in OPERATING_POINTS:
            if_metrics = if_split["operating_points"][point]
            lof_metrics = lof_split["operating_points"][point]
            deltas = {}
            winners = {}
            for metric, higher_is_better in metric_directions.items():
                if_value = float(if_metrics[metric])
                lof_value = float(lof_metrics[metric])
                deltas[metric] = float(lof_value - if_value)
                winners[metric] = _winner(if_value, lof_value, higher_is_better)
            operating_points[point] = {
                "by_model": {
                    "isolation_forest": if_metrics,
                    "lof": lof_metrics,
                },
                "deltas_lof_minus_isolation_forest": deltas,
                "winner_by_metric": winners,
                "paired_outcomes": _paired_outcomes(paired_frames[split], point),
            }
        result[split] = {
            "records": int(len(paired_frames[split])),
            "ranking": ranking,
            "operating_points": operating_points,
        }
    return result


def _validate_training_report(
    path: Path,
    model_key: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Valida a procedencia do modelo sem carregar o joblib."""
    report = _load_json(path)
    if model_key == "isolation_forest":
        expected_stage = "isolation_forest_training_marco_6"
        sha_key = "model_sha256"
        deferred_key = "evaluation_deferred_to_marco_7"
    elif model_key == "lof":
        expected_stage = "lof_training_marco_8"
        sha_key = "pipeline_sha256"
        deferred_key = "evaluation_deferred_to_marco_9"
    else:
        raise ValueError(f"Modelo desconhecido: {model_key}")
    if report.get("stage") != expected_stage:
        raise ValueError(f"Relatorio de treino invalido para {model_key}.")
    if report.get(deferred_key) is not True:
        raise ValueError(f"Treino de {model_key} nao reservou avaliacao posterior.")
    model_path = Path(report["artifacts"]["model"])
    if not model_path.is_file():
        raise FileNotFoundError(f"Modelo referenciado nao encontrado: {model_path}")
    expected_sha = str(report[sha_key])
    observed_sha = _sha256_file(model_path)
    if expected_sha != observed_sha:
        raise ValueError(f"SHA-256 do modelo {model_key} diverge do treino.")
    return report, {
        "training_report_stage": expected_stage,
        "training_report_path": str(path.resolve()),
        "training_report_sha256": _sha256_file(path),
        "model_path": str(model_path.resolve()),
        "model_sha256_expected": expected_sha,
        "model_sha256_observed": observed_sha,
        "model_sha256_verified": True,
        "model_loaded": False,
    }


def _validate_prior_iforest_evaluation(
    path: Path,
    selected_threshold: float,
    expected_model_sha: str,
) -> dict[str, Any]:
    """Confirma que o resultado do Marco 7 foi reproduzido no Marco 9."""
    report = _load_json(path)
    if report.get("stage") != "isolation_forest_evaluation_marco_7":
        raise ValueError("O relatorio anterior nao pertence ao Marco 7.")
    previous_threshold = float(
        report["thresholds"]["validation_f1_calibrated"]["threshold"]
    )
    if not np.isclose(previous_threshold, selected_threshold, rtol=0.0, atol=1e-12):
        raise ValueError("Limiar do Isolation Forest nao reproduz o Marco 7.")
    previous_sha = str(report["integrity"]["model_sha256_observed"])
    if previous_sha != expected_model_sha:
        raise ValueError("Modelo do Isolation Forest diverge do avaliado no Marco 7.")
    return {
        "path": str(path.resolve()),
        "sha256": _sha256_file(path),
        "stage": report["stage"],
        "validation_f1_threshold_previous": previous_threshold,
        "validation_f1_threshold_recomputed": float(selected_threshold),
        "threshold_reproduced": True,
        "model_sha256_reproduced": True,
    }


def _timing_summary(
    iforest_training: dict[str, Any],
    lof_training: dict[str, Any],
) -> dict[str, Any]:
    """Normaliza tempos historicos e calcula razoes LOF/IF."""
    if_times = {
        "fit": float(iforest_training["timing_seconds"]["training"]),
        "inference_validation": float(
            iforest_training["predictions_without_ground_truth"]["validation"][
                "inference_seconds"
            ]
        ),
        "inference_test": float(
            iforest_training["predictions_without_ground_truth"]["test"][
                "inference_seconds"
            ]
        ),
    }
    lof_times = {
        "fit": float(lof_training["timing_seconds"]["pipeline_fit"]),
        "inference_validation": float(
            lof_training["predictions_without_ground_truth"]["validation"][
                "inference_seconds"
            ]
        ),
        "inference_test": float(
            lof_training["predictions_without_ground_truth"]["test"][
                "inference_seconds"
            ]
        ),
    }
    return {
        "source": "frozen training reports from Marcos 6 and 8",
        "hardware_and_library_version_dependent": True,
        "by_model_seconds": {
            "isolation_forest": if_times,
            "lof": lof_times,
        },
        "ratio_lof_over_isolation_forest": {
            key: _safe_ratio(lof_times[key], if_times[key]) for key in if_times
        },
    }


def _build_summary_table(
    evaluations: dict[str, ModelEvaluation],
) -> pd.DataFrame:
    """Cria tabela longa pronta para analise e inclusao no TCC."""
    rows: list[dict[str, Any]] = []
    for model_key in MODEL_KEYS:
        evaluation = evaluations[model_key]
        for split in ("validation", "test"):
            ranking = evaluation.splits[split]["ranking_metrics"]
            for point in OPERATING_POINTS:
                metrics = evaluation.splits[split]["operating_points"][point]
                rows.append(
                    {
                        "model": model_key,
                        "model_label": MODEL_LABELS[model_key],
                        "split": split,
                        "operating_point": point,
                        "threshold": (
                            evaluation.thresholds["native"][
                                "equivalent_anomaly_score_threshold"
                            ]
                            if point == "native"
                            else evaluation.thresholds[
                                "validation_f1_calibrated"
                            ]["threshold"]
                        ),
                        "roc_auc": ranking["roc_auc"],
                        "average_precision": ranking["average_precision"],
                        **{
                            key: metrics[key]
                            for key in (
                                "true_negative",
                                "false_positive",
                                "false_negative",
                                "true_positive",
                                "accuracy",
                                "balanced_accuracy",
                                "precision",
                                "recall_tpr",
                                "f1_score",
                                "specificity_tnr",
                                "false_positive_rate",
                                "false_negative_rate",
                            )
                        },
                    }
                )
    return pd.DataFrame(rows)


def _build_attack_table(
    evaluations: dict[str, ModelEvaluation],
) -> pd.DataFrame:
    """Cria comparacao por categoria para validacao e teste."""
    rows: list[dict[str, Any]] = []
    for split in ("validation", "test"):
        all_labels = sorted(
            set(
                evaluations["isolation_forest"].splits[split][
                    "attack_categories"
                ]
            )
            | set(evaluations["lof"].splits[split]["attack_categories"])
        )
        for label in all_labels:
            for model_key in MODEL_KEYS:
                metrics = evaluations[model_key].splits[split]["attack_categories"][
                    label
                ]
                rows.append(
                    {
                        "split": split,
                        "attack_category": label,
                        "model": model_key,
                        "model_label": MODEL_LABELS[model_key],
                        **metrics,
                    }
                )
    return pd.DataFrame(rows)


def _artifact_paths(
    evaluation_data_dir: Path,
    metrics_dir: Path,
    figures_dir: Path,
) -> dict[str, Path]:
    """Centraliza os doze artefatos produzidos pelo Marco 9."""
    return {
        "lof_validation_evaluated": evaluation_data_dir
        / "lof_validation_evaluated.parquet",
        "lof_test_evaluated": evaluation_data_dir / "lof_test_evaluated.parquet",
        "comparison_validation": evaluation_data_dir
        / "model_comparison_validation.parquet",
        "comparison_test": evaluation_data_dir / "model_comparison_test.parquet",
        "lof_report": metrics_dir / "lof_evaluation.json",
        "comparison_report": metrics_dir / "model_comparison.json",
        "summary_table": metrics_dir / "model_comparison_summary.csv",
        "attack_table": metrics_dir / "attack_category_comparison.csv",
        "roc_pr_figure": figures_dir / "model_comparison_roc_pr_curves.png",
        "confusion_figure": figures_dir / "model_comparison_confusion_matrices.png",
        "metrics_figure": figures_dir / "model_comparison_test_metrics.png",
        "attack_figure": figures_dir / "model_comparison_attack_detection.png",
    }


def _plot_roc_pr_curves(result: Marco9Result, output_path: Path) -> None:
    """Compara curvas de ranking nos mesmos registros."""
    figure, axes = plt.subplots(2, 2, figsize=(13, 10))
    split_labels = {"validation": "Validação", "test": "Teste"}
    for row, split in enumerate(("validation", "test")):
        roc_axis, pr_axis = axes[row]
        for model_key in MODEL_KEYS:
            frame = result.model_evaluations[model_key].evaluated_frames[split]
            y_true = frame["binary_label"].to_numpy(dtype=np.int8)
            scores = frame["anomaly_score"].to_numpy(dtype=np.float64)
            ranking = result.model_evaluations[model_key].splits[split][
                "ranking_metrics"
            ]
            fpr, tpr, _ = roc_curve(y_true, scores, pos_label=1)
            precision, recall, _ = precision_recall_curve(
                y_true, scores, pos_label=1
            )
            roc_axis.plot(
                fpr,
                tpr,
                color=MODEL_COLORS[model_key],
                label=f"{MODEL_LABELS[model_key]} (AUC={ranking['roc_auc']:.3f})",
            )
            pr_axis.plot(
                recall,
                precision,
                color=MODEL_COLORS[model_key],
                label=(
                    f"{MODEL_LABELS[model_key]} "
                    f"(AP={ranking['average_precision']:.3f})"
                ),
            )
        roc_axis.plot([0, 1], [0, 1], "--", color="gray", label="Aleatório")
        roc_axis.set(
            xlabel="False Positive Rate",
            ylabel="True Positive Rate",
            xlim=(0, 1),
            ylim=(0, 1.02),
            title=f"ROC — {split_labels[split]}",
        )
        prevalence = float(
            result.paired_frames[split]["binary_label"].mean()
        )
        pr_axis.axhline(
            prevalence,
            linestyle="--",
            color="gray",
            label=f"Prevalência={prevalence:.2f}",
        )
        pr_axis.set(
            xlabel="Recall",
            ylabel="Precision",
            xlim=(0, 1),
            ylim=(0, 1.02),
            title=f"Precision–Recall — {split_labels[split]}",
        )
        for axis in (roc_axis, pr_axis):
            axis.grid(alpha=0.25)
            axis.legend(loc="best")
    figure.suptitle("Isolation Forest versus LOF — desempenho de ranking", fontsize=15)
    figure.tight_layout()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(output_path, dpi=160, bbox_inches="tight")
    plt.close(figure)


def _plot_confusion_matrices(result: Marco9Result, output_path: Path) -> None:
    """Exibe os quatro cenarios finais no conjunto de teste."""
    figure, axes = plt.subplots(2, 2, figsize=(10, 9))
    for row, model_key in enumerate(MODEL_KEYS):
        for column, point in enumerate(OPERATING_POINTS):
            metrics = result.model_evaluations[model_key].splits["test"][
                "operating_points"
            ][point]
            matrix = np.asarray(metrics["confusion_matrix"])
            axis = axes[row, column]
            # Todos os painéis usam a mesma escala para permitir comparação visual.
            image = axis.imshow(matrix, cmap="Blues", vmin=0, vmax=10_000)
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
            axis.set_title(
                f"{MODEL_LABELS[model_key]} — {OPERATING_POINT_LABELS[point]}"
            )
            figure.colorbar(image, ax=axis, fraction=0.046, pad=0.04)
    figure.suptitle("Teste — matrizes de confusão", fontsize=15)
    figure.tight_layout()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(output_path, dpi=160, bbox_inches="tight")
    plt.close(figure)


def _plot_test_metrics(result: Marco9Result, output_path: Path) -> None:
    """Compara metricas operacionais finais sem ocultar o FPR."""
    figure, axes = plt.subplots(1, 2, figsize=(13, 5.5), sharey=True)
    metric_keys = ("precision", "recall_tpr", "f1_score", "false_positive_rate")
    metric_labels = ("Precision", "Recall", "F1", "FPR")
    x = np.arange(len(metric_keys))
    width = 0.36
    for axis, point in zip(axes, OPERATING_POINTS):
        for index, model_key in enumerate(MODEL_KEYS):
            metrics = result.model_evaluations[model_key].splits["test"][
                "operating_points"
            ][point]
            values = [metrics[key] for key in metric_keys]
            offset = (-width / 2) if index == 0 else (width / 2)
            bars = axis.bar(
                x + offset,
                values,
                width,
                color=MODEL_COLORS[model_key],
                label=MODEL_LABELS[model_key],
            )
            axis.bar_label(bars, fmt="%.3f", fontsize=8, padding=2)
        axis.set_xticks(x, labels=metric_labels)
        axis.set_ylim(0, 1.08)
        axis.set_title(OPERATING_POINT_LABELS[point])
        axis.grid(axis="y", alpha=0.25)
        axis.legend(loc="upper right")
    axes[0].set_ylabel("Valor da métrica")
    figure.suptitle("Teste — comparação por ponto operacional", fontsize=15)
    figure.tight_layout()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(output_path, dpi=160, bbox_inches="tight")
    plt.close(figure)


def _plot_attack_detection(result: Marco9Result, output_path: Path) -> None:
    """Compara taxa de deteccao por familia no conjunto de teste."""
    test_table = result.attack_table.loc[result.attack_table["split"].eq("test")]
    labels = sorted(test_table["attack_category"].unique())
    y = np.arange(len(labels))
    height = 0.36
    figure, axes = plt.subplots(1, 2, figsize=(15, 9), sharey=True)
    for axis, (point, rate_column) in zip(
        axes,
        (
            ("native", "native_detection_rate"),
            ("validation_f1_calibrated", "calibrated_f1_detection_rate"),
        ),
    ):
        for index, model_key in enumerate(MODEL_KEYS):
            model_table = (
                test_table.loc[test_table["model"].eq(model_key)]
                .set_index("attack_category")
                .reindex(labels)
            )
            offset = (-height / 2) if index == 0 else (height / 2)
            axis.barh(
                y + offset,
                model_table[rate_column].to_numpy(dtype=np.float64),
                height,
                color=MODEL_COLORS[model_key],
                label=MODEL_LABELS[model_key],
            )
        axis.set_xlim(0, 1.02)
        axis.set_xlabel("Taxa de detecção")
        axis.set_title(OPERATING_POINT_LABELS[point])
        axis.grid(axis="x", alpha=0.25)
        axis.legend(loc="lower right")
    axes[0].set_yticks(y, labels=labels)
    figure.suptitle("Teste — detecção por categoria de ataque", fontsize=15)
    figure.tight_layout()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(output_path, dpi=160, bbox_inches="tight")
    plt.close(figure)


def save_marco9_artifacts(
    result: Marco9Result,
    evaluation_data_dir: Path,
    metrics_dir: Path,
    figures_dir: Path,
    overwrite: bool = False,
) -> dict[str, Path]:
    """Persiste dados avaliados, tabelas, relatorios e figuras."""
    paths = _artifact_paths(evaluation_data_dir, metrics_dir, figures_dir)
    existing = [path for path in paths.values() if path.exists()]
    if existing and not overwrite:
        raise FileExistsError(
            "Artefato(s) ja existente(s); use --overwrite para substituir: "
            + ", ".join(str(path) for path in existing)
        )
    for path in paths.values():
        path.parent.mkdir(parents=True, exist_ok=True)

    result.model_evaluations["lof"].evaluated_frames["validation"].to_parquet(
        paths["lof_validation_evaluated"], index=False, compression="snappy"
    )
    result.model_evaluations["lof"].evaluated_frames["test"].to_parquet(
        paths["lof_test_evaluated"], index=False, compression="snappy"
    )
    result.paired_frames["validation"].to_parquet(
        paths["comparison_validation"], index=False, compression="snappy"
    )
    result.paired_frames["test"].to_parquet(
        paths["comparison_test"], index=False, compression="snappy"
    )
    result.summary_table.to_csv(paths["summary_table"], index=False)
    result.attack_table.to_csv(paths["attack_table"], index=False)
    _plot_roc_pr_curves(result, paths["roc_pr_figure"])
    _plot_confusion_matrices(result, paths["confusion_figure"])
    _plot_test_metrics(result, paths["metrics_figure"])
    _plot_attack_detection(result, paths["attack_figure"])

    artifacts = {name: str(path.resolve()) for name, path in paths.items()}
    result.lof_report["artifacts"] = artifacts
    result.comparison_report["artifacts"] = artifacts
    save_json(result.lof_report, paths["lof_report"])
    save_json(result.comparison_report, paths["comparison_report"])
    return paths


def run_marco9_comparison(
    prediction_paths: dict[str, dict[str, Path]],
    label_paths: dict[str, Path],
    training_report_paths: dict[str, Path],
    prior_iforest_evaluation_path: Path,
    evaluation_data_dir: Path,
    metrics_dir: Path,
    figures_dir: Path,
    overwrite: bool = False,
) -> Marco9Result:
    """Avalia o LOF e compara os modelos sem retreino nem ajuste pelo teste."""
    paths = _artifact_paths(evaluation_data_dir, metrics_dir, figures_dir)
    existing = [path for path in paths.values() if path.exists()]
    if existing and not overwrite:
        raise FileExistsError(
            "Artefato(s) ja existente(s); use --overwrite para substituir: "
            + ", ".join(str(path) for path in existing)
        )
    for model_key in MODEL_KEYS:
        if model_key not in prediction_paths or model_key not in training_report_paths:
            raise ValueError(f"Entradas ausentes para {model_key}.")
        for split in ("validation", "test"):
            path = prediction_paths[model_key].get(split)
            if path is None or not path.is_file():
                raise FileNotFoundError(
                    f"Previsao de {model_key}/{split} nao encontrada: {path}"
                )
    for split in ("validation", "test"):
        path = label_paths.get(split)
        if path is None or not path.is_file():
            raise FileNotFoundError(f"Rotulo de {split} nao encontrado: {path}")

    training_reports: dict[str, dict[str, Any]] = {}
    model_integrity: dict[str, Any] = {}
    for model_key in MODEL_KEYS:
        training_reports[model_key], model_integrity[model_key] = (
            _validate_training_report(training_report_paths[model_key], model_key)
        )

    evaluation_started = time.perf_counter()
    join_audits: dict[str, dict[str, Any]] = {
        "isolation_forest": {},
        "lof": {},
    }
    joined: dict[str, dict[str, pd.DataFrame]] = {
        "isolation_forest": {},
        "lof": {},
    }

    # Primeiro abre apenas a validacao e congela ambos os limiares.
    validation_labels = pd.read_parquet(label_paths["validation"])
    threshold_selections: dict[str, dict[str, Any]] = {}
    for model_key in MODEL_KEYS:
        validation_predictions = pd.read_parquet(
            prediction_paths[model_key]["validation"]
        )
        joined[model_key]["validation"], join_audits[model_key]["validation"] = (
            join_predictions_and_labels(
                validation_predictions,
                validation_labels,
                f"{model_key}/validation",
            )
        )
        threshold_selections[model_key] = select_f1_threshold(
            joined[model_key]["validation"]["binary_label"].to_numpy(
                dtype=np.int8
            ),
            joined[model_key]["validation"]["anomaly_score"].to_numpy(
                dtype=np.float64
            ),
        )
        LOGGER.info(
            "%s: limiar F1 congelado na validacao = %.12f.",
            MODEL_LABELS[model_key],
            threshold_selections[model_key]["threshold"],
        )
    _assert_model_frames_aligned(
        joined["isolation_forest"]["validation"],
        joined["lof"]["validation"],
        "validation",
    )
    thresholds_frozen_at_utc = datetime.now(timezone.utc).isoformat()

    # y_test so e aberto depois de os dois limiares estarem congelados.
    test_labels = pd.read_parquet(label_paths["test"])
    for model_key in MODEL_KEYS:
        test_predictions = pd.read_parquet(prediction_paths[model_key]["test"])
        joined[model_key]["test"], join_audits[model_key]["test"] = (
            join_predictions_and_labels(
                test_predictions,
                test_labels,
                f"{model_key}/test",
            )
        )
    _assert_model_frames_aligned(
        joined["isolation_forest"]["test"],
        joined["lof"]["test"],
        "test",
    )
    test_labels_loaded_at_utc = datetime.now(timezone.utc).isoformat()

    evaluations: dict[str, ModelEvaluation] = {}
    for model_key in MODEL_KEYS:
        evaluations[model_key] = evaluate_model_splits(
            validation=joined[model_key]["validation"],
            test=joined[model_key]["test"],
            learned_offset=float(training_reports[model_key]["learned_offset"]),
            threshold_selection=threshold_selections[model_key],
        )
    paired_frames = {
        split: build_paired_frame(
            evaluations["isolation_forest"].evaluated_frames[split],
            evaluations["lof"].evaluated_frames[split],
            split,
        )
        for split in ("validation", "test")
    }
    comparisons = compare_model_evaluations(evaluations, paired_frames)

    # O relatorio anterior so e consultado depois da avaliacao atual do teste.
    prior_evaluation_audit = _validate_prior_iforest_evaluation(
        prior_iforest_evaluation_path,
        threshold_selections["isolation_forest"]["threshold"],
        model_integrity["isolation_forest"]["model_sha256_observed"],
    )

    input_hashes = {
        "training_reports": {
            model_key: {
                "path": str(training_report_paths[model_key].resolve()),
                "sha256": _sha256_file(training_report_paths[model_key]),
            }
            for model_key in MODEL_KEYS
        },
        "predictions": {
            model_key: {
                split: {
                    "path": str(prediction_paths[model_key][split].resolve()),
                    "sha256": _sha256_file(prediction_paths[model_key][split]),
                }
                for split in ("validation", "test")
            }
            for model_key in MODEL_KEYS
        },
        "labels": {
            split: {
                "path": str(label_paths[split].resolve()),
                "sha256": _sha256_file(label_paths[split]),
            }
            for split in ("validation", "test")
        },
        "prior_iforest_evaluation": prior_evaluation_audit,
    }
    timing = _timing_summary(
        training_reports["isolation_forest"], training_reports["lof"]
    )
    evaluation_seconds = float(time.perf_counter() - evaluation_started)
    created_at = datetime.now(timezone.utc).isoformat()
    methodology = {
        "predictions_frozen_before_labels_loaded": True,
        "models_loaded": False,
        "models_refitted_or_modified": False,
        "same_records_compared_by_record_hash": True,
        "positive_class": "attack=1",
        "score_direction": "higher anomaly_score means more anomalous",
        "native_predictions_are_primary_baselines": True,
        "secondary_operating_point": "per-model threshold maximizing F1 on validation",
        "validation_labels_used_for_threshold_selection": True,
        "test_labels_used_for_threshold_selection": False,
        "both_thresholds_frozen_before_test_labels_loaded": True,
        "thresholds_frozen_at_utc": thresholds_frozen_at_utc,
        "test_labels_loaded_at_utc": test_labels_loaded_at_utc,
        "raw_score_values_compared_directly": False,
        "raw_score_note": (
            "score scales differ by algorithm; comparison uses ranking metrics and "
            "explicit operating points"
        ),
        "balanced_split_warning": (
            "validation and test are controlled 50/50 samples; precision and "
            "accuracy do not estimate production prevalence"
        ),
    }
    integrity = {
        "models": model_integrity,
        "joins": join_audits,
        "model_prediction_hash_order_identical": {
            "validation": True,
            "test": True,
        },
        "prior_isolation_forest_evaluation": prior_evaluation_audit,
        "status": "passed",
    }

    lof_report = {
        "schema_version": 1,
        "stage": "lof_evaluation_marco_9",
        "created_at_utc": created_at,
        "status": "completed_with_labels_after_frozen_predictions",
        "methodology": methodology,
        "integrity": {
            "model": model_integrity["lof"],
            "joins": join_audits["lof"],
            "status": "passed",
        },
        "inputs": {
            "training_report": input_hashes["training_reports"]["lof"],
            "predictions": input_hashes["predictions"]["lof"],
            "labels": input_hashes["labels"],
        },
        "thresholds": evaluations["lof"].thresholds,
        "splits": evaluations["lof"].splits,
        "model_timing_seconds_from_marco_8": timing["by_model_seconds"]["lof"],
        "evaluation_seconds_in_shared_marco_9_run": evaluation_seconds,
        "libraries": {
            "python": platform.python_version(),
            "numpy": np.__version__,
            "pandas": pd.__version__,
            "scikit_learn": sklearn.__version__,
            "matplotlib": matplotlib.__version__,
        },
    }
    comparison_report = {
        "schema_version": 1,
        "stage": "isolation_forest_lof_comparison_marco_9",
        "created_at_utc": created_at,
        "status": "completed",
        "methodology": methodology,
        "integrity": integrity,
        "inputs": input_hashes,
        "models": {
            model_key: {
                "display_name": MODEL_LABELS[model_key],
                "thresholds": evaluations[model_key].thresholds,
                "splits": evaluations[model_key].splits,
            }
            for model_key in MODEL_KEYS
        },
        "comparisons": comparisons,
        "timing": timing,
        "evaluation_seconds_excluding_artifact_writes": evaluation_seconds,
        "libraries": lof_report["libraries"],
    }
    result = Marco9Result(
        model_evaluations=evaluations,
        paired_frames=paired_frames,
        comparison_report=comparison_report,
        lof_report=lof_report,
        summary_table=_build_summary_table(evaluations),
        attack_table=_build_attack_table(evaluations),
    )
    save_marco9_artifacts(
        result,
        evaluation_data_dir=evaluation_data_dir,
        metrics_dir=metrics_dir,
        figures_dir=figures_dir,
        overwrite=overwrite,
    )
    return result


def format_marco9_summary(report: dict[str, Any]) -> str:
    """Apresenta os principais resultados dos dois modelos no teste."""
    lines = ["\n=== COMPARACAO ISOLATION FOREST x LOF — MARCO 9 ==="]
    for model_key in MODEL_KEYS:
        model = report["models"][model_key]
        ranking = model["splits"]["test"]["ranking_metrics"]
        lines.append(
            f"\n{MODEL_LABELS[model_key]} — "
            f"ROC-AUC={ranking['roc_auc']:.4f}, "
            f"AP={ranking['average_precision']:.4f}"
        )
        for point in OPERATING_POINTS:
            metrics = model["splits"]["test"]["operating_points"][point]
            lines.append(
                f"  {OPERATING_POINT_LABELS[point]}: "
                f"precision={metrics['precision']:.4f}, "
                f"recall={metrics['recall_tpr']:.4f}, "
                f"F1={metrics['f1_score']:.4f}, "
                f"FPR={metrics['false_positive_rate']:.4f}, "
                f"FP={metrics['false_positive']:,}, "
                f"FN={metrics['false_negative']:,}"
            )
    lines.extend(
        [
            "\nModelos retreinados: nao",
            "Teste usado para escolher limiares: nao",
            "Comparacao pareada pelos mesmos record_hash: sim",
        ]
    )
    return "\n".join(lines)
