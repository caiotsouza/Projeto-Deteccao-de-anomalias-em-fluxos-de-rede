"""Comparacao auditavel entre os experimentos de escala 20k e 100k."""

from __future__ import annotations

import hashlib
import json
import logging
import platform
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

from src.utils import save_json


LOGGER = logging.getLogger(__name__)
logging.getLogger("matplotlib").setLevel(logging.WARNING)

MODEL_KEYS = ("isolation_forest", "lof")
MODEL_LABELS = {
    "isolation_forest": "Isolation Forest",
    "lof": "Local Outlier Factor",
}
EXPERIMENT_KEYS = ("baseline_20k", "expanded_100k")
EXPERIMENT_LABELS = {
    "baseline_20k": "Baseline 20k",
    "expanded_100k": "Expandido 100k",
}
EXPERIMENT_COLORS = {
    "baseline_20k": "#7f7f7f",
    "expanded_100k": "#2ca02c",
}
OPERATING_POINTS = ("native", "validation_f1_calibrated")
OPERATING_POINT_LABELS = {
    "native": "Limiar nativo",
    "validation_f1_calibrated": "Calibrado por F1",
}
RATE_METRICS = (
    "accuracy",
    "balanced_accuracy",
    "precision",
    "recall_tpr",
    "f1_score",
    "specificity_tnr",
    "false_positive_rate",
    "false_negative_rate",
)
COUNT_METRICS = (
    "true_negative",
    "false_positive",
    "false_negative",
    "true_positive",
)


@dataclass
class ScaleComparisonResult:
    """Relatorio, tabelas e fontes da comparacao de escala."""

    report: dict[str, Any]
    summary_table: pd.DataFrame
    delta_table: pd.DataFrame
    comparison_reports: dict[str, dict[str, Any]]


def _load_json(path: Path) -> dict[str, Any]:
    """Carrega um JSON obrigatorio."""
    if not path.is_file():
        raise FileNotFoundError(f"Arquivo JSON nao encontrado: {path}")
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def _sha256_file(path: Path) -> str:
    """Calcula SHA-256 em blocos."""
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for block in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _winner(
    baseline_value: float,
    expanded_value: float,
    higher_is_better: bool,
) -> str:
    """Compara valores considerando a orientacao da metrica."""
    if np.isclose(baseline_value, expanded_value, rtol=0.0, atol=1e-12):
        return "tie"
    if higher_is_better:
        return "expanded_100k" if expanded_value > baseline_value else "baseline_20k"
    return "expanded_100k" if expanded_value < baseline_value else "baseline_20k"


def _validate_comparison_report(report: dict[str, Any], name: str) -> None:
    """Confirma o contrato de saida do Marco 9."""
    if report.get("stage") != "isolation_forest_lof_comparison_marco_9":
        raise ValueError(f"{name} nao e um relatorio comparativo do Marco 9.")
    if report.get("status") != "completed":
        raise ValueError(f"{name} nao esta concluido.")
    if set(report.get("models", {})) != set(MODEL_KEYS):
        raise ValueError(f"{name} nao possui os dois modelos esperados.")
    methodology = report.get("methodology", {})
    required_flags = (
        "predictions_frozen_before_labels_loaded",
        "models_refitted_or_modified",
        "test_labels_used_for_threshold_selection",
        "both_thresholds_frozen_before_test_labels_loaded",
    )
    if any(flag not in methodology for flag in required_flags):
        raise ValueError(f"{name} nao registra o protocolo metodologico completo.")
    if methodology["predictions_frozen_before_labels_loaded"] is not True:
        raise ValueError(f"{name} nao congelou previsoes antes dos rotulos.")
    if methodology["models_refitted_or_modified"] is not False:
        raise ValueError(f"{name} modificou modelos durante a avaliacao.")
    if methodology["test_labels_used_for_threshold_selection"] is not False:
        raise ValueError(f"{name} utilizou o teste para selecionar limiar.")
    if methodology["both_thresholds_frozen_before_test_labels_loaded"] is not True:
        raise ValueError(f"{name} nao congelou os limiares antes de y_test.")


def _validate_split_reports(
    baseline: dict[str, Any],
    expanded: dict[str, Any],
) -> dict[str, Any]:
    """Valida fator cinco, esquema e politica de amostragem."""
    expected_baseline = {
        "train_benign_size": 20_000,
        "validation_benign_size": 5_000,
        "validation_attack_size": 5_000,
        "test_benign_size": 10_000,
        "test_attack_size": 10_000,
    }
    expected_expanded = {key: value * 5 for key, value in expected_baseline.items()}
    for key, value in expected_baseline.items():
        if int(baseline["configuration"][key]) != value:
            raise ValueError(f"Baseline possui {key} diferente de {value}.")
    for key, value in expected_expanded.items():
        if int(expanded["configuration"][key]) != value:
            raise ValueError(f"Experimento expandido possui {key} diferente de {value}.")
    baseline_seed = int(baseline["configuration"]["random_state"])
    expanded_seed = int(expanded["configuration"]["random_state"])
    if baseline_seed != expanded_seed:
        raise ValueError("Os experimentos usam random_state diferentes.")
    baseline_schema = baseline["leakage_checks"]["model_input_schema_sha256"]
    expanded_schema = expanded["leakage_checks"]["model_input_schema_sha256"]
    if baseline_schema != expanded_schema:
        raise ValueError("Os experimentos usam esquemas de features diferentes.")
    for name, report in (("baseline", baseline), ("expanded", expanded)):
        checks = report["leakage_checks"]
        if checks["status"] != "passed":
            raise ValueError(f"Verificacao de vazamento falhou em {name}.")
        if any(int(value) != 0 for value in checks["hash_overlaps"].values()):
            raise ValueError(f"Ha sobreposicao de hashes em {name}.")
        if int(checks["train_attack_records"]) != 0:
            raise ValueError(f"Treino de {name} contem ataques.")
    return {
        "scale_factor": 5,
        "baseline_configuration": expected_baseline,
        "expanded_configuration": expected_expanded,
        "random_state": baseline_seed,
        "schema_sha256": baseline_schema,
        "zero_hash_overlap_within_each_experiment": True,
        "training_is_benign_only": True,
        "status": "passed",
    }


def _training_reports_from_comparison(
    comparison: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    """Abre os relatorios de treino registrados pela comparacao."""
    result: dict[str, dict[str, Any]] = {}
    for model_key in MODEL_KEYS:
        item = comparison["inputs"]["training_reports"][model_key]
        path = Path(item["path"])
        if _sha256_file(path) != item["sha256"]:
            raise ValueError(f"Relatorio de treino alterado para {model_key}.")
        result[model_key] = _load_json(path)
    return result


def _validate_model_configurations(
    baseline: dict[str, dict[str, Any]],
    expanded: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Confirma que tamanho da amostra foi a variavel planejada."""
    result: dict[str, Any] = {}
    for model_key in MODEL_KEYS:
        baseline_config = baseline[model_key]["configuration"]
        expanded_config = expanded[model_key]["configuration"]
        if baseline_config != expanded_config:
            raise ValueError(f"Hiperparametros divergentes para {model_key}.")
        result[model_key] = {
            "configuration": baseline_config,
            "identical_between_experiments": True,
        }
    return result


def _build_summary_table(
    reports: dict[str, dict[str, Any]],
) -> pd.DataFrame:
    """Cria tabela longa com todos os resultados comparaveis."""
    rows: list[dict[str, Any]] = []
    for experiment_key in EXPERIMENT_KEYS:
        report = reports[experiment_key]
        for model_key in MODEL_KEYS:
            model = report["models"][model_key]
            timing = report["timing"]["by_model_seconds"][model_key]
            for split in ("validation", "test"):
                ranking = model["splits"][split]["ranking_metrics"]
                for point in OPERATING_POINTS:
                    metrics = model["splits"][split]["operating_points"][point]
                    rows.append(
                        {
                            "experiment": experiment_key,
                            "experiment_label": EXPERIMENT_LABELS[experiment_key],
                            "model": model_key,
                            "model_label": MODEL_LABELS[model_key],
                            "split": split,
                            "records": model["splits"][split]["records"],
                            "operating_point": point,
                            "threshold": (
                                model["thresholds"]["native"][
                                    "equivalent_anomaly_score_threshold"
                                ]
                                if point == "native"
                                else model["thresholds"][
                                    "validation_f1_calibrated"
                                ]["threshold"]
                            ),
                            "roc_auc": ranking["roc_auc"],
                            "average_precision": ranking["average_precision"],
                            **{metric: metrics[metric] for metric in COUNT_METRICS},
                            **{metric: metrics[metric] for metric in RATE_METRICS},
                            "fit_seconds": timing["fit"],
                            "inference_validation_seconds": timing[
                                "inference_validation"
                            ],
                            "inference_test_seconds": timing["inference_test"],
                        }
                    )
    return pd.DataFrame(rows)


def _build_delta_table(summary: pd.DataFrame) -> pd.DataFrame:
    """Calcula 100k menos 20k para taxas, ranking, limiar e tempo."""
    rows: list[dict[str, Any]] = []
    directions = {
        **{metric: True for metric in RATE_METRICS},
        "false_positive_rate": False,
        "false_negative_rate": False,
        "roc_auc": True,
        "average_precision": True,
        "fit_seconds": False,
        "inference_validation_seconds": False,
        "inference_test_seconds": False,
        "threshold": None,
    }
    for model_key in MODEL_KEYS:
        for split in ("validation", "test"):
            for point in OPERATING_POINTS:
                selector = (
                    summary["model"].eq(model_key)
                    & summary["split"].eq(split)
                    & summary["operating_point"].eq(point)
                )
                baseline = summary.loc[
                    selector & summary["experiment"].eq("baseline_20k")
                ].iloc[0]
                expanded = summary.loc[
                    selector & summary["experiment"].eq("expanded_100k")
                ].iloc[0]
                for metric, higher_is_better in directions.items():
                    baseline_value = float(baseline[metric])
                    expanded_value = float(expanded[metric])
                    rows.append(
                        {
                            "model": model_key,
                            "model_label": MODEL_LABELS[model_key],
                            "split": split,
                            "operating_point": point,
                            "metric": metric,
                            "baseline_20k": baseline_value,
                            "expanded_100k": expanded_value,
                            "delta_100k_minus_20k": expanded_value
                            - baseline_value,
                            "higher_is_better": higher_is_better,
                            "winner": (
                                "not_applicable"
                                if higher_is_better is None
                                else _winner(
                                    baseline_value,
                                    expanded_value,
                                    higher_is_better,
                                )
                            ),
                        }
                    )
    return pd.DataFrame(rows)


def compare_scale_reports(
    baseline_report: dict[str, Any],
    expanded_report: dict[str, Any],
) -> dict[str, Any]:
    """Compara resultados preservando pontos operacionais e splits."""
    reports = {
        "baseline_20k": baseline_report,
        "expanded_100k": expanded_report,
    }
    result: dict[str, Any] = {}
    for model_key in MODEL_KEYS:
        model_result: dict[str, Any] = {
            "thresholds": {},
            "splits": {},
            "timing": {},
        }
        for point in OPERATING_POINTS:
            threshold_key = "native" if point == "native" else point
            if point == "native":
                key = "equivalent_anomaly_score_threshold"
            else:
                key = "threshold"
            baseline_value = float(
                baseline_report["models"][model_key]["thresholds"][threshold_key][key]
            )
            expanded_value = float(
                expanded_report["models"][model_key]["thresholds"][threshold_key][key]
            )
            model_result["thresholds"][point] = {
                "baseline_20k": baseline_value,
                "expanded_100k": expanded_value,
                "delta_100k_minus_20k": expanded_value - baseline_value,
            }
        for split in ("validation", "test"):
            split_result: dict[str, Any] = {"ranking": {}, "operating_points": {}}
            for metric in ("roc_auc", "average_precision"):
                baseline_value = float(
                    baseline_report["models"][model_key]["splits"][split][
                        "ranking_metrics"
                    ][metric]
                )
                expanded_value = float(
                    expanded_report["models"][model_key]["splits"][split][
                        "ranking_metrics"
                    ][metric]
                )
                split_result["ranking"][metric] = {
                    "baseline_20k": baseline_value,
                    "expanded_100k": expanded_value,
                    "delta_100k_minus_20k": expanded_value - baseline_value,
                    "winner": _winner(baseline_value, expanded_value, True),
                }
            for point in OPERATING_POINTS:
                point_result: dict[str, Any] = {}
                for metric in RATE_METRICS:
                    higher_is_better = metric not in (
                        "false_positive_rate",
                        "false_negative_rate",
                    )
                    baseline_value = float(
                        baseline_report["models"][model_key]["splits"][split][
                            "operating_points"
                        ][point][metric]
                    )
                    expanded_value = float(
                        expanded_report["models"][model_key]["splits"][split][
                            "operating_points"
                        ][point][metric]
                    )
                    point_result[metric] = {
                        "baseline_20k": baseline_value,
                        "expanded_100k": expanded_value,
                        "delta_100k_minus_20k": expanded_value - baseline_value,
                        "winner": _winner(
                            baseline_value, expanded_value, higher_is_better
                        ),
                    }
                split_result["operating_points"][point] = point_result
            model_result["splits"][split] = split_result
        for stage in ("fit", "inference_validation", "inference_test"):
            baseline_time = float(
                baseline_report["timing"]["by_model_seconds"][model_key][stage]
            )
            expanded_time = float(
                expanded_report["timing"]["by_model_seconds"][model_key][stage]
            )
            model_result["timing"][stage] = {
                "baseline_20k_seconds": baseline_time,
                "expanded_100k_seconds": expanded_time,
                "ratio_100k_over_20k": (
                    expanded_time / baseline_time if baseline_time else None
                ),
            }
        result[model_key] = model_result
    return result


def _artifact_paths(metrics_dir: Path, figures_dir: Path) -> dict[str, Path]:
    """Define os artefatos exclusivos da comparacao 20k x 100k."""
    return {
        "report": metrics_dir / "scale_comparison.json",
        "summary_table": metrics_dir / "scale_comparison_summary.csv",
        "delta_table": metrics_dir / "scale_comparison_deltas.csv",
        "test_metrics_figure": figures_dir / "scale_comparison_test_metrics.png",
        "ranking_figure": figures_dir / "scale_comparison_ranking.png",
        "timing_figure": figures_dir / "scale_comparison_timing.png",
    }


def _plot_test_metrics(result: ScaleComparisonResult, output_path: Path) -> None:
    """Compara as quatro metricas operacionais centrais no teste."""
    figure, axes = plt.subplots(2, 2, figsize=(13, 10), sharey=True)
    metric_keys = ("precision", "recall_tpr", "f1_score", "false_positive_rate")
    metric_labels = ("Precision", "Recall", "F1", "FPR")
    x = np.arange(len(metric_keys))
    width = 0.36
    for row, model_key in enumerate(MODEL_KEYS):
        for column, point in enumerate(OPERATING_POINTS):
            axis = axes[row, column]
            for experiment_index, experiment_key in enumerate(EXPERIMENT_KEYS):
                report = result.comparison_reports[experiment_key]
                metrics = report["models"][model_key]["splits"]["test"][
                    "operating_points"
                ][point]
                values = [metrics[key] for key in metric_keys]
                offset = -width / 2 if experiment_index == 0 else width / 2
                bars = axis.bar(
                    x + offset,
                    values,
                    width,
                    color=EXPERIMENT_COLORS[experiment_key],
                    label=EXPERIMENT_LABELS[experiment_key],
                )
                axis.bar_label(bars, fmt="%.3f", fontsize=8, padding=2)
            axis.set_xticks(x, metric_labels)
            axis.set_ylim(0, 1.08)
            axis.set_title(
                f"{MODEL_LABELS[model_key]} — {OPERATING_POINT_LABELS[point]}"
            )
            axis.grid(axis="y", alpha=0.25)
            axis.legend(loc="upper right")
        axes[row, 0].set_ylabel("Valor da métrica")
    figure.suptitle("Efeito da escala no conjunto de teste", fontsize=15)
    figure.tight_layout()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(output_path, dpi=160, bbox_inches="tight")
    plt.close(figure)


def _plot_ranking(result: ScaleComparisonResult, output_path: Path) -> None:
    """Compara ROC-AUC e AP sem depender de um limiar."""
    figure, axes = plt.subplots(1, 2, figsize=(13, 5.5), sharey=True)
    metric_keys = ("roc_auc", "average_precision")
    metric_labels = ("ROC-AUC", "Average Precision")
    x = np.arange(len(metric_keys))
    width = 0.36
    for axis, split in zip(axes, ("validation", "test")):
        groups: list[tuple[str, str]] = [
            (model_key, experiment_key)
            for model_key in MODEL_KEYS
            for experiment_key in EXPERIMENT_KEYS
        ]
        group_width = 0.18
        for index, (model_key, experiment_key) in enumerate(groups):
            report = result.comparison_reports[experiment_key]
            ranking = report["models"][model_key]["splits"][split][
                "ranking_metrics"
            ]
            offset = (index - 1.5) * group_width
            bars = axis.bar(
                x + offset,
                [ranking[key] for key in metric_keys],
                group_width,
                color=EXPERIMENT_COLORS[experiment_key],
                hatch="" if model_key == "isolation_forest" else "//",
                edgecolor="black" if model_key == "lof" else None,
                linewidth=0.5,
                label=f"{MODEL_LABELS[model_key]} — {EXPERIMENT_LABELS[experiment_key]}",
            )
            axis.bar_label(bars, fmt="%.3f", fontsize=7, padding=2)
        axis.set_xticks(x, metric_labels)
        axis.set_ylim(0, 1.08)
        axis.set_title("Validação" if split == "validation" else "Teste")
        axis.grid(axis="y", alpha=0.25)
        axis.legend(loc="lower right", fontsize=8)
    axes[0].set_ylabel("Valor da métrica")
    figure.suptitle("Ranking — baseline 20k versus expandido 100k", fontsize=15)
    figure.tight_layout()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(output_path, dpi=160, bbox_inches="tight")
    plt.close(figure)


def _plot_timing(result: ScaleComparisonResult, output_path: Path) -> None:
    """Compara custos em escala logaritmica."""
    figure, axes = plt.subplots(1, 2, figsize=(13, 5.5), sharey=True)
    stage_keys = ("fit", "inference_validation", "inference_test")
    stage_labels = ("Treino", "Inferência\nvalidação", "Inferência\nteste")
    x = np.arange(len(stage_keys))
    width = 0.36
    for axis, model_key in zip(axes, MODEL_KEYS):
        for index, experiment_key in enumerate(EXPERIMENT_KEYS):
            timing = result.comparison_reports[experiment_key]["timing"][
                "by_model_seconds"
            ][model_key]
            values = [timing[key] for key in stage_keys]
            offset = -width / 2 if index == 0 else width / 2
            bars = axis.bar(
                x + offset,
                values,
                width,
                color=EXPERIMENT_COLORS[experiment_key],
                label=EXPERIMENT_LABELS[experiment_key],
            )
            axis.bar_label(bars, fmt="%.3f", fontsize=8, padding=2)
        axis.set_xticks(x, stage_labels)
        axis.set_yscale("log")
        axis.set_title(MODEL_LABELS[model_key])
        axis.grid(axis="y", alpha=0.25, which="both")
    axes[0].set_ylabel("Segundos — escala logarítmica")
    handles, labels = axes[0].get_legend_handles_labels()
    figure.legend(
        handles,
        labels,
        loc="upper center",
        bbox_to_anchor=(0.5, 0.94),
        ncol=2,
    )
    figure.suptitle("Custo computacional por escala", fontsize=15, y=1.01)
    figure.tight_layout(rect=(0, 0, 1, 0.88))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(output_path, dpi=160, bbox_inches="tight")
    plt.close(figure)


def save_scale_comparison_artifacts(
    result: ScaleComparisonResult,
    metrics_dir: Path,
    figures_dir: Path,
    overwrite: bool = False,
) -> dict[str, Path]:
    """Persiste o relatorio, duas tabelas e tres figuras."""
    paths = _artifact_paths(metrics_dir, figures_dir)
    existing = [path for path in paths.values() if path.exists()]
    if existing and not overwrite:
        raise FileExistsError(
            "Artefato(s) ja existente(s); use --overwrite para substituir: "
            + ", ".join(str(path) for path in existing)
        )
    for path in paths.values():
        path.parent.mkdir(parents=True, exist_ok=True)
    result.summary_table.to_csv(paths["summary_table"], index=False)
    result.delta_table.to_csv(paths["delta_table"], index=False)
    _plot_test_metrics(result, paths["test_metrics_figure"])
    _plot_ranking(result, paths["ranking_figure"])
    _plot_timing(result, paths["timing_figure"])
    result.report["artifacts"] = {
        name: str(path.resolve()) for name, path in paths.items()
    }
    save_json(result.report, paths["report"])
    return paths


def run_scale_comparison(
    baseline_comparison_path: Path,
    expanded_comparison_path: Path,
    baseline_split_report_path: Path,
    expanded_split_report_path: Path,
    metrics_dir: Path,
    figures_dir: Path,
    overwrite: bool = False,
) -> ScaleComparisonResult:
    """Valida, compara e persiste os experimentos 20k e 100k."""
    paths = _artifact_paths(metrics_dir, figures_dir)
    existing = [path for path in paths.values() if path.exists()]
    if existing and not overwrite:
        raise FileExistsError(
            "Artefato(s) ja existente(s); use --overwrite para substituir: "
            + ", ".join(str(path) for path in existing)
        )
    comparison_reports = {
        "baseline_20k": _load_json(baseline_comparison_path),
        "expanded_100k": _load_json(expanded_comparison_path),
    }
    for key, report in comparison_reports.items():
        _validate_comparison_report(report, key)
    split_reports = {
        "baseline_20k": _load_json(baseline_split_report_path),
        "expanded_100k": _load_json(expanded_split_report_path),
    }
    split_integrity = _validate_split_reports(
        split_reports["baseline_20k"], split_reports["expanded_100k"]
    )
    training_reports = {
        experiment_key: _training_reports_from_comparison(report)
        for experiment_key, report in comparison_reports.items()
    }
    model_config_integrity = _validate_model_configurations(
        training_reports["baseline_20k"], training_reports["expanded_100k"]
    )
    summary = _build_summary_table(comparison_reports)
    deltas = _build_delta_table(summary)
    report = {
        "schema_version": 1,
        "stage": "sample_scale_20k_vs_100k_comparison",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "completed",
        "methodology": {
            "planned_change": "fivefold increase in all split sizes",
            "training": "BENIGN only in both experiments",
            "evaluation_prevalence": "50% BENIGN and 50% attacks",
            "hyperparameters_identical": True,
            "random_state_identical": True,
            "feature_schema_identical": True,
            "thresholds_reselected_on_each_validation_split": True,
            "test_labels_used_for_threshold_selection": False,
            "baseline_artifacts_overwritten": False,
            "comparison_scope_warning": (
                "training and evaluation sample sizes changed together; metric deltas "
                "reflect both broader training coverage and a larger evaluation sample"
            ),
            "rare_class_warning": (
                "rare attack classes cannot grow exactly fivefold; stratified quotas "
                "preserve every class subject to source availability"
            ),
        },
        "integrity": {
            "splits": split_integrity,
            "model_configurations": model_config_integrity,
            "source_reports_verified_by_sha256": True,
            "status": "passed",
        },
        "inputs": {
            "baseline_comparison": {
                "path": str(baseline_comparison_path.resolve()),
                "sha256": _sha256_file(baseline_comparison_path),
            },
            "expanded_comparison": {
                "path": str(expanded_comparison_path.resolve()),
                "sha256": _sha256_file(expanded_comparison_path),
            },
            "baseline_split_report": {
                "path": str(baseline_split_report_path.resolve()),
                "sha256": _sha256_file(baseline_split_report_path),
            },
            "expanded_split_report": {
                "path": str(expanded_split_report_path.resolve()),
                "sha256": _sha256_file(expanded_split_report_path),
            },
        },
        "sample_sizes": {
            experiment_key: {
                split: int(
                    report_["models"]["isolation_forest"]["splits"][split][
                        "records"
                    ]
                )
                for split in ("validation", "test")
            }
            for experiment_key, report_ in comparison_reports.items()
        },
        "comparisons": compare_scale_reports(
            comparison_reports["baseline_20k"],
            comparison_reports["expanded_100k"],
        ),
        "libraries": {
            "python": platform.python_version(),
            "numpy": np.__version__,
            "pandas": pd.__version__,
            "scikit_learn": sklearn.__version__,
            "matplotlib": matplotlib.__version__,
        },
    }
    result = ScaleComparisonResult(
        report=report,
        summary_table=summary,
        delta_table=deltas,
        comparison_reports=comparison_reports,
    )
    save_scale_comparison_artifacts(
        result,
        metrics_dir=metrics_dir,
        figures_dir=figures_dir,
        overwrite=overwrite,
    )
    return result


def format_scale_summary(report: dict[str, Any]) -> str:
    """Formata os principais deltas do teste."""
    lines = ["\n=== ESCALA 20k x 100k ==="]
    for model_key in MODEL_KEYS:
        lines.append(f"\n{MODEL_LABELS[model_key]}")
        model = report["comparisons"][model_key]
        for point in OPERATING_POINTS:
            metrics = model["splits"]["test"]["operating_points"][point]
            lines.append(
                f"  {OPERATING_POINT_LABELS[point]}: "
                f"Δprecision={metrics['precision']['delta_100k_minus_20k']:+.4f}, "
                f"Δrecall={metrics['recall_tpr']['delta_100k_minus_20k']:+.4f}, "
                f"ΔF1={metrics['f1_score']['delta_100k_minus_20k']:+.4f}, "
                f"ΔFPR={metrics['false_positive_rate']['delta_100k_minus_20k']:+.4f}"
            )
        ranking = model["splits"]["test"]["ranking"]
        lines.append(
            f"  Ranking: ΔROC-AUC={ranking['roc_auc']['delta_100k_minus_20k']:+.4f}, "
            f"ΔAP={ranking['average_precision']['delta_100k_minus_20k']:+.4f}"
        )
        timing = model["timing"]
        lines.append(
            f"  Tempo: treino={timing['fit']['ratio_100k_over_20k']:.2f}x, "
            f"inferência teste={timing['inference_test']['ratio_100k_over_20k']:.2f}x"
        )
    return "\n".join(lines)
