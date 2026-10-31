"""Calibração pós-Marco 11 orientada a orçamento de falsos positivos."""

from __future__ import annotations

import copy
import csv
import hashlib
import json
import math
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from src.config import DEFAULT_OPERATIONAL_TARGET_FPR, PROJECT_ROOT
from src.evaluation import calculate_classification_metrics


MODEL_KEYS = ("isolation_forest", "lof")
MODEL_LABELS = {
    "isolation_forest": "Isolation Forest",
    "lof": "Local Outlier Factor",
}
DEFAULT_SENSITIVITY_FPRS = (0.001, 0.005, 0.01, 0.02, 0.05)
OPERATIONAL_POINT = "validation_fpr_operational"
REQUIRED_COLUMNS = (
    "row_position",
    "record_hash",
    "label",
    "binary_label",
    "anomaly_score",
)
OUTPUT_FILENAMES = {
    "report": "operational_calibration.json",
    "sensitivity": "threshold_sensitivity.csv",
    "figure": "operational_threshold_tradeoff.png",
    "registry": "model_registry_operational.json",
    "summary": "OPERATIONAL_CALIBRATION_SUMMARY.md",
    "manifest": "operational_calibration_manifest.json",
}


@dataclass(frozen=True)
class OperationalCalibrationResult:
    """Relatório, registro derivado e linhas tabulares da calibração."""

    report: dict[str, Any]
    registry: dict[str, Any]
    sensitivity_rows: list[dict[str, Any]]


@dataclass(frozen=True)
class _FrozenValidationSelection:
    """Estado decidido antes da leitura do conjunto de teste."""

    validations: dict[str, pd.DataFrame]
    budgets: list[float]
    selections: dict[str, dict[float, dict[str, Any]]]
    validation_metrics: dict[str, dict[float, dict[str, Any]]]
    recommended_model: str
    frozen_at_utc: str


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(f"JSON obrigatório não encontrado: {path}")
    with path.open("r", encoding="utf-8") as file:
        data = json.load(file)
    if not isinstance(data, dict):
        raise ValueError(f"O JSON deve possuir um objeto na raiz: {path}")
    return data


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for block in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _relative(path: Path, project_root: Path) -> str:
    try:
        return path.resolve().relative_to(project_root.resolve()).as_posix()
    except ValueError as exc:
        raise ValueError(f"Caminho fora do projeto: {path}") from exc


def _write_json_atomic(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("w", encoding="utf-8") as file:
        json.dump(data, file, ensure_ascii=False, indent=2)
        file.write("\n")
    os.replace(temporary, path)


def _write_text_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(text, encoding="utf-8")
    os.replace(temporary, path)


def _validate_target_fpr(target_fpr: float) -> float:
    value = float(target_fpr)
    if not math.isfinite(value) or not 0.0 < value < 0.5:
        raise ValueError("target_fpr deve ser finito e estar no intervalo (0, 0.5).")
    return value


def _validate_evaluated_frame(frame: pd.DataFrame, name: str) -> pd.DataFrame:
    missing = [column for column in REQUIRED_COLUMNS if column not in frame.columns]
    if missing:
        raise ValueError(f"{name} não possui as colunas obrigatórias: {missing}")
    if frame.empty:
        raise ValueError(f"{name} está vazio.")
    validated = frame.loc[:, REQUIRED_COLUMNS].copy()
    if validated["record_hash"].isna().any() or validated["record_hash"].duplicated().any():
        raise ValueError(f"{name} possui record_hash ausente ou duplicado.")
    labels = validated["binary_label"].to_numpy(dtype=np.int8)
    if set(np.unique(labels)) != {0, 1}:
        raise ValueError(f"{name} deve conter classes binárias 0 e 1.")
    scores = validated["anomaly_score"].to_numpy(dtype=np.float64)
    if not np.isfinite(scores).all():
        raise ValueError(f"{name} possui anomaly_score ausente ou infinito.")
    positions = validated["row_position"].to_numpy(dtype=np.int64)
    if not np.array_equal(positions, np.arange(len(validated), dtype=np.int64)):
        raise ValueError(f"{name} possui row_position fora da sequência 0..N-1.")
    return validated


def _assert_frames_aligned(frames: Mapping[str, pd.DataFrame], split: str) -> None:
    reference = frames[MODEL_KEYS[0]]
    for model_key in MODEL_KEYS[1:]:
        candidate = frames[model_key]
        if len(reference) != len(candidate):
            raise ValueError(f"Modelos possuem quantidades diferentes em {split}.")
        for column in ("row_position", "record_hash", "label", "binary_label"):
            if not reference[column].reset_index(drop=True).equals(
                candidate[column].reset_index(drop=True)
            ):
                raise ValueError(
                    f"Modelos não estão alinhados pela coluna {column} em {split}."
                )


def select_fpr_constrained_threshold(
    y_true: Sequence[int] | np.ndarray,
    anomaly_score: Sequence[float] | np.ndarray,
    target_fpr: float = DEFAULT_OPERATIONAL_TARGET_FPR,
) -> dict[str, Any]:
    """Seleciona o menor limiar que respeita o FPR usando só escores benignos.

    Como a regra positiva é ``score >= threshold``, o menor limiar elegível
    maximiza a cobertura sem exceder o orçamento empírico de falsos positivos.
    Rótulos de ataque não participam da escolha numérica do limiar.
    """
    target = _validate_target_fpr(target_fpr)
    labels = np.asarray(y_true, dtype=np.int8)
    scores = np.asarray(anomaly_score, dtype=np.float64)
    if labels.ndim != 1 or scores.ndim != 1 or labels.shape != scores.shape:
        raise ValueError("y_true e anomaly_score devem ser vetores alinhados.")
    if not len(labels) or not np.isfinite(scores).all():
        raise ValueError("A calibração requer escores finitos e não vazios.")
    if set(np.unique(labels)) != {0, 1}:
        raise ValueError("A calibração requer as classes binárias 0 e 1.")

    normal_scores = scores[labels == 0]
    normal_support = int(len(normal_scores))
    maximum_false_positives = int(math.floor(target * normal_support))
    unique_scores, counts = np.unique(normal_scores, return_counts=True)
    false_positives_at_threshold = np.cumsum(counts[::-1])[::-1]
    eligible = np.flatnonzero(
        false_positives_at_threshold <= maximum_false_positives
    )
    if len(eligible):
        threshold = float(unique_scores[int(eligible[0])])
        achieved_fp = int(false_positives_at_threshold[int(eligible[0])])
        threshold_source = "smallest_observed_benign_score_within_budget"
    else:
        threshold = float(np.nextafter(np.max(normal_scores), np.inf))
        achieved_fp = 0
        threshold_source = "next_float_above_maximum_benign_score"
    return {
        "objective": "limit_empirical_false_positive_rate",
        "score": "anomaly_score",
        "positive_rule": "anomaly_score >= threshold",
        "threshold": threshold,
        "target_false_positive_rate": target,
        "validation_normal_support": normal_support,
        "maximum_validation_false_positives": maximum_false_positives,
        "achieved_validation_false_positives": achieved_fp,
        "achieved_validation_false_positive_rate": float(
            achieved_fp / normal_support
        ),
        "threshold_source": threshold_source,
        "selection_uses_validation_benign_scores_only": True,
        "attack_labels_used_for_threshold_selection": False,
        "test_labels_used": False,
        "tie_handling": "raises threshold when tied benign scores exceed budget",
    }


def _metrics_at_threshold(frame: pd.DataFrame, threshold: float) -> dict[str, Any]:
    labels = frame["binary_label"].to_numpy(dtype=np.int8)
    predictions = frame["anomaly_score"].ge(threshold).to_numpy(dtype=np.int8)
    return calculate_classification_metrics(labels, predictions)


def _project_precision(recall: float, fpr: float, prevalence: float) -> float:
    numerator = recall * prevalence
    denominator = numerator + fpr * (1.0 - prevalence)
    return float(numerator / denominator) if denominator else 0.0


def _freeze_validation_selection(
    validation_frames: Mapping[str, pd.DataFrame],
    *,
    target_fpr: float,
    sensitivity_fprs: Sequence[float],
    frozen_at_utc: str,
) -> _FrozenValidationSelection:
    """Seleciona limiares e modelo sem receber nenhum dado de teste."""
    target = _validate_target_fpr(target_fpr)
    budgets = sorted(
        {_validate_target_fpr(value) for value in sensitivity_fprs} | {target}
    )
    validations = {
        key: _validate_evaluated_frame(validation_frames[key], f"{key}/validation")
        for key in MODEL_KEYS
    }
    _assert_frames_aligned(validations, "validation")
    selections: dict[str, dict[float, dict[str, Any]]] = {}
    validation_metrics: dict[str, dict[float, dict[str, Any]]] = {}
    for model_key in MODEL_KEYS:
        labels = validations[model_key]["binary_label"].to_numpy(dtype=np.int8)
        scores = validations[model_key]["anomaly_score"].to_numpy(dtype=np.float64)
        selections[model_key] = {}
        validation_metrics[model_key] = {}
        for budget in budgets:
            selection = select_fpr_constrained_threshold(labels, scores, budget)
            selections[model_key][budget] = selection
            validation_metrics[model_key][budget] = _metrics_at_threshold(
                validations[model_key], selection["threshold"]
            )

    # A recomendação usa apenas a validação: maior recall sob o mesmo teto de
    # FPR; precision e menor FPR são desempates explícitos.
    recommended_model = max(
        MODEL_KEYS,
        key=lambda key: (
            validation_metrics[key][target]["recall_tpr"],
            validation_metrics[key][target]["precision"],
            -validation_metrics[key][target]["false_positive_rate"],
            key,
        ),
    )
    return _FrozenValidationSelection(
        validations=validations,
        budgets=budgets,
        selections=selections,
        validation_metrics=validation_metrics,
        recommended_model=recommended_model,
        frozen_at_utc=frozen_at_utc,
    )


def build_operational_calibration(
    validation_frames: Mapping[str, pd.DataFrame],
    test_frames: Mapping[str, pd.DataFrame],
    parent_registry: dict[str, Any],
    *,
    target_fpr: float = DEFAULT_OPERATIONAL_TARGET_FPR,
    sensitivity_fprs: Sequence[float] = DEFAULT_SENSITIVITY_FPRS,
    experiment: str = "expanded_100k",
    created_at_utc: str | None = None,
    parent_registry_reference: dict[str, Any] | None = None,
    frozen_selection: _FrozenValidationSelection | None = None,
    test_opened_after_selection: bool = False,
) -> OperationalCalibrationResult:
    """Compara modelos no orçamento de FPR e cria um registro derivado."""
    target = _validate_target_fpr(target_fpr)
    created = created_at_utc or _utc_now()
    frozen = frozen_selection or _freeze_validation_selection(
        validation_frames,
        target_fpr=target,
        sensitivity_fprs=sensitivity_fprs,
        frozen_at_utc=created,
    )
    budgets = frozen.budgets
    validations = frozen.validations
    selections = frozen.selections
    validation_metrics = frozen.validation_metrics
    recommended_model = frozen.recommended_model
    tests = {
        key: _validate_evaluated_frame(test_frames[key], f"{key}/test")
        for key in MODEL_KEYS
    }
    _assert_frames_aligned(tests, "test")

    test_metrics: dict[str, dict[float, dict[str, Any]]] = {}
    sensitivity_rows: list[dict[str, Any]] = []
    models_report: dict[str, Any] = {}
    for model_key in MODEL_KEYS:
        test_metrics[model_key] = {}
        budget_report: dict[str, Any] = {}
        for budget in budgets:
            selection = selections[model_key][budget]
            threshold = float(selection["threshold"])
            test_metric = _metrics_at_threshold(tests[model_key], threshold)
            test_metrics[model_key][budget] = test_metric
            validation_metric = validation_metrics[model_key][budget]
            budget_key = f"{budget:.6f}"
            budget_report[budget_key] = {
                "selection": selection,
                "validation_metrics": validation_metric,
                "test_metrics": test_metric,
            }
            for split, metrics in (
                ("validation", validation_metric),
                ("test", test_metric),
            ):
                sensitivity_rows.append(
                    {
                        "model": model_key,
                        "model_display_name": MODEL_LABELS[model_key],
                        "split": split,
                        "target_false_positive_rate": budget,
                        "threshold": threshold,
                        "false_positive_rate": metrics["false_positive_rate"],
                        "false_positive": metrics["false_positive"],
                        "precision": metrics["precision"],
                        "recall_tpr": metrics["recall_tpr"],
                        "f1_score": metrics["f1_score"],
                        "predicted_anomaly_rate": metrics["predicted_anomaly_rate"],
                    }
                )
        selected_test = test_metrics[model_key][target]
        models_report[model_key] = {
            "display_name": MODEL_LABELS[model_key],
            "budgets": budget_report,
            "selected_operating_point": {
                "name": OPERATIONAL_POINT,
                "selection": selections[model_key][target],
                "validation_metrics": validation_metrics[model_key][target],
                "test_metrics": selected_test,
            },
        }

    selected_metrics = test_metrics[recommended_model][target]
    prevalence_scenarios = {}
    for prevalence in (0.001, 0.01, 0.05):
        prevalence_scenarios[f"{prevalence:.3f}"] = {
            "assumed_attack_prevalence": prevalence,
            "projected_precision": _project_precision(
                selected_metrics["recall_tpr"],
                selected_metrics["false_positive_rate"],
                prevalence,
            ),
            "note": (
                "Projeção baseada em TPR/FPR do teste rotulado; não é uma "
                "medição de produção."
            ),
        }

    report = {
        "schema_version": 1,
        "stage": "operational_threshold_calibration_post_marco_11",
        "created_at_utc": created,
        "status": "completed",
        "experiment": experiment,
        "operating_point": OPERATIONAL_POINT,
        "methodology": {
            "primary_objective": "cap validation false-positive rate",
            "target_false_positive_rate": target,
            "thresholds_selected_from_validation_benign_scores_only": True,
            "attack_labels_used_for_numeric_threshold_selection": False,
            "validation_attack_labels_used_for_model_recommendation": True,
            "test_labels_used_for_threshold_or_model_selection": False,
            "test_opened_after_all_thresholds_and_recommendation_were_frozen": (
                bool(test_opened_after_selection)
            ),
            "models_retrained": False,
            "predictions_recomputed": False,
            "previous_operating_points_preserved": True,
        },
        "recommendation": {
            "experiment": experiment,
            "model": recommended_model,
            "model_display_name": MODEL_LABELS[recommended_model],
            "operating_point": OPERATIONAL_POINT,
            "threshold": selections[recommended_model][target]["threshold"],
            "selection_rule": "highest validation recall subject to target FPR",
            "frozen_at_utc": frozen.frozen_at_utc,
            "production_approved": False,
            "reason_not_production_approved": (
                "Target and threshold still require temporal calibration with "
                "representative benign traffic and an explicit analyst alert budget."
            ),
        },
        "models": models_report,
        "production_prevalence_scenarios": prevalence_scenarios,
        "operational_warnings": [
            "Um FPR de 1% ainda representa cerca de 10.000 fluxos falso-positivos por milhão de fluxos benignos antes da agregação.",
            "E-mails por fluxo não são recomendados; os eventos devem ser agregados e deduplicados primeiro.",
            "O tráfego de validação do CICIDS não substitui tráfego temporalmente separado da rede-alvo.",
            "A precision medida no teste balanceado 50/50 não representa a precision de produção.",
        ],
        "parent_registry": parent_registry_reference or {},
    }

    registry = copy.deepcopy(parent_registry)
    if registry.get("status") != "completed":
        raise ValueError("O registro-pai de modelos não está concluído.")
    try:
        experiment_entry = registry["experiments"][experiment]
    except KeyError as exc:
        raise ValueError(f"Experimento ausente no registro-pai: {experiment}") from exc
    for model_key in MODEL_KEYS:
        model_entry = experiment_entry["models"][model_key]
        threshold_entry = copy.deepcopy(selections[model_key][target])
        threshold_entry.update(
            {
                "operating_point": OPERATIONAL_POINT,
                "selected_model_for_operation": model_key == recommended_model,
            }
        )
        model_entry["thresholds"][OPERATIONAL_POINT] = threshold_entry
        for split, metrics in (
            ("validation", validation_metrics[model_key][target]),
            ("test", test_metrics[model_key][target]),
        ):
            model_entry["validation_and_test_metrics"][split]["operating_points"][
                OPERATIONAL_POINT
            ] = metrics
    registry["schema_version"] = 2
    registry["stage"] = "operational_model_registry_post_marco_11"
    registry["created_at_utc"] = created
    registry["parent_registry"] = parent_registry_reference or {}
    registry["operational_methodology"] = report["methodology"]
    registry["recommended_operational_candidate"] = report["recommendation"]
    registry.setdefault("warnings", []).extend(report["operational_warnings"])
    return OperationalCalibrationResult(report, registry, sensitivity_rows)


def _write_sensitivity_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    fields = list(rows[0])
    with temporary.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    os.replace(temporary, path)


def _plot_tradeoff(path: Path, rows: list[dict[str, Any]], target_fpr: float) -> None:
    test_rows = [row for row in rows if row["split"] == "test"]
    figure, axis = plt.subplots(figsize=(9, 5.5))
    colors = {"isolation_forest": "#1f77b4", "lof": "#d62728"}
    for model_key in MODEL_KEYS:
        selected = sorted(
            (row for row in test_rows if row["model"] == model_key),
            key=lambda row: row["target_false_positive_rate"],
        )
        axis.plot(
            [100.0 * row["false_positive_rate"] for row in selected],
            [100.0 * row["recall_tpr"] for row in selected],
            marker="o",
            linewidth=2,
            color=colors[model_key],
            label=MODEL_LABELS[model_key],
        )
    axis.axvline(100.0 * target_fpr, color="black", linestyle="--", label="FPR-alvo")
    axis.set_xlabel("FPR observado no teste (%)")
    axis.set_ylabel("Recall de ataques no teste (%)")
    axis.set_title("Trade-off operacional entre falsos positivos e detecção")
    axis.grid(alpha=0.25)
    axis.legend()
    figure.tight_layout()
    path.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(path, dpi=170, bbox_inches="tight")
    plt.close(figure)


def _summary_markdown(report: dict[str, Any]) -> str:
    recommendation = report["recommendation"]
    target = report["methodology"]["target_false_positive_rate"]
    lines = [
        "# Calibração operacional do limiar",
        "",
        "## Decisão",
        "",
        (
            f"O candidato recomendado é **{recommendation['model_display_name']}** "
            f"no ponto `{recommendation['operating_point']}`, com limiar "
            f"`{recommendation['threshold']:.12g}` e FPR-alvo de `{target:.2%}`."
        ),
        "",
        "A recomendação maximiza o recall de validação entre os modelos que "
        "respeitam o mesmo teto de falsos positivos. Ela não usa o teste para "
        "escolher o limiar nem para escolher o modelo.",
        "",
        "## Resultado no ponto de 1%",
        "",
        "| Modelo | Limiar | FPR teste | Precision teste | Recall teste | F1 teste |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for model_key in MODEL_KEYS:
        point = report["models"][model_key]["selected_operating_point"]
        metrics = point["test_metrics"]
        lines.append(
            f"| {MODEL_LABELS[model_key]} | {point['selection']['threshold']:.12g} "
            f"| {metrics['false_positive_rate']:.2%} "
            f"| {metrics['precision']:.2%} | {metrics['recall_tpr']:.2%} "
            f"| {metrics['f1_score']:.2%} |"
        )
    lines.extend(
        [
            "",
            "## Limitações operacionais",
            "",
            *[f"- {warning}" for warning in report["operational_warnings"]],
            "",
            "Este é um candidato de laboratório, não uma aprovação de produção. "
            "O próximo ajuste deve usar uma janela temporal de tráfego benigno da "
            "rede-alvo e um orçamento real de alertas por hora/dia.",
            "",
        ]
    )
    return "\n".join(lines)


def run_operational_calibration(
    *,
    project_root: Path = PROJECT_ROOT,
    output_dir: Path | None = None,
    target_fpr: float = DEFAULT_OPERATIONAL_TARGET_FPR,
    sensitivity_fprs: Sequence[float] = DEFAULT_SENSITIVITY_FPRS,
    experiment: str = "expanded_100k",
    overwrite: bool = False,
) -> dict[str, Any]:
    """Executa a calibração sem retreinar ou recalcular previsões."""
    project_root = project_root.resolve()
    output_dir = (output_dir or project_root / "reports" / "operational").resolve()
    try:
        output_dir.relative_to(project_root)
    except ValueError as exc:
        raise ValueError("O destino deve permanecer dentro do projeto.") from exc
    paths = {key: output_dir / name for key, name in OUTPUT_FILENAMES.items()}
    existing = [path for path in paths.values() if path.exists()]
    if existing and not overwrite:
        raise FileExistsError(
            "A calibração operacional já existe; use --overwrite: "
            + ", ".join(str(path) for path in existing)
        )

    base = project_root / "experiments" / "scale_100k" / "data" / "evaluation"
    parent_registry_path = project_root / "reports" / "final" / "model_registry.json"
    validation_paths = {
        key: base / f"{key}_validation_evaluated.parquet" for key in MODEL_KEYS
    }
    test_paths = {key: base / f"{key}_test_evaluated.parquet" for key in MODEL_KEYS}
    sources = [parent_registry_path, *validation_paths.values(), *test_paths.values()]
    for path in sources:
        if not path.is_file():
            raise FileNotFoundError(f"Fonte obrigatória não encontrada: {path}")
    source_hashes_before = {
        _relative(path, project_root): _sha256_file(path) for path in sources
    }
    parent_reference = {
        "relative_path": _relative(parent_registry_path, project_root),
        "sha256": source_hashes_before[_relative(parent_registry_path, project_root)],
    }

    # Nenhum arquivo de teste é aberto antes de congelarmos limiares e modelo.
    validation_frames = {
        key: pd.read_parquet(path) for key, path in validation_paths.items()
    }
    frozen_at_utc = _utc_now()
    frozen_selection = _freeze_validation_selection(
        validation_frames,
        target_fpr=target_fpr,
        sensitivity_fprs=sensitivity_fprs,
        frozen_at_utc=frozen_at_utc,
    )
    test_frames = {key: pd.read_parquet(path) for key, path in test_paths.items()}
    result = build_operational_calibration(
        validation_frames,
        test_frames,
        _load_json(parent_registry_path),
        target_fpr=target_fpr,
        sensitivity_fprs=sensitivity_fprs,
        experiment=experiment,
        created_at_utc=frozen_at_utc,
        parent_registry_reference=parent_reference,
        frozen_selection=frozen_selection,
        test_opened_after_selection=True,
    )
    source_hashes_after = {
        _relative(path, project_root): _sha256_file(path) for path in sources
    }
    if source_hashes_before != source_hashes_after:
        raise RuntimeError("Uma fonte mudou durante a calibração operacional.")

    _write_json_atomic(paths["report"], result.report)
    _write_sensitivity_csv(paths["sensitivity"], result.sensitivity_rows)
    _plot_tradeoff(paths["figure"], result.sensitivity_rows, float(target_fpr))
    _write_json_atomic(paths["registry"], result.registry)
    _write_text_atomic(paths["summary"], _summary_markdown(result.report))
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
        "stage": "operational_threshold_calibration_post_marco_11",
        "created_at_utc": result.report["created_at_utc"],
        "status": "completed",
        "target_false_positive_rate": float(target_fpr),
        "recommendation": result.report["recommendation"],
        "source_integrity": {
            "hashes_before": source_hashes_before,
            "hashes_after": source_hashes_after,
            "unchanged": True,
        },
        "outputs": outputs,
        "validation": {
            "models_compared": list(MODEL_KEYS),
            "sensitivity_budget_count": len(
                set(float(value) for value in sensitivity_fprs) | {float(target_fpr)}
            ),
            "test_labels_used_for_selection": False,
            "previous_operating_points_preserved": True,
            "status": "passed",
        },
    }
    _write_json_atomic(paths["manifest"], manifest)
    return manifest


def format_operational_summary(manifest: dict[str, Any]) -> str:
    recommendation = manifest["recommendation"]
    return "\n".join(
        [
            "Calibração operacional concluída.",
            f"FPR-alvo: {manifest['target_false_positive_rate']:.2%}",
            (
                "Candidato recomendado: "
                f"{recommendation['model_display_name']} / "
                f"{recommendation['operating_point']}"
            ),
            f"Limiar: {recommendation['threshold']:.12g}",
            f"Fontes inalteradas: {manifest['source_integrity']['unchanged']}",
            f"Validação: {manifest['validation']['status']}",
        ]
    )
