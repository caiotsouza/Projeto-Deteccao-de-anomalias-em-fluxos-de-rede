"""Consolidacao auditavel de modelos, metricas e figuras do Marco 10."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import struct
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from src.config import PROJECT_ROOT


MODEL_KEYS = ("isolation_forest", "lof")
SPLITS = ("validation", "test")
OPERATING_POINTS = ("native", "validation_f1_calibrated")
MODEL_LABELS = {
    "isolation_forest": "Isolation Forest",
    "lof": "Local Outlier Factor",
}
EXPERIMENT_LABELS = {
    "baseline_20k": "Baseline 20k",
    "expanded_100k": "Expandido 100k",
}
METRIC_FIELDS = (
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
REQUIRED_REPORTS = (
    "data_split_report.json",
    "isolation_forest_training.json",
    "lof_training.json",
    "model_comparison.json",
)
FINAL_FILENAMES = {
    "inventory": "artifact_inventory.json",
    "registry": "model_registry.json",
    "metrics": "metrics_summary.csv",
    "figures": "figure_catalog.csv",
    "summary": "MARCO_10_SUMMARY.md",
    "manifest": "marco_10_manifest.json",
}
FIGURE_DESCRIPTIONS = {
    "isolation_forest_confusion_matrices": (
        "Matrizes de confusão do Isolation Forest nos pontos nativo e calibrado."
    ),
    "isolation_forest_roc_pr_curves": (
        "Curvas ROC e Precision-Recall do Isolation Forest."
    ),
    "isolation_forest_score_distributions": (
        "Distribuições do anomaly score por classe verdadeira."
    ),
    "model_comparison_attack_detection": (
        "Taxa de detecção por categoria de ataque nos dois modelos."
    ),
    "model_comparison_confusion_matrices": (
        "Matrizes de confusão comparativas do Isolation Forest e do LOF."
    ),
    "model_comparison_roc_pr_curves": (
        "Curvas ROC e Precision-Recall comparativas dos dois modelos."
    ),
    "model_comparison_test_metrics": (
        "Comparação das métricas operacionais no conjunto de teste."
    ),
    "scale_comparison_ranking": (
        "Comparação de ROC-AUC e Average Precision entre 20k e 100k."
    ),
    "scale_comparison_test_metrics": (
        "Efeito da escala nas métricas do conjunto de teste."
    ),
    "scale_comparison_timing": (
        "Comparação do custo computacional entre 20k e 100k."
    ),
}


@dataclass(frozen=True)
class ExperimentSpec:
    """Diretórios que compõem uma execução já concluída."""

    key: str
    label: str
    root: Path
    models_dir: Path
    metrics_dir: Path
    figures_dir: Path


def _utc_now() -> str:
    """Retorna o instante UTC no formato ISO 8601."""
    return datetime.now(timezone.utc).isoformat()


def _load_json(path: Path) -> dict[str, Any]:
    """Carrega um objeto JSON obrigatório."""
    if not path.is_file():
        raise FileNotFoundError(f"JSON obrigatório não encontrado: {path}")
    with path.open("r", encoding="utf-8") as file:
        data = json.load(file)
    if not isinstance(data, dict):
        raise ValueError(f"O JSON deve possuir um objeto na raiz: {path}")
    return data


def _sha256_file(path: Path) -> str:
    """Calcula SHA-256 em blocos para não duplicar arquivos grandes em memória."""
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for block in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _relative_path(path: Path, project_root: Path) -> str:
    """Converte um caminho em referência relativa e portátil dentro do projeto."""
    try:
        relative = path.resolve().relative_to(project_root.resolve())
    except ValueError as exc:
        raise ValueError(f"Artefato fora da raiz do projeto: {path}") from exc
    return relative.as_posix()


def _aggregate_digest(entries: Iterable[dict[str, Any]]) -> str:
    """Cria um digest único da lista ordenada de caminhos e hashes."""
    digest = hashlib.sha256()
    ordered = sorted(entries, key=lambda item: item["relative_path"])
    for entry in ordered:
        digest.update(entry["relative_path"].encode("utf-8"))
        digest.update(b"\0")
        digest.update(entry["sha256"].encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def _png_dimensions(path: Path) -> tuple[int, int]:
    """Lê largura e altura diretamente do cabeçalho PNG."""
    with path.open("rb") as file:
        header = file.read(24)
    if len(header) != 24 or header[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError(f"Figura não é um PNG válido: {path}")
    if header[12:16] != b"IHDR":
        raise ValueError(f"PNG sem bloco IHDR no início: {path}")
    width, height = struct.unpack(">II", header[16:24])
    if width <= 0 or height <= 0:
        raise ValueError(f"PNG possui dimensões inválidas: {path}")
    return int(width), int(height)


def _csv_metadata(path: Path) -> dict[str, Any]:
    """Obtém cabeçalho e quantidade de linhas sem depender de Pandas."""
    with path.open("r", encoding="utf-8-sig", newline="") as file:
        reader = csv.reader(file)
        try:
            columns = next(reader)
        except StopIteration as exc:
            raise ValueError(f"Tabela CSV vazia: {path}") from exc
        rows = sum(1 for _ in reader)
    if not columns:
        raise ValueError(f"Tabela CSV sem cabeçalho: {path}")
    return {"row_count": rows, "columns": columns}


def build_experiment_specs(
    project_root: Path = PROJECT_ROOT,
    include_scale_experiment: bool = True,
) -> list[ExperimentSpec]:
    """Monta as origens do baseline e, quando solicitado, do experimento 100k."""
    project_root = project_root.resolve()
    specs = [
        ExperimentSpec(
            key="baseline_20k",
            label=EXPERIMENT_LABELS["baseline_20k"],
            root=project_root,
            models_dir=project_root / "models",
            metrics_dir=project_root / "reports" / "metrics",
            figures_dir=project_root / "reports" / "figures",
        )
    ]
    if include_scale_experiment:
        scale_root = project_root / "experiments" / "scale_100k"
        specs.append(
            ExperimentSpec(
                key="expanded_100k",
                label=EXPERIMENT_LABELS["expanded_100k"],
                root=scale_root,
                models_dir=scale_root / "models",
                metrics_dir=scale_root / "metrics",
                figures_dir=scale_root / "figures",
            )
        )
    return specs


def _artifact_category(path: Path, spec: ExperimentSpec) -> str:
    """Classifica cada arquivo conforme sua função metodológica."""
    if path.parent == spec.models_dir and path.suffix.lower() == ".joblib":
        return "model"
    if path.parent == spec.models_dir and path.suffix.lower() == ".json":
        return "model_metadata"
    if path.is_relative_to(spec.metrics_dir) and path.suffix.lower() == ".json":
        return "metric_report"
    if path.is_relative_to(spec.metrics_dir) and path.suffix.lower() == ".csv":
        return "metric_table"
    if path.is_relative_to(spec.figures_dir) and path.suffix.lower() == ".png":
        return "figure"
    raise ValueError(f"Tipo de artefato não reconhecido: {path}")


def inspect_artifact(
    path: Path,
    spec: ExperimentSpec,
    project_root: Path,
) -> dict[str, Any]:
    """Inspeciona um arquivo sem modificar ou desserializar modelos."""
    if not path.is_file():
        raise FileNotFoundError(f"Artefato não encontrado: {path}")
    size = path.stat().st_size
    if size <= 0:
        raise ValueError(f"Artefato vazio: {path}")
    category = _artifact_category(path, spec)
    relative = _relative_path(path, project_root)
    entry: dict[str, Any] = {
        "artifact_id": f"{spec.key}:{category}:{relative}",
        "experiment": spec.key,
        "category": category,
        "relative_path": relative,
        "filename": path.name,
        "size_bytes": int(size),
        "sha256": _sha256_file(path),
        "integrity": "verified",
    }
    if category in {"metric_report", "model_metadata"}:
        data = _load_json(path)
        entry["json_metadata"] = {
            key: data[key]
            for key in ("schema_version", "stage", "status")
            if key in data
        }
    elif category == "metric_table":
        entry["csv_metadata"] = _csv_metadata(path)
    elif category == "figure":
        width, height = _png_dimensions(path)
        entry["image_metadata"] = {
            "format": "PNG",
            "width_pixels": width,
            "height_pixels": height,
        }
    return entry


def collect_artifacts(
    specs: Iterable[ExperimentSpec],
    project_root: Path,
) -> list[dict[str, Any]]:
    """Descobre somente modelos, relatórios, tabelas e figuras finais."""
    entries: list[dict[str, Any]] = []
    seen_paths: set[Path] = set()
    for spec in specs:
        for directory in (spec.models_dir, spec.metrics_dir, spec.figures_dir):
            if not directory.is_dir():
                raise FileNotFoundError(
                    f"Diretório obrigatório não encontrado: {directory}"
                )
        candidates = [
            *spec.models_dir.glob("*.joblib"),
            *spec.models_dir.glob("*.json"),
            *spec.metrics_dir.glob("*.json"),
            *spec.metrics_dir.glob("*.csv"),
            *spec.figures_dir.rglob("*.png"),
        ]
        for path in sorted(candidates, key=lambda item: str(item).lower()):
            resolved = path.resolve()
            if resolved in seen_paths:
                continue
            seen_paths.add(resolved)
            entries.append(inspect_artifact(resolved, spec, project_root))
    return sorted(entries, key=lambda item: (item["experiment"], item["relative_path"]))


def _find_entry(
    entries: Iterable[dict[str, Any]],
    experiment: str,
    relative_path: str,
) -> dict[str, Any]:
    """Localiza exatamente um item do inventário."""
    matches = [
        entry
        for entry in entries
        if entry["experiment"] == experiment
        and entry["relative_path"] == relative_path
    ]
    if len(matches) != 1:
        raise ValueError(
            f"Esperado um artefato para {experiment}:{relative_path}; "
            f"encontrados={len(matches)}"
        )
    return matches[0]


def _threshold_value(thresholds: dict[str, Any], point: str) -> float:
    """Extrai o valor numérico sem alterar a regra congelada."""
    if point == "native":
        value = thresholds[point]["equivalent_anomaly_score_threshold"]
    else:
        value = thresholds[point]["threshold"]
    return float(value)


def validate_experiment(
    spec: ExperimentSpec,
    entries: list[dict[str, Any]],
    project_root: Path,
) -> dict[str, Any]:
    """Confere proveniência, hashes, esquema, splits e congelamento de limiares."""
    for filename in REQUIRED_REPORTS:
        if not (spec.metrics_dir / filename).is_file():
            raise FileNotFoundError(
                f"Relatório obrigatório ausente em {spec.key}: {filename}"
            )
    split_report = _load_json(spec.metrics_dir / "data_split_report.json")
    comparison = _load_json(spec.metrics_dir / "model_comparison.json")
    if comparison.get("status") != "completed":
        raise ValueError(f"Comparação não concluída em {spec.key}.")
    methodology = comparison.get("methodology", {})
    required_guards = {
        "predictions_frozen_before_labels_loaded": True,
        "models_loaded": False,
        "models_refitted_or_modified": False,
        "test_labels_used_for_threshold_selection": False,
        "both_thresholds_frozen_before_test_labels_loaded": True,
    }
    for key, expected in required_guards.items():
        if methodology.get(key) is not expected:
            raise ValueError(
                f"Contrato metodológico inválido em {spec.key}: {key}"
            )
    leakage = split_report.get("leakage_checks", {})
    if leakage.get("status") != "passed":
        raise ValueError(f"Verificação de vazamento não aprovada em {spec.key}.")
    if any(int(value) != 0 for value in leakage.get("hash_overlaps", {}).values()):
        raise ValueError(f"Há sobreposição de hashes em {spec.key}.")
    if int(leakage.get("train_attack_records", -1)) != 0:
        raise ValueError(f"Treino contém ataques em {spec.key}.")
    schema_hash = str(leakage["model_input_schema_sha256"])

    model_audit: dict[str, Any] = {}
    for model_key in MODEL_KEYS:
        training_path = spec.metrics_dir / f"{model_key}_training.json"
        metadata_path = spec.models_dir / f"{model_key}_metadata.json"
        model_path = spec.models_dir / f"{model_key}.joblib"
        training = _load_json(training_path)
        metadata = _load_json(metadata_path)
        hash_key = (
            "model_sha256"
            if model_key == "isolation_forest"
            else "pipeline_sha256"
        )
        model_hash = _sha256_file(model_path)
        recorded_hashes = {training.get(hash_key), metadata.get(hash_key)}
        if recorded_hashes != {model_hash}:
            raise ValueError(
                f"Hash do modelo divergente em {spec.key}/{model_key}: "
                f"calculado={model_hash} registrados={recorded_hashes}"
            )
        metadata_schema = str(metadata.get("model_input_schema_sha256"))
        if metadata_schema != schema_hash:
            raise ValueError(f"Esquema divergente em {spec.key}/{model_key}.")
        if int(metadata.get("feature_count", -1)) != 60:
            raise ValueError(
                f"Quantidade de features inválida em {spec.key}/{model_key}."
            )
        comparison_model = comparison.get("models", {}).get(model_key, {})
        thresholds = comparison_model.get("thresholds", {})
        if set(thresholds) != set(OPERATING_POINTS):
            raise ValueError(
                f"Pontos operacionais incompletos em {spec.key}/{model_key}."
            )
        calibrated = thresholds["validation_f1_calibrated"]
        if calibrated.get("test_labels_used") is not False:
            raise ValueError(f"Limiar usa teste em {spec.key}/{model_key}.")
        for split in SPLITS:
            expected_records = int(split_report["outputs"][split]["records"])
            actual_records = int(comparison_model["splits"][split]["records"])
            if actual_records != expected_records:
                raise ValueError(
                    f"Contagem divergente em {spec.key}/{model_key}/{split}."
                )
        model_audit[model_key] = {
            "model_sha256": model_hash,
            "configuration_matches_metadata": (
                training.get("configuration") == metadata.get("configuration")
            ),
            "feature_count": 60,
            "schema_sha256": schema_hash,
            "thresholds_frozen": True,
        }
        if not model_audit[model_key]["configuration_matches_metadata"]:
            raise ValueError(f"Configuração divergente em {spec.key}/{model_key}.")
        _find_entry(
            entries,
            spec.key,
            _relative_path(model_path, project_root),
        )

    outputs = split_report["outputs"]
    return {
        "status": "passed",
        "model_input_schema_sha256": schema_hash,
        "split_records": {
            split: int(outputs[split]["records"])
            for split in ("train", "validation", "test")
        },
        "training_is_benign_only": int(leakage["train_attack_records"]) == 0,
        "zero_hash_overlap": True,
        "models": model_audit,
        "source_artifact_count": sum(
            entry["experiment"] == spec.key for entry in entries
        ),
    }


def build_model_registry(
    specs: Iterable[ExperimentSpec],
    entries: list[dict[str, Any]],
    audits: dict[str, dict[str, Any]],
    project_root: Path,
    created_at_utc: str,
) -> dict[str, Any]:
    """Cria o registro dos modelos e copia somente resultados já congelados."""
    experiments: dict[str, Any] = {}
    observed_candidates: list[dict[str, Any]] = []
    for spec in specs:
        split_report = _load_json(spec.metrics_dir / "data_split_report.json")
        comparison = _load_json(spec.metrics_dir / "model_comparison.json")
        models: dict[str, Any] = {}
        for model_key in MODEL_KEYS:
            training_path = spec.metrics_dir / f"{model_key}_training.json"
            model_path = spec.models_dir / f"{model_key}.joblib"
            metadata_path = spec.models_dir / f"{model_key}_metadata.json"
            training = _load_json(training_path)
            evaluated = comparison["models"][model_key]
            models[model_key] = {
                "display_name": MODEL_LABELS[model_key],
                "model_artifact": {
                    "relative_path": _relative_path(model_path, project_root),
                    "sha256": _sha256_file(model_path),
                    "size_bytes": model_path.stat().st_size,
                },
                "metadata_artifact": {
                    "relative_path": _relative_path(metadata_path, project_root),
                    "sha256": _sha256_file(metadata_path),
                },
                "training_report": {
                    "relative_path": _relative_path(training_path, project_root),
                    "sha256": _sha256_file(training_path),
                },
                "configuration": training["configuration"],
                "libraries": training["libraries"],
                "feature_count": 60,
                "model_input_schema_sha256": audits[spec.key][
                    "model_input_schema_sha256"
                ],
                "thresholds": evaluated["thresholds"],
                "validation_and_test_metrics": {
                    split: {
                        "records": evaluated["splits"][split]["records"],
                        "ranking_metrics": evaluated["splits"][split][
                            "ranking_metrics"
                        ],
                        "operating_points": evaluated["splits"][split][
                            "operating_points"
                        ],
                    }
                    for split in SPLITS
                },
                "timing_seconds": comparison["timing"]["by_model_seconds"][
                    model_key
                ],
            }
            for point in OPERATING_POINTS:
                metrics = evaluated["splits"]["test"]["operating_points"][point]
                observed_candidates.append(
                    {
                        "experiment": spec.key,
                        "model": model_key,
                        "operating_point": point,
                        "test_f1_score": float(metrics["f1_score"]),
                        "test_precision": float(metrics["precision"]),
                        "test_recall_tpr": float(metrics["recall_tpr"]),
                        "test_false_positive_rate": float(
                            metrics["false_positive_rate"]
                        ),
                    }
                )
        experiments[spec.key] = {
            "display_name": spec.label,
            "experiment_root": _relative_path(spec.root, project_root)
            if spec.root != project_root
            else ".",
            "split_records": {
                split: int(split_report["outputs"][split]["records"])
                for split in ("train", "validation", "test")
            },
            "model_input_schema_sha256": audits[spec.key][
                "model_input_schema_sha256"
            ],
            "models": models,
        }
    best = max(observed_candidates, key=lambda item: item["test_f1_score"])
    return {
        "schema_version": 1,
        "stage": "model_registry_marco_10",
        "created_at_utc": created_at_utc,
        "status": "completed",
        "methodology": {
            "models_loaded": False,
            "models_retrained": False,
            "predictions_recomputed": False,
            "metrics_recomputed": False,
            "thresholds_recalibrated": False,
            "source": "frozen Marco 9 comparison reports",
        },
        "experiments": experiments,
        "observed_best_test_f1": {
            **best,
            "interpretation": (
                "Descriptive result among already frozen candidates; it is not a "
                "production approval or a new threshold selection."
            ),
        },
        "warnings": [
            (
                "Validation and test use controlled 50/50 prevalence; production "
                "precision and alert volume will differ."
            ),
            (
                "The 20k-versus-100k experiment changed training and evaluation "
                "sample sizes together."
            ),
        ],
    }


def build_metrics_rows(registry: dict[str, Any]) -> list[dict[str, Any]]:
    """Transforma o registro em tabela longa de 16 combinações auditáveis."""
    rows: list[dict[str, Any]] = []
    for experiment_key, experiment in registry["experiments"].items():
        split_records = experiment["split_records"]
        for model_key, model in experiment["models"].items():
            for split in SPLITS:
                evaluated = model["validation_and_test_metrics"][split]
                ranking = evaluated["ranking_metrics"]
                for point in OPERATING_POINTS:
                    metrics = evaluated["operating_points"][point]
                    row: dict[str, Any] = {
                        "experiment": experiment_key,
                        "experiment_label": experiment["display_name"],
                        "train_records": split_records["train"],
                        "validation_records": split_records["validation"],
                        "test_records": split_records["test"],
                        "model": model_key,
                        "model_label": model["display_name"],
                        "split": split,
                        "operating_point": point,
                        "threshold": _threshold_value(model["thresholds"], point),
                        "records": int(evaluated["records"]),
                        "roc_auc": float(ranking["roc_auc"]),
                        "average_precision": float(ranking["average_precision"]),
                        "fit_seconds": float(model["timing_seconds"]["fit"]),
                        "inference_seconds": float(
                            model["timing_seconds"][f"inference_{split}"]
                        ),
                        "model_relative_path": model["model_artifact"][
                            "relative_path"
                        ],
                        "model_sha256": model["model_artifact"]["sha256"],
                    }
                    row.update({field: metrics[field] for field in METRIC_FIELDS})
                    rows.append(row)
    return rows


def build_figure_rows(entries: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Cria catálogo de figuras com dimensão, finalidade e integridade."""
    rows = []
    for entry in entries:
        if entry["category"] != "figure":
            continue
        stem = Path(entry["filename"]).stem
        rows.append(
            {
                "experiment": entry["experiment"],
                "experiment_label": EXPERIMENT_LABELS[entry["experiment"]],
                "relative_path": entry["relative_path"],
                "description": FIGURE_DESCRIPTIONS.get(
                    stem, "Figura científica produzida pelo pipeline."
                ),
                "width_pixels": entry["image_metadata"]["width_pixels"],
                "height_pixels": entry["image_metadata"]["height_pixels"],
                "size_bytes": entry["size_bytes"],
                "sha256": entry["sha256"],
            }
        )
    return sorted(rows, key=lambda item: (item["experiment"], item["relative_path"]))


def build_summary_markdown(
    inventory: dict[str, Any],
    registry: dict[str, Any],
    metrics_rows: list[dict[str, Any]],
    figure_rows: list[dict[str, Any]],
) -> str:
    """Gera uma leitura humana do fechamento sem recalcular resultados."""
    lines = [
        "# Marco 10 — inventário final de artefatos",
        "",
        "Status: **concluído**.",
        "",
        (
            "Este relatório cataloga os modelos, métricas, tabelas e gráficos já "
            "produzidos. Nenhum modelo foi carregado, retreinado ou modificado; "
            "nenhuma previsão, métrica ou calibração foi refeita."
        ),
        "",
        "## Integridade",
        "",
        f"- Artefatos de origem: {inventory['summary']['artifact_count']}",
        f"- Tamanho total indexado: {inventory['summary']['total_size_bytes']} bytes",
        f"- Figuras catalogadas: {len(figure_rows)}",
        f"- Modelos registrados: {len(registry['experiments']) * len(MODEL_KEYS)}",
        f"- Digest agregado: `{inventory['summary']['aggregate_sha256']}`",
        "",
        "## Modelos registrados",
        "",
        "| Experimento | Modelo | Treino | Modelo serializado |",
        "|---|---|---:|---|",
    ]
    for experiment in registry["experiments"].values():
        for model in experiment["models"].values():
            link = "../../" + model["model_artifact"]["relative_path"]
            lines.append(
                f"| {experiment['display_name']} | {model['display_name']} | "
                f"{experiment['split_records']['train']} | "
                f"[{Path(link).name}]({link}) |"
            )
    lines.extend(
        [
            "",
            "## Métricas no teste",
            "",
            "| Experimento | Modelo | Ponto | Precision | Recall | F1 | FPR |",
            "|---|---|---|---:|---:|---:|---:|",
        ]
    )
    for row in metrics_rows:
        if row["split"] != "test":
            continue
        point = "Nativo" if row["operating_point"] == "native" else "Calibrado F1"
        lines.append(
            f"| {row['experiment_label']} | {row['model_label']} | {point} | "
            f"{row['precision']:.4f} | {row['recall_tpr']:.4f} | "
            f"{row['f1_score']:.4f} | {row['false_positive_rate']:.4f} |"
        )
    best = registry["observed_best_test_f1"]
    lines.extend(
        [
            "",
            "## Leitura do resultado",
            "",
            (
                f"O maior F1 observado entre os candidatos já congelados foi "
                f"`{best['test_f1_score']:.4f}`: "
                f"{EXPERIMENT_LABELS[best['experiment']]}, "
                f"{MODEL_LABELS[best['model']]}, ponto "
                f"`{best['operating_point']}`. Isso é uma descrição do teste, "
                "não uma aprovação automática para produção."
            ),
            "",
            (
                "Os conjuntos de validação e teste têm prevalência controlada de "
                "50% de ataques. Antes de implantação, o limiar deve ser validado "
                "com a prevalência e o orçamento de alertas da rede real."
            ),
            "",
            "## Arquivos deste fechamento",
            "",
            "- `artifact_inventory.json`: caminho, tamanho, SHA-256 e metadados.",
            "- `model_registry.json`: configuração, limiares, métricas e tempos.",
            "- `metrics_summary.csv`: tabela longa com 16 combinações.",
            "- `figure_catalog.csv`: finalidade, dimensões e hash das figuras.",
            "- `marco_10_manifest.json`: prova de imutabilidade e hashes das saídas.",
            "",
        ]
    )
    return "\n".join(lines)


def _write_text_atomic(path: Path, text: str) -> None:
    """Escreve texto por substituição atômica dentro do destino final."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(text, encoding="utf-8")
    os.replace(temporary, path)


def _write_json_atomic(path: Path, data: dict[str, Any]) -> None:
    """Persiste JSON UTF-8 por substituição atômica."""
    _write_text_atomic(
        path,
        json.dumps(data, ensure_ascii=False, indent=2) + "\n",
    )


def _write_csv_atomic(path: Path, rows: list[dict[str, Any]]) -> None:
    """Persiste uma tabela com cabeçalho estável por substituição atômica."""
    if not rows:
        raise ValueError(f"Não é possível salvar tabela vazia: {path}")
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(
        buffer,
        fieldnames=list(rows[0]),
        lineterminator="\n",
    )
    writer.writeheader()
    writer.writerows(rows)
    _write_text_atomic(path, buffer.getvalue())


def run_marco10(
    project_root: Path = PROJECT_ROOT,
    output_dir: Path | None = None,
    include_scale_experiment: bool = True,
    overwrite: bool = False,
) -> dict[str, Any]:
    """Executa o fechamento documental do Marco 10 sem tocar nas fontes."""
    project_root = project_root.resolve()
    default_output_dir = project_root / "reports" / "final"
    output_dir = (output_dir or default_output_dir).resolve()
    try:
        output_dir.relative_to(project_root)
    except ValueError as exc:
        raise ValueError(
            "O diretório final deve ficar dentro da raiz do projeto."
        ) from exc

    specs = build_experiment_specs(project_root, include_scale_experiment)
    source_directories = {
        directory.resolve()
        for spec in specs
        for directory in (spec.models_dir, spec.metrics_dir, spec.figures_dir)
    }
    if any(
        output_dir == directory or output_dir.is_relative_to(directory)
        for directory in source_directories
    ):
        raise ValueError(
            "O diretório final não pode ficar dentro de uma pasta de artefatos "
            "de origem."
        )
    output_paths = {
        key: output_dir / filename for key, filename in FINAL_FILENAMES.items()
    }
    existing = [path for path in output_paths.values() if path.exists()]
    if existing and not overwrite:
        raise FileExistsError(
            "Marco 10 já possui artefatos; use --overwrite para substituir: "
            + ", ".join(str(path) for path in existing)
        )

    entries = collect_artifacts(specs, project_root)
    if not entries:
        raise ValueError("Nenhum artefato foi localizado para o Marco 10.")
    created_at = _utc_now()
    audits = {
        spec.key: validate_experiment(spec, entries, project_root) for spec in specs
    }
    counts_by_category = Counter(entry["category"] for entry in entries)
    counts_by_experiment = Counter(entry["experiment"] for entry in entries)
    source_digest_before = _aggregate_digest(entries)
    inventory = {
        "schema_version": 1,
        "stage": "artifact_inventory_marco_10",
        "created_at_utc": created_at,
        "status": "completed",
        "scope": {
            "included": [
                "serialized models",
                "model metadata",
                "metric reports",
                "metric tables",
                "scientific figures",
            ],
            "excluded": [
                "raw CSV datasets",
                "processed feature matrices",
                "predictions and evaluated Parquets",
                "Marco 10 output files themselves",
            ],
            "reason": (
                "Marco 10 consolidates final models, metrics and figures without "
                "duplicating large intermediate datasets."
            ),
        },
        "summary": {
            "artifact_count": len(entries),
            "total_size_bytes": sum(entry["size_bytes"] for entry in entries),
            "counts_by_category": dict(sorted(counts_by_category.items())),
            "counts_by_experiment": dict(sorted(counts_by_experiment.items())),
            "aggregate_sha256": source_digest_before,
        },
        "experiment_validation": audits,
        "artifacts": entries,
    }
    registry = build_model_registry(
        specs, entries, audits, project_root, created_at
    )
    metrics_rows = build_metrics_rows(registry)
    figure_rows = build_figure_rows(entries)
    if len(metrics_rows) != len(specs) * len(MODEL_KEYS) * len(SPLITS) * len(
        OPERATING_POINTS
    ):
        raise ValueError("Tabela final não contém todas as combinações esperadas.")

    source_entries_after = collect_artifacts(specs, project_root)
    source_digest_after = _aggregate_digest(source_entries_after)
    if source_digest_after != source_digest_before:
        raise RuntimeError("Um artefato de origem mudou durante o inventário.")

    _write_json_atomic(output_paths["inventory"], inventory)
    _write_json_atomic(output_paths["registry"], registry)
    _write_csv_atomic(output_paths["metrics"], metrics_rows)
    _write_csv_atomic(output_paths["figures"], figure_rows)
    _write_text_atomic(
        output_paths["summary"],
        build_summary_markdown(inventory, registry, metrics_rows, figure_rows),
    )

    persisted_outputs = {
        key: {
            "relative_path": _relative_path(path, project_root),
            "size_bytes": path.stat().st_size,
            "sha256": _sha256_file(path),
        }
        for key, path in output_paths.items()
        if key != "manifest"
    }
    manifest = {
        "schema_version": 1,
        "stage": "marco_10_final_artifact_consolidation",
        "created_at_utc": created_at,
        "status": "completed",
        "methodology": {
            "models_loaded": False,
            "models_retrained": False,
            "models_modified": False,
            "predictions_recomputed": False,
            "metrics_recomputed": False,
            "thresholds_recalibrated": False,
            "source_artifacts_modified": False,
            "large_artifacts_duplicated": False,
        },
        "source_integrity": {
            "artifact_count": len(entries),
            "aggregate_sha256_before": source_digest_before,
            "aggregate_sha256_after": source_digest_after,
            "unchanged": source_digest_before == source_digest_after,
            "experiments": audits,
        },
        "validation": {
            "all_sources_non_empty": True,
            "all_model_hashes_match_training_reports_and_metadata": True,
            "all_feature_schemas_match": True,
            "all_split_leakage_checks_passed": True,
            "all_thresholds_frozen_before_test": True,
            "metrics_summary_rows": len(metrics_rows),
            "figure_catalog_rows": len(figure_rows),
            "status": "passed",
        },
        "outputs": persisted_outputs,
    }
    _write_json_atomic(output_paths["manifest"], manifest)
    return manifest


def format_marco10_summary(manifest: dict[str, Any]) -> str:
    """Resume o resultado do Marco 10 para o terminal."""
    source = manifest["source_integrity"]
    validation = manifest["validation"]
    return "\n".join(
        [
            "Marco 10 concluído.",
            f"Artefatos de origem inventariados: {source['artifact_count']}",
            f"Modelos preservados: {len(source['experiments']) * len(MODEL_KEYS)}",
            f"Linhas da tabela de métricas: {validation['metrics_summary_rows']}",
            f"Figuras catalogadas: {validation['figure_catalog_rows']}",
            f"Fontes inalteradas: {source['unchanged']}",
            f"Validação: {validation['status']}",
        ]
    )
