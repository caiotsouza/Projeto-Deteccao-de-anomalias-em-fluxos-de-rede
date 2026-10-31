"""Executa o experimento isolado de escala 100k e compara com o baseline."""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from src.config import (
    DEFAULT_IFOREST_CONTAMINATION,
    DEFAULT_IFOREST_MAX_FEATURES,
    DEFAULT_IFOREST_MAX_SAMPLES,
    DEFAULT_IFOREST_N_ESTIMATORS,
    DEFAULT_LOF_ALGORITHM,
    DEFAULT_LOF_CONTAMINATION,
    DEFAULT_LOF_LEAF_SIZE,
    DEFAULT_LOF_METRIC,
    DEFAULT_LOF_N_NEIGHBORS,
    DEFAULT_LOF_P,
    DEFAULT_RANDOM_STATE,
    DEFAULT_SPLIT_CHUNK_SIZE,
    METRICS_DIR,
    PROCESSED_DATA_DIR,
    PROJECT_ROOT,
    RAW_DATA_DIR,
)
from src.data_split import SplitConfig, build_data_splits, save_data_splits
from src.evaluation import run_isolation_forest_evaluation
from src.isolation_forest import IsolationForestConfig, run_isolation_forest_training
from src.local_outlier_factor import LOFConfig, run_lof_training
from src.model_comparison import run_marco9_comparison
from src.scale_experiment import format_scale_summary, run_scale_comparison
from src.utils import configure_logging, save_json


LOGGER = logging.getLogger(__name__)


def _sha256_file(path: Path) -> str:
    """Calcula SHA-256 em blocos."""
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for block in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _timed_stage(
    name: str,
    function: Callable[[], Any],
    timings: dict[str, float],
) -> Any:
    """Executa uma etapa e registra seu tempo de parede."""
    LOGGER.info("Iniciando etapa: %s", name)
    started = time.perf_counter()
    result = function()
    timings[name] = float(time.perf_counter() - started)
    LOGGER.info("Etapa concluida: %s (%.3f s)", name, timings[name])
    return result


def parse_args() -> argparse.Namespace:
    """Define a raiz isolada do experimento e politicas de escrita."""
    parser = argparse.ArgumentParser(
        description=(
            "Cria splits cinco vezes maiores, treina IF/LOF com os mesmos "
            "hiperparametros e compara com o baseline 20k."
        )
    )
    parser.add_argument(
        "--experiment-dir",
        type=Path,
        default=PROJECT_ROOT / "experiments" / "scale_100k",
    )
    parser.add_argument("--chunk-size", type=int, default=DEFAULT_SPLIT_CHUNK_SIZE)
    parser.add_argument("--n-jobs", type=int, default=-1)
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args()


def run_experiment(
    experiment_dir: Path,
    chunk_size: int = DEFAULT_SPLIT_CHUNK_SIZE,
    n_jobs: int = -1,
    overwrite: bool = False,
) -> dict[str, Any]:
    """Executa todas as etapas sem escrever nos destinos do baseline."""
    experiment_dir = experiment_dir.resolve()
    splits_dir = experiment_dir / "data" / "splits"
    predictions_dir = experiment_dir / "data" / "predictions"
    evaluation_dir = experiment_dir / "data" / "evaluation"
    models_dir = experiment_dir / "models"
    metrics_dir = experiment_dir / "metrics"
    iforest_figures_dir = experiment_dir / "figures" / "isolation_forest"
    model_figures_dir = experiment_dir / "figures" / "model_comparison"
    scale_figures_dir = experiment_dir / "figures" / "scale_comparison"
    manifest_path = experiment_dir / "experiment_manifest.json"
    if manifest_path.exists() and not overwrite:
        raise FileExistsError(
            f"Experimento ja concluido: {manifest_path}. Use --overwrite para repetir."
        )

    baseline_paths = {
        "isolation_forest_model": PROJECT_ROOT / "models" / "isolation_forest.joblib",
        "lof_model": PROJECT_ROOT / "models" / "lof.joblib",
        "split_report": METRICS_DIR / "data_split_report.json",
        "comparison_report": METRICS_DIR / "model_comparison.json",
    }
    missing_baseline = [path for path in baseline_paths.values() if not path.is_file()]
    if missing_baseline:
        raise FileNotFoundError(f"Baseline incompleto: {missing_baseline}")
    baseline_hashes_before = {
        name: _sha256_file(path) for name, path in baseline_paths.items()
    }

    monday_features_path = PROCESSED_DATA_DIR / "monday_selected_features.parquet"
    monday_labels_path = PROCESSED_DATA_DIR / "monday_labels.parquet"
    feature_manifest_path = PROCESSED_DATA_DIR / "monday_feature_manifest.json"
    required_inputs = (
        monday_features_path,
        monday_labels_path,
        feature_manifest_path,
    )
    missing_inputs = [path for path in required_inputs if not path.is_file()]
    if missing_inputs:
        raise FileNotFoundError(f"Entradas processadas ausentes: {missing_inputs}")
    external_files = sorted(
        path
        for path in RAW_DATA_DIR.glob("*.csv")
        if path.is_file() and not path.name.lower().startswith("monday")
    )
    if not external_files:
        raise FileNotFoundError("Nenhum CSV externo ao Monday foi encontrado.")

    split_config = SplitConfig(
        train_benign_size=100_000,
        validation_benign_size=25_000,
        validation_attack_size=25_000,
        test_benign_size=50_000,
        test_attack_size=50_000,
        minimum_attack_per_split=5,
        chunk_size=chunk_size,
        random_state=DEFAULT_RANDOM_STATE,
    )
    iforest_config = IsolationForestConfig(
        n_estimators=DEFAULT_IFOREST_N_ESTIMATORS,
        max_samples=DEFAULT_IFOREST_MAX_SAMPLES,
        contamination=DEFAULT_IFOREST_CONTAMINATION,
        max_features=DEFAULT_IFOREST_MAX_FEATURES,
        bootstrap=False,
        random_state=DEFAULT_RANDOM_STATE,
        n_jobs=n_jobs,
    )
    lof_config = LOFConfig(
        n_neighbors=DEFAULT_LOF_N_NEIGHBORS,
        contamination=DEFAULT_LOF_CONTAMINATION,
        algorithm=DEFAULT_LOF_ALGORITHM,
        leaf_size=DEFAULT_LOF_LEAF_SIZE,
        metric=DEFAULT_LOF_METRIC,
        p=DEFAULT_LOF_P,
        n_jobs=n_jobs,
    )

    timings: dict[str, float] = {}
    split_result = _timed_stage(
        "create_splits",
        lambda: build_data_splits(
            monday_features_path=monday_features_path,
            monday_labels_path=monday_labels_path,
            feature_manifest_path=feature_manifest_path,
            external_csv_files=external_files,
            config=split_config,
        ),
        timings,
    )
    _timed_stage(
        "save_splits",
        lambda: save_data_splits(
            split_result,
            output_dir=splits_dir,
            report_path=metrics_dir / "data_split_report.json",
            overwrite=overwrite,
        ),
        timings,
    )
    split_paths = {
        "train": splits_dir / "X_train.parquet",
        "validation": splits_dir / "X_validation.parquet",
        "test": splits_dir / "X_test.parquet",
    }
    label_paths = {
        "validation": splits_dir / "y_validation.parquet",
        "test": splits_dir / "y_test.parquet",
    }

    iforest_training = _timed_stage(
        "train_isolation_forest",
        lambda: run_isolation_forest_training(
            split_paths=split_paths,
            manifest_path=splits_dir / "split_manifest.json",
            model_path=models_dir / "isolation_forest.joblib",
            metadata_path=models_dir / "isolation_forest_metadata.json",
            predictions_dir=predictions_dir,
            report_path=metrics_dir / "isolation_forest_training.json",
            config=iforest_config,
            overwrite=overwrite,
        ),
        timings,
    )
    lof_training = _timed_stage(
        "train_lof",
        lambda: run_lof_training(
            split_paths=split_paths,
            manifest_path=splits_dir / "split_manifest.json",
            model_path=models_dir / "lof.joblib",
            metadata_path=models_dir / "lof_metadata.json",
            predictions_dir=predictions_dir,
            report_path=metrics_dir / "lof_training.json",
            config=lof_config,
            overwrite=overwrite,
        ),
        timings,
    )

    _timed_stage(
        "evaluate_isolation_forest",
        lambda: run_isolation_forest_evaluation(
            prediction_paths={
                "validation": predictions_dir
                / "isolation_forest_validation_predictions.parquet",
                "test": predictions_dir / "isolation_forest_test_predictions.parquet",
            },
            label_paths=label_paths,
            training_report_path=metrics_dir / "isolation_forest_training.json",
            evaluation_data_dir=evaluation_dir,
            report_path=metrics_dir / "isolation_forest_evaluation.json",
            figures_dir=iforest_figures_dir,
            overwrite=overwrite,
        ),
        timings,
    )
    expanded_comparison = _timed_stage(
        "evaluate_and_compare_models",
        lambda: run_marco9_comparison(
            prediction_paths={
                "isolation_forest": {
                    "validation": predictions_dir
                    / "isolation_forest_validation_predictions.parquet",
                    "test": predictions_dir
                    / "isolation_forest_test_predictions.parquet",
                },
                "lof": {
                    "validation": predictions_dir / "lof_validation_predictions.parquet",
                    "test": predictions_dir / "lof_test_predictions.parquet",
                },
            },
            label_paths=label_paths,
            training_report_paths={
                "isolation_forest": metrics_dir
                / "isolation_forest_training.json",
                "lof": metrics_dir / "lof_training.json",
            },
            prior_iforest_evaluation_path=metrics_dir
            / "isolation_forest_evaluation.json",
            evaluation_data_dir=evaluation_dir,
            metrics_dir=metrics_dir,
            figures_dir=model_figures_dir,
            overwrite=overwrite,
        ),
        timings,
    )
    scale_comparison = _timed_stage(
        "compare_20k_and_100k",
        lambda: run_scale_comparison(
            baseline_comparison_path=baseline_paths["comparison_report"],
            expanded_comparison_path=metrics_dir / "model_comparison.json",
            baseline_split_report_path=baseline_paths["split_report"],
            expanded_split_report_path=metrics_dir / "data_split_report.json",
            metrics_dir=metrics_dir,
            figures_dir=scale_figures_dir,
            overwrite=overwrite,
        ),
        timings,
    )

    baseline_hashes_after = {
        name: _sha256_file(path) for name, path in baseline_paths.items()
    }
    if baseline_hashes_before != baseline_hashes_after:
        raise RuntimeError("Um artefato do baseline foi alterado durante o experimento.")
    manifest = {
        "schema_version": 1,
        "stage": "scale_100k_experiment",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "completed",
        "experiment_dir": str(experiment_dir),
        "configuration": {
            "splits": split_result.report["configuration"],
            "isolation_forest": iforest_training.report["configuration"],
            "lof": lof_training.report["configuration"],
        },
        "outputs": split_result.report["outputs"],
        "baseline_integrity": {
            "hashes_before": baseline_hashes_before,
            "hashes_after": baseline_hashes_after,
            "unchanged": True,
        },
        "stage_wall_clock_seconds": timings,
        "reports": {
            "expanded_model_comparison": str(
                (metrics_dir / "model_comparison.json").resolve()
            ),
            "scale_comparison": str(
                (metrics_dir / "scale_comparison.json").resolve()
            ),
        },
        "expanded_status": expanded_comparison.comparison_report["status"],
        "scale_comparison_status": scale_comparison.report["status"],
    }
    save_json(manifest, manifest_path)
    return manifest


def main() -> int:
    """Executa o experimento completo e apresenta os deltas centrais."""
    args = parse_args()
    configure_logging(args.verbose)
    try:
        manifest = run_experiment(
            experiment_dir=args.experiment_dir,
            chunk_size=args.chunk_size,
            n_jobs=args.n_jobs,
            overwrite=args.overwrite,
        )
        scale_report_path = Path(manifest["reports"]["scale_comparison"])
        with scale_report_path.open("r", encoding="utf-8") as file:
            scale_report = json.load(file)
        print(format_scale_summary(scale_report))
        LOGGER.info("Experimento concluido em %s", args.experiment_dir.resolve())
        return 0
    except (
        FileNotFoundError,
        FileExistsError,
        KeyError,
        RuntimeError,
        ValueError,
    ) as exc:
        LOGGER.error("%s", exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
