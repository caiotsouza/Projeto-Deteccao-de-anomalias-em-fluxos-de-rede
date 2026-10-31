"""Interface de linha de comando para o Marco 6."""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

from src.config import (
    DEFAULT_IFOREST_CONTAMINATION,
    DEFAULT_IFOREST_MAX_FEATURES,
    DEFAULT_IFOREST_MAX_SAMPLES,
    DEFAULT_IFOREST_N_ESTIMATORS,
    DEFAULT_RANDOM_STATE,
    METRICS_DIR,
    MODELS_DIR,
    PREDICTIONS_DIR,
    SPLITS_DIR,
)
from src.isolation_forest import (
    IsolationForestConfig,
    format_training_summary,
    run_isolation_forest_training,
)
from src.utils import configure_logging


LOGGER = logging.getLogger(__name__)


def parse_contamination(value: str) -> str | float:
    """Aceita a politica automatica ou uma proporcao explicita."""
    if value.casefold() == "auto":
        return "auto"
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "use 'auto' ou um numero no intervalo (0, 0.5]"
        ) from exc
    if not 0.0 < parsed <= 0.5:
        raise argparse.ArgumentTypeError("o valor deve estar no intervalo (0, 0.5]")
    return parsed


def parse_args() -> argparse.Namespace:
    """Define entradas X, hiperparametros e destinos dos artefatos."""
    parser = argparse.ArgumentParser(
        description="Treina Isolation Forest somente com X_train, sem ler rotulos."
    )
    parser.add_argument("--x-train-path", type=Path, default=SPLITS_DIR / "X_train.parquet")
    parser.add_argument(
        "--x-validation-path", type=Path, default=SPLITS_DIR / "X_validation.parquet"
    )
    parser.add_argument("--x-test-path", type=Path, default=SPLITS_DIR / "X_test.parquet")
    parser.add_argument(
        "--split-manifest-path", type=Path, default=SPLITS_DIR / "split_manifest.json"
    )
    parser.add_argument(
        "--model-path", type=Path, default=MODELS_DIR / "isolation_forest.joblib"
    )
    parser.add_argument(
        "--metadata-path",
        type=Path,
        default=MODELS_DIR / "isolation_forest_metadata.json",
    )
    parser.add_argument("--predictions-dir", type=Path, default=PREDICTIONS_DIR)
    parser.add_argument(
        "--report-path",
        type=Path,
        default=METRICS_DIR / "isolation_forest_training.json",
    )
    parser.add_argument("--n-estimators", type=int, default=DEFAULT_IFOREST_N_ESTIMATORS)
    parser.add_argument("--max-samples", type=int, default=DEFAULT_IFOREST_MAX_SAMPLES)
    parser.add_argument(
        "--contamination",
        type=parse_contamination,
        default=DEFAULT_IFOREST_CONTAMINATION,
    )
    parser.add_argument("--max-features", type=float, default=DEFAULT_IFOREST_MAX_FEATURES)
    parser.add_argument("--bootstrap", action="store_true")
    parser.add_argument("--random-state", type=int, default=DEFAULT_RANDOM_STATE)
    parser.add_argument("--n-jobs", type=int, default=-1)
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args()


def main() -> int:
    """Treina, infere e salva o baseline sem acessar os arquivos y."""
    args = parse_args()
    configure_logging(args.verbose)
    split_paths = {
        "train": args.x_train_path,
        "validation": args.x_validation_path,
        "test": args.x_test_path,
    }
    try:
        config = IsolationForestConfig(
            n_estimators=args.n_estimators,
            max_samples=args.max_samples,
            contamination=args.contamination,
            max_features=args.max_features,
            bootstrap=args.bootstrap,
            random_state=args.random_state,
            n_jobs=args.n_jobs,
        )
        result = run_isolation_forest_training(
            split_paths=split_paths,
            manifest_path=args.split_manifest_path,
            model_path=args.model_path,
            metadata_path=args.metadata_path,
            predictions_dir=args.predictions_dir,
            report_path=args.report_path,
            config=config,
            overwrite=args.overwrite,
        )
        print(format_training_summary(result.report))
        LOGGER.info("Modelo salvo em %s", args.model_path.resolve())
        LOGGER.info("Previsoes sem rotulos salvas em %s", args.predictions_dir.resolve())
        LOGGER.info("Relatorio salvo em %s", args.report_path.resolve())
        return 0
    except (FileNotFoundError, FileExistsError, ValueError) as exc:
        LOGGER.error("%s", exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
