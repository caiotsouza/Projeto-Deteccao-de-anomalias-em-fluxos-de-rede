"""Interface de linha de comando para o Marco 9."""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

from src.config import EVALUATION_DATA_DIR, FIGURES_DIR, METRICS_DIR, PREDICTIONS_DIR, SPLITS_DIR
from src.model_comparison import format_marco9_summary, run_marco9_comparison
from src.utils import configure_logging


LOGGER = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    """Define entradas congeladas e destinos da comparacao."""
    parser = argparse.ArgumentParser(
        description=(
            "Avalia as previsoes congeladas do LOF e compara LOF e Isolation "
            "Forest nos mesmos splits, sem usar o teste para ajuste."
        )
    )
    parser.add_argument(
        "--iforest-validation-predictions-path",
        type=Path,
        default=PREDICTIONS_DIR / "isolation_forest_validation_predictions.parquet",
    )
    parser.add_argument(
        "--iforest-test-predictions-path",
        type=Path,
        default=PREDICTIONS_DIR / "isolation_forest_test_predictions.parquet",
    )
    parser.add_argument(
        "--lof-validation-predictions-path",
        type=Path,
        default=PREDICTIONS_DIR / "lof_validation_predictions.parquet",
    )
    parser.add_argument(
        "--lof-test-predictions-path",
        type=Path,
        default=PREDICTIONS_DIR / "lof_test_predictions.parquet",
    )
    parser.add_argument(
        "--validation-labels-path",
        type=Path,
        default=SPLITS_DIR / "y_validation.parquet",
    )
    parser.add_argument(
        "--test-labels-path",
        type=Path,
        default=SPLITS_DIR / "y_test.parquet",
    )
    parser.add_argument(
        "--iforest-training-report-path",
        type=Path,
        default=METRICS_DIR / "isolation_forest_training.json",
    )
    parser.add_argument(
        "--lof-training-report-path",
        type=Path,
        default=METRICS_DIR / "lof_training.json",
    )
    parser.add_argument(
        "--prior-iforest-evaluation-path",
        type=Path,
        default=METRICS_DIR / "isolation_forest_evaluation.json",
    )
    parser.add_argument(
        "--evaluation-data-dir",
        type=Path,
        default=EVALUATION_DATA_DIR,
    )
    parser.add_argument("--metrics-dir", type=Path, default=METRICS_DIR)
    parser.add_argument("--figures-dir", type=Path, default=FIGURES_DIR)
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args()


def main() -> int:
    """Executa, persiste e resume a comparacao do Marco 9."""
    args = parse_args()
    configure_logging(args.verbose)
    try:
        result = run_marco9_comparison(
            prediction_paths={
                "isolation_forest": {
                    "validation": args.iforest_validation_predictions_path,
                    "test": args.iforest_test_predictions_path,
                },
                "lof": {
                    "validation": args.lof_validation_predictions_path,
                    "test": args.lof_test_predictions_path,
                },
            },
            label_paths={
                "validation": args.validation_labels_path,
                "test": args.test_labels_path,
            },
            training_report_paths={
                "isolation_forest": args.iforest_training_report_path,
                "lof": args.lof_training_report_path,
            },
            prior_iforest_evaluation_path=args.prior_iforest_evaluation_path,
            evaluation_data_dir=args.evaluation_data_dir,
            metrics_dir=args.metrics_dir,
            figures_dir=args.figures_dir,
            overwrite=args.overwrite,
        )
        print(format_marco9_summary(result.comparison_report))
        LOGGER.info("Relatorios e tabelas salvos em %s", args.metrics_dir.resolve())
        LOGGER.info("Dados avaliados salvos em %s", args.evaluation_data_dir.resolve())
        LOGGER.info("Figuras salvas em %s", args.figures_dir.resolve())
        return 0
    except (FileNotFoundError, FileExistsError, KeyError, ValueError) as exc:
        LOGGER.error("%s", exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
