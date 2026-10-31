"""Interface de linha de comando para avaliar o Isolation Forest no Marco 7."""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

from src.config import (
    EVALUATION_DATA_DIR,
    FIGURES_DIR,
    METRICS_DIR,
    PREDICTIONS_DIR,
    SPLITS_DIR,
)
from src.evaluation import format_evaluation_summary, run_isolation_forest_evaluation
from src.utils import configure_logging


LOGGER = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    """Define previsoes congeladas, rotulos e destinos da avaliacao."""
    parser = argparse.ArgumentParser(
        description=(
            "Avalia previsoes congeladas do Isolation Forest e calibra o limiar "
            "somente na validacao."
        )
    )
    parser.add_argument(
        "--validation-predictions-path",
        type=Path,
        default=PREDICTIONS_DIR / "isolation_forest_validation_predictions.parquet",
    )
    parser.add_argument(
        "--test-predictions-path",
        type=Path,
        default=PREDICTIONS_DIR / "isolation_forest_test_predictions.parquet",
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
        "--training-report-path",
        type=Path,
        default=METRICS_DIR / "isolation_forest_training.json",
    )
    parser.add_argument(
        "--evaluation-data-dir", type=Path, default=EVALUATION_DATA_DIR
    )
    parser.add_argument(
        "--report-path",
        type=Path,
        default=METRICS_DIR / "isolation_forest_evaluation.json",
    )
    parser.add_argument("--figures-dir", type=Path, default=FIGURES_DIR)
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args()


def main() -> int:
    """Associa, calibra, avalia e persiste os resultados do Marco 7."""
    args = parse_args()
    configure_logging(args.verbose)
    try:
        result = run_isolation_forest_evaluation(
            prediction_paths={
                "validation": args.validation_predictions_path,
                "test": args.test_predictions_path,
            },
            label_paths={
                "validation": args.validation_labels_path,
                "test": args.test_labels_path,
            },
            training_report_path=args.training_report_path,
            evaluation_data_dir=args.evaluation_data_dir,
            report_path=args.report_path,
            figures_dir=args.figures_dir,
            overwrite=args.overwrite,
        )
        print(format_evaluation_summary(result.report))
        LOGGER.info("Relatorio salvo em %s", args.report_path.resolve())
        LOGGER.info("Dados avaliados salvos em %s", args.evaluation_data_dir.resolve())
        LOGGER.info("Figuras salvas em %s", args.figures_dir.resolve())
        return 0
    except (FileNotFoundError, FileExistsError, KeyError, ValueError) as exc:
        LOGGER.error("%s", exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
