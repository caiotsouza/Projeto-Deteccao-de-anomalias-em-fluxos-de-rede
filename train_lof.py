"""Interface de linha de comando para o Marco 8."""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

from src.config import (
    DEFAULT_LOF_ALGORITHM,
    DEFAULT_LOF_CONTAMINATION,
    DEFAULT_LOF_LEAF_SIZE,
    DEFAULT_LOF_METRIC,
    DEFAULT_LOF_N_NEIGHBORS,
    DEFAULT_LOF_P,
    METRICS_DIR,
    MODELS_DIR,
    PREDICTIONS_DIR,
    SPLITS_DIR,
)
from src.local_outlier_factor import LOFConfig, format_lof_summary, run_lof_training
from src.utils import configure_logging


LOGGER = logging.getLogger(__name__)


def parse_contamination(value: str) -> str | float:
    """Aceita a politica automatica ou uma fracao explicita."""
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
    """Define entradas X, hiperparametros e destinos do pipeline LOF."""
    parser = argparse.ArgumentParser(
        description=(
            "Treina StandardScaler + LOF com novelty=True e pontua somente "
            "validacao/teste, sem ler rotulos."
        )
    )
    parser.add_argument("--x-train-path", type=Path, default=SPLITS_DIR / "X_train.parquet")
    parser.add_argument(
        "--x-validation-path", type=Path, default=SPLITS_DIR / "X_validation.parquet"
    )
    parser.add_argument("--x-test-path", type=Path, default=SPLITS_DIR / "X_test.parquet")
    parser.add_argument(
        "--split-manifest-path", type=Path, default=SPLITS_DIR / "split_manifest.json"
    )
    parser.add_argument("--model-path", type=Path, default=MODELS_DIR / "lof.joblib")
    parser.add_argument(
        "--metadata-path", type=Path, default=MODELS_DIR / "lof_metadata.json"
    )
    parser.add_argument("--predictions-dir", type=Path, default=PREDICTIONS_DIR)
    parser.add_argument(
        "--report-path", type=Path, default=METRICS_DIR / "lof_training.json"
    )
    parser.add_argument("--n-neighbors", type=int, default=DEFAULT_LOF_N_NEIGHBORS)
    parser.add_argument(
        "--contamination",
        type=parse_contamination,
        default=DEFAULT_LOF_CONTAMINATION,
    )
    parser.add_argument(
        "--algorithm",
        choices=("auto", "ball_tree", "kd_tree", "brute"),
        default=DEFAULT_LOF_ALGORITHM,
    )
    parser.add_argument("--leaf-size", type=int, default=DEFAULT_LOF_LEAF_SIZE)
    parser.add_argument("--metric", default=DEFAULT_LOF_METRIC)
    parser.add_argument("--p", type=int, default=DEFAULT_LOF_P)
    parser.add_argument("--n-jobs", type=int, default=-1)
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args()


def main() -> int:
    """Treina o pipeline, pontua dados novos e salva os artefatos."""
    args = parse_args()
    configure_logging(args.verbose)
    try:
        config = LOFConfig(
            n_neighbors=args.n_neighbors,
            contamination=args.contamination,
            algorithm=args.algorithm,
            leaf_size=args.leaf_size,
            metric=args.metric,
            p=args.p,
            n_jobs=args.n_jobs,
        )
        result = run_lof_training(
            split_paths={
                "train": args.x_train_path,
                "validation": args.x_validation_path,
                "test": args.x_test_path,
            },
            manifest_path=args.split_manifest_path,
            model_path=args.model_path,
            metadata_path=args.metadata_path,
            predictions_dir=args.predictions_dir,
            report_path=args.report_path,
            config=config,
            overwrite=args.overwrite,
        )
        print(format_lof_summary(result.report))
        LOGGER.info("Pipeline salvo em %s", args.model_path.resolve())
        LOGGER.info("Previsoes sem rotulos salvas em %s", args.predictions_dir.resolve())
        LOGGER.info("Relatorio salvo em %s", args.report_path.resolve())
        return 0
    except (FileNotFoundError, FileExistsError, KeyError, ValueError) as exc:
        LOGGER.error("%s", exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
