"""Interface de linha de comando para a selecao de features do Marco 4."""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

import pandas as pd

from src.config import (
    DEFAULT_CORRELATION_THRESHOLD,
    DEFAULT_NEAR_CONSTANT_THRESHOLD,
    DEFAULT_RANDOM_STATE,
    METRICS_DIR,
    PROCESSED_DATA_DIR,
)
from src.feature_selection import (
    FeatureSelectionConfig,
    format_feature_selection_summary,
    save_feature_selection,
    select_features,
)
from src.utils import configure_logging, normalize_column_name


LOGGER = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    """Define os argumentos de entrada, analise e persistencia."""
    parser = argparse.ArgumentParser(
        description="Analisa e seleciona features processadas do CIC-IDS2017."
    )
    parser.add_argument(
        "--features-path",
        type=Path,
        default=PROCESSED_DATA_DIR / "monday_features.parquet",
    )
    parser.add_argument("--output-prefix", default=None)
    parser.add_argument("--output-dir", type=Path, default=PROCESSED_DATA_DIR)
    parser.add_argument("--report-dir", type=Path, default=METRICS_DIR)
    parser.add_argument(
        "--near-constant-threshold",
        type=float,
        default=DEFAULT_NEAR_CONSTANT_THRESHOLD,
    )
    parser.add_argument(
        "--correlation-threshold",
        type=float,
        default=DEFAULT_CORRELATION_THRESHOLD,
    )
    parser.add_argument(
        "--correlation-sample-size",
        type=int,
        default=None,
        help="Opcional; por padrao, usa todos os registros na correlacao.",
    )
    parser.add_argument("--keep-constant-features", action="store_true")
    parser.add_argument("--random-state", type=int, default=DEFAULT_RANDOM_STATE)
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args()


def _derive_prefix(features_path: Path, requested_prefix: str | None) -> str:
    """Deriva prefixo estavel, removendo o sufixo _features quando presente."""
    raw = requested_prefix or features_path.stem.removesuffix("_features")
    prefix = normalize_column_name(raw)
    if not prefix:
        raise ValueError("O prefixo de saida ficou vazio apos normalizacao.")
    return prefix


def main() -> int:
    """Carrega X, executa a politica e persiste o esquema selecionado."""
    args = parse_args()
    configure_logging(args.verbose)
    try:
        if not args.features_path.exists():
            raise FileNotFoundError(f"Arquivo de features nao encontrado: {args.features_path}")
        prefix = _derive_prefix(args.features_path, args.output_prefix)
        LOGGER.info("Lendo features processadas de %s", args.features_path.resolve())
        features = pd.read_parquet(args.features_path)
        config = FeatureSelectionConfig(
            near_constant_threshold=args.near_constant_threshold,
            correlation_threshold=args.correlation_threshold,
            correlation_sample_size=args.correlation_sample_size,
            random_state=args.random_state,
            drop_constant_features=not args.keep_constant_features,
        )
        result = select_features(features, config)
        result.report["source_features_path"] = str(args.features_path.resolve())
        result.manifest["source_features_path"] = str(args.features_path.resolve())

        selected_path = args.output_dir / f"{prefix}_selected_features.parquet"
        manifest_path = args.output_dir / f"{prefix}_feature_manifest.json"
        report_path = args.report_dir / f"{prefix}_feature_selection.json"
        save_feature_selection(
            result,
            selected_path=selected_path,
            manifest_path=manifest_path,
            report_path=report_path,
            overwrite=args.overwrite,
        )
        print(format_feature_selection_summary(result.report))
        LOGGER.info("Features selecionadas salvas em %s", selected_path.resolve())
        LOGGER.info("Manifesto salvo em %s", manifest_path.resolve())
        LOGGER.info("Relatorio salvo em %s", report_path.resolve())
        return 0
    except (FileNotFoundError, FileExistsError, ValueError) as exc:
        LOGGER.error("%s", exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
