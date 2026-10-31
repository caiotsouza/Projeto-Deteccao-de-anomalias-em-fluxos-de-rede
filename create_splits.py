"""Interface de linha de comando para o Marco 5."""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

from src.config import (
    DEFAULT_MINIMUM_ATTACK_PER_SPLIT,
    DEFAULT_RANDOM_STATE,
    DEFAULT_SPLIT_CHUNK_SIZE,
    DEFAULT_TEST_ATTACK_SIZE,
    DEFAULT_TEST_BENIGN_SIZE,
    DEFAULT_TRAIN_BENIGN_SIZE,
    DEFAULT_VALIDATION_ATTACK_SIZE,
    DEFAULT_VALIDATION_BENIGN_SIZE,
    METRICS_DIR,
    PROCESSED_DATA_DIR,
    RAW_DATA_DIR,
)
from src.data_split import SplitConfig, build_data_splits, format_split_summary, save_data_splits
from src.utils import configure_logging


LOGGER = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    """Define fontes, tamanhos do experimento e destinos."""
    parser = argparse.ArgumentParser(
        description="Cria treino BENIGN e validacao/teste com BENIGN e ataques."
    )
    parser.add_argument(
        "--monday-features-path",
        type=Path,
        default=PROCESSED_DATA_DIR / "monday_selected_features.parquet",
    )
    parser.add_argument(
        "--monday-labels-path",
        type=Path,
        default=PROCESSED_DATA_DIR / "monday_labels.parquet",
    )
    parser.add_argument(
        "--feature-manifest-path",
        type=Path,
        default=PROCESSED_DATA_DIR / "monday_feature_manifest.json",
    )
    parser.add_argument("--raw-data-dir", type=Path, default=RAW_DATA_DIR)
    parser.add_argument("--external-pattern", default="*.csv")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=PROCESSED_DATA_DIR / "splits",
    )
    parser.add_argument(
        "--report-path",
        type=Path,
        default=METRICS_DIR / "data_split_report.json",
    )
    parser.add_argument("--train-benign-size", type=int, default=DEFAULT_TRAIN_BENIGN_SIZE)
    parser.add_argument(
        "--validation-benign-size", type=int, default=DEFAULT_VALIDATION_BENIGN_SIZE
    )
    parser.add_argument(
        "--validation-attack-size", type=int, default=DEFAULT_VALIDATION_ATTACK_SIZE
    )
    parser.add_argument("--test-benign-size", type=int, default=DEFAULT_TEST_BENIGN_SIZE)
    parser.add_argument("--test-attack-size", type=int, default=DEFAULT_TEST_ATTACK_SIZE)
    parser.add_argument(
        "--minimum-attack-per-split",
        type=int,
        default=DEFAULT_MINIMUM_ATTACK_PER_SPLIT,
    )
    parser.add_argument("--chunk-size", type=int, default=DEFAULT_SPLIT_CHUNK_SIZE)
    parser.add_argument("--random-state", type=int, default=DEFAULT_RANDOM_STATE)
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args()


def main() -> int:
    """Localiza dias externos, constroi, verifica e salva os conjuntos."""
    args = parse_args()
    configure_logging(args.verbose)
    try:
        required = (
            args.monday_features_path,
            args.monday_labels_path,
            args.feature_manifest_path,
        )
        missing = [path for path in required if not path.exists()]
        if missing:
            raise FileNotFoundError(f"Artefatos obrigatorios ausentes: {missing}")
        external_files = sorted(
            path
            for path in args.raw_data_dir.glob(args.external_pattern)
            if path.is_file() and not path.name.lower().startswith("monday")
        )
        if not external_files:
            raise FileNotFoundError("Nenhum CSV nao-Monday foi encontrado.")
        LOGGER.info("CSVs externos (%s): %s", len(external_files), ", ".join(p.name for p in external_files))

        config = SplitConfig(
            train_benign_size=args.train_benign_size,
            validation_benign_size=args.validation_benign_size,
            validation_attack_size=args.validation_attack_size,
            test_benign_size=args.test_benign_size,
            test_attack_size=args.test_attack_size,
            minimum_attack_per_split=args.minimum_attack_per_split,
            chunk_size=args.chunk_size,
            random_state=args.random_state,
        )
        result = build_data_splits(
            monday_features_path=args.monday_features_path,
            monday_labels_path=args.monday_labels_path,
            feature_manifest_path=args.feature_manifest_path,
            external_csv_files=external_files,
            config=config,
        )
        save_data_splits(
            result,
            output_dir=args.output_dir,
            report_path=args.report_path,
            overwrite=args.overwrite,
        )
        print(format_split_summary(result.report))
        LOGGER.info("Conjuntos salvos em %s", args.output_dir.resolve())
        LOGGER.info("Relatorio salvo em %s", args.report_path.resolve())
        return 0
    except (FileNotFoundError, FileExistsError, NotADirectoryError, ValueError) as exc:
        LOGGER.error("%s", exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
