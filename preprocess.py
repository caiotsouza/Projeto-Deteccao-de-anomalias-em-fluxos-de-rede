"""Interface de linha de comando para o Marco 3."""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

from src.config import (
    DEFAULT_CSV_PATTERN,
    DEFAULT_NEAR_CONSTANT_THRESHOLD,
    METRICS_DIR,
    PROCESSED_DATA_DIR,
    RAW_DATA_DIR,
)
from src.load_data import discover_csv_files, load_cicids_csvs
from src.preprocessing import (
    PreprocessingConfig,
    format_preprocessing_summary,
    preprocess_dataframe,
    save_preprocessed_data,
)
from src.utils import configure_logging, normalize_column_name


LOGGER = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    """Define argumentos de carga, politica e persistencia."""
    parser = argparse.ArgumentParser(
        description="Limpa CSVs do CIC-IDS2017 e salva features e labels separadas."
    )
    parser.add_argument("--data-dir", type=Path, default=RAW_DATA_DIR)
    parser.add_argument("--pattern", default=DEFAULT_CSV_PATTERN)
    parser.add_argument("--recursive", action="store_true")
    parser.add_argument("--max-files", type=int, default=None)
    parser.add_argument("--nrows-per-file", type=int, default=None)
    parser.add_argument(
        "--output-prefix",
        default=None,
        help="Prefixo dos artefatos; para um arquivo, o nome e derivado automaticamente.",
    )
    parser.add_argument("--output-dir", type=Path, default=PROCESSED_DATA_DIR)
    parser.add_argument("--report-dir", type=Path, default=METRICS_DIR)
    parser.add_argument(
        "--near-constant-threshold",
        type=float,
        default=DEFAULT_NEAR_CONSTANT_THRESHOLD,
    )
    parser.add_argument("--keep-duplicates", action="store_true")
    parser.add_argument(
        "--drop-constant-columns",
        action="store_true",
        help="Opcional; por padrao, constantes sao mantidas para decisao no Marco 4.",
    )
    parser.add_argument(
        "--drop-duplicate-columns",
        action="store_true",
        help="Opcional; por padrao, colunas identicas sao mantidas para o Marco 4.",
    )
    parser.add_argument("--keep-float64", action="store_true")
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args()


def _derive_prefix(files: list[Path], requested_prefix: str | None) -> str:
    """Cria um prefixo seguro e previsivel para os artefatos."""
    raw_prefix = requested_prefix or (files[0].stem if len(files) == 1 else "combined")
    prefix = normalize_column_name(raw_prefix)
    if not prefix:
        raise ValueError("O prefixo de saida ficou vazio apos normalizacao.")
    return prefix


def main() -> int:
    """Executa carga, limpeza, verificacoes e salvamento."""
    args = parse_args()
    configure_logging(args.verbose)
    try:
        files = discover_csv_files(
            args.data_dir,
            pattern=args.pattern,
            recursive=args.recursive,
            max_files=args.max_files,
        )
        prefix = _derive_prefix(files, args.output_prefix)
        LOGGER.info("Arquivos selecionados (%s): %s", len(files), ", ".join(p.name for p in files))
        frame = load_cicids_csvs(files, nrows_per_file=args.nrows_per_file)
        config = PreprocessingConfig(
            drop_duplicates=not args.keep_duplicates,
            drop_constant_columns=args.drop_constant_columns,
            drop_duplicate_columns=args.drop_duplicate_columns,
            near_constant_threshold=args.near_constant_threshold,
            downcast_numeric=not args.keep_float64,
        )
        result = preprocess_dataframe(frame, config)
        result.report["source_files"] = [str(path.resolve()) for path in files]
        result.report["sampling"] = {
            "enabled": args.nrows_per_file is not None,
            "maximum_rows_per_file": args.nrows_per_file,
        }

        features_path = args.output_dir / f"{prefix}_features.parquet"
        labels_path = args.output_dir / f"{prefix}_labels.parquet"
        report_path = args.report_dir / f"{prefix}_preprocessing.json"
        save_preprocessed_data(
            result,
            features_path=features_path,
            labels_path=labels_path,
            report_path=report_path,
            overwrite=args.overwrite,
        )
        print(format_preprocessing_summary(result.report))
        LOGGER.info("Features salvas em %s", features_path.resolve())
        LOGGER.info("Labels salvas em %s", labels_path.resolve())
        LOGGER.info("Relatorio salvo em %s", report_path.resolve())
        return 0
    except (FileNotFoundError, FileExistsError, NotADirectoryError, ValueError) as exc:
        LOGGER.error("%s", exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
