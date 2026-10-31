"""Ponto de entrada dos Marcos 1 e 2 do projeto."""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

from src.config import DEFAULT_CSV_PATTERN, DEFAULT_REPORT_PATH, RAW_DATA_DIR
from src.inspect_data import format_summary, inspect_dataframe
from src.load_data import discover_csv_files, load_cicids_csvs
from src.utils import configure_logging, save_json


LOGGER = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    """Define e interpreta os argumentos de linha de comando."""
    parser = argparse.ArgumentParser(
        description="Carrega e inspeciona CSVs do CIC-IDS2017 sem limpar registros."
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=RAW_DATA_DIR,
        help=f"Diretorio dos CSVs (padrao: {RAW_DATA_DIR})",
    )
    parser.add_argument(
        "--pattern",
        default=DEFAULT_CSV_PATTERN,
        help="Padrao de arquivo; use um nome exato para ler somente um CSV.",
    )
    parser.add_argument(
        "--recursive",
        action="store_true",
        help="Procura CSVs tambem em subdiretorios.",
    )
    parser.add_argument(
        "--max-files",
        type=int,
        default=None,
        help="Limita quantos arquivos, em ordem alfabetica, serao lidos.",
    )
    parser.add_argument(
        "--nrows-per-file",
        type=int,
        default=None,
        help="Le no maximo N linhas de cada CSV e informa a amostragem no relatorio.",
    )
    parser.add_argument(
        "--report-path",
        type=Path,
        default=DEFAULT_REPORT_PATH,
        help=f"Destino do relatorio JSON (padrao: {DEFAULT_REPORT_PATH})",
    )
    parser.add_argument("--verbose", action="store_true", help="Ativa logs detalhados.")
    return parser.parse_args()


def main() -> int:
    """Executa descoberta, carga, inspecao e persistencia do relatorio."""
    args = parse_args()
    configure_logging(args.verbose)

    try:
        files = discover_csv_files(
            args.data_dir,
            pattern=args.pattern,
            recursive=args.recursive,
            max_files=args.max_files,
        )
        LOGGER.info("Arquivos selecionados (%s): %s", len(files), ", ".join(p.name for p in files))
        frame = load_cicids_csvs(files, nrows_per_file=args.nrows_per_file)
        report = inspect_dataframe(frame)
        report["source_files"] = [str(path.resolve()) for path in files]
        report["sampling"] = {
            "enabled": args.nrows_per_file is not None,
            "maximum_rows_per_file": args.nrows_per_file,
        }
        print(format_summary(report))
        save_json(report, args.report_path.resolve())
        LOGGER.info("Relatorio JSON salvo em %s", args.report_path.resolve())
        return 0
    except (FileNotFoundError, NotADirectoryError, ValueError) as exc:
        LOGGER.error("%s", exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

