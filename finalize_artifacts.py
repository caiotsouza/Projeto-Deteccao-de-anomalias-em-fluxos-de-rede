"""Executa o inventário final de modelos, métricas e figuras do Marco 10."""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

from src.artifact_inventory import format_marco10_summary, run_marco10
from src.config import FINAL_REPORTS_DIR, PROJECT_ROOT
from src.utils import configure_logging


LOGGER = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    """Define o destino e as proteções de escrita do fechamento."""
    parser = argparse.ArgumentParser(
        description=(
            "Cataloga e valida os modelos, métricas, tabelas e figuras já "
            "produzidos, sem retreinar ou recalibrar modelos."
        )
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=FINAL_REPORTS_DIR,
        help="Diretório dos índices finais (padrão: reports/final).",
    )
    parser.add_argument(
        "--without-scale-experiment",
        action="store_true",
        help="Inclui somente o baseline 20k no inventário.",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Substitui deliberadamente os índices do Marco 10 já existentes.",
    )
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args()


def main() -> int:
    """Executa o Marco 10 e informa o resultado no terminal."""
    args = parse_args()
    configure_logging(args.verbose)
    try:
        manifest = run_marco10(
            project_root=PROJECT_ROOT,
            output_dir=args.output_dir,
            include_scale_experiment=not args.without_scale_experiment,
            overwrite=args.overwrite,
        )
        print(format_marco10_summary(manifest))
        LOGGER.info("Inventário final salvo em %s", args.output_dir.resolve())
        return 0
    except (
        FileNotFoundError,
        FileExistsError,
        KeyError,
        RuntimeError,
        TypeError,
        ValueError,
    ) as exc:
        LOGGER.error("%s", exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
