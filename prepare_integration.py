"""Gera os contratos do Marco 11 para integração e dashboards."""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

from src.config import INTEGRATION_REPORTS_DIR, PROJECT_ROOT
from src.inference_service import (
    DEFAULT_MODEL,
    DEFAULT_OPERATING_POINT,
    ModelSelection,
    SUPPORTED_MODELS,
    SUPPORTED_OPERATING_POINTS,
)
from src.integration_contracts import (
    format_marco11_summary,
    run_marco11_preparation,
)
from src.utils import configure_logging


LOGGER = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    """Define o modelo de referência e a política de escrita."""
    parser = argparse.ArgumentParser(
        description=(
            "Prepara contratos de inferência, MongoDB e Grafana sem iniciar "
            "serviços externos."
        )
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=INTEGRATION_REPORTS_DIR,
    )
    parser.add_argument("--experiment", default="expanded_100k")
    parser.add_argument(
        "--model",
        choices=SUPPORTED_MODELS,
        default=DEFAULT_MODEL,
    )
    parser.add_argument(
        "--operating-point",
        choices=SUPPORTED_OPERATING_POINTS,
        default=DEFAULT_OPERATING_POINT,
    )
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args()


def main() -> int:
    """Executa a preparação e informa os limites desta etapa."""
    args = parse_args()
    configure_logging(args.verbose)
    try:
        manifest = run_marco11_preparation(
            project_root=PROJECT_ROOT,
            output_dir=args.output_dir,
            selection=ModelSelection(
                experiment=args.experiment,
                model=args.model,
                operating_point=args.operating_point,
            ),
            overwrite=args.overwrite,
        )
        print(format_marco11_summary(manifest))
        LOGGER.info("Contratos salvos em %s", args.output_dir.resolve())
        return 0
    except (
        FileExistsError,
        FileNotFoundError,
        KeyError,
        RuntimeError,
        TypeError,
        ValueError,
    ) as exc:
        LOGGER.error("%s", exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
