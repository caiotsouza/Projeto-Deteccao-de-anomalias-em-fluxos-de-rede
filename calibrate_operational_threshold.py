"""CLI para calibrar um ponto operacional com orçamento de falsos positivos."""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

from src.config import (
    DEFAULT_OPERATIONAL_TARGET_FPR,
    OPERATIONAL_REPORTS_DIR,
    PROJECT_ROOT,
)
from src.operational_calibration import (
    format_operational_summary,
    run_operational_calibration,
)
from src.utils import configure_logging


LOGGER = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Compara Isolation Forest e LOF sob um teto de FPR, sem retreinar "
            "modelos nem usar o teste para selecionar o limiar."
        )
    )
    parser.add_argument("--output-dir", type=Path, default=OPERATIONAL_REPORTS_DIR)
    parser.add_argument(
        "--target-fpr",
        type=float,
        default=DEFAULT_OPERATIONAL_TARGET_FPR,
        help="Taxa máxima de falsos positivos na validação (padrão: 0.01).",
    )
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    configure_logging(args.verbose)
    try:
        manifest = run_operational_calibration(
            project_root=PROJECT_ROOT,
            output_dir=args.output_dir,
            target_fpr=args.target_fpr,
            overwrite=args.overwrite,
        )
        print(format_operational_summary(manifest))
        LOGGER.info("Artefatos salvos em %s", args.output_dir.resolve())
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
