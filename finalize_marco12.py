"""CLI para validar e documentar o Marco 12."""

from __future__ import annotations

import argparse
import json
import logging

from src.marco12_artifacts import finalize_marco12
from src.utils import configure_logging


LOGGER = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Valida replay/API/Grafana e gera as evidências do Marco 12."
    )
    parser.add_argument("--replay-limit", type=int, default=5_000)
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    configure_logging(args.verbose)
    try:
        manifest = finalize_marco12(
            replay_limit=args.replay_limit,
            overwrite=args.overwrite,
        )
        print(
            json.dumps(
                {
                    "status": manifest["status"],
                    "unit_tests": manifest["validation"]["unit_tests"],
                    "integrated_validation": manifest["validation"][
                        "integrated_in_memory_http"
                    ],
                    "external_validation": manifest["validation"][
                        "external_mongodb_grafana"
                    ],
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0
    except (FileExistsError, FileNotFoundError, KeyError, RuntimeError, ValueError) as exc:
        LOGGER.error("%s", exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
