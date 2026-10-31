"""CLI do replay congelado para MongoDB ou validação dry-run."""

from __future__ import annotations

import argparse
import json
import logging
from datetime import datetime
from pathlib import Path

from src.config import (
    DEFAULT_REPLAY_BATCH_SIZE,
    DEFAULT_REPLAY_INTERVAL_MILLISECONDS,
    DEFAULT_REPLAY_LIMIT,
    MARCO12_REPORTS_DIR,
    PROJECT_ROOT,
)
from src.monitoring_repository import (
    DocumentConflict,
    InMemoryPredictionRepository,
    RepositoryUnavailable,
    create_mongo_repository,
)
from src.replay import ReplayConfig, run_replay
from src.runtime_config import RuntimeSettings
from src.utils import configure_logging


LOGGER = logging.getLogger(__name__)


def _aware_datetime(value: str) -> datetime:
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    moment = datetime.fromisoformat(normalized)
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise argparse.ArgumentTypeError("A data deve informar o fuso horário.")
    return moment


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Reaplica o limiar operacional às previsões congeladas e insere "
            "documentos idempotentes no MongoDB."
        )
    )
    parser.add_argument("--limit", type=int, default=DEFAULT_REPLAY_LIMIT)
    parser.add_argument("--offset", type=int, default=0)
    parser.add_argument("--batch-size", type=int, default=DEFAULT_REPLAY_BATCH_SIZE)
    parser.add_argument(
        "--interval-ms", type=int, default=DEFAULT_REPLAY_INTERVAL_MILLISECONDS
    )
    parser.add_argument("--start-time", type=_aware_datetime)
    parser.add_argument("--namespace")
    parser.add_argument(
        "--network-context-dir",
        type=Path,
        help=(
            "Diretório GeneratedLabelledFlows com Source IP, Destination IP e "
            "Protocol. Cada linha é validada contra X_test antes da escrita."
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Gera e valida documentos sem abrir conexão de escrita com MongoDB.",
    )
    parser.add_argument(
        "--report-path",
        type=Path,
        default=MARCO12_REPORTS_DIR / "replay_last_run.json",
    )
    parser.add_argument("--overwrite-report", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    configure_logging(args.verbose)
    try:
        settings = RuntimeSettings.from_env(PROJECT_ROOT)
        repository = (
            InMemoryPredictionRepository()
            if args.dry_run
            else create_mongo_repository(settings)
        )
        report = run_replay(
            repository,
            project_root=PROJECT_ROOT,
            config=ReplayConfig(
                limit=args.limit,
                offset=args.offset,
                batch_size=args.batch_size,
                interval_milliseconds=args.interval_ms,
                start_time=args.start_time,
                namespace=args.namespace,
                network_context_dir=args.network_context_dir,
                dry_run=args.dry_run,
            ),
            report_path=args.report_path,
            overwrite_report=args.overwrite_report,
        )
        print(json.dumps(report["counts"], ensure_ascii=False, indent=2))
        LOGGER.info("Relatório salvo em %s", args.report_path.resolve())
        return 0
    except (
        DocumentConflict,
        FileExistsError,
        FileNotFoundError,
        KeyError,
        RepositoryUnavailable,
        RuntimeError,
        TypeError,
        ValueError,
    ) as exc:
        LOGGER.error("%s", exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
