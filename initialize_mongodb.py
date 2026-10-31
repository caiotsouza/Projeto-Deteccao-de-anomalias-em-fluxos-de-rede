"""Inicializa coleção, validador e índices do MongoDB do Marco 12."""

from __future__ import annotations

import json
import logging

from src.monitoring_repository import RepositoryUnavailable, create_mongo_repository
from src.runtime_config import RuntimeSettings
from src.utils import configure_logging


LOGGER = logging.getLogger(__name__)


def main() -> int:
    configure_logging()
    try:
        settings = RuntimeSettings.from_env()
        repository = create_mongo_repository(settings)
        result = repository.initialize()
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (FileNotFoundError, KeyError, RepositoryUnavailable, ValueError) as exc:
        LOGGER.error("%s", exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
