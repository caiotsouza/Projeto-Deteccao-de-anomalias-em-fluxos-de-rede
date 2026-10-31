"""Executa inferência em um objeto ou lote JSON sem depender de CSV."""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
from typing import Any

from src.config import PROJECT_ROOT
from src.inference_service import (
    DEFAULT_MODEL,
    DEFAULT_OPERATING_POINT,
    AnomalyInferenceService,
    ModelSelection,
    SUPPORTED_MODELS,
    SUPPORTED_OPERATING_POINTS,
)
from src.utils import configure_logging


LOGGER = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    """Define a entrada estruturada e a seleção explícita do modelo."""
    parser = argparse.ArgumentParser(
        description="Valida e classifica um objeto ou lote JSON de fluxos."
    )
    parser.add_argument("input_json", type=Path)
    parser.add_argument("--output", type=Path)
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
    parser.add_argument("--max-batch-size", type=int, default=1000)
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Permite substituir deliberadamente o arquivo indicado em --output.",
    )
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args()


def _load_payload(path: Path) -> tuple[list[dict[str, Any]], bool]:
    """Carrega um objeto ou array JSON e preserva o formato de resposta."""
    if not path.is_file():
        raise FileNotFoundError(f"Entrada JSON não encontrada: {path}")
    with path.open("r", encoding="utf-8") as file:
        payload = json.load(file)
    if isinstance(payload, dict):
        return [payload], True
    if isinstance(payload, list) and all(isinstance(item, dict) for item in payload):
        return payload, False
    raise ValueError("A entrada deve ser um objeto JSON ou um array de objetos.")


def main() -> int:
    """Carrega uma vez o modelo e classifica toda a entrada em lote."""
    args = parse_args()
    configure_logging(args.verbose)
    try:
        if args.output and args.output.exists() and not args.overwrite:
            raise FileExistsError(
                f"Saída já existente: {args.output}. Use --overwrite para substituir."
            )
        records, single = _load_payload(args.input_json)
        service = AnomalyInferenceService.from_registry(
            project_root=PROJECT_ROOT,
            selection=ModelSelection(
                experiment=args.experiment,
                model=args.model,
                operating_point=args.operating_point,
            ),
            max_batch_size=args.max_batch_size,
        )
        predictions = service.predict_many(records)
        result: Any = predictions[0] if single else predictions
        rendered = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered, encoding="utf-8")
            LOGGER.info("Predições salvas em %s", args.output.resolve())
        else:
            print(rendered, end="")
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
