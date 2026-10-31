"""Funcoes utilitarias pequenas e reutilizaveis."""

from __future__ import annotations

import json
import logging
import re
import unicodedata
from pathlib import Path
from typing import Any


def configure_logging(verbose: bool = False) -> None:
    """Configura mensagens de execucao para console."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
        datefmt="%H:%M:%S",
    )


def normalize_column_name(name: object) -> str:
    """Converte um nome de coluna para snake_case ASCII consistente.

    Exemplo: ``" Flow Duration "`` se torna ``"flow_duration"``.
    """
    text = str(name).strip()
    text = unicodedata.normalize("NFKD", text)
    text = "".join(char for char in text if not unicodedata.combining(char))
    text = re.sub(r"[^0-9A-Za-z]+", "_", text)
    return text.strip("_").lower()


def normalize_columns(columns: list[object]) -> list[str]:
    """Normaliza nomes e impede colisoes silenciosas."""
    normalized = [normalize_column_name(column) for column in columns]
    empty = [str(original) for original, new in zip(columns, normalized) if not new]
    if empty:
        raise ValueError(f"Nome(s) de coluna vazio(s) apos normalizacao: {empty}")

    duplicates = sorted({name for name in normalized if normalized.count(name) > 1})
    if duplicates:
        raise ValueError(
            "A normalizacao gerou nomes de coluna duplicados: "
            + ", ".join(duplicates)
        )
    return normalized


def save_json(data: dict[str, Any], output_path: Path) -> None:
    """Salva um dicionario como JSON UTF-8, criando o diretorio se preciso."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as file:
        json.dump(data, file, ensure_ascii=False, indent=2)

