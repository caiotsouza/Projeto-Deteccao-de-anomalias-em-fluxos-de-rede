"""Descoberta e carregamento dos CSVs do CIC-IDS2017."""

from __future__ import annotations

import logging
from pathlib import Path

import pandas as pd

from src.utils import normalize_columns


LOGGER = logging.getLogger(__name__)


def discover_csv_files(
    data_dir: Path,
    pattern: str = "*.csv",
    recursive: bool = False,
    max_files: int | None = None,
) -> list[Path]:
    """Localiza CSVs de modo deterministico no diretorio informado."""
    data_dir = data_dir.expanduser().resolve()
    if not data_dir.exists():
        raise FileNotFoundError(f"Diretorio de dados nao encontrado: {data_dir}")
    if not data_dir.is_dir():
        raise NotADirectoryError(f"O caminho nao e um diretorio: {data_dir}")
    if max_files is not None and max_files <= 0:
        raise ValueError("max_files deve ser maior que zero.")

    iterator = data_dir.rglob(pattern) if recursive else data_dir.glob(pattern)
    files = sorted(path for path in iterator if path.is_file())
    if max_files is not None:
        files = files[:max_files]
    if not files:
        raise FileNotFoundError(
            f"Nenhum arquivo correspondente a '{pattern}' foi encontrado em {data_dir}"
        )
    return files


def read_cicids_csv(file_path: Path, nrows: int | None = None) -> pd.DataFrame:
    """Le um CSV do CIC-IDS2017 e normaliza apenas seus nomes de coluna.

    Nenhuma linha e removida e nenhum valor de feature e alterado nesta etapa.
    """
    if nrows is not None and nrows <= 0:
        raise ValueError("nrows deve ser maior que zero.")

    LOGGER.info("Lendo %s%s", file_path.name, f" (ate {nrows:,} linhas)" if nrows else "")
    try:
        frame = pd.read_csv(file_path, nrows=nrows, low_memory=False)
    except UnicodeDecodeError:
        LOGGER.warning("UTF-8 falhou em %s; tentando codificacao latin-1.", file_path.name)
        frame = pd.read_csv(file_path, nrows=nrows, low_memory=False, encoding="latin-1")
    except pd.errors.EmptyDataError as exc:
        raise ValueError(f"O arquivo CSV esta vazio: {file_path}") from exc
    except pd.errors.ParserError as exc:
        raise ValueError(f"Nao foi possivel interpretar o CSV {file_path}: {exc}") from exc

    original_columns = list(frame.columns)
    frame.columns = normalize_columns(original_columns)
    changed = sum(str(old) != new for old, new in zip(original_columns, frame.columns))
    LOGGER.info(
        "%s: %s registros, %s colunas, %s nomes de coluna normalizados.",
        file_path.name,
        f"{len(frame):,}",
        len(frame.columns),
        changed,
    )
    return frame


def load_cicids_csvs(
    files: list[Path],
    nrows_per_file: int | None = None,
) -> pd.DataFrame:
    """Le e concatena um ou varios CSVs, sem descartar registros.

    Colunas ausentes em algum arquivo sao preservadas pelo ``concat`` e recebem
    NaN nas linhas correspondentes. Diferencas de esquema sao registradas.
    """
    if not files:
        raise ValueError("A lista de arquivos CSV esta vazia.")

    frames: list[pd.DataFrame] = []
    reference_columns: set[str] | None = None
    for file_path in files:
        frame = read_cicids_csv(file_path, nrows=nrows_per_file)
        current_columns = set(frame.columns)
        if reference_columns is None:
            reference_columns = current_columns
        elif current_columns != reference_columns:
            LOGGER.warning(
                "Esquema diferente em %s: faltantes=%s; adicionais=%s",
                file_path.name,
                sorted(reference_columns - current_columns),
                sorted(current_columns - reference_columns),
            )
        frames.append(frame)

    combined = pd.concat(frames, axis=0, ignore_index=True, sort=False)
    LOGGER.info(
        "Carga concluida: %s arquivo(s), %s registros e %s colunas.",
        len(files),
        f"{len(combined):,}",
        len(combined.columns),
    )
    if nrows_per_file is not None:
        LOGGER.warning(
            "Execucao controlada: foram lidas no maximo %s linhas por arquivo.",
            f"{nrows_per_file:,}",
        )
    return combined
