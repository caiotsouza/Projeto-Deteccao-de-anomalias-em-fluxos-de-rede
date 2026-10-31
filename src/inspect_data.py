"""Diagnostico exploratorio basico do CIC-IDS2017."""

from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd


def _numeric_conversion_candidates(
    frame: pd.DataFrame,
    label_column: str,
    sample_size: int = 10_000,
    threshold: float = 0.95,
) -> dict[str, dict[str, float | int]]:
    """Aponta colunas texto que parecem numericas, sem modificar os dados."""
    candidates: dict[str, dict[str, float | int]] = {}
    object_columns = frame.select_dtypes(exclude=np.number).columns
    for column in object_columns:
        if column == label_column:
            continue
        values = frame[column].dropna().head(sample_size)
        if values.empty:
            continue
        converted = pd.to_numeric(values, errors="coerce")
        success_count = int(converted.notna().sum())
        success_rate = success_count / len(values)
        if success_rate >= threshold:
            candidates[column] = {
                "sampled_non_null_values": int(len(values)),
                "numeric_values": success_count,
                "conversion_success_rate": round(success_rate, 6),
            }
    return candidates


def inspect_dataframe(frame: pd.DataFrame, label_column: str = "label") -> dict[str, Any]:
    """Calcula estatisticas de qualidade sem limpar ou remover registros."""
    if frame.empty:
        raise ValueError("O conjunto carregado nao possui registros.")

    missing_by_column = frame.isna().sum()
    numeric_frame = frame.select_dtypes(include=np.number)
    if numeric_frame.empty:
        infinite_by_column = pd.Series(dtype="int64")
    else:
        infinite_by_column = pd.Series(
            np.isinf(numeric_frame.to_numpy(copy=False)).sum(axis=0),
            index=numeric_frame.columns,
            dtype="int64",
        )

    if label_column in frame.columns:
        label_distribution = {
            str(label): int(count)
            for label, count in frame[label_column]
            .fillna("<AUSENTE>")
            .astype(str)
            .str.strip()
            .value_counts(dropna=False)
            .items()
        }
    else:
        label_distribution = {}

    non_numeric_columns = [
        column for column in frame.columns if not pd.api.types.is_numeric_dtype(frame[column])
    ]
    return {
        "records": int(frame.shape[0]),
        "columns": int(frame.shape[1]),
        "memory_usage_mb": round(float(frame.memory_usage(deep=True).sum() / 1024**2), 3),
        "dtypes": {column: str(dtype) for column, dtype in frame.dtypes.items()},
        "dtype_distribution": {
            str(dtype): int(count) for dtype, count in frame.dtypes.astype(str).value_counts().items()
        },
        "missing_values_total": int(missing_by_column.sum()),
        "missing_values_by_column": {
            column: int(count) for column, count in missing_by_column.items() if count > 0
        },
        "infinite_values_total": int(infinite_by_column.sum()),
        "infinite_values_by_column": {
            column: int(count) for column, count in infinite_by_column.items() if count > 0
        },
        "duplicate_records": int(frame.duplicated(keep="first").sum()),
        "records_removed": 0,
        "removal_note": "Nenhum registro e removido nos Marcos 1 e 2.",
        "label_column_found": label_column in frame.columns,
        "label_distribution": label_distribution,
        "non_numeric_columns": non_numeric_columns,
        "numeric_conversion_candidates": _numeric_conversion_candidates(frame, label_column),
    }


def format_summary(report: dict[str, Any]) -> str:
    """Formata os principais resultados para leitura no terminal."""
    lines = [
        "\n=== INSPECAO DO CIC-IDS2017 ===",
        f"Registros: {report['records']:,}",
        f"Colunas: {report['columns']:,}",
        f"Memoria estimada do DataFrame: {report['memory_usage_mb']:.3f} MB",
        f"Valores ausentes: {report['missing_values_total']:,}",
        f"Valores infinitos: {report['infinite_values_total']:,}",
        f"Registros duplicados: {report['duplicate_records']:,}",
        f"Registros removidos: {report['records_removed']:,}",
        "\nTipos por coluna:",
    ]
    lines.extend(f"  {column}: {dtype}" for column, dtype in report["dtypes"].items())

    lines.append("\nDistribuicao de label:")
    if report["label_column_found"]:
        lines.extend(
            f"  {label}: {count:,}" for label, count in report["label_distribution"].items()
        )
    else:
        lines.append("  ERRO: coluna 'label' nao encontrada.")

    if report["missing_values_by_column"]:
        lines.append("\nAusentes por coluna (somente valores > 0):")
        lines.extend(
            f"  {column}: {count:,}"
            for column, count in report["missing_values_by_column"].items()
        )
    if report["infinite_values_by_column"]:
        lines.append("\nInfinitos por coluna (somente valores > 0):")
        lines.extend(
            f"  {column}: {count:,}"
            for column, count in report["infinite_values_by_column"].items()
        )
    if report["numeric_conversion_candidates"]:
        lines.append("\nColunas texto potencialmente numericas (nao convertidas neste marco):")
        lines.extend(
            f"  {column}: {details['conversion_success_rate']:.1%} da amostra convertivel"
            for column, details in report["numeric_conversion_candidates"].items()
        )
    return "\n".join(lines)
