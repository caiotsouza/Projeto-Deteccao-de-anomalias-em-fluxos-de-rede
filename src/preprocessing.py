"""Limpeza reprodutivel dos fluxos do CIC-IDS2017 (Marco 3)."""

from __future__ import annotations

import hashlib
import logging
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from src.config import DEFAULT_NEAR_CONSTANT_THRESHOLD
from src.utils import save_json


LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class PreprocessingConfig:
    """Politicas explicitas aplicadas na limpeza do dataset."""

    label_column: str = "label"
    drop_invalid_rows: bool = True
    drop_duplicates: bool = True
    # A remocao de features pertence ao Marco 4. Neste marco, elas sao apenas
    # avaliadas e mantidas por padrao para evitar selecao prematura.
    drop_constant_columns: bool = False
    drop_duplicate_columns: bool = False
    near_constant_threshold: float = DEFAULT_NEAR_CONSTANT_THRESHOLD
    downcast_numeric: bool = True

    def __post_init__(self) -> None:
        if not 0.5 < self.near_constant_threshold <= 1.0:
            raise ValueError("near_constant_threshold deve estar no intervalo (0.5, 1.0].")


@dataclass
class PreprocessingResult:
    """Dados limpos e relatorio completo das transformacoes."""

    features: pd.DataFrame
    labels: pd.Series
    report: dict[str, Any]


def _non_zero_counts(series: pd.Series) -> dict[str, int]:
    """Converte uma Series de contagens para um dicionario JSON compacto."""
    return {str(column): int(count) for column, count in series.items() if count > 0}


def _label_distribution(labels: pd.Series) -> dict[str, int]:
    """Conta rotulos, representando ausentes de forma explicita."""
    normalized = labels.fillna("<AUSENTE>").astype(str).str.strip()
    return {str(label): int(count) for label, count in normalized.value_counts().items()}


def _convert_features_to_numeric(
    features: pd.DataFrame,
) -> tuple[pd.DataFrame, dict[str, dict[str, Any]]]:
    """Converte features textuais e relata cada falha de conversao.

    Uma coluna inteiramente textual interrompe o processo, pois removê-la sem
    decisao metodologica poderia descartar uma feature importante. Falhas
    isoladas viram NaN e seguem para a politica explicita de linhas invalidas.
    """
    conversion_report: dict[str, dict[str, Any]] = {}
    for column in features.columns:
        if pd.api.types.is_numeric_dtype(features[column]):
            continue

        original = features[column]
        non_null_mask = original.notna()
        converted = pd.to_numeric(original, errors="coerce")
        failed_mask = non_null_mask & converted.isna()
        failed_count = int(failed_mask.sum())
        converted_count = int(converted.notna().sum())
        examples = original.loc[failed_mask].astype(str).drop_duplicates().head(5).tolist()

        conversion_report[column] = {
            "original_dtype": str(original.dtype),
            "converted_dtype": str(converted.dtype),
            "non_null_values": int(non_null_mask.sum()),
            "converted_values": converted_count,
            "failed_values": failed_count,
            "failed_examples": examples,
        }
        if non_null_mask.any() and converted_count == 0:
            raise ValueError(
                f"A feature '{column}' nao possui valores numericos convertiveis. "
                "Revise o esquema antes de decidir remove-la ou codifica-la."
            )
        features[column] = converted

    remaining = [
        column
        for column in features.columns
        if not pd.api.types.is_numeric_dtype(features[column])
    ]
    if remaining:
        raise ValueError(f"Features nao numericas restantes apos conversao: {remaining}")
    return features, conversion_report


def _count_infinities(features: pd.DataFrame) -> tuple[dict[str, int], dict[str, int]]:
    """Conta infinitos positivos e negativos por coluna sem copiar toda a matriz."""
    positive: dict[str, int] = {}
    negative: dict[str, int] = {}
    for column in features.columns:
        values = features[column].to_numpy(copy=False)
        positive_count = int(np.isposinf(values).sum())
        negative_count = int(np.isneginf(values).sum())
        if positive_count:
            positive[column] = positive_count
        if negative_count:
            negative[column] = negative_count
    return positive, negative


def _find_duplicate_columns(features: pd.DataFrame) -> dict[str, str]:
    """Localiza colunas identicas usando hash e confirmacao por igualdade."""
    digest_groups: dict[str, list[str]] = {}
    duplicates: dict[str, str] = {}
    for column in features.columns:
        value_hashes = pd.util.hash_pandas_object(features[column], index=False)
        digest = hashlib.sha256(value_hashes.to_numpy().tobytes()).hexdigest()
        candidates = digest_groups.setdefault(digest, [])
        original = next(
            (candidate for candidate in candidates if features[column].equals(features[candidate])),
            None,
        )
        if original is None:
            candidates.append(column)
        else:
            duplicates[column] = original
    return duplicates


def _find_near_constant_columns(
    features: pd.DataFrame,
    threshold: float,
) -> dict[str, dict[str, Any]]:
    """Reporta features dominadas por um valor, mas nao as remove."""
    near_constant: dict[str, dict[str, Any]] = {}
    row_count = len(features)
    if row_count == 0:
        return near_constant

    for column in features.columns:
        counts = features[column].value_counts(dropna=False)
        if len(counts) <= 1:
            continue
        most_frequent_value = counts.index[0]
        most_frequent_count = int(counts.iloc[0])
        ratio = most_frequent_count / row_count
        if ratio >= threshold:
            near_constant[column] = {
                "most_frequent_value": str(most_frequent_value),
                "most_frequent_count": most_frequent_count,
                "most_frequent_ratio": round(ratio, 8),
                "unique_values": int(len(counts)),
                "action": "retained_for_feature_selection_review",
            }
    return near_constant


def _downcast_features(
    features: pd.DataFrame,
) -> tuple[pd.DataFrame, dict[str, dict[str, str]]]:
    """Reduz tipos numericos apenas quando os valores cabem no tipo menor."""
    changes: dict[str, dict[str, str]] = {}
    float32_max = np.finfo(np.float32).max
    for column in features.columns:
        original_dtype = str(features[column].dtype)
        if pd.api.types.is_integer_dtype(features[column]):
            features[column] = pd.to_numeric(features[column], downcast="integer")
        elif pd.api.types.is_float_dtype(features[column]):
            maximum_absolute = features[column].abs().max()
            if pd.isna(maximum_absolute) or maximum_absolute <= float32_max:
                features[column] = features[column].astype(np.float32)

        new_dtype = str(features[column].dtype)
        if new_dtype != original_dtype:
            changes[column] = {"from": original_dtype, "to": new_dtype}
    return features, changes


def preprocess_dataframe(
    frame: pd.DataFrame,
    config: PreprocessingConfig | None = None,
) -> PreprocessingResult:
    """Limpa um DataFrame, mantendo rotulos fora da matriz de features."""
    config = config or PreprocessingConfig()
    if frame.empty:
        raise ValueError("O conjunto carregado nao possui registros.")
    if config.label_column not in frame.columns:
        raise ValueError(
            f"Coluna de rotulo '{config.label_column}' nao encontrada. "
            f"Colunas disponiveis: {list(frame.columns)}"
        )

    input_rows, input_columns = frame.shape
    input_memory_mb = float(frame.memory_usage(deep=True).sum() / 1024**2)
    labels = frame[config.label_column].astype("string").str.strip()
    labels = labels.mask(labels.eq(""), pd.NA)
    features = frame.drop(columns=[config.label_column]).copy()
    original_feature_dtypes = {column: str(dtype) for column, dtype in features.dtypes.items()}

    LOGGER.info("Label separada: %s features permanecem em X.", len(features.columns))
    features, numeric_conversion = _convert_features_to_numeric(features)

    missing_before = features.isna().sum()
    positive_infinity, negative_infinity = _count_infinities(features)
    infinity_total = sum(positive_infinity.values()) + sum(negative_infinity.values())
    features.replace([np.inf, -np.inf], np.nan, inplace=True)
    LOGGER.info("Infinitos substituidos por NaN: %s.", f"{infinity_total:,}")

    invalid_feature_mask = features.isna().any(axis=1)
    invalid_label_mask = labels.isna()
    invalid_row_mask = invalid_feature_mask | invalid_label_mask
    invalid_rows = int(invalid_row_mask.sum())
    if invalid_rows and not config.drop_invalid_rows:
        raise ValueError(
            f"Foram encontradas {invalid_rows} linhas invalidas e drop_invalid_rows=False."
        )
    if invalid_rows:
        features = features.loc[~invalid_row_mask].copy()
        labels = labels.loc[~invalid_row_mask].copy()
    LOGGER.info("Linhas invalidas removidas: %s.", f"{invalid_rows:,}")

    # O hash identifica grupos com as mesmas features para revelar eventuais
    # rotulos contraditorios antes de remover apenas registros exatos.
    feature_hash = pd.util.hash_pandas_object(features, index=False)
    conflict_frame = pd.DataFrame(
        {"feature_hash": feature_hash.to_numpy(), "label": labels.to_numpy()},
        index=features.index,
    )
    conflicting_hashes = conflict_frame.groupby("feature_hash")["label"].nunique()
    conflicting_hashes = conflicting_hashes[conflicting_hashes > 1]
    conflicting_rows = int(conflict_frame["feature_hash"].isin(conflicting_hashes.index).sum())

    record_keys = pd.DataFrame(
        {
            "feature_hash": feature_hash.to_numpy(),
            "label_hash": pd.util.hash_pandas_object(labels, index=False).to_numpy(),
        },
        index=features.index,
    )
    duplicate_mask = record_keys.duplicated(keep="first")
    duplicate_rows = int(duplicate_mask.sum())
    if config.drop_duplicates and duplicate_rows:
        features = features.loc[~duplicate_mask].copy()
        labels = labels.loc[~duplicate_mask].copy()
    LOGGER.info("Duplicatas exatas removidas: %s.", f"{duplicate_rows:,}" if config.drop_duplicates else "0")

    constant_columns = features.columns[features.nunique(dropna=False) <= 1].tolist()
    if config.drop_constant_columns and constant_columns:
        features.drop(columns=constant_columns, inplace=True)
    LOGGER.info(
        "Colunas constantes encontradas: %s; removidas: %s.",
        len(constant_columns),
        len(constant_columns) if config.drop_constant_columns else 0,
    )

    # Colunas constantes ja foram classificadas acima. Exclui-las desta busca
    # evita contar varias colunas totalmente zeradas tambem como duplicadas.
    duplicate_search_columns = [
        column for column in features.columns if column not in constant_columns
    ]
    duplicate_columns = _find_duplicate_columns(features[duplicate_search_columns])
    if config.drop_duplicate_columns and duplicate_columns:
        features.drop(columns=list(duplicate_columns), inplace=True)
    LOGGER.info(
        "Colunas duplicadas encontradas: %s; removidas: %s.",
        len(duplicate_columns),
        len(duplicate_columns) if config.drop_duplicate_columns else 0,
    )

    near_constant_columns = _find_near_constant_columns(
        features, config.near_constant_threshold
    )
    if near_constant_columns:
        LOGGER.info(
            "Colunas quase constantes mantidas para revisao: %s.",
            len(near_constant_columns),
        )

    memory_before_downcast_mb = float(features.memory_usage(deep=True).sum() / 1024**2)
    downcast_changes: dict[str, dict[str, str]] = {}
    if config.downcast_numeric:
        features, downcast_changes = _downcast_features(features)
    memory_after_downcast_mb = float(features.memory_usage(deep=True).sum() / 1024**2)

    features.reset_index(drop=True, inplace=True)
    labels.reset_index(drop=True, inplace=True)
    labels.name = config.label_column
    remaining_positive_infinity, remaining_negative_infinity = _count_infinities(features)

    rows_after_invalid = input_rows - invalid_rows
    rows_after_duplicates = len(features)
    removed_duplicates = duplicate_rows if config.drop_duplicates else 0
    total_removed_rows = invalid_rows + removed_duplicates
    report: dict[str, Any] = {
        "stage": "preprocessing_marco_3",
        "configuration": asdict(config),
        "input": {
            "records": int(input_rows),
            "columns_including_label": int(input_columns),
            "feature_columns": int(input_columns - 1),
            "memory_usage_mb": round(input_memory_mb, 3),
            "label_distribution": _label_distribution(frame[config.label_column]),
            "feature_dtypes": original_feature_dtypes,
        },
        "label_separation": {
            "label_column": config.label_column,
            "label_present_in_features": config.label_column in features.columns,
            "output_strategy": "features_and_labels_saved_separately",
        },
        "numeric_conversion": numeric_conversion,
        "invalid_values": {
            "missing_cells_before_infinity_replacement": int(missing_before.sum()),
            "missing_by_column_before_infinity_replacement": _non_zero_counts(missing_before),
            "positive_infinity_total": int(sum(positive_infinity.values())),
            "positive_infinity_by_column": positive_infinity,
            "negative_infinity_total": int(sum(negative_infinity.values())),
            "negative_infinity_by_column": negative_infinity,
            "infinity_replacement": "inf_and_minus_inf_to_nan",
            "rows_with_invalid_features": int(invalid_feature_mask.sum()),
            "rows_with_missing_label": int(invalid_label_mask.sum()),
            "invalid_rows_removed": invalid_rows,
            "records_after_invalid_removal": int(rows_after_invalid),
        },
        "duplicates": {
            "exact_duplicate_rows_found": duplicate_rows,
            "exact_duplicate_rows_removed": removed_duplicates,
            "records_after_duplicate_removal": int(rows_after_duplicates),
            "feature_patterns_with_conflicting_labels": int(len(conflicting_hashes)),
            "rows_in_conflicting_label_patterns": conflicting_rows,
        },
        "column_analysis": {
            "constant_columns_found": constant_columns,
            "constant_columns_removed": constant_columns if config.drop_constant_columns else [],
            "duplicate_columns_found": duplicate_columns,
            "duplicate_columns_removed": (
                list(duplicate_columns) if config.drop_duplicate_columns else []
            ),
            "near_constant_threshold": config.near_constant_threshold,
            "near_constant_columns_retained": near_constant_columns,
        },
        "numeric_optimization": {
            "enabled": config.downcast_numeric,
            "dtype_changes": downcast_changes,
            "memory_before_downcast_mb": round(memory_before_downcast_mb, 3),
            "memory_after_downcast_mb": round(memory_after_downcast_mb, 3),
        },
        "output": {
            "records": int(len(features)),
            "feature_columns": int(len(features.columns)),
            "label_records": int(len(labels)),
            "label_distribution": _label_distribution(labels),
            "feature_columns_list": features.columns.tolist(),
            "feature_dtypes": {
                column: str(dtype) for column, dtype in features.dtypes.items()
            },
            "remaining_missing_feature_values": int(features.isna().sum().sum()),
            "remaining_infinite_feature_values": int(
                sum(remaining_positive_infinity.values())
                + sum(remaining_negative_infinity.values())
            ),
            "total_rows_removed": int(total_removed_rows),
            "rows_removed_percentage": round(total_removed_rows / input_rows * 100, 6),
        },
    }
    return PreprocessingResult(features=features, labels=labels, report=report)


def save_preprocessed_data(
    result: PreprocessingResult,
    features_path: Path,
    labels_path: Path,
    report_path: Path,
    overwrite: bool = False,
) -> None:
    """Persiste X, y e relatorio; recusa sobrescrita acidental por padrao."""
    paths = [features_path, labels_path, report_path]
    existing = [path for path in paths if path.exists()]
    if existing and not overwrite:
        raise FileExistsError(
            "Artefato(s) ja existente(s); use --overwrite para substituir: "
            + ", ".join(str(path) for path in existing)
        )
    for path in paths:
        path.parent.mkdir(parents=True, exist_ok=True)

    result.features.to_parquet(features_path, index=False, compression="snappy")
    result.labels.to_frame().to_parquet(labels_path, index=False, compression="snappy")
    result.report["artifacts"] = {
        "features_path": str(features_path.resolve()),
        "labels_path": str(labels_path.resolve()),
        "report_path": str(report_path.resolve()),
        "format": "parquet_snappy",
    }
    save_json(result.report, report_path)


def format_preprocessing_summary(report: dict[str, Any]) -> str:
    """Resume as transformacoes principais para o terminal."""
    invalid = report["invalid_values"]
    duplicates = report["duplicates"]
    columns = report["column_analysis"]
    output = report["output"]
    return "\n".join(
        [
            "\n=== PRE-PROCESSAMENTO CIC-IDS2017 — MARCO 3 ===",
            f"Registros de entrada: {report['input']['records']:,}",
            f"Features de entrada: {report['input']['feature_columns']:,}",
            f"Infinitos substituidos por NaN: "
            f"{invalid['positive_infinity_total'] + invalid['negative_infinity_total']:,}",
            f"Linhas invalidas removidas: {invalid['invalid_rows_removed']:,}",
            f"Duplicatas exatas removidas: {duplicates['exact_duplicate_rows_removed']:,}",
            f"Colunas constantes removidas: {len(columns['constant_columns_removed']):,}",
            f"Colunas duplicadas removidas: {len(columns['duplicate_columns_removed']):,}",
            f"Colunas quase constantes mantidas: "
            f"{len(columns['near_constant_columns_retained']):,}",
            f"Registros finais: {output['records']:,}",
            f"Features finais: {output['feature_columns']:,}",
            f"Total de linhas removidas: {output['total_rows_removed']:,} "
            f"({output['rows_removed_percentage']:.4f}%)",
            f"Label presente em X: {report['label_separation']['label_present_in_features']}",
            f"NaN restantes em X: {output['remaining_missing_feature_values']:,}",
            f"Infinitos restantes em X: {output['remaining_infinite_feature_values']:,}",
        ]
    )
