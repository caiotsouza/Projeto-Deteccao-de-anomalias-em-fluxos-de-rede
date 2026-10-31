"""Construcao reproduzivel dos conjuntos de treino, validacao e teste (Marco 5)."""

from __future__ import annotations

import logging
import math
import re
import hashlib
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from src.config import (
    DEFAULT_MINIMUM_ATTACK_PER_SPLIT,
    DEFAULT_RANDOM_STATE,
    DEFAULT_SPLIT_CHUNK_SIZE,
    DEFAULT_TEST_ATTACK_SIZE,
    DEFAULT_TEST_BENIGN_SIZE,
    DEFAULT_TRAIN_BENIGN_SIZE,
    DEFAULT_VALIDATION_ATTACK_SIZE,
    DEFAULT_VALIDATION_BENIGN_SIZE,
)
from src.feature_selection import load_feature_manifest
from src.utils import normalize_columns, save_json


LOGGER = logging.getLogger(__name__)
BENIGN_LABEL = "BENIGN"


@dataclass(frozen=True)
class SplitConfig:
    """Tamanhos e parametros da divisao controlada."""

    train_benign_size: int = DEFAULT_TRAIN_BENIGN_SIZE
    validation_benign_size: int = DEFAULT_VALIDATION_BENIGN_SIZE
    validation_attack_size: int = DEFAULT_VALIDATION_ATTACK_SIZE
    test_benign_size: int = DEFAULT_TEST_BENIGN_SIZE
    test_attack_size: int = DEFAULT_TEST_ATTACK_SIZE
    minimum_attack_per_split: int = DEFAULT_MINIMUM_ATTACK_PER_SPLIT
    chunk_size: int = DEFAULT_SPLIT_CHUNK_SIZE
    random_state: int = DEFAULT_RANDOM_STATE
    candidate_buffer_ratio: float = 0.25

    def __post_init__(self) -> None:
        integer_fields = (
            "train_benign_size",
            "validation_benign_size",
            "validation_attack_size",
            "test_benign_size",
            "test_attack_size",
            "minimum_attack_per_split",
            "chunk_size",
        )
        for field in integer_fields:
            if getattr(self, field) <= 0:
                raise ValueError(f"{field} deve ser maior que zero.")
        if self.candidate_buffer_ratio < 0:
            raise ValueError("candidate_buffer_ratio nao pode ser negativo.")


@dataclass
class DataSplitResult:
    """Matrizes, metadados, manifesto e relatorio da divisao."""

    x_train: pd.DataFrame
    y_train: pd.DataFrame
    x_validation: pd.DataFrame
    y_validation: pd.DataFrame
    x_test: pd.DataFrame
    y_test: pd.DataFrame
    manifest: dict[str, Any]
    report: dict[str, Any]


def normalize_label_value(value: object) -> str | None:
    """Normaliza espacos e separadores corrompidos sem agrupar ataques distintos."""
    if value is None or pd.isna(value):
        return None
    text = str(value).strip()
    if not text:
        return None
    text = text.replace("\ufffd", " - ").replace("\u2013", " - ").replace("\u2014", " - ")
    text = text.replace("\x96", " - ")
    text = re.sub(r"\s+", " ", text).strip()
    return BENIGN_LABEL if text.casefold() == "benign" else text


def normalize_label_series(labels: pd.Series) -> pd.Series:
    """Aplica a normalizacao de rótulos preservando o dtype string do pandas."""
    normalized = labels.map(normalize_label_value)
    return normalized.astype("string")


def allocate_stratified_quota(
    available_by_label: dict[str, int],
    total_size: int,
    minimum_per_label: int,
) -> dict[str, int]:
    """Distribui uma cota exata proporcionalmente, garantindo classes raras."""
    available = {label: int(count) for label, count in available_by_label.items() if count > 0}
    if not available:
        raise ValueError("Nao ha classes disponiveis para amostragem estratificada.")
    if total_size > sum(available.values()):
        raise ValueError(
            f"Cota solicitada ({total_size}) excede os registros disponiveis "
            f"({sum(available.values())})."
        )

    quotas = {label: min(minimum_per_label, count) for label, count in available.items()}
    minimum_total = sum(quotas.values())
    if minimum_total > total_size:
        raise ValueError(
            "A cota total e insuficiente para o minimo por classe: "
            f"necessario={minimum_total}, solicitado={total_size}."
        )

    remaining = total_size - minimum_total
    capacity = {label: available[label] - quotas[label] for label in available}
    while remaining > 0:
        total_capacity = sum(capacity.values())
        if total_capacity <= 0:
            raise ValueError("Capacidade esgotada antes de completar a cota.")
        exact_shares = {
            label: remaining * capacity[label] / total_capacity for label in available
        }
        additions = {
            label: min(capacity[label], int(math.floor(exact_shares[label])))
            for label in available
        }
        added = sum(additions.values())
        for label, addition in additions.items():
            quotas[label] += addition
            capacity[label] -= addition
        remaining -= added
        if remaining == 0:
            break

        order = sorted(
            available,
            key=lambda label: (
                -(exact_shares[label] - math.floor(exact_shares[label])),
                label,
            ),
        )
        progressed = False
        for label in order:
            if remaining == 0:
                break
            if capacity[label] > 0:
                quotas[label] += 1
                capacity[label] -= 1
                remaining -= 1
                progressed = True
        if not progressed:
            raise ValueError("Nao foi possivel completar a distribuicao estratificada.")
    return dict(sorted(quotas.items()))


def count_external_labels(
    csv_files: list[Path],
    chunk_size: int,
) -> tuple[dict[str, int], dict[str, dict[str, int]]]:
    """Primeira passagem: conta somente Label em blocos."""
    total: Counter[str] = Counter()
    by_file: dict[str, dict[str, int]] = {}
    for path in csv_files:
        counts: Counter[str] = Counter()
        for chunk in pd.read_csv(
            path,
            usecols=lambda column: str(column).strip().lower() == "label",
            chunksize=chunk_size,
            low_memory=False,
            encoding="utf-8",
            encoding_errors="replace",
        ):
            labels = normalize_label_series(chunk.iloc[:, 0])
            counts.update(labels.fillna("<AUSENTE>").tolist())
        total.update(counts)
        by_file[path.name] = dict(sorted(counts.items()))
        LOGGER.info("Rotulos contados em %s: %s registros.", path.name, f"{sum(counts.values()):,}")
    return dict(sorted(total.items())), by_file


def _mix_uint64(values: np.ndarray, random_state: int) -> np.ndarray:
    """Mistura hashes de forma deterministica usando SplitMix64."""
    x = values.astype(np.uint64, copy=True) ^ np.uint64(random_state & 0xFFFFFFFFFFFFFFFF)
    with np.errstate(over="ignore"):
        x += np.uint64(0x9E3779B97F4A7C15)
        x = (x ^ (x >> np.uint64(30))) * np.uint64(0xBF58476D1CE4E5B9)
        x = (x ^ (x >> np.uint64(27))) * np.uint64(0x94D049BB133111EB)
    return x ^ (x >> np.uint64(31))


def _record_hashes(features: pd.DataFrame) -> np.ndarray:
    """Calcula assinatura de 64 bits com base somente nas features selecionadas."""
    return pd.util.hash_pandas_object(features, index=False).to_numpy(dtype=np.uint64)


def align_features_to_manifest(
    features: pd.DataFrame,
    manifest: dict[str, Any],
) -> pd.DataFrame:
    """Seleciona e converte para tipos canonicos sem impor limites do Monday.

    Os tipos compactos do manifesto descrevem o armazenamento do treino. Eles
    definem a familia numerica esperada, mas nao um limite para outros dias.
    Inteiros sao promovidos a int64 e floats a float64 para preservar valores.
    """
    selected_columns = manifest.get("selected_features", [])
    expected_dtypes = manifest.get("expected_dtypes", {})
    missing = [column for column in selected_columns if column not in features.columns]
    if missing:
        raise ValueError(f"Features obrigatorias ausentes antes do alinhamento: {missing}")
    aligned = features.loc[:, selected_columns].copy()

    for column in selected_columns:
        expected_family = np.dtype(expected_dtypes[column])
        series = pd.to_numeric(aligned[column], errors="coerce")
        if series.isna().any():
            raise ValueError(f"A feature '{column}' possui valores nao numericos apos limpeza.")
        if np.issubdtype(expected_family, np.integer):
            values = series.to_numpy(dtype=np.float64, copy=False)
            if not np.equal(values, np.floor(values)).all():
                raise ValueError(f"A feature '{column}' possui fracao, mas espera inteiro.")
            converted = series.astype(np.int64)
        elif np.issubdtype(expected_family, np.floating):
            converted = series.astype(np.float64)
        else:
            raise ValueError(
                f"Familia numerica nao suportada em '{column}': {expected_family}."
            )
        if np.isinf(converted.to_numpy(copy=False)).any():
            raise ValueError(f"A conversao canonica de '{column}' gerou infinito.")
        aligned[column] = converted
    if aligned.columns.tolist() != selected_columns:
        raise ValueError("A ordem das features nao corresponde ao manifesto.")
    return aligned


def _schema_fingerprint(features: pd.DataFrame) -> str:
    """Identifica nomes, ordem e tipos canonicos dos dados de modelagem."""
    schema = "\n".join(f"{column}:{features[column].dtype}" for column in features.columns)
    return hashlib.sha256(schema.encode("utf-8")).hexdigest()


def _clean_external_chunk(
    chunk: pd.DataFrame,
) -> tuple[pd.DataFrame, pd.Series, pd.Series, dict[str, Any]]:
    """Aplica as regras essenciais do Marco 3 a um bloco externo."""
    chunk.columns = normalize_columns(list(chunk.columns))
    if "label" not in chunk.columns:
        raise ValueError("Coluna label ausente em um bloco externo.")
    labels = normalize_label_series(chunk["label"])
    source_rows = pd.Series(chunk.index.to_numpy(dtype=np.int64), index=chunk.index)
    features = chunk.drop(columns=["label"]).copy()

    conversion_failures: dict[str, int] = {}
    for column in features.columns:
        if pd.api.types.is_numeric_dtype(features[column]):
            continue
        original_non_null = features[column].notna()
        converted = pd.to_numeric(features[column], errors="coerce")
        failures = int((original_non_null & converted.isna()).sum())
        if failures:
            conversion_failures[column] = failures
        features[column] = converted

    missing_before = features.isna().sum()
    positive_infinity: dict[str, int] = {}
    negative_infinity: dict[str, int] = {}
    for column in features.columns:
        values = features[column].to_numpy(copy=False)
        positive = int(np.isposinf(values).sum())
        negative = int(np.isneginf(values).sum())
        if positive:
            positive_infinity[column] = positive
        if negative:
            negative_infinity[column] = negative
    features.replace([np.inf, -np.inf], np.nan, inplace=True)

    invalid_features = features.isna().any(axis=1)
    invalid_labels = labels.isna()
    valid = ~(invalid_features | invalid_labels)
    metrics = {
        "input_records": int(len(chunk)),
        "missing_cells_before_infinity_replacement": int(missing_before.sum()),
        "positive_infinity_total": int(sum(positive_infinity.values())),
        "negative_infinity_total": int(sum(negative_infinity.values())),
        "conversion_failures": conversion_failures,
        "invalid_feature_rows": int(invalid_features.sum()),
        "missing_label_rows": int(invalid_labels.sum()),
        "invalid_rows_removed": int((~valid).sum()),
        "valid_records": int(valid.sum()),
    }
    return (
        features.loc[valid].copy(),
        labels.loc[valid].copy(),
        source_rows.loc[valid].copy(),
        metrics,
    )


def _merge_numeric_metrics(target: dict[str, Any], source: dict[str, Any]) -> None:
    """Soma contadores de limpeza entre blocos."""
    for key in (
        "input_records",
        "missing_cells_before_infinity_replacement",
        "positive_infinity_total",
        "negative_infinity_total",
        "invalid_feature_rows",
        "missing_label_rows",
        "invalid_rows_removed",
        "valid_records",
    ):
        target[key] = int(target.get(key, 0) + source.get(key, 0))
    failures = target.setdefault("conversion_failures", {})
    for column, count in source.get("conversion_failures", {}).items():
        failures[column] = int(failures.get(column, 0) + count)


def _candidate_capacity(quota: int, ratio: float, available: int) -> int:
    """Adiciona reserva para compensar duplicatas e conflitos entre fontes."""
    buffer = max(10, int(math.ceil(quota * ratio)))
    return min(available, quota + buffer)


def _update_reservoir(
    current: pd.DataFrame | None,
    candidates: pd.DataFrame,
    capacity: int,
) -> pd.DataFrame:
    """Mantem os menores hashes de prioridade, sem duplicatas da mesma feature."""
    combined = candidates if current is None else pd.concat([current, candidates], ignore_index=True)
    combined.sort_values(["_priority", "_record_hash"], kind="mergesort", inplace=True)
    combined.drop_duplicates(subset=["_record_hash"], keep="first", inplace=True)
    return combined.head(capacity).copy()


def _prepare_monday_training(
    features_path: Path,
    labels_path: Path,
    manifest: dict[str, Any],
    config: SplitConfig,
) -> tuple[pd.DataFrame, dict[str, Any]]:
    """Seleciona treino normal somente a partir do Monday processado."""
    features = pd.read_parquet(features_path)
    labels_frame = pd.read_parquet(labels_path)
    if len(features) != len(labels_frame):
        raise ValueError("Features e labels do Monday possuem quantidades diferentes.")
    if "label" not in labels_frame.columns:
        raise ValueError("Arquivo de labels do Monday nao possui a coluna label.")
    labels = normalize_label_series(labels_frame["label"])
    attack_count = int(labels.ne(BENIGN_LABEL).sum())
    if attack_count:
        raise ValueError(f"Treino Monday contem {attack_count} registros nao BENIGN.")

    aligned = align_features_to_manifest(features, manifest)
    hashes = _record_hashes(aligned)
    priority = _mix_uint64(hashes, config.random_state)
    candidates = aligned.copy()
    candidates["_label"] = labels.to_numpy()
    candidates["_source_file"] = "Monday-WorkingHours.pcap_ISCX.csv"
    candidates["_source_row"] = np.arange(len(candidates), dtype=np.int64)
    candidates["_record_hash"] = hashes
    candidates["_priority"] = priority
    unique_before = len(candidates)
    candidates.sort_values(["_priority", "_record_hash"], kind="mergesort", inplace=True)
    candidates.drop_duplicates(subset=["_record_hash"], keep="first", inplace=True)
    if len(candidates) < config.train_benign_size:
        raise ValueError(
            f"Treino solicitado={config.train_benign_size}, normais unicos={len(candidates)}."
        )
    selected = candidates.head(config.train_benign_size).copy()
    report = {
        "source_records": int(unique_before),
        "unique_feature_records": int(len(candidates)),
        "duplicates_after_feature_selection": int(unique_before - len(candidates)),
        "selected_records": int(len(selected)),
        "selection": "smallest_deterministic_hash_priority",
        "source_row_semantics": "processed_monday_row_index",
    }
    return selected, report


def _collect_external_reservoirs(
    csv_files: list[Path],
    manifest: dict[str, Any],
    capacities: dict[str, int],
    config: SplitConfig,
) -> tuple[dict[str, pd.DataFrame], dict[str, Any]]:
    """Segunda passagem: limpa blocos e mantem somente candidatos necessarios."""
    reservoirs: dict[str, pd.DataFrame] = {}
    by_file: dict[str, Any] = {}
    eligible_counts: Counter[str] = Counter()
    feature_columns = manifest["selected_features"]

    for path in csv_files:
        file_metrics: dict[str, Any] = {}
        file_eligible_counts: Counter[str] = Counter()
        for chunk in pd.read_csv(
            path,
            chunksize=config.chunk_size,
            low_memory=False,
            encoding="utf-8",
            encoding_errors="replace",
        ):
            cleaned, labels, source_rows, chunk_metrics = _clean_external_chunk(chunk)
            _merge_numeric_metrics(file_metrics, chunk_metrics)
            aligned = align_features_to_manifest(cleaned, manifest)
            eligible_counts.update(labels.tolist())
            file_eligible_counts.update(labels.tolist())
            interested = labels.isin(capacities)
            if not interested.any():
                continue
            aligned = aligned.loc[interested].copy()
            selected_labels = labels.loc[interested]
            selected_rows = source_rows.loc[interested]
            hashes = _record_hashes(aligned)
            priorities = _mix_uint64(hashes, config.random_state)
            candidate_frame = aligned.reset_index(drop=True)
            candidate_frame["_label"] = selected_labels.to_numpy()
            candidate_frame["_source_file"] = path.name
            candidate_frame["_source_row"] = selected_rows.to_numpy(dtype=np.int64)
            candidate_frame["_record_hash"] = hashes
            candidate_frame["_priority"] = priorities

            for label, group in candidate_frame.groupby("_label", sort=False):
                label_text = str(label)
                reservoirs[label_text] = _update_reservoir(
                    reservoirs.get(label_text),
                    group[feature_columns + [
                        "_label",
                        "_source_file",
                        "_source_row",
                        "_record_hash",
                        "_priority",
                    ]],
                    capacities[label_text],
                )
        file_metrics["eligible_label_distribution"] = dict(
            sorted(file_eligible_counts.items())
        )
        by_file[path.name] = file_metrics
        LOGGER.info("Candidatos processados de %s.", path.name)

    report = {
        "cleaning_by_file": by_file,
        "eligible_label_distribution_after_cleaning": dict(sorted(eligible_counts.items())),
        "reservoir_records_by_label": {
            label: int(len(frame)) for label, frame in sorted(reservoirs.items())
        },
    }
    return reservoirs, report


def _pick_from_reservoir(
    reservoir: pd.DataFrame,
    count: int,
    used_hashes: set[int],
    label: str,
    split_name: str,
) -> tuple[pd.DataFrame, int]:
    """Seleciona linhas unicas e informa quantos conflitos foram ignorados."""
    available_mask = ~reservoir["_record_hash"].map(lambda value: int(value) in used_hashes)
    available = reservoir.loc[available_mask].sort_values(
        ["_priority", "_record_hash"], kind="mergesort"
    )
    if len(available) < count:
        raise ValueError(
            f"Candidatos insuficientes para {split_name}/{label}: "
            f"necessario={count}, disponivel={len(available)}."
        )
    selected = available.head(count).copy()
    used_hashes.update(int(value) for value in selected["_record_hash"])
    skipped = int((~available_mask).sum())
    return selected, skipped


def _assemble_split(
    parts: list[pd.DataFrame],
    feature_columns: list[str],
    random_state: int,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Concatena, embaralha e separa X dos metadados de avaliacao."""
    combined = pd.concat(parts, ignore_index=True)
    combined = combined.sample(frac=1.0, random_state=random_state).reset_index(drop=True)
    x = combined[feature_columns].copy()
    y = pd.DataFrame(
        {
            "label": combined["_label"].astype("string"),
            "binary_label": combined["_label"].ne(BENIGN_LABEL).astype("int8"),
            "source_file": combined["_source_file"].astype("string"),
            "source_row": combined["_source_row"].astype("int64"),
            "record_hash": combined["_record_hash"].map(
                lambda value: f"{int(value):016x}"
            ),
        }
    )
    return x, y


def _split_summary(x: pd.DataFrame, y: pd.DataFrame) -> dict[str, Any]:
    """Resume dimensoes, classes e fontes de um conjunto."""
    return {
        "records": int(len(x)),
        "feature_count": int(len(x.columns)),
        "label_present_in_features": "label" in x.columns,
        "binary_distribution": {
            str(label): int(count)
            for label, count in y["binary_label"].value_counts().sort_index().items()
        },
        "label_distribution": {
            str(label): int(count) for label, count in y["label"].value_counts().items()
        },
        "source_distribution": {
            str(source): int(count)
            for source, count in y["source_file"].value_counts().items()
        },
    }


def build_data_splits(
    monday_features_path: Path,
    monday_labels_path: Path,
    feature_manifest_path: Path,
    external_csv_files: list[Path],
    config: SplitConfig | None = None,
) -> DataSplitResult:
    """Constroi os tres conjuntos, sem compartilhar assinaturas entre eles."""
    config = config or SplitConfig()
    if not external_csv_files:
        raise ValueError("Nenhum CSV externo foi informado.")
    manifest = load_feature_manifest(feature_manifest_path)
    feature_columns = manifest["selected_features"]

    total_labels, labels_by_file = count_external_labels(external_csv_files, config.chunk_size)
    benign_available = int(total_labels.get(BENIGN_LABEL, 0))
    attack_available = {
        label: count
        for label, count in total_labels.items()
        if label not in (BENIGN_LABEL, "<AUSENTE>")
    }
    validation_attack_quotas = allocate_stratified_quota(
        attack_available,
        config.validation_attack_size,
        config.minimum_attack_per_split,
    )
    remaining_attacks = {
        label: attack_available[label] - validation_attack_quotas.get(label, 0)
        for label in attack_available
    }
    test_attack_quotas = allocate_stratified_quota(
        remaining_attacks,
        config.test_attack_size,
        config.minimum_attack_per_split,
    )
    total_attack_quotas = {
        label: validation_attack_quotas.get(label, 0) + test_attack_quotas.get(label, 0)
        for label in attack_available
    }
    benign_total_quota = config.validation_benign_size + config.test_benign_size
    if benign_total_quota > benign_available:
        raise ValueError("Nao ha BENIGN externo suficiente para validacao e teste.")

    capacities = {
        BENIGN_LABEL: _candidate_capacity(
            benign_total_quota, config.candidate_buffer_ratio, benign_available
        )
    }
    for label, quota in total_attack_quotas.items():
        capacities[label] = _candidate_capacity(
            quota, config.candidate_buffer_ratio, attack_available[label]
        )

    train_candidates, monday_report = _prepare_monday_training(
        monday_features_path, monday_labels_path, manifest, config
    )
    reservoirs, external_report = _collect_external_reservoirs(
        external_csv_files, manifest, capacities, config
    )

    used_hashes = {int(value) for value in train_candidates["_record_hash"]}
    validation_parts: list[pd.DataFrame] = []
    test_parts: list[pd.DataFrame] = []
    skipped_conflicts: dict[str, dict[str, int]] = {"validation": {}, "test": {}}

    # Classes raras sao escolhidas primeiro para preserva-las em caso de conflito.
    attack_order = sorted(attack_available, key=lambda label: (attack_available[label], label))
    for label in attack_order:
        validation_part, skipped = _pick_from_reservoir(
            reservoirs[label],
            validation_attack_quotas[label],
            used_hashes,
            label,
            "validation",
        )
        validation_parts.append(validation_part)
        skipped_conflicts["validation"][label] = skipped
        test_part, skipped = _pick_from_reservoir(
            reservoirs[label],
            test_attack_quotas[label],
            used_hashes,
            label,
            "test",
        )
        test_parts.append(test_part)
        skipped_conflicts["test"][label] = skipped

    validation_benign, skipped = _pick_from_reservoir(
        reservoirs[BENIGN_LABEL],
        config.validation_benign_size,
        used_hashes,
        BENIGN_LABEL,
        "validation",
    )
    validation_parts.append(validation_benign)
    skipped_conflicts["validation"][BENIGN_LABEL] = skipped
    test_benign, skipped = _pick_from_reservoir(
        reservoirs[BENIGN_LABEL],
        config.test_benign_size,
        used_hashes,
        BENIGN_LABEL,
        "test",
    )
    test_parts.append(test_benign)
    skipped_conflicts["test"][BENIGN_LABEL] = skipped

    x_train, y_train = _assemble_split(
        [train_candidates], feature_columns, config.random_state
    )
    x_validation, y_validation = _assemble_split(
        validation_parts, feature_columns, config.random_state + 1
    )
    x_test, y_test = _assemble_split(
        test_parts, feature_columns, config.random_state + 2
    )

    train_hashes = set(y_train["record_hash"])
    validation_hashes = set(y_validation["record_hash"])
    test_hashes = set(y_test["record_hash"])
    overlaps = {
        "train_validation": int(len(train_hashes & validation_hashes)),
        "train_test": int(len(train_hashes & test_hashes)),
        "validation_test": int(len(validation_hashes & test_hashes)),
    }
    if any(overlaps.values()):
        raise ValueError(f"Vazamento por registros identicos detectado: {overlaps}")
    if int(y_train["binary_label"].sum()) != 0:
        raise ValueError("O conjunto de treino contem ataques.")

    schema_fingerprints = {
        "train": _schema_fingerprint(x_train),
        "validation": _schema_fingerprint(x_validation),
        "test": _schema_fingerprint(x_test),
    }
    if len(set(schema_fingerprints.values())) != 1:
        raise ValueError(f"Esquemas diferentes entre os conjuntos: {schema_fingerprints}")

    split_manifest: dict[str, Any] = {
        "schema_version": 1,
        "stage": "data_split_marco_5",
        "random_state": config.random_state,
        "selection_manifest_sha256": manifest["feature_schema_sha256"],
        "model_input_schema_sha256": schema_fingerprints["train"],
        "dtype_policy": "integer_to_int64_and_float_to_float64",
        "feature_count": len(feature_columns),
        "feature_columns": feature_columns,
        "split_files": {},
    }
    report: dict[str, Any] = {
        "stage": "data_split_marco_5",
        "configuration": asdict(config),
        "methodology": {
            "training_source": "Monday BENIGN only",
            "validation_test_sources": "non-Monday BENIGN and attacks",
            "labels_used_for_model_features": False,
            "labels_used_for_stratification_only": True,
            "sampling": "deterministic hash priority without replacement",
            "record_identity": "pandas 64-bit hash of the 60 selected features",
            "dtype_policy": (
                "manifest defines numeric family; integers are widened to int64 and "
                "floats to float64 so Monday storage limits do not constrain other days"
            ),
            "evaluation_prevalence_note": (
                "validation and test are balanced 50/50; precision reflects this "
                "controlled prevalence"
            ),
        },
        "external_raw_label_distribution": total_labels,
        "external_raw_label_distribution_by_file": labels_by_file,
        "attack_quotas": {
            "validation": validation_attack_quotas,
            "test": test_attack_quotas,
        },
        "monday_training_preparation": monday_report,
        "external_preparation": external_report,
        "skipped_hash_conflicts": skipped_conflicts,
        "outputs": {
            "train": _split_summary(x_train, y_train),
            "validation": _split_summary(x_validation, y_validation),
            "test": _split_summary(x_test, y_test),
        },
        "leakage_checks": {
            "hash_overlaps": overlaps,
            "train_attack_records": int(y_train["binary_label"].sum()),
            "label_present_in_x_train": "label" in x_train.columns,
            "label_present_in_x_validation": "label" in x_validation.columns,
            "label_present_in_x_test": "label" in x_test.columns,
            "selection_manifest_sha256": manifest["feature_schema_sha256"],
            "model_input_schema_sha256": schema_fingerprints["train"],
            "schema_fingerprints_by_split": schema_fingerprints,
            "status": "passed",
        },
    }
    return DataSplitResult(
        x_train=x_train,
        y_train=y_train,
        x_validation=x_validation,
        y_validation=y_validation,
        x_test=x_test,
        y_test=y_test,
        manifest=split_manifest,
        report=report,
    )


def save_data_splits(
    result: DataSplitResult,
    output_dir: Path,
    report_path: Path,
    overwrite: bool = False,
) -> None:
    """Persiste seis Parquets e dois manifestos, recusando sobrescrita acidental."""
    paths = {
        "x_train": output_dir / "X_train.parquet",
        "y_train": output_dir / "y_train.parquet",
        "x_validation": output_dir / "X_validation.parquet",
        "y_validation": output_dir / "y_validation.parquet",
        "x_test": output_dir / "X_test.parquet",
        "y_test": output_dir / "y_test.parquet",
        "split_manifest": output_dir / "split_manifest.json",
        "report": report_path,
    }
    existing = [path for path in paths.values() if path.exists()]
    if existing and not overwrite:
        raise FileExistsError(
            "Artefato(s) ja existente(s); use --overwrite para substituir: "
            + ", ".join(str(path) for path in existing)
        )
    output_dir.mkdir(parents=True, exist_ok=True)
    report_path.parent.mkdir(parents=True, exist_ok=True)

    result.x_train.to_parquet(paths["x_train"], index=False, compression="snappy")
    result.y_train.to_parquet(paths["y_train"], index=False, compression="snappy")
    result.x_validation.to_parquet(paths["x_validation"], index=False, compression="snappy")
    result.y_validation.to_parquet(paths["y_validation"], index=False, compression="snappy")
    result.x_test.to_parquet(paths["x_test"], index=False, compression="snappy")
    result.y_test.to_parquet(paths["y_test"], index=False, compression="snappy")
    result.manifest["split_files"] = {
        key: str(path.resolve())
        for key, path in paths.items()
        if key not in ("split_manifest", "report")
    }
    result.manifest["report_path"] = str(report_path.resolve())
    result.report["artifacts"] = {key: str(path.resolve()) for key, path in paths.items()}
    save_json(result.manifest, paths["split_manifest"])
    save_json(result.report, report_path)


def format_split_summary(report: dict[str, Any]) -> str:
    """Apresenta as principais contagens e verificacoes no terminal."""
    train = report["outputs"]["train"]
    validation = report["outputs"]["validation"]
    test = report["outputs"]["test"]
    overlaps = report["leakage_checks"]["hash_overlaps"]
    return "\n".join(
        [
            "\n=== DIVISAO DOS DADOS — MARCO 5 ===",
            f"Treino: {train['records']:,} registros "
            f"(BENIGN={train['binary_distribution'].get('0', 0):,}, ataques=0)",
            f"Validacao: {validation['records']:,} registros "
            f"(BENIGN={validation['binary_distribution'].get('0', 0):,}, "
            f"ataques={validation['binary_distribution'].get('1', 0):,})",
            f"Teste: {test['records']:,} registros "
            f"(BENIGN={test['binary_distribution'].get('0', 0):,}, "
            f"ataques={test['binary_distribution'].get('1', 0):,})",
            f"Features por conjunto: {train['feature_count']}",
            f"Sobreposicao treino/validacao: {overlaps['train_validation']}",
            f"Sobreposicao treino/teste: {overlaps['train_test']}",
            f"Sobreposicao validacao/teste: {overlaps['validation_test']}",
            f"Status de vazamento: {report['leakage_checks']['status']}",
        ]
    )
