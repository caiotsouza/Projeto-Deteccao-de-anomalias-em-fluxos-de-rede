"""Selecao conservadora e auditavel de features do CIC-IDS2017 (Marco 4)."""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from src.config import (
    DEFAULT_CORRELATION_THRESHOLD,
    DEFAULT_NEAR_CONSTANT_THRESHOLD,
    DEFAULT_RANDOM_STATE,
)
from src.utils import save_json


LOGGER = logging.getLogger(__name__)


# Regras semanticas avaliadas somente se as duas colunas estiverem presentes.
# Cada exclusao mantem uma feature canonica equivalente no conjunto final.
REDUNDANCY_RULES: tuple[dict[str, str], ...] = (
    {
        "excluded": "fwd_header_length_1",
        "retained": "fwd_header_length",
        "relation": "allclose",
        "reason": "segunda exportacao do comprimento de cabecalho forward",
    },
    {
        "excluded": "subflow_fwd_packets",
        "retained": "total_fwd_packets",
        "relation": "allclose",
        "reason": "equivalente ao total de pacotes forward no conjunto de treino",
    },
    {
        "excluded": "subflow_fwd_bytes",
        "retained": "total_length_of_fwd_packets",
        "relation": "allclose",
        "reason": "equivalente ao total de bytes forward no conjunto de treino",
    },
    {
        "excluded": "subflow_bwd_packets",
        "retained": "total_backward_packets",
        "relation": "allclose",
        "reason": "equivalente ao total de pacotes backward no conjunto de treino",
    },
    {
        "excluded": "subflow_bwd_bytes",
        "retained": "total_length_of_bwd_packets",
        "relation": "allclose",
        "reason": "equivalente ao total de bytes backward no conjunto de treino",
    },
    {
        "excluded": "avg_fwd_segment_size",
        "retained": "fwd_packet_length_mean",
        "relation": "allclose",
        "reason": "mesma media de tamanho observada na direcao forward",
    },
    {
        "excluded": "avg_bwd_segment_size",
        "retained": "bwd_packet_length_mean",
        "relation": "allclose",
        "reason": "mesma media de tamanho observada na direcao backward",
    },
    {
        "excluded": "packet_length_variance",
        "retained": "packet_length_std",
        "relation": "square",
        "reason": "variancia e transformacao deterministica do desvio-padrao",
    },
)


@dataclass(frozen=True)
class FeatureSelectionConfig:
    """Parametros centralizados da analise e selecao."""

    near_constant_threshold: float = DEFAULT_NEAR_CONSTANT_THRESHOLD
    correlation_threshold: float = DEFAULT_CORRELATION_THRESHOLD
    correlation_sample_size: int | None = None
    random_state: int = DEFAULT_RANDOM_STATE
    drop_constant_features: bool = True

    def __post_init__(self) -> None:
        if not 0.5 < self.near_constant_threshold <= 1.0:
            raise ValueError("near_constant_threshold deve estar em (0.5, 1.0].")
        if not 0.0 < self.correlation_threshold <= 1.0:
            raise ValueError("correlation_threshold deve estar em (0.0, 1.0].")
        if self.correlation_sample_size is not None and self.correlation_sample_size <= 1:
            raise ValueError("correlation_sample_size deve ser maior que 1.")


@dataclass
class FeatureSelectionResult:
    """Features selecionadas, manifesto de esquema e relatorio metodologico."""

    selected_features: pd.DataFrame
    manifest: dict[str, Any]
    report: dict[str, Any]


def _validate_features(features: pd.DataFrame) -> None:
    """Impede selecao sobre entrada vazia, invalida ou com vazamento de label."""
    if features.empty:
        raise ValueError("A matriz de features esta vazia.")
    if "label" in features.columns:
        raise ValueError("Vazamento detectado: a coluna 'label' nao pode participar da selecao.")
    if features.columns.duplicated().any():
        duplicated = features.columns[features.columns.duplicated()].tolist()
        raise ValueError(f"Nomes de features duplicados: {duplicated}")
    non_numeric = [
        column
        for column in features.columns
        if not pd.api.types.is_numeric_dtype(features[column])
    ]
    if non_numeric:
        raise ValueError(f"Features nao numericas encontradas: {non_numeric}")

    missing_total = int(features.isna().sum().sum())
    if missing_total:
        raise ValueError(f"A entrada possui {missing_total} valores ausentes; execute o Marco 3.")
    infinity_total = 0
    for column in features.columns:
        infinity_total += int(np.isinf(features[column].to_numpy(copy=False)).sum())
    if infinity_total:
        raise ValueError(f"A entrada possui {infinity_total} infinitos; execute o Marco 3.")


def _near_constant_analysis(
    features: pd.DataFrame,
    constants: list[str],
    threshold: float,
) -> dict[str, dict[str, Any]]:
    """Identifica baixa variabilidade sem excluir automaticamente."""
    result: dict[str, dict[str, Any]] = {}
    constant_set = set(constants)
    for column in features.columns:
        if column in constant_set:
            continue
        counts = features[column].value_counts(dropna=False)
        ratio = float(counts.iloc[0] / len(features))
        if ratio >= threshold:
            result[column] = {
                "most_frequent_value": str(counts.index[0]),
                "most_frequent_count": int(counts.iloc[0]),
                "most_frequent_ratio": round(ratio, 8),
                "unique_values": int(len(counts)),
                "decision": "retained",
                "reason": "baixa variabilidade nao prova irrelevancia em seguranca",
            }
    return result


def _validate_redundancy_rule(
    features: pd.DataFrame,
    rule: dict[str, str],
) -> dict[str, Any]:
    """Confirma numericamente uma regra antes de permitir a exclusao."""
    excluded = rule["excluded"]
    retained = rule["retained"]
    decision: dict[str, Any] = dict(rule)
    if excluded not in features.columns or retained not in features.columns:
        decision.update(
            {
                "validation": "not_applicable",
                "excluded_from_selection": False,
                "missing_columns": [
                    column for column in (excluded, retained) if column not in features.columns
                ],
            }
        )
        return decision

    left = features[excluded].to_numpy(dtype=np.float64, copy=False)
    right = features[retained].to_numpy(dtype=np.float64, copy=False)
    if rule["relation"] == "square":
        expected = np.square(right)
    else:
        expected = right

    absolute_difference = np.abs(left - expected)
    scale = np.maximum(np.abs(left), np.abs(expected))
    relative_difference = np.divide(
        absolute_difference,
        scale,
        out=np.zeros_like(absolute_difference),
        where=scale != 0,
    )
    valid = bool(np.allclose(left, expected, rtol=1e-5, atol=1e-6, equal_nan=False))
    decision.update(
        {
            "validation": "confirmed" if valid else "failed",
            "excluded_from_selection": valid,
            "different_rows_exact_comparison": int(np.count_nonzero(absolute_difference)),
            "maximum_absolute_difference": float(absolute_difference.max(initial=0.0)),
            "maximum_relative_difference": float(relative_difference.max(initial=0.0)),
            "rtol": 1e-5,
            "atol": 1e-6,
        }
    )
    return decision


def _correlation_pairs(
    features: pd.DataFrame,
    constants: list[str],
    threshold: float,
    sample_size: int | None,
    random_state: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Calcula Pearson para diagnostico; nao decide exclusoes."""
    variable_columns = [column for column in features.columns if column not in constants]
    correlation_input = features[variable_columns]
    sampling_enabled = sample_size is not None and sample_size < len(correlation_input)
    if sampling_enabled:
        correlation_input = correlation_input.sample(
            n=sample_size, random_state=random_state, replace=False
        )

    correlation = correlation_input.corr(method="pearson")
    pairs: list[dict[str, Any]] = []
    columns = correlation.columns.tolist()
    for left_index, left in enumerate(columns):
        for right in columns[left_index + 1 :]:
            coefficient = correlation.at[left, right]
            if pd.notna(coefficient) and abs(float(coefficient)) >= threshold:
                pairs.append(
                    {
                        "feature_a": left,
                        "feature_b": right,
                        "pearson_correlation": round(float(coefficient), 10),
                        "absolute_correlation": round(abs(float(coefficient)), 10),
                    }
                )
    pairs.sort(key=lambda item: item["absolute_correlation"], reverse=True)
    metadata = {
        "method": "pearson",
        "threshold_absolute": threshold,
        "input_records": int(len(features)),
        "records_used": int(len(correlation_input)),
        "sampling_enabled": sampling_enabled,
        "random_state": random_state if sampling_enabled else None,
        "constant_features_excluded_from_calculation": constants,
    }
    return pairs, metadata


def _schema_fingerprint(features: pd.DataFrame) -> str:
    """Gera identificador do nome, ordem e tipo das features."""
    schema = "\n".join(f"{column}:{features[column].dtype}" for column in features.columns)
    return hashlib.sha256(schema.encode("utf-8")).hexdigest()


def select_features(
    features: pd.DataFrame,
    config: FeatureSelectionConfig | None = None,
) -> FeatureSelectionResult:
    """Analisa X e remove somente constantes e redundancias comprovadas."""
    config = config or FeatureSelectionConfig()
    _validate_features(features)
    LOGGER.info("Entrada validada: %s registros e %s features.", f"{len(features):,}", len(features.columns))

    unique_counts = features.nunique(dropna=False)
    constants = unique_counts[unique_counts <= 1].index.tolist()
    near_constants = _near_constant_analysis(
        features, constants, config.near_constant_threshold
    )
    redundancy_decisions = [
        _validate_redundancy_rule(features, rule) for rule in REDUNDANCY_RULES
    ]
    confirmed_redundancies = [
        decision["excluded"]
        for decision in redundancy_decisions
        if decision["excluded_from_selection"]
    ]
    failed_rules = [
        decision["excluded"]
        for decision in redundancy_decisions
        if decision["validation"] == "failed"
    ]
    if failed_rules:
        LOGGER.warning("Regras de redundancia nao confirmadas e mantidas: %s", failed_rules)

    correlation_pairs, correlation_metadata = _correlation_pairs(
        features,
        constants=constants,
        threshold=config.correlation_threshold,
        sample_size=config.correlation_sample_size,
        random_state=config.random_state,
    )

    excluded_reasons: dict[str, dict[str, Any]] = {}
    if config.drop_constant_features:
        for column in constants:
            excluded_reasons[column] = {
                "category": "constant_in_normal_training_data",
                "reason": "sem variacao para aprender o comportamento normal",
                "unique_values": int(unique_counts[column]),
            }
    for decision in redundancy_decisions:
        if decision["excluded_from_selection"]:
            excluded_reasons[decision["excluded"]] = {
                "category": "confirmed_redundancy",
                "reason": decision["reason"],
                "retained_equivalent": decision["retained"],
                "relation": decision["relation"],
            }

    excluded_set = set(excluded_reasons)
    selected_columns = [column for column in features.columns if column not in excluded_set]
    selected = features.loc[:, selected_columns].copy()
    input_memory_mb = float(features.memory_usage(deep=True).sum() / 1024**2)
    selected_memory_mb = float(selected.memory_usage(deep=True).sum() / 1024**2)
    high_correlations_retained = [
        pair
        for pair in correlation_pairs
        if pair["feature_a"] in selected_columns and pair["feature_b"] in selected_columns
    ]
    fingerprint = _schema_fingerprint(selected)

    manifest: dict[str, Any] = {
        "schema_version": 1,
        "stage": "feature_selection_marco_4",
        "feature_schema_sha256": fingerprint,
        "selected_feature_count": int(len(selected_columns)),
        "selected_features": selected_columns,
        "expected_dtypes": {
            column: str(selected[column].dtype) for column in selected_columns
        },
        "excluded_feature_count": int(len(excluded_reasons)),
        "excluded_features": excluded_reasons,
        "application_rule": "select_by_name_and_preserve_manifest_order",
    }
    report: dict[str, Any] = {
        "stage": "feature_selection_marco_4",
        "configuration": asdict(config),
        "methodology": {
            "labels_used": False,
            "attack_records_used": False,
            "automatic_correlation_removal": False,
            "selection_principle": (
                "remove only zero-variance features and numerically confirmed redundancies"
            ),
            "cicflowmeter_feature_reference": (
                "https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt"
            ),
        },
        "input": {
            "records": int(len(features)),
            "feature_count": int(len(features.columns)),
            "memory_usage_mb": round(input_memory_mb, 3),
            "label_present": "label" in features.columns,
            "feature_columns": features.columns.tolist(),
            "feature_dtypes": {
                column: str(features[column].dtype) for column in features.columns
            },
        },
        "constant_analysis": {
            "found_count": int(len(constants)),
            "features": constants,
            "decision": "excluded" if config.drop_constant_features else "retained",
        },
        "near_constant_analysis": {
            "threshold": config.near_constant_threshold,
            "found_count": int(len(near_constants)),
            "features": near_constants,
            "decision": "retained_for_security_review",
        },
        "redundancy_analysis": {
            "rules_evaluated": redundancy_decisions,
            "confirmed_exclusion_count": int(len(confirmed_redundancies)),
            "confirmed_exclusions": confirmed_redundancies,
        },
        "correlation_analysis": {
            **correlation_metadata,
            "high_correlation_pair_count_before_selection": int(len(correlation_pairs)),
            "high_correlation_pairs_before_selection": correlation_pairs,
            "high_correlation_pair_count_retained": int(len(high_correlations_retained)),
            "high_correlation_pairs_retained": high_correlations_retained,
            "decision": "reported_only_no_automatic_exclusion",
        },
        "explicit_retention_decisions": {
            "syn_flag_count_and_fwd_psh_flags": {
                "decision": "retain_both",
                "reason": "flags TCP semanticamente diferentes apesar da igualdade no Monday",
            },
            "near_constant_tcp_flags": {
                "features": [
                    feature
                    for feature in ("rst_flag_count", "ece_flag_count")
                    if feature in selected_columns
                ],
                "decision": "retain",
                "reason": "eventos raros podem carregar sinal de seguranca",
            },
        },
        "selection": {
            "selected_feature_count": int(len(selected_columns)),
            "selected_features": selected_columns,
            "excluded_feature_count": int(len(excluded_reasons)),
            "excluded_features": excluded_reasons,
            "feature_schema_sha256": fingerprint,
            "memory_usage_mb": round(selected_memory_mb, 3),
            "memory_reduction_mb": round(input_memory_mb - selected_memory_mb, 3),
            "memory_reduction_percentage": round(
                (input_memory_mb - selected_memory_mb) / input_memory_mb * 100, 6
            ),
        },
    }
    LOGGER.info(
        "Selecao concluida: %s mantidas e %s excluidas.",
        len(selected_columns),
        len(excluded_reasons),
    )
    return FeatureSelectionResult(selected_features=selected, manifest=manifest, report=report)


def apply_feature_manifest(
    features: pd.DataFrame,
    manifest: dict[str, Any],
) -> pd.DataFrame:
    """Aplica o mesmo nome e ordem de features a dados futuros."""
    if "label" in features.columns:
        raise ValueError("Remova 'label' antes de aplicar o manifesto de features.")
    selected_columns = manifest.get("selected_features")
    if not isinstance(selected_columns, list) or not selected_columns:
        raise ValueError("Manifesto invalido: selected_features ausente ou vazio.")
    missing = [column for column in selected_columns if column not in features.columns]
    if missing:
        raise ValueError(f"Dados de inferencia sem features obrigatorias: {missing}")
    selected = features.loc[:, selected_columns].copy()
    if _schema_fingerprint(selected) != manifest.get("feature_schema_sha256"):
        raise ValueError(
            "O nome, a ordem ou os tipos das features nao correspondem ao manifesto."
        )
    return selected


def load_feature_manifest(path: Path) -> dict[str, Any]:
    """Carrega um manifesto JSON de forma explicita."""
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def save_feature_selection(
    result: FeatureSelectionResult,
    selected_path: Path,
    manifest_path: Path,
    report_path: Path,
    overwrite: bool = False,
) -> None:
    """Salva dataset selecionado, manifesto leve e relatorio completo."""
    paths = [selected_path, manifest_path, report_path]
    existing = [path for path in paths if path.exists()]
    if existing and not overwrite:
        raise FileExistsError(
            "Artefato(s) ja existente(s); use --overwrite para substituir: "
            + ", ".join(str(path) for path in existing)
        )
    for path in paths:
        path.parent.mkdir(parents=True, exist_ok=True)

    result.report["artifacts"] = {
        "selected_features_path": str(selected_path.resolve()),
        "manifest_path": str(manifest_path.resolve()),
        "report_path": str(report_path.resolve()),
        "format": "parquet_snappy_and_json_utf8",
    }
    result.manifest["selection_report_path"] = str(report_path.resolve())
    result.selected_features.to_parquet(selected_path, index=False, compression="snappy")
    save_json(result.manifest, manifest_path)
    save_json(result.report, report_path)


def format_feature_selection_summary(report: dict[str, Any]) -> str:
    """Formata as principais decisoes para o terminal."""
    constants = report["constant_analysis"]
    redundancies = report["redundancy_analysis"]
    near_constants = report["near_constant_analysis"]
    correlation = report["correlation_analysis"]
    selection = report["selection"]
    return "\n".join(
        [
            "\n=== SELECAO DE FEATURES — MARCO 4 ===",
            f"Registros analisados: {report['input']['records']:,}",
            f"Features de entrada: {report['input']['feature_count']:,}",
            f"Features constantes excluidas: {constants['found_count']:,}",
            f"Redundancias comprovadas excluidas: "
            f"{redundancies['confirmed_exclusion_count']:,}",
            f"Features quase constantes mantidas: {near_constants['found_count']:,}",
            f"Pares com correlacao alta reportados: "
            f"{correlation['high_correlation_pair_count_before_selection']:,}",
            f"Pares altamente correlacionados ainda presentes: "
            f"{correlation['high_correlation_pair_count_retained']:,}",
            f"Features finais: {selection['selected_feature_count']:,}",
            f"Features excluidas: {selection['excluded_feature_count']:,}",
            f"Memoria de X: {report['input']['memory_usage_mb']:.3f} MB -> "
            f"{selection['memory_usage_mb']:.3f} MB",
            f"Labels usados na selecao: {report['methodology']['labels_used']}",
            f"Registros de ataque usados: {report['methodology']['attack_records_used']}",
            f"Fingerprint do esquema: {selection['feature_schema_sha256']}",
        ]
    )
