"""Inferência estruturada e independente de CSV para o Marco 11."""

from __future__ import annotations

import hashlib
import json
import math
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from numbers import Real
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd

from src.config import PROJECT_ROOT


DEFAULT_EXPERIMENT = "expanded_100k"
DEFAULT_MODEL = "isolation_forest"
DEFAULT_OPERATING_POINT = "validation_fpr_operational"
SUPPORTED_MODELS = ("isolation_forest", "lof")
SUPPORTED_OPERATING_POINTS = (
    "native",
    "validation_f1_calibrated",
    "validation_fpr_operational",
)
OPERATIONAL_REGISTRY_RELATIVE_PATH = Path(
    "reports/operational/model_registry_operational.json"
)
FORBIDDEN_FEATURE_NAMES = {
    "label",
    "binary_label",
    "is_attack",
    "predicted_anomaly",
}


@dataclass(frozen=True)
class ModelSelection:
    """Identifica um modelo e um ponto operacional do registro final."""

    experiment: str = DEFAULT_EXPERIMENT
    model: str = DEFAULT_MODEL
    operating_point: str = DEFAULT_OPERATING_POINT


def _load_json(path: Path) -> dict[str, Any]:
    """Carrega um objeto JSON obrigatório."""
    if not path.is_file():
        raise FileNotFoundError(f"JSON obrigatório não encontrado: {path}")
    with path.open("r", encoding="utf-8") as file:
        data = json.load(file)
    if not isinstance(data, dict):
        raise ValueError(f"O JSON deve possuir um objeto na raiz: {path}")
    return data


def _sha256_file(path: Path) -> str:
    """Calcula SHA-256 de um artefato local em blocos."""
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for block in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _safe_project_path(project_root: Path, relative_path: str) -> Path:
    """Resolve um caminho do registro sem permitir saída da raiz do projeto."""
    candidate = (project_root / relative_path).resolve()
    try:
        candidate.relative_to(project_root.resolve())
    except ValueError as exc:
        raise ValueError(
            f"O registro aponta para fora da raiz do projeto: {relative_path}"
        ) from exc
    return candidate


def default_registry_path(project_root: Path = PROJECT_ROOT) -> Path:
    """Prefere o registro operacional derivado e mantém fallback ao Marco 10."""
    project_root = project_root.resolve()
    operational = project_root / OPERATIONAL_REGISTRY_RELATIVE_PATH
    if operational.is_file():
        return operational.resolve()
    return (project_root / "reports" / "final" / "model_registry.json").resolve()


def _timestamp_utc(value: object | None, fallback: datetime) -> str:
    """Normaliza uma data ISO 8601 para UTC e exige informação de fuso."""
    if value is None:
        moment = fallback
    elif isinstance(value, datetime):
        moment = value
    elif isinstance(value, str):
        normalized = value.strip()
        if normalized.endswith("Z"):
            normalized = normalized[:-1] + "+00:00"
        try:
            moment = datetime.fromisoformat(normalized)
        except ValueError as exc:
            raise ValueError(f"Data ISO 8601 inválida: {value!r}") from exc
    else:
        raise TypeError("observed_at deve ser string ISO 8601 ou datetime.")
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise ValueError("observed_at deve informar o fuso horário.")
    return moment.astimezone(timezone.utc).isoformat()


def _validate_context(context: object) -> dict[str, Any]:
    """Aceita metadados escalares seguros para JSON/MongoDB."""
    if context is None:
        return {}
    if not isinstance(context, Mapping):
        raise TypeError("context deve ser um objeto chave-valor.")
    validated: dict[str, Any] = {}
    for raw_key, value in context.items():
        if not isinstance(raw_key, str) or not raw_key:
            raise ValueError("Toda chave de context deve ser uma string não vazia.")
        if raw_key.startswith("$") or "." in raw_key:
            raise ValueError(
                f"Chave incompatível com armazenamento seguro no MongoDB: {raw_key}"
            )
        if value is not None and not isinstance(value, (str, int, float, bool)):
            raise TypeError(
                f"context.{raw_key} deve ser string, número, booleano ou null."
            )
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError(f"context.{raw_key} não pode ser NaN ou infinito.")
        validated[raw_key] = value
    return validated


def _threshold_value(thresholds: dict[str, Any], operating_point: str) -> float:
    """Extrai um limiar congelado no registro selecionado."""
    if operating_point == "native":
        value = thresholds[operating_point]["equivalent_anomaly_score_threshold"]
    else:
        value = thresholds[operating_point]["threshold"]
    value = float(value)
    if not math.isfinite(value):
        raise ValueError("O registro contém um limiar não finito.")
    return value


class AnomalyInferenceService:
    """Mantém um modelo validado em memória para inferência em lote."""

    def __init__(
        self,
        *,
        project_root: Path,
        registry_path: Path,
        selection: ModelSelection,
        model_entry: dict[str, Any],
        bundle: dict[str, Any],
        max_batch_size: int = 1000,
    ) -> None:
        if max_batch_size <= 0:
            raise ValueError("max_batch_size deve ser maior que zero.")
        self.project_root = project_root.resolve()
        self.registry_path = registry_path.resolve()
        self.selection = selection
        self.model_entry = model_entry
        self.bundle = bundle
        self.max_batch_size = int(max_batch_size)
        estimator_key = "model" if selection.model == "isolation_forest" else "pipeline"
        if estimator_key not in bundle:
            raise ValueError(
                f"Bundle de {selection.model} não contém a chave {estimator_key!r}."
            )
        self.estimator = bundle[estimator_key]
        self.feature_columns = tuple(str(name) for name in bundle["feature_columns"])
        if not self.feature_columns or len(set(self.feature_columns)) != len(
            self.feature_columns
        ):
            raise ValueError("Bundle contém uma lista de features inválida.")
        if FORBIDDEN_FEATURE_NAMES.intersection(self.feature_columns):
            raise ValueError("Bundle contém rótulo ou saída entre as features.")
        if int(model_entry["feature_count"]) != len(self.feature_columns):
            raise ValueError("Quantidade de features diverge do registro do modelo.")
        registry_schema = str(model_entry["model_input_schema_sha256"])
        bundle_schema = str(bundle["model_input_schema_sha256"])
        if registry_schema != bundle_schema:
            raise ValueError("Fingerprint do esquema diverge entre registro e bundle.")
        self.threshold = _threshold_value(
            model_entry["thresholds"], selection.operating_point
        )

    @classmethod
    def from_registry(
        cls,
        *,
        project_root: Path = PROJECT_ROOT,
        registry_path: Path | None = None,
        selection: ModelSelection | None = None,
        max_batch_size: int = 1000,
    ) -> "AnomalyInferenceService":
        """Valida o hash e carrega um modelo de um registro confiável."""
        project_root = project_root.resolve()
        registry_path = (
            registry_path or default_registry_path(project_root)
        ).resolve()
        selection = selection or ModelSelection()
        if selection.model not in SUPPORTED_MODELS:
            raise ValueError(f"Modelo não suportado: {selection.model}")
        if selection.operating_point not in SUPPORTED_OPERATING_POINTS:
            raise ValueError(
                f"Ponto operacional não suportado: {selection.operating_point}"
            )
        registry = _load_json(registry_path)
        if registry.get("status") != "completed":
            raise ValueError("O registro de modelos não está concluído.")
        try:
            model_entry = registry["experiments"][selection.experiment]["models"][
                selection.model
            ]
        except KeyError as exc:
            raise ValueError(
                "Seleção ausente no registro: "
                f"{selection.experiment}/{selection.model}"
            ) from exc
        try:
            threshold_entry = model_entry["thresholds"][selection.operating_point]
        except KeyError as exc:
            raise ValueError(
                "Ponto operacional ausente no registro selecionado: "
                f"{selection.operating_point}"
            ) from exc
        if (
            selection.operating_point != "native"
            and threshold_entry.get("test_labels_used") is not False
        ):
            raise ValueError("O limiar selecionado não comprova independência do teste.")
        model_reference = model_entry["model_artifact"]
        model_path = _safe_project_path(
            project_root, str(model_reference["relative_path"])
        )
        if not model_path.is_file():
            raise FileNotFoundError(f"Modelo não encontrado: {model_path}")
        expected_hash = str(model_reference["sha256"])
        actual_hash = _sha256_file(model_path)
        if actual_hash != expected_hash:
            raise ValueError(
                "Hash do modelo não coincide com o registro do Marco 10: "
                f"esperado={expected_hash} calculado={actual_hash}"
            )
        bundle = joblib.load(model_path)
        if not isinstance(bundle, dict):
            raise ValueError("O artefato carregado não possui o formato de bundle.")
        service = cls(
            project_root=project_root,
            registry_path=registry_path,
            selection=selection,
            model_entry=model_entry,
            bundle=bundle,
            max_batch_size=max_batch_size,
        )
        service.model_path = model_path
        service.model_sha256 = actual_hash
        service.display_name = str(model_entry["display_name"])
        return service

    def _normalize_record(
        self,
        record: Mapping[str, Any],
        processed_at: datetime,
    ) -> tuple[list[float], dict[str, Any]]:
        """Separa features e contexto, valida tipos e restaura a ordem treinada."""
        if not isinstance(record, Mapping):
            raise TypeError("Cada registro deve ser um objeto chave-valor.")
        wrapped = "features" in record
        features = record.get("features") if wrapped else record
        if not isinstance(features, Mapping):
            raise TypeError("features deve ser um objeto chave-valor.")
        provided = {str(name) for name in features}
        expected = set(self.feature_columns)
        missing = sorted(expected - provided)
        unexpected = sorted(provided - expected)
        if missing or unexpected:
            raise ValueError(
                "Esquema de features inválido. "
                f"ausentes={missing}; inesperadas={unexpected}"
            )
        ordered: list[float] = []
        for feature in self.feature_columns:
            value = features[feature]
            if isinstance(value, bool) or not isinstance(value, Real):
                raise TypeError(f"Feature {feature!r} deve ser numérica.")
            numeric = float(value)
            if not math.isfinite(numeric):
                raise ValueError(f"Feature {feature!r} não pode ser NaN ou infinito.")
            ordered.append(numeric)
        observed_at = _timestamp_utc(
            record.get("observed_at") if wrapped else None,
            processed_at,
        )
        raw_event_id = record.get("event_id") if wrapped else None
        event_id = str(raw_event_id).strip() if raw_event_id is not None else ""
        if not event_id:
            event_id = str(uuid.uuid4())
            event_id_generated = True
        else:
            event_id_generated = False
        source = (
            str(record.get("source", "structured_input")).strip()
            if wrapped
            else "structured_input"
        )
        if not source:
            raise ValueError("source não pode ser vazio.")
        context = _validate_context(record.get("context", {})) if wrapped else {}
        metadata = {
            "event_id": event_id,
            "event_id_generated": event_id_generated,
            "observed_at": observed_at,
            "source": source,
            "context": context,
        }
        return ordered, metadata

    def predict_many(
        self,
        records: Sequence[Mapping[str, Any]],
    ) -> list[dict[str, Any]]:
        """Executa inferência vetorizada e retorna documentos independentes."""
        if isinstance(records, (str, bytes)) or not isinstance(records, Sequence):
            raise TypeError("records deve ser uma sequência de objetos.")
        if not records:
            raise ValueError("records não pode ser vazio.")
        if len(records) > self.max_batch_size:
            raise ValueError(
                f"Lote excede max_batch_size={self.max_batch_size}: {len(records)}"
            )
        processed_at = datetime.now(timezone.utc)
        normalized = [
            self._normalize_record(record, processed_at) for record in records
        ]
        values = [item[0] for item in normalized]
        metadata = [item[1] for item in normalized]
        frame = pd.DataFrame(values, columns=self.feature_columns, dtype=np.float64)
        score_samples = np.asarray(
            self.estimator.score_samples(frame), dtype=np.float64
        )
        decision_function = np.asarray(
            self.estimator.decision_function(frame), dtype=np.float64
        )
        native_prediction = np.asarray(self.estimator.predict(frame), dtype=np.int8)
        expected_shape = (len(records),)
        for name, values_array in (
            ("score_samples", score_samples),
            ("decision_function", decision_function),
            ("native_prediction", native_prediction),
        ):
            if values_array.shape != expected_shape:
                raise RuntimeError(
                    f"Saída {name} possui shape {values_array.shape}; "
                    f"esperado={expected_shape}."
                )
        if not np.isfinite(score_samples).all() or not np.isfinite(
            decision_function
        ).all():
            raise RuntimeError("O modelo produziu escores ausentes ou infinitos.")
        if not set(native_prediction.tolist()).issubset({-1, 1}):
            raise RuntimeError("O modelo produziu classes nativas diferentes de -1/1.")
        anomaly_scores = -score_samples
        native_anomalies = native_prediction == -1
        if self.selection.operating_point == "native":
            selected_anomalies = native_anomalies
            positive_rule = "sklearn predict == -1"
        else:
            selected_anomalies = anomaly_scores >= self.threshold
            positive_rule = "anomaly_score >= threshold"
        processed_text = processed_at.isoformat()
        outputs = []
        for index, record_metadata in enumerate(metadata):
            score = float(anomaly_scores[index])
            selected = int(selected_anomalies[index])
            outputs.append(
                {
                    "schema_version": 1,
                    **record_metadata,
                    "processed_at_utc": processed_text,
                    "model": {
                        "experiment": self.selection.experiment,
                        "key": self.selection.model,
                        "display_name": self.display_name,
                        "sha256": self.model_sha256,
                        "operating_point": self.selection.operating_point,
                        "threshold": self.threshold,
                        "positive_rule": positive_rule,
                    },
                    "prediction": {
                        "label": "anomaly" if selected else "normal",
                        "predicted_anomaly": selected,
                        "native_predicted_anomaly": int(native_anomalies[index]),
                        "sklearn_native_prediction": int(native_prediction[index]),
                        "anomaly_score": score,
                        "score_samples": float(score_samples[index]),
                        "decision_function": float(decision_function[index]),
                        "threshold_distance": float(score - self.threshold),
                        "anomaly_score_is_probability": False,
                    },
                }
            )
        return outputs

    def predict_one(self, record: Mapping[str, Any]) -> dict[str, Any]:
        """Executa a mesma validação em um único registro estruturado."""
        return self.predict_many([record])[0]


def predict_anomaly(
    data: Mapping[str, Any],
    service: AnomalyInferenceService,
) -> dict[str, Any]:
    """Interface conceitual estável para futuras camadas FastAPI/MongoDB."""
    return service.predict_one(data)
