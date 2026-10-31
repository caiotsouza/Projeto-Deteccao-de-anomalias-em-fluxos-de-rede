"""Configuração e identidade congelada usadas pelo runtime do Marco 12."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.config import (
    DEFAULT_DASHBOARD_MAX_RECORDS,
    DEFAULT_DASHBOARD_MAX_WINDOW_DAYS,
    DEFAULT_DASHBOARD_WINDOW_HOURS,
    DEFAULT_MONGODB_COLLECTION,
    DEFAULT_MONGODB_DATABASE,
    DEFAULT_MONGODB_URI,
    PROJECT_ROOT,
)
from src.inference_service import ModelSelection, default_registry_path


@dataclass(frozen=True)
class RuntimeSettings:
    """Parâmetros operacionais carregáveis por variáveis de ambiente."""

    mongodb_uri: str = DEFAULT_MONGODB_URI
    mongodb_database: str = DEFAULT_MONGODB_DATABASE
    mongodb_collection: str = DEFAULT_MONGODB_COLLECTION
    dashboard_window_hours: int = DEFAULT_DASHBOARD_WINDOW_HOURS
    dashboard_max_records: int = DEFAULT_DASHBOARD_MAX_RECORDS
    dashboard_max_window_days: int = DEFAULT_DASHBOARD_MAX_WINDOW_DAYS
    project_root: Path = PROJECT_ROOT

    def __post_init__(self) -> None:
        if not self.mongodb_uri.strip():
            raise ValueError("mongodb_uri não pode ser vazio.")
        for name, value in (
            ("mongodb_database", self.mongodb_database),
            ("mongodb_collection", self.mongodb_collection),
        ):
            if not value.strip() or "\x00" in value:
                raise ValueError(f"{name} é inválido.")
        if self.dashboard_window_hours <= 0:
            raise ValueError("dashboard_window_hours deve ser positivo.")
        if self.dashboard_max_records <= 0:
            raise ValueError("dashboard_max_records deve ser positivo.")
        if self.dashboard_max_window_days <= 0:
            raise ValueError("dashboard_max_window_days deve ser positivo.")

    @classmethod
    def from_env(cls, project_root: Path = PROJECT_ROOT) -> "RuntimeSettings":
        """Carrega somente opções não secretas; credenciais ficam dentro da URI."""
        return cls(
            mongodb_uri=os.getenv("TCC_MONGODB_URI", DEFAULT_MONGODB_URI),
            mongodb_database=os.getenv(
                "TCC_MONGODB_DATABASE", DEFAULT_MONGODB_DATABASE
            ),
            mongodb_collection=os.getenv(
                "TCC_MONGODB_COLLECTION", DEFAULT_MONGODB_COLLECTION
            ),
            dashboard_window_hours=int(
                os.getenv(
                    "TCC_DASHBOARD_WINDOW_HOURS",
                    str(DEFAULT_DASHBOARD_WINDOW_HOURS),
                )
            ),
            dashboard_max_records=int(
                os.getenv(
                    "TCC_DASHBOARD_MAX_RECORDS",
                    str(DEFAULT_DASHBOARD_MAX_RECORDS),
                )
            ),
            dashboard_max_window_days=int(
                os.getenv(
                    "TCC_DASHBOARD_MAX_WINDOW_DAYS",
                    str(DEFAULT_DASHBOARD_MAX_WINDOW_DAYS),
                )
            ),
            project_root=project_root.resolve(),
        )


@dataclass(frozen=True)
class ActiveModelIdentity:
    """Identidade completa que todas as consultas do dashboard devem fixar."""

    experiment: str
    key: str
    display_name: str
    sha256: str
    operating_point: str
    threshold: float
    positive_rule: str
    target_false_positive_rate: float | None
    registry_path: Path
    registry_sha256: str
    model_path: Path
    production_approved: bool

    def as_filter(self) -> dict[str, Any]:
        return {
            "experiment": self.experiment,
            "key": self.key,
            "sha256": self.sha256,
            "operating_point": self.operating_point,
            "threshold": self.threshold,
            "positive_rule": self.positive_rule,
        }


def _load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(f"JSON obrigatório não encontrado: {path}")
    with path.open("r", encoding="utf-8") as file:
        value = json.load(file)
    if not isinstance(value, dict):
        raise ValueError(f"O JSON deve possuir objeto na raiz: {path}")
    return value


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for block in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _safe_project_path(project_root: Path, relative_path: str) -> Path:
    candidate = (project_root / relative_path).resolve()
    try:
        candidate.relative_to(project_root.resolve())
    except ValueError as exc:
        raise ValueError(f"Caminho fora da raiz do projeto: {relative_path}") from exc
    return candidate


def load_active_model_identity(
    *,
    project_root: Path = PROJECT_ROOT,
    selection: ModelSelection | None = None,
    registry_path: Path | None = None,
    verify_model_hash: bool = True,
) -> ActiveModelIdentity:
    """Lê o registro operacional e verifica a identidade sem desserializar modelo."""
    project_root = project_root.resolve()
    selection = selection or ModelSelection()
    registry_path = (registry_path or default_registry_path(project_root)).resolve()
    registry = _load_json(registry_path)
    if registry.get("status") != "completed":
        raise ValueError("O registro de modelos não está concluído.")
    try:
        model = registry["experiments"][selection.experiment]["models"][
            selection.model
        ]
        threshold_entry = model["thresholds"][selection.operating_point]
    except KeyError as exc:
        raise ValueError(f"Seleção não registrada: {selection}") from exc
    if (
        selection.operating_point != "native"
        and threshold_entry.get("test_labels_used") is not False
    ):
        raise ValueError("O ponto operacional não comprova independência do teste.")
    threshold_key = (
        "equivalent_anomaly_score_threshold"
        if selection.operating_point == "native"
        else "threshold"
    )
    threshold = float(threshold_entry[threshold_key])
    if not math.isfinite(threshold):
        raise ValueError("O limiar registrado não é finito.")
    model_reference = model["model_artifact"]
    model_path = _safe_project_path(
        project_root, str(model_reference["relative_path"])
    )
    recorded_model_sha = str(model_reference["sha256"])
    if re.fullmatch(r"[0-9a-f]{64}", recorded_model_sha) is None:
        raise ValueError("SHA-256 registrado do modelo é inválido.")
    if verify_model_hash:
        if not model_path.is_file():
            raise FileNotFoundError(f"Modelo não encontrado: {model_path}")
        calculated = _sha256_file(model_path)
        if calculated != recorded_model_sha:
            raise ValueError(
                "Hash do modelo diverge do registro operacional: "
                f"esperado={recorded_model_sha} calculado={calculated}"
            )
    positive_rule = str(
        threshold_entry.get("positive_rule")
        or (
            "sklearn predict == -1"
            if selection.operating_point == "native"
            else "anomaly_score >= threshold"
        )
    )
    target_fpr = threshold_entry.get("target_false_positive_rate")
    recommendation = registry.get("recommended_operational_candidate", {})
    try:
        recommended_threshold = float(recommendation.get("threshold"))
    except (TypeError, ValueError):
        recommended_threshold = float("nan")
    recommendation_matches = (
            recommendation.get("experiment") == selection.experiment
            and recommendation.get("model") == selection.model
            and recommendation.get("operating_point") == selection.operating_point
            and math.isclose(
                recommended_threshold,
                threshold,
                rel_tol=0.0,
                abs_tol=1e-15,
            )
    )
    production_approved = bool(
        recommendation.get("production_approved", False)
        if recommendation_matches
        else False
    )
    return ActiveModelIdentity(
        experiment=selection.experiment,
        key=selection.model,
        display_name=str(model["display_name"]),
        sha256=recorded_model_sha,
        operating_point=selection.operating_point,
        threshold=threshold,
        positive_rule=positive_rule,
        target_false_positive_rate=(
            float(target_fpr) if target_fpr is not None else None
        ),
        registry_path=registry_path,
        registry_sha256=_sha256_file(registry_path),
        model_path=model_path,
        production_approved=production_approved,
    )
