"""Persistência idempotente de previsões do Marco 12."""

from __future__ import annotations

import copy
import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

from pymongo import ASCENDING, DESCENDING, IndexModel, MongoClient, UpdateOne
from pymongo.errors import BulkWriteError, PyMongoError

from src.config import PROJECT_ROOT
from src.runtime_config import ActiveModelIdentity, RuntimeSettings


FORBIDDEN_CONTEXT_FIELDS = {
    "label",
    "binary_label",
    "attack_category",
    "ground_truth",
    "true_class",
}


def _find_forbidden_keys(value: object, path: str = "$") -> list[str]:
    """Localiza recursivamente chaves que carregariam verdade de teste."""
    matches: list[str] = []
    if isinstance(value, Mapping):
        for raw_key, child in value.items():
            key = str(raw_key).strip().lower()
            child_path = f"{path}.{raw_key}"
            if key in FORBIDDEN_CONTEXT_FIELDS:
                matches.append(child_path)
            matches.extend(_find_forbidden_keys(child, child_path))
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            matches.extend(_find_forbidden_keys(child, f"{path}[{index}]"))
    return matches


def _find_unsafe_mongo_keys(value: object, path: str = "$") -> list[str]:
    """Rejeita chaves ambíguas para caminhos e operadores MongoDB."""
    matches: list[str] = []
    if isinstance(value, Mapping):
        for raw_key, child in value.items():
            key = str(raw_key)
            child_path = f"{path}.{key}"
            if not key or key.startswith("$") or "." in key or "\x00" in key:
                matches.append(child_path)
            matches.extend(_find_unsafe_mongo_keys(child, child_path))
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            matches.extend(_find_unsafe_mongo_keys(child, f"{path}[{index}]"))
    return matches


class RepositoryUnavailable(RuntimeError):
    """Falha estável para indisponibilidade do MongoDB."""


class DocumentConflict(ValueError):
    """Mesmo event_id foi apresentado com conteúdo operacional diferente."""


@dataclass(frozen=True)
class UpsertSummary:
    attempted: int
    inserted: int
    duplicates: int
    conflicts: int

    def as_dict(self) -> dict[str, int]:
        return {
            "attempted": self.attempted,
            "inserted": self.inserted,
            "duplicates": self.duplicates,
            "conflicts": self.conflicts,
        }


@dataclass(frozen=True)
class QueryFilters:
    """Filtro temporal semiaberto e identidade obrigatória do modelo."""

    start: datetime
    end: datetime
    model: ActiveModelIdentity
    source: str | None = None
    protocol: str | None = None
    anomalies_only: bool = False
    newest_first: bool = False
    limit: int = 100_000

    def __post_init__(self) -> None:
        start = _utc_datetime(self.start, "start")
        end = _utc_datetime(self.end, "end")
        if start >= end:
            raise ValueError("A janela deve obedecer start < end.")
        if self.limit <= 0:
            raise ValueError("limit deve ser positivo.")
        object.__setattr__(self, "start", start)
        object.__setattr__(self, "end", end)


@dataclass(frozen=True)
class QueryResult:
    documents: list[dict[str, Any]]
    matched_count: int
    returned_count: int
    truncated: bool


class PredictionRepository(Protocol):
    def initialize(self) -> dict[str, Any]: ...

    def ping(self) -> bool: ...

    def upsert_many(self, documents: Sequence[Mapping[str, Any]]) -> UpsertSummary: ...

    def query(self, filters: QueryFilters) -> QueryResult: ...

    def status(self, model: ActiveModelIdentity) -> dict[str, Any]: ...


def _utc_datetime(value: object, field: str) -> datetime:
    if isinstance(value, datetime):
        moment = value
    elif isinstance(value, str):
        normalized = value.strip()
        if normalized.endswith("Z"):
            normalized = normalized[:-1] + "+00:00"
        try:
            moment = datetime.fromisoformat(normalized)
        except ValueError as exc:
            raise ValueError(f"{field} não é uma data ISO 8601 válida.") from exc
    else:
        raise TypeError(f"{field} deve ser datetime ou string ISO 8601.")
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise ValueError(f"{field} deve informar fuso horário.")
    return moment.astimezone(timezone.utc)


def _finite_number(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{field} deve ser numérico.")
    number = float(value)
    if not math.isfinite(number):
        raise ValueError(f"{field} deve ser finito.")
    return number


def _bson_millisecond_precision(moment: datetime) -> datetime:
    """Normaliza para a precisão efetivamente preservada por BSON Date."""
    return moment.replace(microsecond=(moment.microsecond // 1_000) * 1_000)


def validate_monitoring_document(
    document: Mapping[str, Any],
    expected_model: ActiveModelIdentity | None = None,
) -> dict[str, Any]:
    """Valida invariantes antes que um adaptador persista o documento."""
    if not isinstance(document, Mapping):
        raise TypeError("Cada documento deve ser um objeto.")
    schema_version = document.get("schema_version")
    if (
        not isinstance(schema_version, int)
        or isinstance(schema_version, bool)
        or schema_version != 1
    ):
        raise ValueError("schema_version de monitoramento deve ser 1.")
    event_id_value = document.get("event_id")
    if not isinstance(event_id_value, str) or not event_id_value.strip():
        raise ValueError("event_id deve ser uma string não vazia.")
    event_id = event_id_value.strip()
    if len(event_id) > 200:
        raise ValueError("event_id não pode exceder 200 caracteres.")
    model = document.get("model")
    classification = document.get("classification")
    context = document.get("context", {})
    if not isinstance(model, Mapping) or not isinstance(classification, Mapping):
        raise ValueError("model e classification são obrigatórios.")
    if not isinstance(context, Mapping):
        raise TypeError("context deve ser um objeto.")
    forbidden = _find_forbidden_keys(document)
    if forbidden:
        raise ValueError(
            "O documento operacional não pode persistir verdade de teste: "
            + ", ".join(sorted(forbidden))
        )
    unsafe_keys = _find_unsafe_mongo_keys(document)
    if unsafe_keys:
        raise ValueError(
            "O documento contém chaves incompatíveis com MongoDB: "
            + ", ".join(sorted(unsafe_keys))
        )
    source = document.get("source")
    if not isinstance(source, str) or not source.strip():
        raise ValueError("source deve ser uma string não vazia.")
    predicted = classification.get("predicted_anomaly")
    if not isinstance(predicted, int) or isinstance(predicted, bool):
        raise TypeError("classification.predicted_anomaly deve ser inteiro.")
    if predicted not in (0, 1):
        raise ValueError("classification.predicted_anomaly deve ser 0 ou 1.")
    is_anomaly = classification.get("is_anomaly")
    if not isinstance(is_anomaly, bool) or is_anomaly is not bool(predicted):
        raise ValueError("is_anomaly diverge de predicted_anomaly.")
    expected_status = "anomaly" if predicted else "normal"
    if classification.get("status") != expected_status:
        raise ValueError("classification.status diverge da decisão binária.")
    anomaly_score = _finite_number(
        classification.get("anomaly_score"), "classification.anomaly_score"
    )
    score_samples = _finite_number(
        classification.get("score_samples"), "classification.score_samples"
    )
    threshold = _finite_number(model.get("threshold"), "model.threshold")
    distance = _finite_number(
        classification.get("threshold_distance"),
        "classification.threshold_distance",
    )
    if not math.isclose(anomaly_score, -score_samples, abs_tol=1e-12):
        raise ValueError("anomaly_score deve ser -score_samples.")
    if not math.isclose(distance, anomaly_score - threshold, abs_tol=1e-12):
        raise ValueError("threshold_distance diverge do limiar.")
    if classification.get("anomaly_score_is_probability") is not False:
        raise ValueError("anomaly_score não é probabilidade.")
    for field in (
        "experiment",
        "key",
        "display_name",
        "operating_point",
        "positive_rule",
    ):
        value = model.get(field)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"model.{field} deve ser uma string não vazia.")
    model_sha = model.get("sha256")
    if not isinstance(model_sha, str) or re.fullmatch(r"[0-9a-f]{64}", model_sha) is None:
        raise ValueError("model.sha256 deve ser hexadecimal minúsculo com 64 caracteres.")
    native_predicted = classification.get("native_predicted_anomaly")
    sklearn_prediction = classification.get("sklearn_native_prediction")
    if (
        not isinstance(native_predicted, int)
        or isinstance(native_predicted, bool)
        or native_predicted not in (0, 1)
    ):
        raise ValueError("native_predicted_anomaly deve ser 0 ou 1.")
    if (
        not isinstance(sklearn_prediction, int)
        or isinstance(sklearn_prediction, bool)
        or sklearn_prediction not in (-1, 1)
    ):
        raise ValueError("sklearn_native_prediction deve ser -1 ou 1.")
    if native_predicted != int(sklearn_prediction == -1):
        raise ValueError("Predições nativas estão inconsistentes.")
    decision_function = _finite_number(
        classification.get("decision_function"),
        "classification.decision_function",
    )
    if sklearn_prediction != (-1 if decision_function < 0.0 else 1):
        raise ValueError("sklearn_native_prediction diverge de decision_function.")
    positive_rule = model["positive_rule"]
    if positive_rule == "anomaly_score >= threshold" and predicted != int(
        anomaly_score >= threshold
    ):
        raise ValueError("A decisão selecionada diverge da regra positiva.")
    if positive_rule == "sklearn predict == -1" and predicted != native_predicted:
        raise ValueError("A decisão nativa diverge da regra positiva.")
    if expected_model is not None:
        expected = expected_model.as_filter()
        actual = {
            key: model.get(key)
            for key in (
                "experiment",
                "key",
                "sha256",
                "operating_point",
                "threshold",
                "positive_rule",
            )
        }
        if actual != expected:
            raise ValueError(
                "Documento pertence a outra identidade de modelo: "
                f"esperado={expected} recebido={actual}"
            )
    observed = _bson_millisecond_precision(
        _utc_datetime(document.get("observed_at"), "observed_at")
    )
    processed = _bson_millisecond_precision(
        _utc_datetime(document.get("processed_at_utc"), "processed_at_utc")
    )
    if processed < observed:
        raise ValueError("processed_at_utc não pode anteceder observed_at.")
    normalized = copy.deepcopy(dict(document))
    normalized["event_id"] = event_id
    normalized["source"] = source.strip()
    normalized["observed_at"] = observed.isoformat()
    normalized["processed_at_utc"] = processed.isoformat()
    normalized["context"] = dict(context)
    return normalized


def to_storage_document(document: Mapping[str, Any]) -> dict[str, Any]:
    """Converte datas ISO da fronteira em BSON Date (datetime UTC)."""
    normalized = validate_monitoring_document(document)
    normalized["observed_at"] = _utc_datetime(
        normalized["observed_at"], "observed_at"
    )
    normalized["processed_at_utc"] = _utc_datetime(
        normalized["processed_at_utc"], "processed_at_utc"
    )
    return normalized


def from_storage_document(document: Mapping[str, Any]) -> dict[str, Any]:
    """Remove _id e converte BSON Date para a fronteira JSON ISO 8601."""
    normalized = copy.deepcopy(dict(document))
    normalized.pop("_id", None)
    normalized["observed_at"] = _utc_datetime(
        normalized["observed_at"], "observed_at"
    ).isoformat()
    normalized["processed_at_utc"] = _utc_datetime(
        normalized["processed_at_utc"], "processed_at_utc"
    ).isoformat()
    return validate_monitoring_document(normalized)


def _same_document(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    return validate_monitoring_document(left) == validate_monitoring_document(right)


def _matches_model(document: Mapping[str, Any], model: ActiveModelIdentity) -> bool:
    actual = document["model"]
    return all(actual.get(key) == value for key, value in model.as_filter().items())


class InMemoryPredictionRepository:
    """Fake determinístico usado por testes e validação sem Docker."""

    def __init__(self) -> None:
        self._documents: dict[str, dict[str, Any]] = {}
        self.initialized = False

    def initialize(self) -> dict[str, Any]:
        self.initialized = True
        return {
            "collection_created": True,
            "validator_applied": True,
            "index_names": list(MongoPredictionRepository.INDEX_NAMES),
            "ttl_indexes": [],
        }

    def ping(self) -> bool:
        return True

    def upsert_many(self, documents: Sequence[Mapping[str, Any]]) -> UpsertSummary:
        attempted = len(documents)
        inserted = duplicates = conflicts = 0
        seen: dict[str, dict[str, Any]] = {}
        for raw in documents:
            document = validate_monitoring_document(raw)
            event_id = document["event_id"]
            if event_id in seen and not _same_document(seen[event_id], document):
                raise DocumentConflict(f"event_id repetido com conteúdo diferente: {event_id}")
            seen[event_id] = document
        conflicts = sum(
            1
            for event_id, document in seen.items()
            if event_id in self._documents
            and not _same_document(self._documents[event_id], document)
        )
        if conflicts:
            raise DocumentConflict(
                f"{conflicts} event_id(s) já existem com conteúdo diferente."
            )
        # Só altera o fake depois que o lote inteiro passou pelo preflight.
        for event_id, document in seen.items():
            existing = self._documents.get(event_id)
            if existing is None:
                self._documents[event_id] = copy.deepcopy(document)
                inserted += 1
            else:
                duplicates += 1
        duplicates += attempted - len(seen)
        return UpsertSummary(attempted, inserted, duplicates, conflicts)

    def query(self, filters: QueryFilters) -> QueryResult:
        matched: list[dict[str, Any]] = []
        for document in self._documents.values():
            observed = _utc_datetime(document["observed_at"], "observed_at")
            if not filters.start <= observed < filters.end:
                continue
            if not _matches_model(document, filters.model):
                continue
            if filters.source is not None and document.get("source") != filters.source:
                continue
            if (
                filters.protocol is not None
                and str(document.get("context", {}).get("protocol"))
                != filters.protocol
            ):
                continue
            if filters.anomalies_only and not document["classification"]["is_anomaly"]:
                continue
            matched.append(copy.deepcopy(document))
        matched.sort(
            key=lambda item: (item["observed_at"], item["event_id"]),
            reverse=filters.newest_first,
        )
        count = len(matched)
        returned = matched[: filters.limit]
        return QueryResult(returned, count, len(returned), count > len(returned))

    def status(self, model: ActiveModelIdentity) -> dict[str, Any]:
        selected = [
            document
            for document in self._documents.values()
            if _matches_model(document, model)
        ]
        timestamps = sorted(
            _utc_datetime(document["observed_at"], "observed_at")
            for document in selected
        )
        return {
            "backend": "memory",
            "reachable": True,
            "documents": len(selected),
            "oldest_observed_at": timestamps[0].isoformat() if timestamps else None,
            "newest_observed_at": timestamps[-1].isoformat() if timestamps else None,
        }


class MongoPredictionRepository:
    """Adaptador PyMongo com schema, índices, BSON Date e upsert idempotente."""

    INDEX_NAMES = (
        "uq_event_id",
        "ix_observed_at",
        "ix_anomaly_observed_at",
        "ix_src_ip_observed_at",
        "ix_dst_port_observed_at",
    )

    def __init__(
        self,
        settings: RuntimeSettings,
        *,
        client: MongoClient | None = None,
    ) -> None:
        self.settings = settings
        self.client = client or MongoClient(
            settings.mongodb_uri,
            serverSelectionTimeoutMS=5_000,
            connectTimeoutMS=5_000,
            tz_aware=True,
        )
        self.database = self.client[settings.mongodb_database]
        self.collection = self.database[settings.mongodb_collection]

    def ping(self) -> bool:
        try:
            self.client.admin.command("ping")
            return True
        except PyMongoError as exc:
            raise RepositoryUnavailable("MongoDB não está acessível.") from exc

    def initialize(self) -> dict[str, Any]:
        """Aplica o contrato de coleção e índices de forma repetível."""
        contract_path = (
            self.settings.project_root
            / "reports"
            / "integration"
            / "mongodb_prediction.schema.json"
        )
        try:
            with contract_path.open("r", encoding="utf-8") as file:
                import json

                contract = json.load(file)
            validator = contract["validator"]
            collection_created = (
                self.settings.mongodb_collection
                not in self.database.list_collection_names()
            )
            if collection_created:
                self.database.create_collection(
                    self.settings.mongodb_collection,
                    validator=validator,
                    validationLevel="strict",
                    validationAction="error",
                )
            else:
                self.database.command(
                    {
                        "collMod": self.settings.mongodb_collection,
                        "validator": validator,
                        "validationLevel": "strict",
                        "validationAction": "error",
                    }
                )
            models = [
                IndexModel([("event_id", ASCENDING)], unique=True, name="uq_event_id"),
                IndexModel([("observed_at", DESCENDING)], name="ix_observed_at"),
                IndexModel(
                    [
                        ("classification.is_anomaly", ASCENDING),
                        ("observed_at", DESCENDING),
                    ],
                    name="ix_anomaly_observed_at",
                ),
                IndexModel(
                    [("context.src_ip", ASCENDING), ("observed_at", DESCENDING)],
                    name="ix_src_ip_observed_at",
                ),
                IndexModel(
                    [("context.dst_port", ASCENDING), ("observed_at", DESCENDING)],
                    name="ix_dst_port_observed_at",
                ),
            ]
            self.collection.create_indexes(models)
            index_info = self.collection.index_information()
            ttl_indexes = [
                name
                for name, details in index_info.items()
                if "expireAfterSeconds" in details
            ]
            if ttl_indexes:
                raise RepositoryUnavailable(
                    "A política do Marco 12 proíbe TTL implícito; índices TTL "
                    f"encontrados: {ttl_indexes}."
                )
            return {
                "collection_created": collection_created,
                "validator_applied": True,
                "index_names": sorted(
                    name for name in index_info if name != "_id_"
                ),
                "ttl_indexes": ttl_indexes,
            }
        except (OSError, KeyError, PyMongoError) as exc:
            raise RepositoryUnavailable(
                "Não foi possível inicializar a coleção MongoDB."
            ) from exc

    def upsert_many(self, documents: Sequence[Mapping[str, Any]]) -> UpsertSummary:
        if not documents:
            return UpsertSummary(0, 0, 0, 0)
        normalized: dict[str, dict[str, Any]] = {}
        for raw in documents:
            document = validate_monitoring_document(raw)
            event_id = document["event_id"]
            if event_id in normalized and not _same_document(
                normalized[event_id], document
            ):
                raise DocumentConflict(
                    f"event_id repetido com conteúdo diferente no lote: {event_id}"
                )
            normalized[event_id] = document
        try:
            existing_cursor = self.collection.find(
                {"event_id": {"$in": list(normalized)}}, {"_id": 0}
            )
            existing = {
                item["event_id"]: from_storage_document(item)
                for item in existing_cursor
            }
            conflicts = [
                event_id
                for event_id, document in normalized.items()
                if event_id in existing
                and not _same_document(existing[event_id], document)
            ]
            if conflicts:
                raise DocumentConflict(
                    f"{len(conflicts)} event_id(s) já existem com conteúdo diferente."
                )
            operations = [
                UpdateOne(
                    {"event_id": event_id},
                    {"$setOnInsert": to_storage_document(document)},
                    upsert=True,
                )
                for event_id, document in normalized.items()
            ]
            result = self.collection.bulk_write(operations, ordered=False)
            inserted = int(result.upserted_count)
            # A leitura posterior fecha a janela de corrida entre o preflight e
            # o upsert. Um escritor concorrente nunca pode mascarar conteúdo
            # divergente como simples duplicata.
            persisted = {
                item["event_id"]: from_storage_document(item)
                for item in self.collection.find(
                    {"event_id": {"$in": list(normalized)}}, {"_id": 0}
                )
            }
            missing = sorted(set(normalized).difference(persisted))
            conflicts_after_write = [
                event_id
                for event_id, document in normalized.items()
                if event_id in persisted
                and not _same_document(persisted[event_id], document)
            ]
            if conflicts_after_write:
                raise DocumentConflict(
                    f"{len(conflicts_after_write)} event_id(s) divergiram após o upsert."
                )
            if missing:
                raise RepositoryUnavailable(
                    f"{len(missing)} documento(s) não foram confirmados após o upsert."
                )
            duplicates = len(documents) - inserted
            return UpsertSummary(len(documents), inserted, duplicates, 0)
        except DocumentConflict:
            raise
        except BulkWriteError as exc:
            details = exc.details or {}
            errors = details.get("writeErrors", [])
            if errors and all(error.get("code") == 11000 for error in errors):
                inserted = int(details.get("nUpserted", 0))
                persisted = {
                    item["event_id"]: from_storage_document(item)
                    for item in self.collection.find(
                        {"event_id": {"$in": list(normalized)}}, {"_id": 0}
                    )
                }
                if set(persisted) != set(normalized) or any(
                    not _same_document(persisted[event_id], document)
                    for event_id, document in normalized.items()
                    if event_id in persisted
                ):
                    raise DocumentConflict(
                        "Colisão concorrente de event_id com conteúdo divergente."
                    ) from exc
                return UpsertSummary(
                    len(documents), inserted, len(documents) - inserted, 0
                )
            raise RepositoryUnavailable("Falha no bulk upsert do MongoDB.") from exc
        except PyMongoError as exc:
            raise RepositoryUnavailable("Falha no bulk upsert do MongoDB.") from exc

    def _mongo_filter(self, filters: QueryFilters) -> dict[str, Any]:
        query: dict[str, Any] = {
            "observed_at": {"$gte": filters.start, "$lt": filters.end},
            "model.experiment": filters.model.experiment,
            "model.key": filters.model.key,
            "model.sha256": filters.model.sha256,
            "model.operating_point": filters.model.operating_point,
            "model.threshold": filters.model.threshold,
            "model.positive_rule": filters.model.positive_rule,
        }
        if filters.source is not None:
            query["source"] = filters.source
        if filters.protocol is not None:
            query["context.protocol"] = filters.protocol
        if filters.anomalies_only:
            query["classification.is_anomaly"] = True
        return query

    def query(self, filters: QueryFilters) -> QueryResult:
        query = self._mongo_filter(filters)
        direction = DESCENDING if filters.newest_first else ASCENDING
        try:
            matched_count = int(self.collection.count_documents(query))
            cursor = (
                self.collection.find(query, {"_id": 0})
                .sort([("observed_at", direction), ("event_id", direction)])
                .limit(filters.limit)
            )
            documents = [from_storage_document(item) for item in cursor]
            return QueryResult(
                documents,
                matched_count,
                len(documents),
                matched_count > len(documents),
            )
        except PyMongoError as exc:
            raise RepositoryUnavailable("Falha na consulta ao MongoDB.") from exc

    def status(self, model: ActiveModelIdentity) -> dict[str, Any]:
        query = {
            f"model.{key}": value for key, value in model.as_filter().items()
        }
        try:
            count = int(self.collection.count_documents(query))
            oldest = self.collection.find_one(
                query, {"_id": 0, "observed_at": 1}, sort=[("observed_at", ASCENDING)]
            )
            newest = self.collection.find_one(
                query, {"_id": 0, "observed_at": 1}, sort=[("observed_at", DESCENDING)]
            )
            return {
                "backend": "mongodb",
                "reachable": True,
                "database": self.settings.mongodb_database,
                "collection": self.settings.mongodb_collection,
                "documents": count,
                "oldest_observed_at": (
                    _utc_datetime(oldest["observed_at"], "observed_at").isoformat()
                    if oldest
                    else None
                ),
                "newest_observed_at": (
                    _utc_datetime(newest["observed_at"], "observed_at").isoformat()
                    if newest
                    else None
                ),
            }
        except PyMongoError as exc:
            raise RepositoryUnavailable("Falha ao consultar estado do MongoDB.") from exc


def create_mongo_repository(
    settings: RuntimeSettings | None = None,
) -> MongoPredictionRepository:
    return MongoPredictionRepository(settings or RuntimeSettings.from_env(PROJECT_ROOT))
