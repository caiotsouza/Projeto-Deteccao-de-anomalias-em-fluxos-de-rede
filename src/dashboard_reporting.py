"""Documentos de monitoramento e agregações preparadas para Grafana."""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from typing import Any


def _parse_timestamp(value: object, field: str) -> datetime:
    """Interpreta uma data ISO 8601 e a normaliza para UTC."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} deve ser uma string ISO 8601.")
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    try:
        moment = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError(f"{field} contém uma data inválida: {value!r}") from exc
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise ValueError(f"{field} deve informar o fuso horário.")
    return moment.astimezone(timezone.utc)


def _finite_number(value: object, field: str) -> float:
    """Converte e rejeita valores incompatíveis com séries numéricas."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{field} deve ser numérico.")
    numeric = float(value)
    if not math.isfinite(numeric):
        raise ValueError(f"{field} deve ser finito.")
    return numeric


def build_monitoring_document(result: Mapping[str, Any]) -> dict[str, Any]:
    """Converte uma resposta de inferência em documento pronto para persistência."""
    if not isinstance(result, Mapping):
        raise TypeError("O resultado de inferência deve ser um objeto.")
    if int(result.get("schema_version", -1)) != 1:
        raise ValueError("Versão do resultado de inferência não suportada.")
    try:
        model = result["model"]
        prediction = result["prediction"]
    except KeyError as exc:
        raise ValueError(f"Campo obrigatório ausente no resultado: {exc}") from exc
    if not isinstance(model, Mapping) or not isinstance(prediction, Mapping):
        raise TypeError("model e prediction devem ser objetos.")
    predicted = int(prediction["predicted_anomaly"])
    if predicted not in (0, 1):
        raise ValueError("predicted_anomaly deve ser 0 ou 1.")
    label = str(prediction["label"])
    expected_label = "anomaly" if predicted else "normal"
    if label != expected_label:
        raise ValueError("label diverge de predicted_anomaly.")
    observed_at = _parse_timestamp(result["observed_at"], "observed_at")
    processed_at = _parse_timestamp(result["processed_at_utc"], "processed_at_utc")
    anomaly_score = _finite_number(
        prediction["anomaly_score"], "prediction.anomaly_score"
    )
    score_samples = _finite_number(
        prediction["score_samples"], "prediction.score_samples"
    )
    model_threshold = _finite_number(model["threshold"], "model.threshold")
    threshold_distance = _finite_number(
        prediction["threshold_distance"], "prediction.threshold_distance"
    )
    if not math.isclose(anomaly_score, -score_samples, abs_tol=1e-12):
        raise ValueError("anomaly_score deve ser exatamente -score_samples.")
    if not math.isclose(
        threshold_distance,
        anomaly_score - model_threshold,
        abs_tol=1e-12,
    ):
        raise ValueError("threshold_distance diverge do limiar do modelo.")
    if prediction.get("anomaly_score_is_probability") is not False:
        raise ValueError("anomaly_score não pode ser apresentado como probabilidade.")
    context = result.get("context", {})
    if not isinstance(context, Mapping):
        raise TypeError("context deve ser um objeto.")
    event_id = str(result.get("event_id", "")).strip()
    if not event_id:
        raise ValueError("event_id é obrigatório para idempotência.")
    model_sha256 = str(model.get("sha256", ""))
    if len(model_sha256) != 64:
        raise ValueError("model.sha256 deve possuir 64 caracteres.")
    return {
        "schema_version": 1,
        "event_id": event_id,
        "observed_at": observed_at.isoformat(),
        "processed_at_utc": processed_at.isoformat(),
        "source": str(result.get("source", "structured_input")),
        "model": {
            "experiment": str(model["experiment"]),
            "key": str(model["key"]),
            "display_name": str(model["display_name"]),
            "sha256": model_sha256,
            "operating_point": str(model["operating_point"]),
            "threshold": model_threshold,
            "positive_rule": str(model["positive_rule"]),
        },
        "classification": {
            "status": label,
            "is_anomaly": bool(predicted),
            "predicted_anomaly": predicted,
            "native_predicted_anomaly": int(
                prediction["native_predicted_anomaly"]
            ),
            "sklearn_native_prediction": int(
                prediction["sklearn_native_prediction"]
            ),
            "anomaly_score": anomaly_score,
            "score_samples": score_samples,
            "decision_function": _finite_number(
                prediction["decision_function"], "prediction.decision_function"
            ),
            "threshold_distance": threshold_distance,
            "anomaly_score_is_probability": False,
        },
        "context": dict(context),
    }


def _percentile(values: Sequence[float], percentile: float) -> float:
    """Calcula percentil por interpolação linear em uma sequência não vazia."""
    ordered = sorted(float(value) for value in values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * percentile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def _top_counter(counter: Counter[str], limit: int) -> list[dict[str, Any]]:
    """Transforma um Counter em linhas ordenadas para painéis de ranking."""
    return [
        {"value": value, "count": int(count)}
        for value, count in counter.most_common(limit)
    ]


def build_dashboard_snapshot(
    documents: Sequence[Mapping[str, Any]],
    *,
    bucket_minutes: int = 5,
    top_n: int = 10,
    recent_limit: int = 20,
) -> dict[str, Any]:
    """Agrega documentos de um único modelo em um payload para dashboards."""
    if isinstance(documents, (str, bytes)) or not isinstance(documents, Sequence):
        raise TypeError("documents deve ser uma sequência de objetos.")
    if not documents:
        raise ValueError("documents não pode ser vazio.")
    if bucket_minutes <= 0 or top_n <= 0 or recent_limit <= 0:
        raise ValueError("bucket_minutes, top_n e recent_limit devem ser positivos.")

    normalized: list[tuple[datetime, Mapping[str, Any]]] = []
    identities: set[tuple[str, str, str, str, float, str]] = set()
    for document in documents:
        if not isinstance(document, Mapping):
            raise TypeError("Cada documento deve ser um objeto.")
        model = document.get("model")
        classification = document.get("classification")
        if not isinstance(model, Mapping) or not isinstance(classification, Mapping):
            raise ValueError("Documento sem model ou classification.")
        identity = (
            str(model.get("sha256", "")),
            str(model.get("operating_point", "")),
            str(model.get("experiment", "")),
            str(model.get("key", "")),
            _finite_number(model.get("threshold"), "model.threshold"),
            str(model.get("positive_rule", "")),
        )
        identities.add(identity)
        observed_at = _parse_timestamp(document.get("observed_at"), "observed_at")
        _finite_number(
            classification.get("anomaly_score"), "classification.anomaly_score"
        )
        if int(classification.get("predicted_anomaly", -1)) not in (0, 1):
            raise ValueError("classification.predicted_anomaly deve ser 0 ou 1.")
        normalized.append((observed_at, document))
    if len(identities) != 1:
        raise ValueError(
            "O snapshot não pode misturar modelos, versões, limiares ou pontos operacionais; "
            "aplique um filtro antes da agregação."
        )

    normalized.sort(key=lambda item: item[0])
    interval_seconds = bucket_minutes * 60
    buckets: dict[datetime, dict[str, Any]] = defaultdict(
        lambda: {"flows_total": 0, "anomalies_total": 0, "scores": []}
    )
    protocols: Counter[str] = Counter()
    sources: Counter[str] = Counter()
    anomalous_sources: Counter[str] = Counter()
    anomalous_destinations: Counter[str] = Counter()
    anomalous_destination_ports: Counter[str] = Counter()
    scores: list[float] = []
    anomaly_count = 0
    recent_anomalies: list[dict[str, Any]] = []
    for observed_at, document in normalized:
        classification = document["classification"]
        context = document.get("context", {})
        is_anomaly = int(classification["predicted_anomaly"]) == 1
        score = float(classification["anomaly_score"])
        epoch = int(observed_at.timestamp())
        bucket_epoch = epoch - (epoch % interval_seconds)
        bucket = datetime.fromtimestamp(bucket_epoch, tz=timezone.utc)
        buckets[bucket]["flows_total"] += 1
        buckets[bucket]["anomalies_total"] += int(is_anomaly)
        buckets[bucket]["scores"].append(score)
        scores.append(score)
        protocols[str(context.get("protocol", "unknown"))] += 1
        sources[str(document.get("source", "unknown"))] += 1
        if is_anomaly:
            anomaly_count += 1
            anomalous_sources[str(context.get("src_ip", "unknown"))] += 1
            anomalous_destinations[str(context.get("dst_ip", "unknown"))] += 1
            anomalous_destination_ports[
                str(context.get("dst_port", "unknown"))
            ] += 1
            recent_anomalies.append(
                {
                    "event_id": str(document["event_id"]),
                    "observed_at": observed_at.isoformat(),
                    "anomaly_score": score,
                    "threshold_distance": float(
                        classification["threshold_distance"]
                    ),
                    "src_ip": context.get("src_ip"),
                    "dst_ip": context.get("dst_ip"),
                    "dst_port": context.get("dst_port"),
                    "protocol": context.get("protocol"),
                }
            )

    timeline = []
    for bucket_start in sorted(buckets):
        values = buckets[bucket_start]
        total = int(values["flows_total"])
        anomalies = int(values["anomalies_total"])
        timeline.append(
            {
                "bucket_start": bucket_start.isoformat(),
                "flows_total": total,
                "normal_total": total - anomalies,
                "anomalies_total": anomalies,
                "anomaly_rate": float(anomalies / total),
                "anomaly_score_mean": float(sum(values["scores"]) / total),
            }
        )
    total = len(normalized)
    model = normalized[0][1]["model"]
    recent_anomalies.sort(key=lambda item: item["observed_at"], reverse=True)
    return {
        "schema_version": 1,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "window": {
            "start": normalized[0][0].isoformat(),
            "end": normalized[-1][0].isoformat(),
            "bucket_minutes": bucket_minutes,
        },
        "model_filter": {
            "experiment": model["experiment"],
            "key": model["key"],
            "sha256": model["sha256"],
            "operating_point": model["operating_point"],
            "threshold": model["threshold"],
        },
        "totals": {
            "flows": total,
            "normal": total - anomaly_count,
            "anomalies": anomaly_count,
            "anomaly_rate": float(anomaly_count / total),
        },
        "scores": {
            "minimum": min(scores),
            "mean": float(sum(scores) / len(scores)),
            "p95": _percentile(scores, 0.95),
            "maximum": max(scores),
            "is_probability": False,
            "comparability_note": (
                "Compare scores only inside the same model SHA and operating point."
            ),
        },
        "timeline": timeline,
        "distributions": {
            "protocol": _top_counter(protocols, top_n),
            "source": _top_counter(sources, top_n),
        },
        "top_anomalous_sources": _top_counter(anomalous_sources, top_n),
        "top_anomalous_destinations": _top_counter(
            anomalous_destinations, top_n
        ),
        "top_anomalous_destination_ports": _top_counter(
            anomalous_destination_ports, top_n
        ),
        "recent_anomalies": recent_anomalies[:recent_limit],
    }
