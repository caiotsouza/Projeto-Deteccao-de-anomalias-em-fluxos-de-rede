"""Fábricas pequenas e determinísticas para os testes do Marco 12."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd

from src.runtime_config import ActiveModelIdentity


def model_identity(
    *,
    threshold: float = 0.6,
    sha256: str = "a" * 64,
    root: Path | None = None,
) -> ActiveModelIdentity:
    root = (root or Path.cwd()).resolve()
    return ActiveModelIdentity(
        experiment="expanded_100k",
        key="isolation_forest",
        display_name="Isolation Forest",
        sha256=sha256,
        operating_point="validation_fpr_operational",
        threshold=threshold,
        positive_rule="anomaly_score >= threshold",
        target_false_positive_rate=0.01,
        registry_path=root / "registry.json",
        registry_sha256="b" * 64,
        model_path=root / "model.joblib",
        production_approved=False,
    )


def monitoring_document(
    event_id: str,
    observed_at: datetime | str,
    model: ActiveModelIdentity,
    *,
    score: float = 0.7,
    native_anomaly: int = 1,
    source: str = "offline_replay",
    protocol: str | None = None,
) -> dict:
    observed = observed_at.isoformat() if isinstance(observed_at, datetime) else observed_at
    selected = int(score >= model.threshold)
    context = {
        "dst_port": 443,
        "dataset_provenance_ref": "0123456789abcdef",
        "replay_sequence": int(event_id.rsplit("-", 1)[-1]) if event_id.rsplit("-", 1)[-1].isdigit() else 0,
    }
    if protocol is not None:
        context["protocol"] = protocol
    return {
        "schema_version": 1,
        "event_id": event_id,
        "observed_at": observed,
        "processed_at_utc": observed,
        "source": source,
        "model": {
            "experiment": model.experiment,
            "key": model.key,
            "display_name": model.display_name,
            "sha256": model.sha256,
            "operating_point": model.operating_point,
            "threshold": model.threshold,
            "positive_rule": model.positive_rule,
        },
        "classification": {
            "status": "anomaly" if selected else "normal",
            "is_anomaly": bool(selected),
            "predicted_anomaly": selected,
            "native_predicted_anomaly": native_anomaly,
            "sklearn_native_prediction": -1 if native_anomaly else 1,
            "anomaly_score": score,
            "score_samples": -score,
            "decision_function": -0.1 if native_anomaly else 0.1,
            "threshold_distance": score - model.threshold,
            "anomaly_score_is_probability": False,
        },
        "context": context,
    }


def replay_frames(scores: list[float] | None = None):
    scores = scores or [0.6, 0.59, 0.75, 0.4]
    size = len(scores)
    features = pd.DataFrame(
        {
            "destination_port": np.arange(80, 80 + size, dtype=np.float64),
            "flow_duration": np.arange(1, size + 1, dtype=np.float64) * 10,
            "total_fwd_packets": np.arange(1, size + 1, dtype=np.float64),
            "total_backward_packets": np.arange(2, size + 2, dtype=np.float64),
            "total_length_of_fwd_packets": np.arange(3, size + 3, dtype=np.float64),
            "total_length_of_bwd_packets": np.arange(4, size + 4, dtype=np.float64),
        }
    )
    hashes = pd.Series(
        (
            f"{int(value):016x}"
            for value in pd.util.hash_pandas_object(features, index=False).to_numpy(
                dtype=np.uint64
            )
        ),
        dtype="string",
    )
    decision = np.array([-0.1 if index % 2 == 0 else 0.1 for index in range(size)])
    sklearn_prediction = np.where(decision < 0.0, -1, 1).astype(np.int8)
    predictions = pd.DataFrame(
        {
            "row_position": np.arange(size, dtype=np.int64),
            "record_hash": hashes,
            "sklearn_prediction": sklearn_prediction,
            "predicted_anomaly": (sklearn_prediction == -1).astype(np.int8),
            "score_samples": -np.asarray(scores, dtype=np.float64),
            "decision_function": decision,
            "anomaly_score": np.asarray(scores, dtype=np.float64),
        }
    )
    provenance = pd.DataFrame(
        {
            "source_file": pd.Series([f"secret-scenario-{i}.csv" for i in range(size)], dtype="string"),
            "source_row": np.arange(100, 100 + size, dtype=np.int64),
            "record_hash": hashes,
        }
    )
    return features, predictions, provenance
