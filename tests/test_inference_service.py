"""Testes da inferência estruturada e do payload para dashboards."""

from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import joblib
import numpy as np

from src.dashboard_reporting import (
    build_dashboard_snapshot,
    build_monitoring_document,
)
from src.inference_service import AnomalyInferenceService, ModelSelection


class FakeEstimator:
    """Estimador mínimo com as convenções de score usadas no projeto."""

    def score_samples(self, frame):
        return -frame["feature_a"].to_numpy(dtype=float)

    def decision_function(self, frame):
        return 0.5 - frame["feature_a"].to_numpy(dtype=float)

    def predict(self, frame):
        return np.where(frame["feature_a"].to_numpy(dtype=float) > 0.5, -1, 1)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_registry(project_root: Path) -> None:
    model_path = project_root / "models" / "fake.joblib"
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {
            "model": FakeEstimator(),
            "feature_columns": ["feature_a", "feature_b"],
            "model_input_schema_sha256": "schema",
        },
        model_path,
    )
    registry = {
        "status": "completed",
        "experiments": {
            "synthetic": {
                "models": {
                    "isolation_forest": {
                        "display_name": "Synthetic IF",
                        "model_artifact": {
                            "relative_path": "models/fake.joblib",
                            "sha256": _sha256(model_path),
                        },
                        "feature_count": 2,
                        "model_input_schema_sha256": "schema",
                        "thresholds": {
                            "native": {
                                "equivalent_anomaly_score_threshold": 0.5
                            },
                            "validation_f1_calibrated": {
                                "threshold": 0.6,
                                "test_labels_used": False,
                            },
                        },
                    }
                }
            }
        },
    }
    registry_path = project_root / "reports" / "final" / "model_registry.json"
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    registry_path.write_text(json.dumps(registry), encoding="utf-8")


class InferenceServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.project_root = Path(self.temporary.name)
        _write_registry(self.project_root)
        self.service = AnomalyInferenceService.from_registry(
            project_root=self.project_root,
            selection=ModelSelection(
                experiment="synthetic",
                model="isolation_forest",
                operating_point="validation_f1_calibrated",
            ),
            max_batch_size=3,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _record(
        self,
        score: float,
        event_id: str,
        observed_at: str,
        src_ip: str = "10.0.0.1",
    ) -> dict:
        return {
            "event_id": event_id,
            "observed_at": observed_at,
            "source": "pfsense",
            "features": {"feature_b": 1.0, "feature_a": score},
            "context": {
                "src_ip": src_ip,
                "dst_ip": "10.0.0.2",
                "dst_port": 443,
                "protocol": "TCP",
            },
        }

    def test_prediction_restores_order_and_preserves_score_semantics(self) -> None:
        result = self.service.predict_one(
            self._record(0.7, "flow-1", "2026-09-05T12:00:00-03:00")
        )

        self.assertEqual(result["prediction"]["label"], "anomaly")
        self.assertEqual(result["prediction"]["predicted_anomaly"], 1)
        self.assertEqual(result["prediction"]["sklearn_native_prediction"], -1)
        self.assertAlmostEqual(result["prediction"]["anomaly_score"], 0.7)
        self.assertAlmostEqual(result["prediction"]["score_samples"], -0.7)
        self.assertAlmostEqual(result["prediction"]["threshold_distance"], 0.1)
        self.assertFalse(result["prediction"]["anomaly_score_is_probability"])
        self.assertEqual(result["observed_at"], "2026-09-05T15:00:00+00:00")

    def test_invalid_features_context_time_and_batch_are_rejected(self) -> None:
        missing = self._record(0.7, "flow-1", "2026-09-05T15:00:00Z")
        del missing["features"]["feature_b"]
        with self.assertRaisesRegex(ValueError, "ausentes"):
            self.service.predict_one(missing)

        invalid = self._record(float("nan"), "flow-2", "2026-09-05T15:00:00Z")
        with self.assertRaisesRegex(ValueError, "NaN"):
            self.service.predict_one(invalid)

        unsafe = self._record(0.7, "flow-3", "2026-09-05T15:00:00Z")
        unsafe["context"] = {"$where": "unsafe"}
        with self.assertRaisesRegex(ValueError, "MongoDB"):
            self.service.predict_one(unsafe)

        naive = self._record(0.7, "flow-4", "2026-09-05T15:00:00")
        with self.assertRaisesRegex(ValueError, "fuso"):
            self.service.predict_one(naive)

        valid = self._record(0.1, "flow", "2026-09-05T15:00:00Z")
        with self.assertRaisesRegex(ValueError, "max_batch_size"):
            self.service.predict_many([valid, valid, valid, valid])

    def test_model_hash_is_checked_before_deserialization(self) -> None:
        model_path = self.project_root / "models" / "fake.joblib"
        model_path.write_bytes(b"tampered")

        with self.assertRaisesRegex(ValueError, "Hash do modelo"):
            AnomalyInferenceService.from_registry(
                project_root=self.project_root,
                selection=ModelSelection(
                    experiment="synthetic",
                    model="isolation_forest",
                    operating_point="native",
                ),
            )

    def test_operational_registry_is_preferred_when_available(self) -> None:
        final_path = (
            self.project_root / "reports" / "final" / "model_registry.json"
        )
        registry = json.loads(final_path.read_text(encoding="utf-8"))
        model_entry = registry["experiments"]["synthetic"]["models"][
            "isolation_forest"
        ]
        model_entry["thresholds"]["validation_fpr_operational"] = {
            "threshold": 0.8,
            "target_false_positive_rate": 0.01,
            "test_labels_used": False,
        }
        operational_path = (
            self.project_root
            / "reports"
            / "operational"
            / "model_registry_operational.json"
        )
        operational_path.parent.mkdir(parents=True, exist_ok=True)
        operational_path.write_text(json.dumps(registry), encoding="utf-8")

        service = AnomalyInferenceService.from_registry(
            project_root=self.project_root,
            selection=ModelSelection(
                experiment="synthetic",
                model="isolation_forest",
                operating_point="validation_fpr_operational",
            ),
        )

        self.assertEqual(service.registry_path, operational_path.resolve())
        self.assertAlmostEqual(service.threshold, 0.8)
        result = service.predict_one(
            self._record(0.7, "flow-operational", "2026-09-05T15:00:00Z")
        )
        self.assertEqual(result["prediction"]["label"], "normal")

    def test_monitoring_documents_build_dashboard_snapshot(self) -> None:
        records = [
            self._record(0.2, "flow-1", "2026-09-05T15:00:00Z"),
            self._record(0.7, "flow-2", "2026-09-05T15:02:00Z"),
            self._record(
                0.8,
                "flow-3",
                "2026-09-05T15:07:00Z",
                src_ip="10.0.0.3",
            ),
        ]
        documents = [
            build_monitoring_document(result)
            for result in self.service.predict_many(records)
        ]

        snapshot = build_dashboard_snapshot(documents, bucket_minutes=5)

        self.assertEqual(snapshot["totals"]["flows"], 3)
        self.assertEqual(snapshot["totals"]["anomalies"], 2)
        self.assertAlmostEqual(snapshot["totals"]["anomaly_rate"], 2 / 3)
        self.assertEqual(len(snapshot["timeline"]), 2)
        self.assertFalse(snapshot["scores"]["is_probability"])
        self.assertEqual(len(snapshot["recent_anomalies"]), 2)
        changed = copy.deepcopy(documents)
        changed[0]["model"]["sha256"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "não pode misturar"):
            build_dashboard_snapshot(changed)


if __name__ == "__main__":
    unittest.main()
