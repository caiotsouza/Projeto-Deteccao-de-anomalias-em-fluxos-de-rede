"""Testes dos contratos MongoDB/FastAPI/Grafana do Marco 11."""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from src.inference_service import ModelSelection
from src.integration_contracts import (
    build_grafana_dashboard_spec,
    build_inference_request_schema,
    build_mongodb_prediction_schema,
    run_marco11_preparation,
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _build_project(project_root: Path) -> tuple[Path, Path, Path]:
    features = [f"feature_{index:02d}" for index in range(60)]
    model_path = project_root / "models" / "lof.joblib"
    metadata_path = project_root / "models" / "lof_metadata.json"
    registry_path = project_root / "reports" / "final" / "model_registry.json"
    model_path.parent.mkdir(parents=True, exist_ok=True)
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    model_path.write_bytes(b"trusted-model")
    metadata = {
        "feature_count": 60,
        "feature_columns": features,
        "model_input_schema_sha256": "schema",
    }
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
    registry = {
        "status": "completed",
        "experiments": {
            "expanded_100k": {
                "models": {
                    "lof": {
                        "display_name": "Local Outlier Factor",
                        "feature_count": 60,
                        "model_input_schema_sha256": "schema",
                        "model_artifact": {
                            "relative_path": "models/lof.joblib",
                            "sha256": _sha256(model_path),
                        },
                        "metadata_artifact": {
                            "relative_path": "models/lof_metadata.json",
                            "sha256": _sha256(metadata_path),
                        },
                        "thresholds": {
                            "native": {
                                "equivalent_anomaly_score_threshold": 1.5
                            },
                            "validation_f1_calibrated": {
                                "threshold": 1.6,
                                "test_labels_used": False,
                            },
                        },
                    }
                }
            }
        },
    }
    registry_path.write_text(json.dumps(registry), encoding="utf-8")
    return model_path, metadata_path, registry_path


class IntegrationContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.project_root = Path(self.temporary.name)
        self.model_path, self.metadata_path, self.registry_path = _build_project(
            self.project_root
        )
        self.selection = ModelSelection(
            experiment="expanded_100k",
            model="lof",
            operating_point="validation_f1_calibrated",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_request_and_mongodb_contracts_preserve_boundaries(self) -> None:
        features = [f"feature_{index:02d}" for index in range(60)]
        request = build_inference_request_schema(features)
        mongodb = build_mongodb_prediction_schema()

        self.assertEqual(request["properties"]["features"]["required"], features)
        self.assertFalse(request["properties"]["features"]["additionalProperties"])
        self.assertNotIn("label", request["properties"]["features"]["properties"])
        self.assertIn("propertyNames", request["properties"]["context"])
        self.assertEqual(mongodb["collection"], "network_flow_predictions")
        self.assertTrue(
            any(index.get("unique") for index in mongodb["recommended_indexes"])
        )
        self.assertFalse(mongodb["retention"]["ttl_enabled_by_default"])

    def test_grafana_spec_uses_fundamental_panels_and_avoids_fake_truth(self) -> None:
        registry = json.loads(self.registry_path.read_text(encoding="utf-8"))
        entry = registry["experiments"]["expanded_100k"]["models"]["lof"]

        spec = build_grafana_dashboard_spec(self.selection, entry)

        self.assertEqual(len(spec["panels"]), 11)
        panel_ids = {panel["id"] for panel in spec["panels"]}
        self.assertIn("anomaly_rate", panel_ids)
        self.assertIn("recent_anomalies", panel_ids)
        self.assertNotIn("false_positive_rate", panel_ids)
        self.assertEqual(spec["status"], "design_contract_not_provisioned")
        self.assertIn("not a probability", spec["data_contract"]["score_warning"])

    def test_preparation_generates_six_files_and_preserves_sources(self) -> None:
        before = {
            path: _sha256(path)
            for path in (self.model_path, self.metadata_path, self.registry_path)
        }

        manifest = run_marco11_preparation(
            project_root=self.project_root,
            selection=self.selection,
        )

        output_dir = self.project_root / "reports" / "integration"
        self.assertEqual(len(list(output_dir.iterdir())), 6)
        self.assertTrue(manifest["source_integrity"]["unchanged"])
        self.assertEqual(manifest["validation"]["feature_count"], 60)
        self.assertEqual(manifest["validation"]["dashboard_panel_count"], 11)
        self.assertFalse(manifest["selection"]["production_approved"])
        self.assertEqual(before, {path: _sha256(path) for path in before})
        with self.assertRaises(FileExistsError):
            run_marco11_preparation(
                project_root=self.project_root,
                selection=self.selection,
            )

    def test_preparation_rejects_tampered_model(self) -> None:
        self.model_path.write_bytes(b"tampered")

        with self.assertRaisesRegex(ValueError, "Hash do modelo"):
            run_marco11_preparation(
                project_root=self.project_root,
                selection=self.selection,
            )


if __name__ == "__main__":
    unittest.main()
