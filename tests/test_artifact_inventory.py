"""Testes do inventário final e das proteções do Marco 10."""

from __future__ import annotations

import csv
import hashlib
import json
import struct
import tempfile
import unittest
from pathlib import Path

from src.artifact_inventory import (
    build_experiment_specs,
    collect_artifacts,
    run_marco10,
    validate_experiment,
)


def _save_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _metric_block(value: float) -> dict:
    return {
        "confusion_matrix": [[40, 10], [15, 35]],
        "true_negative": 40,
        "false_positive": 10,
        "false_negative": 15,
        "true_positive": 35,
        "accuracy": value,
        "balanced_accuracy": value,
        "precision": value,
        "recall_tpr": value,
        "f1_score": value,
        "specificity_tnr": value,
        "false_positive_rate": 1.0 - value,
        "false_negative_rate": 1.0 - value,
    }


def _comparison(value: float, validation_records: int, test_records: int) -> dict:
    models = {}
    for model_key in ("isolation_forest", "lof"):
        models[model_key] = {
            "thresholds": {
                "native": {"equivalent_anomaly_score_threshold": 0.5},
                "validation_f1_calibrated": {
                    "threshold": 0.4,
                    "test_labels_used": False,
                },
            },
            "splits": {
                split: {
                    "records": records,
                    "ranking_metrics": {
                        "roc_auc": value,
                        "average_precision": value,
                    },
                    "operating_points": {
                        point: _metric_block(value)
                        for point in ("native", "validation_f1_calibrated")
                    },
                }
                for split, records in (
                    ("validation", validation_records),
                    ("test", test_records),
                )
            },
        }
    return {
        "stage": "isolation_forest_lof_comparison_marco_9",
        "status": "completed",
        "methodology": {
            "predictions_frozen_before_labels_loaded": True,
            "models_loaded": False,
            "models_refitted_or_modified": False,
            "test_labels_used_for_threshold_selection": False,
            "both_thresholds_frozen_before_test_labels_loaded": True,
        },
        "models": models,
        "timing": {
            "by_model_seconds": {
                model_key: {
                    "fit": 1.0,
                    "inference_validation": 0.5,
                    "inference_test": 1.0,
                }
                for model_key in ("isolation_forest", "lof")
            }
        },
    }


def _write_png_header(path: Path, width: int = 1200, height: int = 800) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        b"\x89PNG\r\n\x1a\n"
        + struct.pack(">I", 13)
        + b"IHDR"
        + struct.pack(">II", width, height)
    )


def _create_experiment(project_root: Path, expanded: bool, value: float) -> None:
    if expanded:
        base = project_root / "experiments" / "scale_100k"
        train_records, validation_records, test_records = 100, 50, 100
        figure_dir = base / "figures" / "model_comparison"
    else:
        base = project_root
        train_records, validation_records, test_records = 20, 10, 20
        figure_dir = base / "reports" / "figures"
    models_dir = base / "models"
    metrics_dir = base / "metrics" if expanded else base / "reports" / "metrics"
    models_dir.mkdir(parents=True, exist_ok=True)
    metrics_dir.mkdir(parents=True, exist_ok=True)
    schema = "schema-sha256"
    configurations = {
        "isolation_forest": {"n_estimators": 200},
        "lof": {"n_neighbors": 20, "novelty": True},
    }
    for model_key in ("isolation_forest", "lof"):
        model_path = models_dir / f"{model_key}.joblib"
        model_path.write_bytes(f"{base}:{model_key}".encode("utf-8"))
        digest = _sha256(model_path)
        hash_key = (
            "model_sha256"
            if model_key == "isolation_forest"
            else "pipeline_sha256"
        )
        common = {
            "stage": f"{model_key}_training",
            "configuration": configurations[model_key],
            "libraries": {"python": "3.12", "scikit_learn": "1.9"},
            hash_key: digest,
        }
        _save_json(metrics_dir / f"{model_key}_training.json", common)
        _save_json(
            models_dir / f"{model_key}_metadata.json",
            {
                **common,
                "feature_count": 60,
                "model_input_schema_sha256": schema,
            },
        )
    _save_json(
        metrics_dir / "data_split_report.json",
        {
            "outputs": {
                "train": {"records": train_records},
                "validation": {"records": validation_records},
                "test": {"records": test_records},
            },
            "leakage_checks": {
                "status": "passed",
                "hash_overlaps": {
                    "train_validation": 0,
                    "train_test": 0,
                    "validation_test": 0,
                },
                "train_attack_records": 0,
                "model_input_schema_sha256": schema,
            },
        },
    )
    _save_json(
        metrics_dir / "model_comparison.json",
        _comparison(value, validation_records, test_records),
    )
    _write_png_header(figure_dir / "model_comparison_test_metrics.png")


class ArtifactInventoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.project_root = Path(self.temporary.name)
        _create_experiment(self.project_root, expanded=False, value=0.70)
        _create_experiment(self.project_root, expanded=True, value=0.80)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_inventory_classifies_sources_and_preserves_portable_paths(self) -> None:
        specs = build_experiment_specs(self.project_root, True)
        entries = collect_artifacts(specs, self.project_root)

        self.assertEqual(len(entries), 18)
        self.assertEqual(
            {entry["category"] for entry in entries},
            {"model", "model_metadata", "metric_report", "figure"},
        )
        self.assertTrue(all("\\" not in entry["relative_path"] for entry in entries))
        self.assertTrue(all(entry["integrity"] == "verified" for entry in entries))

    def test_validation_rejects_model_hash_divergence(self) -> None:
        specs = build_experiment_specs(self.project_root, True)
        entries = collect_artifacts(specs, self.project_root)
        validate_experiment(specs[0], entries, self.project_root)

        (self.project_root / "models" / "lof.joblib").write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "Hash do modelo divergente"):
            validate_experiment(specs[0], entries, self.project_root)

    def test_validation_rejects_threshold_selected_on_test(self) -> None:
        report_path = (
            self.project_root / "reports" / "metrics" / "model_comparison.json"
        )
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report["models"]["lof"]["thresholds"]["validation_f1_calibrated"][
            "test_labels_used"
        ] = True
        _save_json(report_path, report)
        specs = build_experiment_specs(self.project_root, True)
        entries = collect_artifacts(specs, self.project_root)

        with self.assertRaisesRegex(ValueError, "Limiar usa teste"):
            validate_experiment(specs[0], entries, self.project_root)

    def test_run_creates_six_outputs_without_changing_sources(self) -> None:
        source_model = self.project_root / "models" / "isolation_forest.joblib"
        before = _sha256(source_model)

        manifest = run_marco10(project_root=self.project_root)

        final_dir = self.project_root / "reports" / "final"
        self.assertEqual(len(list(final_dir.iterdir())), 6)
        self.assertTrue(manifest["source_integrity"]["unchanged"])
        self.assertEqual(manifest["validation"]["metrics_summary_rows"], 16)
        self.assertEqual(manifest["validation"]["figure_catalog_rows"], 2)
        self.assertEqual(before, _sha256(source_model))
        with (final_dir / "metrics_summary.csv").open(
            "r", encoding="utf-8", newline=""
        ) as file:
            self.assertEqual(len(list(csv.DictReader(file))), 16)
        metrics_text = (final_dir / "metrics_summary.csv").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("\n\n", metrics_text)
        self.assertEqual(len(metrics_text.splitlines()), 17)
        with self.assertRaises(FileExistsError):
            run_marco10(project_root=self.project_root)


if __name__ == "__main__":
    unittest.main()
