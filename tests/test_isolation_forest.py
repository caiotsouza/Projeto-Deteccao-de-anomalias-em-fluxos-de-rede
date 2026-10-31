"""Testes das garantias metodologicas do Marco 6."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from src.isolation_forest import (
    IsolationForestConfig,
    save_isolation_forest_artifacts,
    schema_fingerprint,
    train_and_score,
    validate_feature_frame,
)


def make_frame(rows: int = 120) -> pd.DataFrame:
    rng = np.random.default_rng(42)
    return pd.DataFrame(
        {
            "feature_a": rng.normal(0, 1, rows).astype("float64"),
            "feature_b": rng.integers(0, 100, rows, dtype=np.int64),
            "feature_c": rng.normal(10, 2, rows).astype("float64"),
        }
    )


class IsolationForestTests(unittest.TestCase):
    def test_config_rejects_invalid_contamination(self) -> None:
        with self.assertRaisesRegex(ValueError, "contamination"):
            IsolationForestConfig(contamination=0.75)

    def test_validation_rejects_changed_column_order_and_infinity(self) -> None:
        frame = make_frame()
        expected_columns = frame.columns.tolist()
        fingerprint = schema_fingerprint(frame)

        with self.assertRaisesRegex(ValueError, "ordem_alterada=True"):
            validate_feature_frame(
                frame[["feature_b", "feature_a", "feature_c"]],
                "validation",
                expected_columns,
                fingerprint,
            )

        invalid = frame.copy()
        invalid.loc[0, "feature_a"] = np.inf
        with self.assertRaisesRegex(ValueError, "infinito"):
            validate_feature_frame(
                invalid, "validation", expected_columns, fingerprint
            )

    def test_training_and_predictions_follow_explicit_score_conventions(self) -> None:
        train = make_frame(120)
        validation = make_frame(40)
        test = make_frame(50)
        fingerprint = schema_fingerprint(train)
        manifest = {
            "feature_columns": train.columns.tolist(),
            "feature_count": len(train.columns),
            "model_input_schema_sha256": fingerprint,
        }
        paths = {name: Path(f"X_{name}.parquet") for name in ("train", "validation", "test")}

        result = train_and_score(
            {"train": train, "validation": validation, "test": test},
            paths,
            manifest,
            Path("split_manifest.json"),
            IsolationForestConfig(
                n_estimators=20,
                max_samples=32,
                contamination=0.10,
                random_state=42,
                n_jobs=1,
            ),
        )

        prediction = result.predictions["train"]
        self.assertEqual(len(prediction), len(train))
        self.assertTrue(
            np.array_equal(
                prediction["predicted_anomaly"].to_numpy(),
                (prediction["sklearn_prediction"].to_numpy() == -1).astype(np.int8),
            )
        )
        np.testing.assert_allclose(
            prediction["anomaly_score"], -prediction["score_samples"]
        )
        np.testing.assert_allclose(
            prediction["decision_function"],
            prediction["score_samples"] - result.model.offset_,
        )
        self.assertFalse(result.report["methodology"]["labels_loaded"])
        self.assertTrue(result.report["evaluation_deferred_to_marco_7"])

    def test_artifact_bundle_preserves_model_and_feature_order(self) -> None:
        train = make_frame(80)
        fingerprint = schema_fingerprint(train)
        manifest = {
            "feature_columns": train.columns.tolist(),
            "feature_count": len(train.columns),
            "model_input_schema_sha256": fingerprint,
        }
        frames = {"train": train, "validation": train.head(20), "test": train.tail(20)}
        paths = {name: Path(f"X_{name}.parquet") for name in frames}
        result = train_and_score(
            frames,
            paths,
            manifest,
            Path("split_manifest.json"),
            IsolationForestConfig(n_estimators=10, max_samples=32, n_jobs=1),
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact_paths = save_isolation_forest_artifacts(
                result,
                root / "model.joblib",
                root / "metadata.json",
                root / "predictions",
                root / "report.json",
            )
            bundle = joblib.load(artifact_paths["model"])

        self.assertEqual(bundle["feature_columns"], train.columns.tolist())
        self.assertEqual(bundle["model_input_schema_sha256"], fingerprint)
        self.assertEqual(bundle["artifact_type"], "sklearn_isolation_forest_bundle")


if __name__ == "__main__":
    unittest.main()
