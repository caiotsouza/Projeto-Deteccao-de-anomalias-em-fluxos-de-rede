"""Testes das garantias do Local Outlier Factor no Marco 8."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from src.isolation_forest import schema_fingerprint
from src.local_outlier_factor import (
    LOFConfig,
    save_lof_artifacts,
    train_and_score_lof,
)


def make_frame(rows: int, seed: int, shift: float = 0.0) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    return pd.DataFrame(
        {
            "feature_small": rng.normal(shift, 1.0, rows).astype("float64"),
            "feature_large": rng.normal(shift * 10_000, 10_000, rows).astype("float64"),
            "feature_integer": rng.integers(0, 100, rows, dtype=np.int64),
        }
    )


def make_inputs() -> tuple[dict[str, pd.DataFrame], dict[str, object]]:
    train = make_frame(100, seed=1)
    validation = make_frame(30, seed=2, shift=0.2)
    test = make_frame(40, seed=3, shift=0.3)
    fingerprint = schema_fingerprint(train)
    manifest = {
        "feature_columns": train.columns.tolist(),
        "feature_count": len(train.columns),
        "model_input_schema_sha256": fingerprint,
    }
    return {"train": train, "validation": validation, "test": test}, manifest


class LOFTests(unittest.TestCase):
    def test_config_rejects_invalid_neighbors_and_contamination(self) -> None:
        with self.assertRaisesRegex(ValueError, "n_neighbors"):
            LOFConfig(n_neighbors=1)
        with self.assertRaisesRegex(ValueError, "contamination"):
            LOFConfig(contamination=0.75)

    def test_scaler_is_fitted_only_on_training_and_novelty_is_enabled(self) -> None:
        frames, manifest = make_inputs()
        train_mean = frames["train"].mean().to_numpy()
        paths = {name: Path(f"X_{name}.parquet") for name in frames}

        result = train_and_score_lof(
            frames,
            paths,
            manifest,
            Path("split_manifest.json"),
            LOFConfig(n_neighbors=10, n_jobs=1),
        )

        scaler = result.pipeline.named_steps["scaler"]
        lof = result.pipeline.named_steps["lof"]
        np.testing.assert_allclose(scaler.mean_, train_mean)
        self.assertTrue(lof.novelty)
        self.assertEqual(result.report["scaler"]["fitted_on"], "X_train only")
        self.assertFalse(
            result.report["training_diagnostics"][
                "novelty_score_samples_called_on_training"
            ]
        )

    def test_unseen_predictions_follow_score_and_class_conventions(self) -> None:
        frames, manifest = make_inputs()
        paths = {name: Path(f"X_{name}.parquet") for name in frames}
        result = train_and_score_lof(
            frames,
            paths,
            manifest,
            Path("split_manifest.json"),
            LOFConfig(n_neighbors=10, n_jobs=1),
        )
        prediction = result.predictions["validation"]
        scaler = result.pipeline.named_steps["scaler"]
        lof = result.pipeline.named_steps["lof"]
        direct_prediction = lof.predict(scaler.transform(frames["validation"]))

        np.testing.assert_array_equal(
            prediction["sklearn_prediction"].to_numpy(), direct_prediction
        )
        np.testing.assert_array_equal(
            prediction["predicted_anomaly"].to_numpy(),
            (direct_prediction == -1).astype(np.int8),
        )
        np.testing.assert_allclose(
            prediction["anomaly_score"], -prediction["score_samples"]
        )
        np.testing.assert_allclose(
            prediction["decision_function"],
            prediction["score_samples"] - lof.offset_,
        )

    def test_bundle_preserves_pipeline_schema_and_can_be_reloaded(self) -> None:
        frames, manifest = make_inputs()
        paths = {name: Path(f"X_{name}.parquet") for name in frames}
        result = train_and_score_lof(
            frames,
            paths,
            manifest,
            Path("split_manifest.json"),
            LOFConfig(n_neighbors=10, n_jobs=1),
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifacts = save_lof_artifacts(
                result,
                root / "lof.joblib",
                root / "lof_metadata.json",
                root / "predictions",
                root / "lof_training.json",
            )
            bundle = joblib.load(artifacts["model"])

        self.assertEqual(
            bundle["artifact_type"], "sklearn_standard_scaler_lof_pipeline_bundle"
        )
        self.assertEqual(bundle["feature_columns"], frames["train"].columns.tolist())
        self.assertEqual(
            bundle["model_input_schema_sha256"], manifest["model_input_schema_sha256"]
        )
        self.assertEqual(list(bundle["pipeline"].named_steps), ["scaler", "lof"])


if __name__ == "__main__":
    unittest.main()
