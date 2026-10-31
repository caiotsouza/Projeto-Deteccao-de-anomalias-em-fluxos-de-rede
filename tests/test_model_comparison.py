"""Testes do protocolo de avaliacao comparativa do Marco 9."""

from __future__ import annotations

import unittest

import numpy as np
import pandas as pd

from src.evaluation import join_predictions_and_labels
from src.model_comparison import (
    build_paired_frame,
    compare_model_evaluations,
    evaluate_model_splits,
)


def make_prediction_frame(
    anomaly_scores: list[float],
    native_threshold: float = 0.5,
) -> pd.DataFrame:
    scores = np.asarray(anomaly_scores, dtype=np.float64)
    score_samples = -scores
    decision = native_threshold - scores
    sklearn_prediction = np.where(decision < 0.0, -1, 1).astype(np.int8)
    return pd.DataFrame(
        {
            "row_position": np.arange(len(scores), dtype=np.int64),
            "record_hash": pd.Series(
                [f"{index:016x}" for index in range(len(scores))], dtype="string"
            ),
            "sklearn_prediction": sklearn_prediction,
            "predicted_anomaly": (sklearn_prediction == -1).astype(np.int8),
            "score_samples": score_samples,
            "decision_function": decision,
            "anomaly_score": scores,
        }
    )


def make_label_frame(binary: list[int]) -> pd.DataFrame:
    return pd.DataFrame(
        {
            "label": pd.Series(
                ["BENIGN" if value == 0 else "Synthetic Attack" for value in binary],
                dtype="string",
            ),
            "binary_label": pd.Series(binary, dtype="int8"),
            "source_file": pd.Series(["synthetic.csv"] * len(binary), dtype="string"),
            "source_row": np.arange(len(binary), dtype=np.int64),
            "record_hash": pd.Series(
                [f"{index:016x}" for index in range(len(binary))], dtype="string"
            ),
        }
    )


def joined(scores: list[float], binary: list[int]) -> pd.DataFrame:
    frame, _ = join_predictions_and_labels(
        make_prediction_frame(scores),
        make_label_frame(binary),
        "synthetic",
    )
    return frame


class ModelComparisonTests(unittest.TestCase):
    def test_each_threshold_is_selected_from_validation_only(self) -> None:
        validation = joined([0.1, 0.2, 0.8, 0.9], [0, 0, 1, 1])
        test_a = joined([0.15, 0.3, 0.7, 0.95], [0, 0, 1, 1])
        test_b = joined([0.15, 0.3, 0.7, 0.95], [1, 1, 0, 0])

        result_a = evaluate_model_splits(validation, test_a, learned_offset=-0.5)
        result_b = evaluate_model_splits(validation, test_b, learned_offset=-0.5)

        threshold_a = result_a.thresholds["validation_f1_calibrated"]["threshold"]
        threshold_b = result_b.thresholds["validation_f1_calibrated"]["threshold"]
        self.assertEqual(threshold_a, 0.8)
        self.assertEqual(threshold_a, threshold_b)

    def test_paired_frame_requires_identical_records_and_truth(self) -> None:
        iforest = evaluate_model_splits(
            joined([0.1, 0.2, 0.8, 0.9], [0, 0, 1, 1]),
            joined([0.2, 0.3, 0.7, 0.8], [0, 0, 1, 1]),
            learned_offset=-0.5,
        )
        lof = evaluate_model_splits(
            joined([0.2, 0.3, 0.7, 0.8], [0, 0, 1, 1]),
            joined([0.1, 0.4, 0.6, 0.9], [0, 0, 1, 1]),
            learned_offset=-0.5,
        )
        paired = build_paired_frame(
            iforest.evaluated_frames["test"],
            lof.evaluated_frames["test"],
            "test",
        )
        self.assertEqual(len(paired), 4)
        self.assertIn("lof_validation_f1_calibrated_correct", paired.columns)

        changed = lof.evaluated_frames["test"].copy()
        changed.loc[3, "record_hash"] = "ffffffffffffffff"
        with self.assertRaisesRegex(ValueError, "record_hash"):
            build_paired_frame(iforest.evaluated_frames["test"], changed, "test")

    def test_comparison_reports_deltas_winners_and_paired_outcomes(self) -> None:
        labels = [0, 0, 1, 1]
        iforest = evaluate_model_splits(
            joined([0.1, 0.2, 0.8, 0.9], labels),
            joined([0.1, 0.2, 0.8, 0.9], labels),
            learned_offset=-0.5,
        )
        lof = evaluate_model_splits(
            joined([0.3, 0.7, 0.6, 0.95], labels),
            joined([0.3, 0.7, 0.6, 0.95], labels),
            learned_offset=-0.5,
        )
        evaluations = {"isolation_forest": iforest, "lof": lof}
        paired = {
            split: build_paired_frame(
                iforest.evaluated_frames[split],
                lof.evaluated_frames[split],
                split,
            )
            for split in ("validation", "test")
        }

        comparison = compare_model_evaluations(evaluations, paired)

        native = comparison["test"]["operating_points"]["native"]
        expected_delta = (
            native["by_model"]["lof"]["f1_score"]
            - native["by_model"]["isolation_forest"]["f1_score"]
        )
        self.assertAlmostEqual(
            native["deltas_lof_minus_isolation_forest"]["f1_score"],
            expected_delta,
        )
        self.assertEqual(native["winner_by_metric"]["f1_score"], "isolation_forest")
        self.assertEqual(native["paired_outcomes"]["records"], 4)

    def test_native_and_calibrated_predictions_are_both_preserved(self) -> None:
        validation = joined([0.1, 0.4, 0.45, 0.9], [0, 0, 1, 1])
        test = joined([0.2, 0.42, 0.46, 0.8], [0, 0, 1, 1])

        result = evaluate_model_splits(validation, test, learned_offset=-0.5)

        self.assertIn("predicted_anomaly", result.evaluated_frames["test"].columns)
        self.assertIn(
            "predicted_anomaly_calibrated_f1",
            result.evaluated_frames["test"].columns,
        )
        self.assertFalse(
            np.array_equal(
                result.evaluated_frames["test"]["predicted_anomaly"],
                result.evaluated_frames["test"][
                    "predicted_anomaly_calibrated_f1"
                ],
            )
        )


if __name__ == "__main__":
    unittest.main()
