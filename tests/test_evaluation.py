"""Testes de integridade e metricas da avaliacao do Marco 7."""

from __future__ import annotations

import unittest

import numpy as np
import pandas as pd

from src.evaluation import (
    calculate_classification_metrics,
    evaluate_joined_splits,
    join_predictions_and_labels,
    select_f1_threshold,
)


def make_prediction_frame(scores: list[float]) -> pd.DataFrame:
    anomaly_score = np.asarray(scores, dtype=np.float64)
    score_samples = -anomaly_score
    decision_function = 0.5 - anomaly_score
    sklearn_prediction = np.where(decision_function < 0.0, -1, 1).astype(np.int8)
    return pd.DataFrame(
        {
            "row_position": np.arange(len(scores), dtype=np.int64),
            "record_hash": pd.Series(
                [f"{index:016x}" for index in range(len(scores))], dtype="string"
            ),
            "sklearn_prediction": sklearn_prediction,
            "predicted_anomaly": (sklearn_prediction == -1).astype(np.int8),
            "score_samples": score_samples,
            "decision_function": decision_function,
            "anomaly_score": anomaly_score,
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


class EvaluationTests(unittest.TestCase):
    def test_join_is_one_to_one_and_preserves_score_orientation(self) -> None:
        predictions = make_prediction_frame([0.1, 0.2, 0.8, 0.9])
        labels = make_label_frame([0, 0, 1, 1])

        joined, audit = join_predictions_and_labels(predictions, labels, "validation")

        self.assertEqual(len(joined), 4)
        self.assertTrue(audit["hash_sets_identical"])
        self.assertTrue(audit["score_orientation_valid"])
        self.assertEqual(joined["binary_label"].tolist(), [0, 0, 1, 1])

    def test_join_rejects_hash_mismatch_and_inverted_score(self) -> None:
        predictions = make_prediction_frame([0.1, 0.2, 0.8, 0.9])
        labels = make_label_frame([0, 0, 1, 1])
        labels.loc[3, "record_hash"] = "ffffffffffffffff"
        with self.assertRaisesRegex(ValueError, "record_hash divergentes"):
            join_predictions_and_labels(predictions, labels, "validation")

        labels = make_label_frame([0, 0, 1, 1])
        predictions["anomaly_score"] *= -1
        with self.assertRaisesRegex(ValueError, "Orientacao"):
            join_predictions_and_labels(predictions, labels, "validation")

    def test_metrics_have_expected_confusion_matrix(self) -> None:
        metrics = calculate_classification_metrics(
            np.array([0, 0, 1, 1], dtype=np.int8),
            np.array([0, 1, 0, 1], dtype=np.int8),
        )

        self.assertEqual(metrics["confusion_matrix"], [[1, 1], [1, 1]])
        self.assertEqual(metrics["false_positive"], 1)
        self.assertEqual(metrics["false_negative"], 1)
        self.assertAlmostEqual(metrics["precision"], 0.5)
        self.assertAlmostEqual(metrics["recall_tpr"], 0.5)
        self.assertAlmostEqual(metrics["f1_score"], 0.5)
        self.assertAlmostEqual(metrics["false_positive_rate"], 0.5)

    def test_f1_threshold_uses_higher_anomaly_score(self) -> None:
        selection = select_f1_threshold(
            np.array([0, 0, 1, 1], dtype=np.int8),
            np.array([0.1, 0.2, 0.8, 0.9], dtype=np.float64),
        )

        self.assertAlmostEqual(selection["threshold"], 0.8)
        self.assertAlmostEqual(selection["validation_f1_at_selection"], 1.0)
        self.assertFalse(selection["test_labels_used"])

    def test_changing_test_does_not_change_validation_threshold(self) -> None:
        validation_predictions = make_prediction_frame([0.1, 0.2, 0.8, 0.9])
        validation_labels = make_label_frame([0, 0, 1, 1])
        validation, _ = join_predictions_and_labels(
            validation_predictions, validation_labels, "validation"
        )

        test_a, _ = join_predictions_and_labels(
            make_prediction_frame([0.15, 0.3, 0.7, 0.95]),
            make_label_frame([0, 0, 1, 1]),
            "test",
        )
        test_b, _ = join_predictions_and_labels(
            make_prediction_frame([0.15, 0.3, 0.7, 0.95]),
            make_label_frame([1, 1, 0, 0]),
            "test",
        )
        result_a = evaluate_joined_splits(validation, test_a, learned_offset=-0.5)
        result_b = evaluate_joined_splits(validation, test_b, learned_offset=-0.5)

        threshold_a = result_a.report["thresholds"]["validation_f1_calibrated"][
            "threshold"
        ]
        threshold_b = result_b.report["thresholds"]["validation_f1_calibrated"][
            "threshold"
        ]
        self.assertEqual(threshold_a, threshold_b)


if __name__ == "__main__":
    unittest.main()
