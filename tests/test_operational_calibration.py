"""Testes da calibração orientada a orçamento de falsos positivos."""

from __future__ import annotations

import unittest

import numpy as np
import pandas as pd

from src.operational_calibration import (
    OPERATIONAL_POINT,
    build_operational_calibration,
    select_fpr_constrained_threshold,
)


def _frame(normal_scores: list[float], attack_scores: list[float]) -> pd.DataFrame:
    scores = normal_scores + attack_scores
    labels = [0] * len(normal_scores) + [1] * len(attack_scores)
    return pd.DataFrame(
        {
            "row_position": np.arange(len(scores), dtype=np.int64),
            "record_hash": [f"hash-{index}" for index in range(len(scores))],
            "label": ["BENIGN" if value == 0 else "ATTACK" for value in labels],
            "binary_label": labels,
            "anomaly_score": scores,
        }
    )


def _registry() -> dict:
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
            "validation_and_test_metrics": {
                split: {
                    "records": 15,
                    "ranking_metrics": {},
                    "operating_points": {},
                }
                for split in ("validation", "test")
            },
        }
    return {
        "status": "completed",
        "warnings": [],
        "experiments": {"expanded_100k": {"models": models}},
    }


class OperationalCalibrationTests(unittest.TestCase):
    def test_threshold_respects_budget_and_uses_inclusive_rule(self) -> None:
        selection = select_fpr_constrained_threshold(
            np.array([0] * 10 + [1, 1]),
            np.array([0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0, 0.95, 1.2]),
            target_fpr=0.2,
        )

        self.assertEqual(selection["threshold"], 0.9)
        self.assertEqual(selection["achieved_validation_false_positives"], 2)
        self.assertAlmostEqual(
            selection["achieved_validation_false_positive_rate"], 0.2
        )
        self.assertFalse(selection["attack_labels_used_for_threshold_selection"])
        self.assertFalse(selection["test_labels_used"])

    def test_tied_scores_raise_threshold_instead_of_breaking_budget(self) -> None:
        selection = select_fpr_constrained_threshold(
            np.array([0] * 10 + [1]),
            np.array([0.1] * 7 + [0.9] * 3 + [1.0]),
            target_fpr=0.2,
        )

        self.assertGreater(selection["threshold"], 0.9)
        self.assertEqual(selection["achieved_validation_false_positives"], 0)
        self.assertEqual(
            selection["threshold_source"],
            "next_float_above_maximum_benign_score",
        )

    def test_model_and_threshold_do_not_change_when_test_changes(self) -> None:
        normal = [value / 10 for value in range(10)]
        validation = {
            "isolation_forest": _frame(normal, [0.75, 0.85, 0.95, 1.0, 1.1]),
            "lof": _frame(normal, [0.1, 0.2, 0.3, 0.95, 1.0]),
        }
        test_a = {
            "isolation_forest": _frame(normal, [0.95, 1.0, 1.1, 1.2, 1.3]),
            "lof": _frame(normal, [0.95, 1.0, 1.1, 1.2, 1.3]),
        }
        test_b = {
            key: frame.assign(
                anomaly_score=np.where(frame["binary_label"].eq(1), -100.0, frame["anomaly_score"])
            )
            for key, frame in test_a.items()
        }

        result_a = build_operational_calibration(
            validation,
            test_a,
            _registry(),
            target_fpr=0.2,
            sensitivity_fprs=(0.2,),
            created_at_utc="2026-09-05T12:00:00+00:00",
        )
        result_b = build_operational_calibration(
            validation,
            test_b,
            _registry(),
            target_fpr=0.2,
            sensitivity_fprs=(0.2,),
            created_at_utc="2026-09-05T12:00:00+00:00",
        )

        recommendation_a = result_a.report["recommendation"]
        recommendation_b = result_b.report["recommendation"]
        self.assertEqual(recommendation_a["model"], "isolation_forest")
        self.assertEqual(recommendation_a, recommendation_b)
        self.assertEqual(
            recommendation_a["threshold"],
            result_a.registry["experiments"]["expanded_100k"]["models"]
            ["isolation_forest"]["thresholds"][OPERATIONAL_POINT]["threshold"],
        )
        original = _registry()
        self.assertNotIn(
            OPERATIONAL_POINT,
            original["experiments"]["expanded_100k"]["models"]
            ["isolation_forest"]["thresholds"],
        )
        self.assertIn(
            "validation_f1_calibrated",
            result_a.registry["experiments"]["expanded_100k"]["models"]
            ["isolation_forest"]["thresholds"],
        )


if __name__ == "__main__":
    unittest.main()
