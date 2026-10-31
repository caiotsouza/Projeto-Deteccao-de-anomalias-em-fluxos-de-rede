"""Testes da comparacao entre as escalas 20k e 100k."""

from __future__ import annotations

import unittest

from src.scale_experiment import (
    _build_delta_table,
    _build_summary_table,
    _validate_comparison_report,
    _validate_model_configurations,
    _validate_split_reports,
    compare_scale_reports,
)


def metric_block(value: float) -> dict[str, float | int | list[list[int]]]:
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


def make_comparison(value: float, records: int) -> dict:
    models = {}
    for model_key in ("isolation_forest", "lof"):
        models[model_key] = {
            "thresholds": {
                "native": {"equivalent_anomaly_score_threshold": 0.5},
                "validation_f1_calibrated": {"threshold": 0.4},
            },
            "splits": {
                split: {
                    "records": records,
                    "ranking_metrics": {
                        "roc_auc": value,
                        "average_precision": value,
                    },
                    "operating_points": {
                        "native": metric_block(value),
                        "validation_f1_calibrated": metric_block(value),
                    },
                }
                for split in ("validation", "test")
            },
        }
    return {
        "stage": "isolation_forest_lof_comparison_marco_9",
        "status": "completed",
        "methodology": {
            "predictions_frozen_before_labels_loaded": True,
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


def make_split_report(scale: int) -> dict:
    return {
        "configuration": {
            "train_benign_size": 20_000 * scale,
            "validation_benign_size": 5_000 * scale,
            "validation_attack_size": 5_000 * scale,
            "test_benign_size": 10_000 * scale,
            "test_attack_size": 10_000 * scale,
            "random_state": 42,
        },
        "leakage_checks": {
            "model_input_schema_sha256": "schema",
            "hash_overlaps": {
                "train_validation": 0,
                "train_test": 0,
                "validation_test": 0,
            },
            "train_attack_records": 0,
            "status": "passed",
        },
    }


class ScaleExperimentTests(unittest.TestCase):
    def test_report_contract_rejects_test_based_threshold(self) -> None:
        report = make_comparison(0.7, 100)
        _validate_comparison_report(report, "synthetic")

        report["methodology"]["test_labels_used_for_threshold_selection"] = True
        with self.assertRaisesRegex(ValueError, "teste"):
            _validate_comparison_report(report, "synthetic")

    def test_split_validation_requires_exact_factor_five(self) -> None:
        result = _validate_split_reports(make_split_report(1), make_split_report(5))
        self.assertEqual(result["scale_factor"], 5)
        self.assertTrue(result["zero_hash_overlap_within_each_experiment"])

        changed = make_split_report(5)
        changed["configuration"]["test_attack_size"] -= 1
        with self.assertRaisesRegex(ValueError, "test_attack_size"):
            _validate_split_reports(make_split_report(1), changed)

    def test_comparison_calculates_direction_aware_deltas(self) -> None:
        baseline = make_comparison(0.70, 20_000)
        expanded = make_comparison(0.75, 100_000)

        comparison = compare_scale_reports(baseline, expanded)

        f1 = comparison["lof"]["splits"]["test"]["operating_points"][
            "native"
        ]["f1_score"]
        fpr = comparison["lof"]["splits"]["test"]["operating_points"][
            "native"
        ]["false_positive_rate"]
        self.assertAlmostEqual(f1["delta_100k_minus_20k"], 0.05)
        self.assertEqual(f1["winner"], "expanded_100k")
        self.assertAlmostEqual(fpr["delta_100k_minus_20k"], -0.05)
        self.assertEqual(fpr["winner"], "expanded_100k")

    def test_tables_preserve_both_experiments_and_configuration_guard(self) -> None:
        reports = {
            "baseline_20k": make_comparison(0.70, 20_000),
            "expanded_100k": make_comparison(0.75, 100_000),
        }
        summary = _build_summary_table(reports)
        deltas = _build_delta_table(summary)

        self.assertEqual(len(summary), 16)
        self.assertEqual(set(summary["experiment"]), set(reports))
        self.assertFalse(deltas.empty)

        configurations = {
            "isolation_forest": {"configuration": {"n_estimators": 200}},
            "lof": {"configuration": {"n_neighbors": 20}},
        }
        audit = _validate_model_configurations(configurations, configurations)
        self.assertTrue(audit["lof"]["identical_between_experiments"])
        changed = {
            **configurations,
            "lof": {"configuration": {"n_neighbors": 50}},
        }
        with self.assertRaisesRegex(ValueError, "lof"):
            _validate_model_configurations(configurations, changed)


if __name__ == "__main__":
    unittest.main()
