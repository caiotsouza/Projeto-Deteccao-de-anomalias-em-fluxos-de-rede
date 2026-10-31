"""Testes das politicas do Marco 3."""

from __future__ import annotations

import unittest

import numpy as np
import pandas as pd

from src.preprocessing import PreprocessingConfig, preprocess_dataframe


class PreprocessingTests(unittest.TestCase):
    def test_cleaning_is_explicit_and_label_is_separated(self) -> None:
        frame = pd.DataFrame(
            {
                "flow": [1.0, 1.0, 2.0, np.inf, 3.0, 4.0, 5.0],
                "flow_copy": [1.0, 1.0, 2.0, np.inf, 3.0, 4.0, 5.0],
                "numeric_text": ["10", "10", "20", "30", "bad", "40", "50"],
                "constant": [7, 7, 7, 7, 7, 7, 7],
                "rare_flag": [0, 0, 0, 0, 0, 0, 1],
                "label": ["BENIGN"] * 7,
            }
        )
        config = PreprocessingConfig(
            near_constant_threshold=0.75,
            drop_constant_columns=True,
            drop_duplicate_columns=True,
        )

        result = preprocess_dataframe(frame, config)

        self.assertNotIn("label", result.features.columns)
        self.assertEqual(len(result.features), len(result.labels))
        self.assertEqual(len(result.features), 4)
        self.assertEqual(result.report["invalid_values"]["invalid_rows_removed"], 2)
        self.assertEqual(result.report["duplicates"]["exact_duplicate_rows_removed"], 1)
        self.assertIn("constant", result.report["column_analysis"]["constant_columns_removed"])
        self.assertEqual(
            result.report["column_analysis"]["duplicate_columns_found"]["flow_copy"],
            "flow",
        )
        self.assertIn(
            "rare_flag",
            result.report["column_analysis"]["near_constant_columns_retained"],
        )
        self.assertEqual(result.report["output"]["remaining_missing_feature_values"], 0)
        self.assertEqual(result.report["output"]["remaining_infinite_feature_values"], 0)

    def test_feature_analysis_does_not_remove_columns_by_default(self) -> None:
        frame = pd.DataFrame(
            {
                "original": [1, 2, 3],
                "copy": [1, 2, 3],
                "constant": [0, 0, 0],
                "label": ["BENIGN"] * 3,
            }
        )

        result = preprocess_dataframe(frame)

        self.assertEqual(result.features.columns.tolist(), ["original", "copy", "constant"])
        self.assertEqual(result.report["column_analysis"]["constant_columns_found"], ["constant"])
        self.assertEqual(result.report["column_analysis"]["constant_columns_removed"], [])
        self.assertEqual(result.report["column_analysis"]["duplicate_columns_found"], {"copy": "original"})
        self.assertEqual(result.report["column_analysis"]["duplicate_columns_removed"], [])

    def test_fully_non_numeric_feature_stops_processing(self) -> None:
        frame = pd.DataFrame(
            {"protocol_name": ["tcp", "udp"], "label": ["BENIGN", "BENIGN"]}
        )

        with self.assertRaisesRegex(ValueError, "nao possui valores numericos"):
            preprocess_dataframe(frame)


if __name__ == "__main__":
    unittest.main()
