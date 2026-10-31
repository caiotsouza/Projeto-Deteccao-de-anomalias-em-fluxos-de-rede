"""Testes das regras de divisao do Marco 5."""

from __future__ import annotations

import unittest

import pandas as pd

from src.data_split import (
    SplitConfig,
    align_features_to_manifest,
    allocate_stratified_quota,
    normalize_label_value,
)
from src.feature_selection import FeatureSelectionConfig, select_features


class DataSplitTests(unittest.TestCase):
    def test_label_normalization_repairs_web_attack_separator(self) -> None:
        self.assertEqual(
            normalize_label_value("  Web Attack \ufffd Brute Force  "),
            "Web Attack - Brute Force",
        )
        self.assertEqual(normalize_label_value(" benign "), "BENIGN")
        self.assertEqual(normalize_label_value("FTP-Patator"), "FTP-Patator")

    def test_quota_is_exact_and_preserves_rare_classes(self) -> None:
        available = {"large": 1_000, "medium": 100, "rare": 6}

        quotas = allocate_stratified_quota(available, total_size=200, minimum_per_label=5)

        self.assertEqual(sum(quotas.values()), 200)
        self.assertGreaterEqual(quotas["rare"], 5)
        self.assertLessEqual(quotas["rare"], available["rare"])

    def test_manifest_alignment_restores_order_and_types(self) -> None:
        training = pd.DataFrame(
            {
                "feature_a": pd.Series([1, 2, 3], dtype="int16"),
                "feature_b": pd.Series([1.5, 2.5, 3.5], dtype="float32"),
            }
        )
        selection = select_features(
            training,
            FeatureSelectionConfig(drop_constant_features=True),
        )
        external = pd.DataFrame(
            {
                "feature_b": pd.Series([4.5, 5.5], dtype="float64"),
                "feature_a": pd.Series([4, 5], dtype="int64"),
            }
        )

        aligned = align_features_to_manifest(external, selection.manifest)

        self.assertEqual(aligned.columns.tolist(), ["feature_a", "feature_b"])
        self.assertEqual(str(aligned["feature_a"].dtype), "int64")
        self.assertEqual(str(aligned["feature_b"].dtype), "float64")

    def test_split_config_rejects_non_positive_size(self) -> None:
        with self.assertRaisesRegex(ValueError, "train_benign_size"):
            SplitConfig(train_benign_size=0)


if __name__ == "__main__":
    unittest.main()
