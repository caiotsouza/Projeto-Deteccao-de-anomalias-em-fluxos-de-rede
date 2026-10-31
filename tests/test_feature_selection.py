"""Testes da selecao e do manifesto do Marco 4."""

from __future__ import annotations

import unittest

import pandas as pd

from src.feature_selection import (
    FeatureSelectionConfig,
    apply_feature_manifest,
    select_features,
)


class FeatureSelectionTests(unittest.TestCase):
    def _build_features(self) -> pd.DataFrame:
        return pd.DataFrame(
            {
                "fwd_packet_length_mean": [1.0, 2.0, 3.0, 4.0, 5.0],
                "avg_fwd_segment_size": [1.0, 2.0, 3.0, 4.0, 5.0],
                "packet_length_std": [1.0, 2.0, 3.0, 4.0, 5.0],
                "packet_length_variance": [1.0, 4.0, 9.0, 16.0, 25.0],
                "constant_flag": [0, 0, 0, 0, 0],
                "rare_flag": [0, 0, 0, 0, 1],
                "fwd_psh_flags": [0, 1, 0, 1, 0],
                "syn_flag_count": [0, 1, 0, 1, 0],
            }
        )

    def test_selection_removes_only_confirmed_rules_and_constants(self) -> None:
        features = self._build_features()
        config = FeatureSelectionConfig(
            near_constant_threshold=0.8,
            correlation_threshold=0.99,
        )

        result = select_features(features, config)

        selected = result.selected_features.columns.tolist()
        self.assertNotIn("constant_flag", selected)
        self.assertNotIn("avg_fwd_segment_size", selected)
        self.assertNotIn("packet_length_variance", selected)
        self.assertIn("fwd_psh_flags", selected)
        self.assertIn("syn_flag_count", selected)
        self.assertIn("rare_flag", selected)
        self.assertFalse(result.report["methodology"]["labels_used"])
        self.assertEqual(
            result.report["near_constant_analysis"]["features"]["rare_flag"]["decision"],
            "retained",
        )

    def test_manifest_preserves_names_order_and_dtypes(self) -> None:
        result = select_features(self._build_features())
        reordered_input = self._build_features()[list(reversed(self._build_features().columns))]

        reapplied = apply_feature_manifest(reordered_input, result.manifest)

        self.assertEqual(reapplied.columns.tolist(), result.manifest["selected_features"])

    def test_manifest_rejects_missing_feature(self) -> None:
        result = select_features(self._build_features())
        incomplete = self._build_features().drop(columns=[result.manifest["selected_features"][0]])

        with self.assertRaisesRegex(ValueError, "features obrigatorias"):
            apply_feature_manifest(incomplete, result.manifest)

    def test_label_is_rejected(self) -> None:
        features = self._build_features().assign(label="BENIGN")

        with self.assertRaisesRegex(ValueError, "Vazamento detectado"):
            select_features(features)


if __name__ == "__main__":
    unittest.main()
