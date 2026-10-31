from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import pandas as pd

from src.generated_flow_context import GeneratedFlowContextResolver


class GeneratedFlowContextResolverTests(unittest.TestCase):
    def _frames(self) -> tuple[pd.DataFrame, pd.DataFrame]:
        features = pd.DataFrame(
            {
                "destination_port": [80.0, 443.0],
                "flow_duration": [10.0, 20.0],
                "total_fwd_packets": [1.0, 2.0],
            }
        )
        provenance = pd.DataFrame(
            {
                "source_file": pd.Series(["flows.csv", "flows.csv"], dtype="string"),
                "source_row": [0, 2],
            }
        )
        return features, provenance

    @staticmethod
    def _write_reference(
        path: Path,
        *,
        mismatch: bool = False,
        encoding: str = "utf-8",
    ) -> None:
        pd.DataFrame(
            {
                "Flow ID": ["a", "b–legacy", "c"],
                " Source IP": ["192.168.10.5", "192.168.10.6", "192.168.10.7"],
                " Destination IP": ["192.168.10.50", "192.168.10.51", "192.168.10.52"],
                " Protocol": [6, 17, 17],
                " Destination Port": [80, 53, 443],
                " Flow Duration": [10, 15, 999 if mismatch else 20],
                " Total Fwd Packets": [1, 1, 2],
                " Label": ["BENIGN", "BENIGN", "BENIGN"],
            }
        ).to_csv(path, index=False, encoding=encoding)

    def test_resolves_ips_and_standard_protocol_names_after_feature_validation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            self._write_reference(directory / "flows.csv")
            features, provenance = self._frames()

            result = GeneratedFlowContextResolver(
                directory, features.columns, chunk_size=2
            ).resolve(features, provenance, [0, 1])

            self.assertEqual(result.records_validated, 2)
            self.assertEqual(result.by_position[0].src_ip, "192.168.10.5")
            self.assertEqual(result.by_position[1].dst_ip, "192.168.10.52")
            self.assertEqual(result.by_position[0].protocol, "TCP")
            self.assertEqual(result.by_position[1].protocol, "UDP")
            self.assertEqual(result.source_paths, (directory / "flows.csv",))

    def test_rejects_context_when_same_source_row_has_different_features(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            self._write_reference(directory / "flows.csv", mismatch=True)
            features, provenance = self._frames()

            with self.assertRaisesRegex(ValueError, "não correspondem ao X_test"):
                GeneratedFlowContextResolver(directory, features.columns).resolve(
                    features, provenance, [0, 1]
                )

    def test_falls_back_to_latin1_when_the_cicids_csv_is_not_utf8(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            self._write_reference(directory / "flows.csv", encoding="cp1252")
            features, provenance = self._frames()

            result = GeneratedFlowContextResolver(directory, features.columns).resolve(
                features, provenance, [0, 1]
            )

            self.assertEqual(result.by_position[0].protocol, "TCP")
            self.assertEqual(result.by_position[1].src_ip, "192.168.10.7")


if __name__ == "__main__":
    unittest.main()
