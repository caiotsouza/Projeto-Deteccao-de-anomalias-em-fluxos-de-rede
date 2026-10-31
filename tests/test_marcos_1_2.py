"""Testes unitarios dos componentes iniciais."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import numpy as np
import pandas as pd

from src.inspect_data import inspect_dataframe
from src.load_data import discover_csv_files, load_cicids_csvs
from src.utils import normalize_column_name


class InitialMilestonesTests(unittest.TestCase):
    def test_normalize_column_name(self) -> None:
        self.assertEqual(normalize_column_name(" Flow Duration "), "flow_duration")
        self.assertEqual(normalize_column_name("Fwd Packets/s"), "fwd_packets_s")

    def test_load_and_inspect_multiple_csvs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            frame_a = pd.DataFrame(
                {
                    " Flow Duration ": [10.0, 10.0],
                    "Flow Bytes/s": [np.inf, np.inf],
                    " Label ": ["BENIGN", "BENIGN"],
                }
            )
            frame_b = pd.DataFrame(
                {
                    " Flow Duration ": [20.0, np.nan],
                    "Flow Bytes/s": [5.0, 7.0],
                    " Label ": ["DoS", "PortScan"],
                }
            )
            frame_a.to_csv(directory / "a.csv", index=False)
            frame_b.to_csv(directory / "b.csv", index=False)

            files = discover_csv_files(directory)
            loaded = load_cicids_csvs(files)
            report = inspect_dataframe(loaded)

            self.assertEqual(report["records"], 4)
            self.assertEqual(report["columns"], 3)
            self.assertEqual(report["missing_values_total"], 1)
            self.assertEqual(report["infinite_values_total"], 2)
            self.assertEqual(report["records_removed"], 0)
            self.assertEqual(report["label_distribution"]["BENIGN"], 2)
            self.assertEqual(report["label_distribution"]["DoS"], 1)


if __name__ == "__main__":
    unittest.main()
