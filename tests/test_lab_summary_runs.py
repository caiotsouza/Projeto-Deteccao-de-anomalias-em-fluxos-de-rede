import unittest

from src.config import PROJECT_ROOT
from summarize_lab_captures import RUNS, include_runs


class LabSummaryRunsTests(unittest.TestCase):
    def test_defaults_preserved_and_not_mutated(self):
        before = dict(RUNS)
        self.assertEqual(include_runs([]), before)
        result = include_runs(["lab03_small_r2=data/lab/lab03_small/r2/inference"])
        self.assertEqual(result["lab03_small_r2"], "data/lab/lab03_small/r2/inference")
        self.assertEqual(RUNS, before)

    def test_invalid_or_duplicate_names_rejected(self):
        for spec in ("bad", "=data/lab", "new=", "lab03_small_r1=data/lab"):
            with self.subTest(spec=spec), self.assertRaises(ValueError):
                include_runs([spec])
        with self.assertRaises(ValueError):
            include_runs(["new=data/lab", "new=data/lab"])

    def test_paths_outside_project_rejected(self):
        for spec in ("new=../outside", "new=" + str(PROJECT_ROOT / "data/lab")):
            with self.subTest(spec=spec), self.assertRaises(ValueError):
                include_runs([spec])


if __name__ == "__main__":
    unittest.main()
