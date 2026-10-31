import unittest

import numpy as np
import pandas as pd

from src.lab_feature_diagnostics import (
    compare_features, reference_profile, squared_distance_diagnostics, validate_frame,
)


class FeatureDiagnosticsTests(unittest.TestCase):
    def test_reference_uses_population_standard_deviation(self):
        profile, ordered = reference_profile(pd.DataFrame({"x": [0., 0., 2., 2.]}))
        self.assertEqual(profile["x"]["std_population"], 1.)
        self.assertEqual(profile["x"]["median"], 1.)
        np.testing.assert_array_equal(ordered["x"], [0., 0., 2., 2.])

    def test_ties_are_reported_as_empirical_bounds_not_confidence_intervals(self):
        p, o = reference_profile(pd.DataFrame({"x": [0., 0., 1., 1.]}))
        row = compare_features(pd.DataFrame({"x": [1., 1., 2.]}), p, o)[0]
        self.assertEqual(row["outside_training_min_max_count"], 1)
        self.assertEqual(row["training_fraction_below_sample_median"], .5)
        self.assertEqual(row["training_fraction_below_or_equal_sample_median"], 1.)
        self.assertEqual(row["training_count_equal_sample_mode"], 2)

    def test_reference_negative_values_are_counted_not_modified(self):
        frame = pd.DataFrame({"x": [-1., 0., 1.]})
        original = frame.copy(deep=True)
        p, _ = reference_profile(frame)
        self.assertEqual(p["x"]["negative_values"], 1)
        pd.testing.assert_frame_equal(frame, original)

    def test_invalid_frames_are_rejected(self):
        for frame in (pd.DataFrame({"x": []}), pd.DataFrame({"x": [True]}),
                      pd.DataFrame({"x": [float("nan")]}), pd.DataFrame({"x": [float("inf")]}),
                      pd.DataFrame({"x": ["1"]}), pd.DataFrame({"y": [1]})):
            with self.subTest(frame=frame), self.assertRaises(ValueError):
                validate_frame(frame, ["x"])

    def test_squared_shares_are_geometric_not_scores(self):
        q, ref = np.array([[3., 4.]]), np.array([[0., 0.]])
        result = squared_distance_diagnostics(q, ref, np.array([[5.]]), np.array([[0]]), ["x", "y"])
        shares = {r["feature"]: r["pooled_squared_distance_share"] for r in result["features"]}
        self.assertAlmostEqual(shares["x"], .36)
        self.assertAlmostEqual(shares["y"], .64)
        self.assertEqual(result["support_range_distance_lower_bound_median"], 5.)
        self.assertFalse(result["is_lof_score_attribution"])
        self.assertFalse(result["applies_to_isolation_forest"])

    def test_zero_distance_does_not_divide_by_zero(self):
        a = np.array([[0., 0.]])
        result = squared_distance_diagnostics(a, a, np.array([[0.]]), np.array([[0]]), ["x", "y"])
        self.assertEqual(sum(r["pooled_squared_distance_share"] for r in result["features"]), 0.)

    def test_pooled_shares_weight_distant_records(self):
        result = squared_distance_diagnostics(np.array([[1., 0.], [0., 3.]]), np.zeros((1, 2)),
                                              np.array([[1.], [3.]]), np.array([[0], [0]]), ["x", "y"])
        x = next(r for r in result["features"] if r["feature"] == "x")
        self.assertAlmostEqual(x["pooled_squared_distance_share"], .1)
        self.assertAlmostEqual(x["median_record_squared_distance_share"], .5)

    def test_wrong_distances_and_neighbor_indexes_are_rejected(self):
        for distance, index in (([[2.]], [[0]]), ([[1.]], [[-1]]), ([[1.]], [[1]]),
                                ([[1.]], [[0.]]), ([[-1.]], [[0]]), ([[float("nan")]], [[0]])):
            with self.subTest(distance=distance, index=index), self.assertRaises(ValueError):
                squared_distance_diagnostics(np.array([[1., 0.]]), np.zeros((1, 2)),
                                             np.array(distance), np.array(index), ["x", "y"])

    def test_order_mismatch_is_rejected(self):
        p, o = reference_profile(pd.DataFrame({"x": [0., 1.], "y": [1., 2.]}))
        with self.assertRaises(ValueError):
            compare_features(pd.DataFrame({"y": [1.], "x": [0.]}), p, o)


if __name__ == "__main__":
    unittest.main()
