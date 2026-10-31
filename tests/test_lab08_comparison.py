import copy
import unittest

from compare_lab08_subset import aggregate, identity, MODELS


class Lab08ComparisonTests(unittest.TestCase):
    def entry(self, n, alerts):
        return {m: {
            'all_segments': dict(segments=n, signaled_segments=alerts),
            'with_payload': dict(segments=0, signaled_segments=0),
            'zero_payload': dict(segments=n, signaled_segments=alerts),
        } for m in MODELS}

    def test_weighted_counts_not_mean_of_rates(self):
        result = aggregate([self.entry(1, 1), self.entry(3, 0)])
        self.assertEqual(result['lof']['all_segments']['segments'], 4)
        self.assertEqual(result['lof']['all_segments']['signal_rate'], 0.25)

    def test_empty_payload_group_has_no_rate(self):
        self.assertIsNone(aggregate([self.entry(4, 1)])['lof']['with_payload']['signal_rate'])

    def test_different_denominators_rejected(self):
        entry = self.entry(4, 1)
        entry['lof']['all_segments']['segments'] = 5
        with self.assertRaises(ValueError):
            aggregate([entry])

    def test_identity_includes_threshold_and_model_hash(self):
        report = {'models': {m: dict(model_sha256=m, operating_point='operational', threshold=1.0,
                                     summary={}) for m in MODELS}}
        before = identity(report)
        changed = copy.deepcopy(report)
        changed['models']['lof']['threshold'] = 2.0
        self.assertNotEqual(identity(changed), before)
        changed = copy.deepcopy(report)
        changed['models']['lof']['model_sha256'] = 'another-model'
        self.assertNotEqual(identity(changed), before)
