import copy
import unittest

from src.lab_export_scope import validate_export_scope


class ExportScopeTests(unittest.TestCase):
    def setUp(self):
        a = dict(source=['a', 1], destination=['b', 135], packets=4,
                 forward_packets=3, backward_packets=1, duration_us=7)
        b = dict(source=['a', 2], destination=['b', 22], packets=1,
                 forward_packets=1, backward_packets=0, duration_us=0)
        self.independent = dict(packets=5, connections=[a, b])
        self.records = [dict(context=dict(src_ip='a', src_port=1, dst_ip='b', dst_port=135, packet_count=4),
                             features=dict(total_fwd_packets=3, total_backward_packets=1, flow_duration=7))]
        self.structural = dict(rows=1, csv_sha256='fixture')
        self.audit = dict(structural_audit=self.structural, coverage=dict(
            captured_packets=5, represented_packets=4, unrepresented_packets=1,
            captured_endpoint_groups=2, represented_endpoint_groups=1, unrepresented_endpoint_groups=1,
            all_unrepresented_groups_are_single_packet=True, full_packet_coverage=False,
            unrepresented_groups=[b]))

    def call(self, **kwargs):
        return validate_export_scope(self.audit, self.structural, self.records, self.independent, **kwargs)

    def test_partial_requires_explicit_acceptance(self):
        with self.assertRaisesRegex(ValueError, 'autorizacao'):
            self.call()

    def test_denominator_is_exports_not_whole_scan(self):
        before = copy.deepcopy(self.records)
        scope = self.call(accept_partial_export=True)
        self.assertEqual(scope['denominator_records'], 1)
        self.assertFalse(scope['whole_scan_detection_measured'])
        self.assertEqual(self.records, before)

    def test_tampered_counts_hash_group_or_duration_rejected(self):
        original = copy.deepcopy(self.audit)
        self.audit['coverage']['represented_packets'] = 5
        with self.assertRaises(ValueError):
            self.call(accept_partial_export=True)
        self.audit = original
        self.records[0]['features']['flow_duration'] = 8
        with self.assertRaises(ValueError):
            self.call(accept_partial_export=True)
        self.records[0]['features']['flow_duration'] = 7
        self.records.append(copy.deepcopy(self.records[0]))
        with self.assertRaises(ValueError):
            self.call(accept_partial_export=True)

    def test_different_extraction_rejected(self):
        with self.assertRaises(ValueError):
            validate_export_scope(self.audit, dict(rows=1, csv_sha256='changed'), self.records,
                                  self.independent, accept_partial_export=True)
