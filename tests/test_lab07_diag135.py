import unittest

from audit_lab07_diag135 import decode_windows_text, trace_metadata, window_covers
from validate_lab07_scan import parse_scanner


class Diagnostic135Tests(unittest.TestCase):
    def fixture(self, ports='135'):
        from tests.test_lab07_scan import Lab07Tests
        xml, normal, grepable = Lab07Tests().fixture(ports)
        def change(value):
            return (value.replace('--max-rate 10', '--max-rate 1').replace(' --scan-delay 100ms', '')
                    .replace('--max-retries 1', '--max-retries 0').replace('--host-timeout 120s', '--host-timeout 20s')
                    .replace('/tmp/lab07-r1/scan', '/tmp/lab07-diag135-r2/scan'))
        return change(xml.decode()).encode(), change(normal), change(grepable)

    def test_diagnostic_profile_is_explicit_and_single_port(self):
        result = parse_scanner(*self.fixture(), profile='diag135_r2')
        self.assertEqual(result['actual_ports'], [135])
        self.assertEqual(result['planned_ports'], [135])
        self.assertEqual(result['missing_planned_ports'], [])
        with self.assertRaises(ValueError):
            parse_scanner(*self.fixture())

    def test_other_port_or_profile_rejected(self):
        with self.assertRaises(ValueError):
            parse_scanner(*self.fixture('22'), profile='diag135_r2')
        with self.assertRaises(ValueError):
            parse_scanner(*self.fixture(), profile='unknown')

    def test_unicode_windows_text_bom(self):
        value = 'Evento: Cabeçalho'
        for encoding in ('utf-16', 'utf-8-sig', 'utf-8'):
            self.assertEqual(decode_windows_text(value.encode(encoding)), value)
        with self.assertRaises(UnicodeDecodeError):
            decode_windows_text(value.encode('cp1252'))

    def test_filetime_window_covers_scan_but_not_packet_reception(self):
        trace = trace_metadata('Header EndTime: 134374557967987258, StartTime: 134374555910726139')
        self.assertEqual(trace['start_utc'], '2026-10-26T02:33:11.072613+00:00')
        self.assertEqual(trace['pktmon_provider_lines'], 0)
        self.assertFalse(trace['inbound_packet_observation_proven'])
        self.assertTrue(window_covers(trace, {'start_epoch_seconds': 1792982162, 'finish_epoch_seconds': 1792982163}))
        self.assertFalse(window_covers(trace, {'start_epoch_seconds': 1792981990, 'finish_epoch_seconds': 1792982163}))

    def test_invalid_header_rejected(self):
        for text in ('Header only', 'StartTime: 10, EndTime: 0'):
            with self.assertRaises(ValueError):
                trace_metadata(text)

    def test_provider_metadata_not_automatically_a_packet(self):
        trace = trace_metadata('[Microsoft-Windows-PktMon] Header StartTime: 0, EndTime: 100')
        self.assertEqual(trace['pktmon_provider_lines'], 1)
        self.assertFalse(trace['inbound_packet_observation_proven'])


if __name__ == '__main__':
    unittest.main()
