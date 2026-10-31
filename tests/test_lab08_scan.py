import unittest

from tests import test_lab07_scan as pilot_tests
from validate_lab07_scan import parse_scanner


class Lab08ScopeTests(unittest.TestCase):
    def fixture(self, ports):
        xml, normal, grepable = pilot_tests.Lab07Tests().fixture(ports)
        return (xml.replace(b'/tmp/lab07-r1/scan', b'/tmp/lab08-r1/scan'),
                normal.replace('/tmp/lab07-r1/scan', '/tmp/lab08-r1/scan'),
                grepable.replace('/tmp/lab07-r1/scan', '/tmp/lab08-r1/scan'))

    def test_explicit_profile_keeps_pilot_separate(self):
        from validate_lab07_scan import PORTS
        data = self.fixture(','.join(map(str, sorted(PORTS))))
        self.assertEqual(parse_scanner(*data, profile='lab08_r1')['missing_planned_ports'], [])
        with self.assertRaises(ValueError):
            parse_scanner(*data)

    def test_missing_port_or_wrong_output_rejected(self):
        with self.assertRaises(ValueError):
            parse_scanner(*self.fixture('135'), profile='lab08_r1')
        data = pilot_tests.Lab07Tests().fixture('135')
        with self.assertRaises(ValueError):
            parse_scanner(*data, profile='lab08_r1')


if __name__ == '__main__':
    unittest.main()
