import unittest
import pandas as pd

from audit_lab07_extraction import compare_groups
from validate_lab07_scan import PORTS, expand_ports, parse_scanner


class Lab07Tests(unittest.TestCase):
    def fixture(self, ports="21,22"):
        selected = sorted(expand_ports(ports))
        args = ("/usr/lib/nmap/nmap -n -Pn -sT -p " + ports +
                " --max-rate 10 --scan-delay 100ms --max-retries 1 --host-timeout 120s"
                " -oA /tmp/lab07-r1/scan 172.31.50.161")
        xml = ('<nmaprun scanner="nmap" args="' + args + '" start="100" version="7.99">'
               '<scaninfo type="connect" protocol="tcp" numservices="' + str(len(selected)) +
               '" services="' + ports + '"/><host><status state="up" reason="user-set"/>'
               '<address addr="172.31.50.161" addrtype="ipv4"/><ports>' +
               ''.join('<port protocol="tcp" portid="' + str(p) + '"><state state="filtered" reason="no-response"/></port>'
                       for p in selected) + '</ports></host><runstats><finished exit="success" time="105" elapsed="5"/>'
               '</runstats></nmaprun>').encode()
        normal = "# Nmap scan as: " + args + "\n" + ''.join(str(p) + '/tcp filtered unknown\n' for p in selected)
        grep = "# Nmap scan as: " + args + "\n" + ', '.join(str(p) + '/filtered/tcp//unknown///' for p in selected)
        return xml, normal, grep

    def test_missing_ports_are_explicit_and_host_up_not_proof(self):
        result = parse_scanner(*self.fixture())
        self.assertEqual(result["actual_ports"], [21, 22])
        self.assertIn(5985, result["missing_planned_ports"])
        self.assertFalse(result["host_reachability_proven_by_scanner_status"])

    def test_full_port_list_has_no_deviation(self):
        result = parse_scanner(*self.fixture(','.join(map(str, sorted(PORTS)))))
        self.assertEqual(result["missing_planned_ports"], [])

    def test_invalid_or_out_of_scope_ports_rejected(self):
        for ports in ("", "0", "65536", "21,21", "21-8080", "9999", "22-21", "21;id"):
            with self.subTest(ports=ports), self.assertRaises(ValueError):
                expand_ports(ports)

    def test_alias_ranges_expand_to_same_ports(self):
        self.assertEqual(expand_ports('21-23'), {21, 22, 23})

    def test_wrong_target_or_flags_rejected(self):
        xml, normal, grep = self.fixture()
        for old, new in ((b'172.31.50.161', b'192.168.1.1'), (b'-sT', b'-sV'), (b'--max-rate 10', b'--max-rate 99')):
            with self.subTest(new=new), self.assertRaises(ValueError):
                parse_scanner(xml.replace(old, new), normal, grep)

    def test_inconsistent_formats_or_empty_logs_rejected(self):
        xml, normal, grep = self.fixture()
        for text in ('', normal.replace('21/tcp filtered', '21/tcp open')):
            with self.assertRaises(ValueError):
                parse_scanner(xml, text, grep)

    def test_external_entities_rejected(self):
        xml, normal, grep = self.fixture()
        with self.assertRaises(ValueError):
            parse_scanner(b'<!DOCTYPE nmaprun SYSTEM "file:///secret">' + xml, normal, grep)

    def coverage_fixture(self):
        frame = pd.DataFrame([dict(src_ip='172.31.60.10', src_port=50000, dst_ip='172.31.50.161',
                                   destination_port=21, total_fwd_packets=2, total_backward_packets=0, flow_duration=100)])
        group = dict(source=['172.31.60.10', 50000], destination=['172.31.50.161', 21],
                     packets=2, forward_packets=2, backward_packets=0, duration_us=100)
        single = dict(source=['172.31.60.10', 50001], destination=['172.31.50.161', 22],
                      packets=1, forward_packets=1, backward_packets=0, duration_us=0)
        return frame, group, single

    def test_partial_coverage_keeps_single_packet_groups(self):
        frame, group, single = self.coverage_fixture()
        result = compare_groups(frame, dict(packets=3, connections=[group, single]))
        self.assertFalse(result['full_packet_coverage'])
        self.assertEqual(result['unrepresented_packets'], 1)
        self.assertTrue(result['all_unrepresented_groups_are_single_packet'])

    def test_full_coverage_recognized(self):
        frame, group, _ = self.coverage_fixture()
        self.assertTrue(compare_groups(frame, dict(packets=2, connections=[group]))['full_packet_coverage'])

    def test_mismatched_or_duplicated_csv_rows_rejected(self):
        frame, group, _ = self.coverage_fixture()
        with self.assertRaises(ValueError):
            compare_groups(pd.concat([frame, frame]), dict(packets=2, connections=[group]))
        frame.loc[0, 'total_fwd_packets'] = 1
        with self.assertRaises(ValueError):
            compare_groups(frame, dict(packets=2, connections=[group]))


if __name__ == '__main__':
    unittest.main()
