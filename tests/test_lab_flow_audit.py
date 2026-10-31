"""Regressoes da auditoria; nao dependem do PCAP privado nem de Docker."""

import json
import socket
import struct
import tempfile
import unittest
from pathlib import Path

import pandas as pd

from src.lab_flow_audit import (
    COMMITS, FLAGS, audit_extraction, audit_original_flags, audit_pcap,
    map_columns, sha256,
)


ROOT = Path(__file__).resolve().parents[1]


def packet(source, destination, sport, dport, flags, window, payload=b"", fragment=0):
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 5 << 4, flags, window, 0, 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0, fragment, 64, 6, 0,
                     socket.inet_aton(source), socket.inet_aton(destination))
    return b"\0" * 12 + b"\x08\x00" + ip + tcp


def pcap_bytes(frames):
    header = struct.pack("<I H H i I I I", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    return header + b"".join(struct.pack("<IIII", 100, i * 100, len(frame), len(frame)) + frame
                              for i, frame in enumerate(frames))


class LabFlowAuditTests(unittest.TestCase):
    def setUp(self):
        (ROOT / "tmp").mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=ROOT / "tmp")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.pcap = self.directory / "sample.pcap"
        self.pcap.write_bytes(pcap_bytes([
            packet("10.0.0.1", "10.0.0.2", 1234, 8000, 2, 8192),
            packet("10.0.0.2", "10.0.0.1", 8000, 1234, 18, 64240),
            packet("10.0.0.2", "10.0.0.1", 8000, 1234, 17, 126, b"abc"),
        ]))
        self.selection = json.loads((ROOT / "data/processed/monday_feature_manifest.json").read_text())
        self.split = json.loads((ROOT / "experiments/scale_100k/data/splits/split_manifest.json").read_text())

    def extraction(self, **overrides):
        row = dict.fromkeys(self.selection["selected_features"], 0)
        row.update(total_fwd_packets=1, total_backward_packets=2, flow_duration=200)
        row.update(overrides)
        # An arbitrary Label must have no effect on the audit or numeric features.
        row["Label"] = "DO NOT USE THIS AS GROUND TRUTH"
        csv_path = self.directory / "flows.csv"
        pd.DataFrame([row]).to_csv(csv_path, index=False)
        run = {
            "source_commit": COMMITS["v4"], "image_id": "test-image",
            "pcap_sha256_before": sha256(self.pcap), "pcap_sha256_after": sha256(self.pcap),
            "csv_files": [{"name": csv_path.name, "sha256": sha256(csv_path)}],
        }
        (self.directory / "extraction_run.json").write_text(json.dumps(run), encoding="utf-8")
        return run

    def audit(self):
        return audit_extraction(self.directory, "v4", self.pcap, self.selection, self.split)

    def test_independent_pcap_counts_windows_and_first_fin(self):
        result = audit_pcap(self.pcap)
        self.assertEqual(result["packets"], 3)
        connection = result["connections"][0]
        self.assertEqual(connection["forward_packets"], 1)
        self.assertEqual(connection["backward_packets"], 2)
        self.assertEqual(connection["backward_initial_window_raw"], 64240)
        self.assertEqual(connection["backward_last_window_raw"], 126)
        self.assertEqual(connection["first_fin_prefix_duration_us"], 200)
        self.assertEqual(connection["payload_bytes"], 3)

    def test_rejects_truncated_capture(self):
        self.pcap.write_bytes(self.pcap.read_bytes()[:-1])
        with self.assertRaises(ValueError):
            audit_pcap(self.pcap)

    def test_rejects_fragment_instead_of_reporting_partial_metrics(self):
        self.pcap.write_bytes(pcap_bytes([packet("10.0.0.1", "10.0.0.2", 1, 2, 2, 10, fragment=0x2000)]))
        with self.assertRaisesRegex(ValueError, "fragmentacao"):
            audit_pcap(self.pcap)

    def test_aliases_reject_collision_and_unknown_profile(self):
        with self.assertRaisesRegex(ValueError, "duplicadas"):
            map_columns(["Dst Port", "Destination Port"], "v4")
        with self.assertRaises(ValueError):
            map_columns(["Dst Port"], "unknown")
        self.assertEqual(map_columns(["Tot Fwd Pkts", "SYN Flag Cnt"], "legacy_pre2019"),
                         ["total_fwd_packets", "syn_flag_count"])

    def test_structural_pass_never_grants_semantic_approval(self):
        self.extraction(syn_flag_count=2, ack_flag_count=6)
        before = sha256(self.directory / "flows.csv")
        result = self.audit()
        self.assertEqual(result["feature_count"], 60)
        self.assertEqual(result["structural_validation"], "passed")
        self.assertEqual(result["semantic_compatibility"], "not_established")
        self.assertFalse(result["automatic_inference_allowed"])
        self.assertTrue(result["label_ignored"])
        # No clipping modern counts to make them resemble old binary flags.
        self.assertEqual(result["flag_values"]["ack_flag_count"], [6])
        self.assertEqual(before, sha256(self.directory / "flows.csv"))

    def test_rejects_hash_tampering(self):
        self.extraction()
        with (self.directory / "flows.csv").open("a") as stream:
            stream.write("\n")
        with self.assertRaisesRegex(ValueError, "hash"):
            self.audit()

    def test_rejects_wrong_commit(self):
        run = self.extraction()
        run["source_commit"] = "unexpected"
        (self.directory / "extraction_run.json").write_text(json.dumps(run))
        with self.assertRaisesRegex(ValueError, "Proveniencia"):
            self.audit()

    def test_rejects_missing_feature(self):
        self.extraction()
        path = self.directory / "flows.csv"
        pd.read_csv(path).drop(columns=["flow_duration"]).to_csv(path, index=False)
        run = json.loads((self.directory / "extraction_run.json").read_text())
        run["csv_files"][0]["sha256"] = sha256(path)
        (self.directory / "extraction_run.json").write_text(json.dumps(run))
        with self.assertRaisesRegex(ValueError, "ausentes"):
            self.audit()

    def test_rejects_nonfinite_and_fractional_integer(self):
        for value in (float("inf"), 1.5):
            with self.subTest(value=value):
                self.extraction(flow_duration=value)
                with self.assertRaises((ValueError, OverflowError)):
                    self.audit()

    def test_full_flag_scan_rejects_late_nonbinary_value(self):
        path = self.directory / "original.csv"
        data = {name: [0, 1] for name in FLAGS}
        pd.DataFrame(data).to_csv(path, index=False)
        self.assertEqual(audit_original_flags([path])[0]["rows"], 2)
        data["ack_flag_count"][-1] = 2
        pd.DataFrame(data).to_csv(path, index=False)
        with self.assertRaisesRegex(ValueError, "fora de 0/1"):
            audit_original_flags([path])


if __name__ == "__main__":
    unittest.main()
