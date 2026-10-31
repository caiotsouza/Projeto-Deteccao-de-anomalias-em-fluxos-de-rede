"""Validacao offline de HTTP controlado; fixtures sinteticas, sem rede/Docker."""

import json
import socket
import struct
import tempfile
import unittest
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from validate_benign_http_capture import CLIENT, SERVER, reassemble, validate


def frame(src, dst, sport, dport, seq, ack, flags, payload=b""):
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 8192, 0, 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, len(tcp) + 20, 0, 0, 64, 6, 0,
                     socket.inet_aton(src), socket.inet_aton(dst))
    return b"\0" * 12 + b"\x08\x00" + ip + tcp


class BenignCaptureValidationTests(unittest.TestCase):
    def setUp(self):
        root = Path(__file__).resolve().parents[1]
        (root / "tmp").mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=root / "tmp")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def fixture(self, corrupt_body=False):
        request = b"GET /benign-v1/small_16k.bin HTTP/1.0\r\n\r\n"
        pattern = b"TCC2026-BENIGN-HTTP-DATA\n"
        body = (pattern * (16384 // len(pattern) + 1))[:16384]
        if corrupt_body:
            body = b"X" + body[1:]
        response = b"HTTP/1.0 200 OK\r\nContent-Length: 16384\r\n\r\n" + body
        raw = bytearray(struct.pack("<IHH iIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        logs = []
        for index in range(30):
            port, sec = 28000 + index, 1770000000 + 2 * index
            cs, ss = 101 + len(request), 201 + len(response)
            packets = [
                frame(CLIENT, SERVER, port, 8000, 100, 0, 2),
                frame(SERVER, CLIENT, 8000, port, 200, 101, 18),
                frame(CLIENT, SERVER, port, 8000, 101, 201, 16),
                frame(CLIENT, SERVER, port, 8000, 101, 201, 24, request),
                frame(SERVER, CLIENT, 8000, port, 201, cs, 24, response),
                frame(SERVER, CLIENT, 8000, port, ss, cs, 17),
                frame(CLIENT, SERVER, port, 8000, cs, ss + 1, 16),
                frame(CLIENT, SERVER, port, 8000, cs, ss + 1, 17),
                frame(SERVER, CLIENT, 8000, port, ss + 1, cs + 1, 16),
            ]
            for offset, packet in enumerate(packets):
                raw.extend(struct.pack("<IIII", sec, offset * 100, len(packet), len(packet)))
                raw.extend(packet)
            logs.append({"request_number": index + 1, "success": True, "error": None,
                         "curl_exit_code": 0, "http_status": 200, "body_bytes": 16384,
                         "url": f"http://{SERVER}:8000/benign-v1/small_16k.bin",
                         "local_ip": CLIENT, "remote_ip": SERVER,
                         "started_at_utc": datetime.fromtimestamp(sec, timezone.utc).isoformat(),
                         "completed_at_utc": datetime.fromtimestamp(sec + 1, timezone.utc).isoformat()})
        config = {"description": "lab03_small_r1", "interface": "hn2", "fam": "ip", "protocol": "TCP",
                  "host": CLIENT, "port": "8000", "protocol_not": "0", "port_not": "0",
                  "snaplen": "65535", "count": "50000"}
        archive = self.root / "capture.zip"
        with zipfile.ZipFile(archive, "w") as z:
            z.writestr("capture.json", json.dumps(config))
            z.writestr("capture.pcap", raw)
        manifest = {"status": "completed", "attempted_requests": 30, "successful_requests": 30,
                    "definition": {"scenario": "lab03_small", "repetition": 1, "source_ip": CLIENT,
                                   "target_ip": SERVER, "url": logs[0]["url"], "requests": 30,
                                   "expected_bytes_per_request": 16384, "expected_total_body_bytes": 491520,
                                   "concurrency": 1, "http_version": "1.0", "redirects": False, "retries": 0}}
        client_manifest, requests = self.root / "manifest.json", self.root / "requests.jsonl"
        client_manifest.write_text(json.dumps(manifest))
        requests.write_text("\n".join(json.dumps(p) for p in logs))
        return dict(archive=archive, client_manifest=client_manifest, requests=requests,
                    output_dir=self.root / "session", scenario="lab03_small")

    def test_complete_session_validates_and_preserves_sources(self):
        options = self.fixture()
        result = validate(**options)
        self.assertEqual(result["connections"], 30)
        self.assertEqual(result["packets"], 270)
        self.assertEqual(result["total_http_body_bytes"], 491520)
        self.assertEqual(result["successful_http_responses"], 30)
        self.assertTrue(result["source_files_unchanged"])
        self.assertFalse(result["capture_drop_counter_available"])
        with self.assertRaises(FileExistsError):
            validate(**options)

    def test_body_hash_mismatch_is_not_accepted_as_complete_http(self):
        with self.assertRaisesRegex(ValueError, "corpo diverge"):
            validate(**self.fixture(corrupt_body=True))

    def test_missing_client_record_rejected_before_copy(self):
        options = self.fixture()
        rows = options["requests"].read_text().splitlines()
        options["requests"].write_text("\n".join(rows[:-1]))
        with self.assertRaisesRegex(ValueError, "Numeracao"):
            validate(**options)
        self.assertFalse(options["output_dir"].exists())

    def test_archive_traversal_is_rejected_before_copy(self):
        options = self.fixture()
        with zipfile.ZipFile(options["archive"], "w") as z:
            z.writestr("../capture.json", "{}")
            z.writestr("capture.pcap", b"invalid")
        with self.assertRaisesRegex(ValueError, "ZIP"):
            validate(**options)
        self.assertFalse(options["output_dir"].exists())

    def test_reassembly_handles_identical_overlap_and_rejects_conflict_or_gap(self):
        endpoint = (CLIENT, 1234)
        group = [{"src": endpoint, "seq": 100, "flags": 2, "payload": b""},
                 {"src": endpoint, "seq": 101, "flags": 16, "payload": b"abc"},
                 {"src": endpoint, "seq": 103, "flags": 16, "payload": b"cdef"}]
        self.assertEqual(reassemble(group, endpoint), (b"abcdef", 1))
        group[-1]["payload"] = b"Xdef"
        with self.assertRaisesRegex(ValueError, "conflitantes"):
            reassemble(group, endpoint)
        group[-1]["seq"] = 106
        with self.assertRaisesRegex(ValueError, "Lacuna"):
            reassemble(group, endpoint)


if __name__ == "__main__":
    unittest.main()
