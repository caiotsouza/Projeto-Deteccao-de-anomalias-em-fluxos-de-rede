"""LAB06 sem trafego real: relogio simulado, handler em memoria e mocks PS5."""

import hashlib
import http.client
import io
import json
import shutil
import struct
import subprocess
import tempfile
import threading
import time
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from lab_tools import lab06_server as lab
from lab_tools.prepare_http_payloads import prepare
from validate_benign_http_capture import validate, validate_server_logs
from tests.test_benign_capture_validation import frame


class FakeClock:
    def __init__(self):
        self.time = 0.0
        self.pauses = []

    def now(self):
        return self.time

    def sleep(self, seconds):
        self.pauses.append(seconds)
        self.time += seconds


class Lab06Tests(unittest.TestCase):
    def setUp(self):
        root = Path(__file__).resolve().parents[1]
        (root / "tmp").mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=root / "tmp")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        prepare(self.root / "payloads")
        self.payload = self.root / "payloads/large_2m.bin"
        self.clock = FakeClock()
        self.server = SimpleNamespace(payload_path=self.payload, attempted_gets=0, successful_gets=0,
                                      events=io.StringIO(), copy_body=self.copy_body)

    def copy_body(self, source, out):
        return lab.paced_copy(source, out, sleep=self.clock.sleep, clock=self.clock.now)

    def handler(self, method="GET", path=lab.DATA_PATH, client=lab.CLIENT, output=None):
        handler = object.__new__(lab.Lab06Handler)
        handler.server = self.server
        handler.client_address = (client, 50000)
        handler.command = method
        handler.path = path
        handler.request_version = "HTTP/1.0"
        handler.requestline = f"{method} {path} HTTP/1.0"
        handler.wfile = output if output is not None else io.BytesIO()
        getattr(handler, "do_" + method)()
        return handler.wfile

    def test_pacing_has_128_writes_and_127_real_scheduled_pauses(self):
        out = io.BytesIO()
        with self.payload.open("rb") as source:
            result = self.copy_body(source, out)
        self.assertEqual(result["body_bytes_written"], 2097152)
        self.assertEqual(result["chunks_written"], 128)
        self.assertEqual(self.clock.pauses, [0.125] * 127)
        self.assertEqual(result["duration_seconds"], 15.875)
        self.assertEqual(out.getvalue(), self.payload.read_bytes())
        self.assertEqual(result["chunk_events"][-1]["body_bytes_cumulative"], 2097152)

    def test_head_is_bodyless_and_does_not_consume_get_budget(self):
        wire = self.handler("HEAD").getvalue()
        head, _, body = wire.partition(b"\r\n\r\n")
        self.assertIn(b"X-TCC-Pacing: server-128k-v1", head)
        self.assertIn(b"Content-Length: 2097152", head)
        self.assertEqual(body, b"")
        self.assertEqual(self.server.attempted_gets, 0)
        self.assertEqual(self.clock.pauses, [])

    def test_get_sends_same_body_with_marker_and_stops_after_six(self):
        for _ in range(6):
            head, _, body = self.handler().getvalue().partition(b"\r\n\r\n")
            self.assertTrue(head.startswith(b"HTTP/1.0 200"))
            self.assertEqual(hashlib.sha256(body).hexdigest(), lab.BODY_SHA256)
        self.assertEqual(self.server.successful_gets, 6)
        self.assertTrue(self.handler().getvalue().startswith(b"HTTP/1.0 429"))
        self.assertEqual(self.server.attempted_gets, 6)

    def test_does_not_serve_other_clients_or_paths(self):
        self.assertTrue(self.handler(client="192.168.1.20").getvalue().startswith(b"HTTP/1.0 403"))
        self.assertTrue(self.handler(path="/../secret.txt").getvalue().startswith(b"HTTP/1.0 404"))
        self.assertEqual(self.server.attempted_gets, 0)

    def test_rejects_wrong_payload_before_serving(self):
        wrong = self.root / "wrong.bin"
        wrong.write_bytes(b"X" * lab.BODY_BYTES)
        with self.assertRaisesRegex(ValueError, "Hash"):
            lab.verify_payload(wrong)

    def test_broken_transfer_is_logged_as_failure(self):
        class BrokenOutput(io.BytesIO):
            def write(self, value):
                if value.startswith(b"TCC2026-"):
                    raise BrokenPipeError("client disconnected")
                return super().write(value)
        self.handler(output=BrokenOutput())
        row = json.loads(self.server.events.getvalue().splitlines()[-1])
        self.assertFalse(row["success"])
        self.assertIn("disconnected", row["error"])
        self.assertEqual(self.server.successful_gets, 0)

    def test_server_receipt_validates_and_rejects_missing_pauses(self):
        manifest, log = self.server_receipts()
        self.assertTrue(validate_server_logs(manifest, log)["server_write_pacing_trace_validated"])
        rows = [json.loads(line) for line in log.read_text().splitlines()]
        rows[0]["chunk_events"][-1]["elapsed_seconds"] = 0
        log.write_text("\n".join(json.dumps(row) for row in rows))
        with self.assertRaisesRegex(ValueError, "Trace"):
            validate_server_logs(manifest, log)

    def server_receipts(self):
        for _ in range(6):
            self.handler()
        manifest = self.root / "server_manifest.json"
        log = self.root / "server_requests.jsonl"
        manifest.write_text(json.dumps({"status": "stopped", "attempted_gets": 6, "successful_gets": 6,
                                       "plan": lab.plan(),
                                       "server_script_sha256": hashlib.sha256(Path(lab.__file__).read_bytes()).hexdigest()}))
        log.write_text(self.server.events.getvalue())
        return manifest, log

    def capture_fixture(self, *, paced=True, marker=True):
        manifest, server_requests = self.server_receipts()
        body = self.payload.read_bytes()
        request = b"GET /benign-v1/large_2m.bin HTTP/1.0\r\n\r\n"
        head = b"HTTP/1.0 200 OK\r\nContent-Length: 2097152\r\n"
        if marker:
            head += b"X-TCC-Pacing: server-128k-v1\r\n"
        head += b"\r\n"
        raw = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        logs = []
        for index in range(6):
            sec, port = 1770000000 + 20 * index, 28000 + index
            cs, ss = 101 + len(request), 201 + len(head) + len(body)
            pieces = [
                (0, frame(lab.CLIENT, lab.BIND, port, 8000, 100, 0, 2)),
                (100, frame(lab.BIND, lab.CLIENT, 8000, port, 200, 101, 18)),
                (200, frame(lab.CLIENT, lab.BIND, port, 8000, 101, 201, 16)),
                (300, frame(lab.CLIENT, lab.BIND, port, 8000, 101, 201, 24, request)),
                (400, frame(lab.BIND, lab.CLIENT, 8000, port, 201, cs, 24, head)),
            ]
            for chunk in range(128):
                offset = chunk * lab.CHUNK_BYTES
                tick = 500 + chunk * (125000 if paced else 100)
                pieces.append((tick, frame(lab.BIND, lab.CLIENT, 8000, port,
                                           201 + len(head) + offset, cs, 24,
                                           body[offset:offset + lab.CHUNK_BYTES])))
            end = pieces[-1][0]
            pieces.extend([
                (end + 100, frame(lab.BIND, lab.CLIENT, 8000, port, ss, cs, 17)),
                (end + 200, frame(lab.CLIENT, lab.BIND, port, 8000, cs, ss + 1, 16)),
                (end + 300, frame(lab.CLIENT, lab.BIND, port, 8000, cs, ss + 1, 17)),
                (end + 400, frame(lab.BIND, lab.CLIENT, 8000, port, ss + 1, cs + 1, 16)),
            ])
            for tick, packet in pieces:
                raw.extend(struct.pack("<IIII", sec + tick // 1000000, tick % 1000000, len(packet), len(packet)))
                raw.extend(packet)
            logs.append({"request_number": index + 1, "success": True, "error": None,
                         "curl_exit_code": 0, "http_status": 200, "body_bytes": lab.BODY_BYTES,
                         "url": f"http://{lab.BIND}:8000{lab.DATA_PATH}", "local_ip": lab.CLIENT,
                         "remote_ip": lab.BIND, "server_marker_verified": True,
                         "started_at_utc": lab.datetime.fromtimestamp(sec, lab.timezone.utc).isoformat(),
                         "completed_at_utc": lab.datetime.fromtimestamp(sec + 18, lab.timezone.utc).isoformat()})
        config = {"description": "lab06_serverpaced_r1", "interface": "hn2", "fam": "ip", "protocol": "TCP",
                  "host": lab.CLIENT, "port": "8000", "protocol_not": "0", "port_not": "0",
                  "snaplen": "65535", "count": "50000"}
        archive = self.root / "capture.zip"
        with zipfile.ZipFile(archive, "w") as z:
            z.writestr("capture.json", json.dumps(config))
            z.writestr("capture.pcap", raw)
        client = {"status": "completed", "attempted_requests": 6, "successful_requests": 6,
                  "definition": {"scenario": "lab06_serverpaced", "repetition": 1,
                                 "source_ip": lab.CLIENT, "target_ip": lab.BIND, "url": logs[0]["url"],
                                 "requests": 6, "expected_bytes_per_request": lab.BODY_BYTES,
                                 "expected_total_body_bytes": lab.BODY_BYTES * 6, "concurrency": 1,
                                 "http_version": "1.0", "redirects": False, "retries": 0,
                                 "pacing_location": "server", "maximum_transfer_rate": None,
                                 "required_server_marker": lab.MARKER}}
        client_path, requests_path = self.root / "client.json", self.root / "client.jsonl"
        client_path.write_text(json.dumps(client))
        requests_path.write_text("\n".join(json.dumps(row) for row in logs))
        return dict(archive=archive, client_manifest=client_path, requests=requests_path,
                    output_dir=self.root / "validated", scenario="lab06_serverpaced",
                    server_manifest=manifest, server_requests=server_requests)

    def test_complete_lab06_requires_pacing_in_actual_packet_times(self):
        report = validate(**self.capture_fixture())
        self.assertEqual(report["status"], "validated_for_exploratory_v4_extraction")
        self.assertTrue(report["server_pacing_observed_at_capture"])
        self.assertEqual(report["total_http_body_bytes"], 12582912)

    def test_slow_server_log_does_not_override_burst_observed_in_pcap(self):
        report = validate(**self.capture_fixture(paced=False))
        self.assertEqual(report["status"], "validated_http_but_server_pacing_not_observed")
        self.assertFalse(report["server_pacing_observed_at_capture"])

    def test_capture_without_server_marker_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "marcador HTTP"):
            validate(**self.capture_fixture(marker=False))

    def test_real_http_on_loopback_preserves_body_and_takes_at_least_15_seconds(self):
        # O unico teste com socket usa 127.0.0.1 e porta efemera, nunca a rede das VMs.
        with patch.object(lab, "CLIENT", "127.0.0.1"):
            with lab.HTTPServer(("127.0.0.1", 0), lab.Lab06Handler) as server:
                server.payload_path = self.payload
                server.attempted_gets = server.successful_gets = 0
                server.events = io.StringIO()
                server.copy_body = lab.paced_copy
                thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
                thread.start()
                connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=35)
                started = time.monotonic()
                try:
                    connection.request("GET", lab.DATA_PATH)
                    response = connection.getresponse()
                    self.assertEqual(response.status, 200)
                    self.assertEqual(response.getheader("X-TCC-Pacing"), lab.MARKER)
                    body = response.read()
                    elapsed = time.monotonic() - started
                finally:
                    connection.close()
                    server.shutdown()
                    thread.join(timeout=5)
                self.assertGreaterEqual(elapsed, 15.5)
                self.assertLess(elapsed, 35)
                self.assertEqual(hashlib.sha256(body).hexdigest(), lab.BODY_SHA256)
                self.assertEqual(server.successful_gets, 1)
                self.assertEqual(json.loads(server.events.getvalue())["chunks_written"], 128)

    @unittest.skipUnless(shutil.which("powershell.exe"), "Requer Windows PowerShell")
    def test_windows_client_without_rate_limit_requires_marker_and_stops_on_failure(self):
        root = Path(__file__).resolve().parents[1]
        result = subprocess.run([shutil.which("powershell.exe"), "-NoProfile", "-ExecutionPolicy", "Bypass",
                                 "-File", str(root / "tests/test_lab06_client.ps1"),
                                 "-OutputRoot", str(self.root / "client")],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("mocked requests only", result.stdout)


if __name__ == "__main__":
    unittest.main()
