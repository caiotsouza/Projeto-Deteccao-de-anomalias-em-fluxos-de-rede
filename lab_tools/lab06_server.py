"""LAB06: unico payload sintetico, HTTP/1.0, pausas no envio pelo servidor.

Somente biblioteca padrao. Nao e servidor de producao. Nao altera a rede.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


BIND = "172.31.60.10"
CLIENT = "172.31.50.161"
PORT = 8000
DATA_PATH = "/benign-v1/large_2m.bin"
BODY_BYTES = 2 * 1024 * 1024
BODY_SHA256 = "21ad43464ff341f863b1149c5a11d95fb8a325bb44ad51ed4afc17979ad44245"
CHUNK_BYTES = 16384
PAUSE_SECONDS = 0.125
MARKER = "server-128k-v1"
MAX_GETS = 6


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def verify_payload(path: Path):
    if not path.is_file() or path.stat().st_size != BODY_BYTES:
        raise ValueError("O payload precisa ser o arquivo sintetico de 2 MiB preparado anteriormente.")
    if hashlib.sha256(path.read_bytes()).hexdigest() != BODY_SHA256:
        raise ValueError("Hash inesperado: nao sera servido um arquivo pessoal ou diferente do sintetico.")


def paced_copy(source, output, *, sleep=time.sleep, clock=time.monotonic):
    """Nao compensa atrasos com rajadas: pausa antes de cada bloco apos o primeiro."""
    started, events = clock(), []
    sent = 0
    while chunk := source.read(CHUNK_BYTES):
        if events:
            sleep(PAUSE_SECONDS)
        written = output.write(chunk)
        if written is not None and written != len(chunk):
            raise OSError("Escrita parcial do bloco HTTP.")
        output.flush()
        sent += len(chunk)
        events.append({"chunk": len(events) + 1, "elapsed_seconds": clock() - started,
                       "body_bytes_cumulative": sent})
    return {"body_bytes_written": sent, "chunks_written": len(events),
            "duration_seconds": clock() - started, "chunk_events": events}


class Lab06Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    server_version = "TCCLab06/1"
    sys_version = ""

    def log_message(self, *_):
        pass

    def do_HEAD(self):
        self._serve(head_only=True)

    def do_GET(self):
        self._serve(head_only=False)

    def _serve(self, *, head_only):
        self.close_connection = True
        row = {"method": self.command, "path": self.path, "client_ip": self.client_address[0],
               "started_at_utc": utc_now(), "pacing_marker": MARKER,
               "success": False, "status": None, "error": None}
        try:
            if self.client_address[0] != CLIENT:
                row["status"] = 403
                self.send_error(403, "Only Windows-LAB is allowed")
                return
            if self.path != DATA_PATH:
                row["status"] = 404
                self.send_error(404, "Only the synthetic LAB06 payload is served")
                return
            if not head_only:
                if self.server.attempted_gets >= MAX_GETS:
                    row["status"] = 429
                    self.send_error(429, "Six GET attempts reached; start a separate session")
                    return
                self.server.attempted_gets += 1
                row["get_attempt"] = self.server.attempted_gets
            verify_payload(self.server.payload_path)
            row["status"] = 200
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(BODY_BYTES))
            self.send_header("Connection", "close")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-TCC-Pacing", MARKER)
            self.send_header("X-TCC-Chunk-Bytes", str(CHUNK_BYTES))
            self.send_header("X-TCC-Pause-Seconds", str(PAUSE_SECONDS))
            self.end_headers()
            if not head_only:
                with self.server.payload_path.open("rb") as source:
                    row.update(self.server.copy_body(source, self.wfile))
                if row["body_bytes_written"] != BODY_BYTES:
                    raise OSError("Quantidade de bytes enviada difere do payload.")
                self.server.successful_gets += 1
            row["success"] = True
        except (OSError, ValueError) as exc:
            row["error"] = str(exc)
        finally:
            row["completed_at_utc"] = utc_now()
            self.server.events.write(json.dumps(row, allow_nan=False) + "\n")
            self.server.events.flush()


def plan():
    return {"scenario": "lab06_serverpaced", "bind": BIND, "port": PORT,
            "allowed_client": CLIENT, "path": DATA_PATH, "http_version": "1.0",
            "body_bytes": BODY_BYTES, "body_sha256": BODY_SHA256,
            "chunk_bytes": CHUNK_BYTES, "pause_between_chunks_seconds": PAUSE_SECONDS,
            "expected_chunks": BODY_BYTES // CHUNK_BYTES,
            "nominal_first_to_last_chunk_seconds": (BODY_BYTES // CHUNK_BYTES - 1) * PAUSE_SECONDS,
            "maximum_get_attempts": MAX_GETS, "pacing_location": "server",
            "required_client_marker": MARKER, "ground_truth_labels_generated": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--payload", type=Path, default=Path("/lab-http/benign-v1/large_2m.bin"))
    parser.add_argument("--log-dir", type=Path, default=Path("/tmp/lab06-r1"))
    parser.add_argument("--describe", action="store_true")
    args = parser.parse_args()
    if args.describe:
        print(json.dumps(plan(), indent=2))
        return
    verify_payload(args.payload)
    if args.log_dir.exists():
        raise FileExistsError("Use uma pasta de logs nova: nao sobrescreva sessoes anteriores.")
    # Vincula a porta antes de criar logs. Se ocupada, encerra sem trocar o servidor.
    with HTTPServer((BIND, PORT), Lab06Handler) as server:
        args.log_dir.mkdir(parents=True, exist_ok=False)
        server.payload_path = args.payload
        server.attempted_gets = server.successful_gets = 0
        server.copy_body = paced_copy
        manifest = {"started_at_utc": utc_now(), "plan": plan(), "python": platform.python_version(),
                    "server_script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                    "status": "ready", "payload_verified": True}
        manifest_path = args.log_dir / "server_manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        with (args.log_dir / "server_requests.jsonl").open("x", encoding="utf-8") as server.events:
            print(f"LAB06 pronto: http://{BIND}:{PORT}{DATA_PATH}", flush=True)
            print(f"Somente {CLIENT}; 16 KiB por bloco, pausa 0.125 s; maximo 6 GETs.", flush=True)
            print(f"Logs: {args.log_dir}; Ctrl+C encerra apos a coleta.", flush=True)
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
            finally:
                manifest.update(status="stopped", completed_at_utc=utc_now(),
                                attempted_gets=server.attempted_gets, successful_gets=server.successful_gets)
                manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
