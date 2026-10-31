"""Preserva e valida evidencias dos downloads HTTP controlados, sem inferencia."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import shutil
import socket
import statistics
import struct
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from src.lab_flow_audit import audit_pcap, sha256


PLANS = {"lab03_small": ("small_16k.bin", 16384, 30),
         "lab04_medium": ("medium_256k.bin", 262144, 12),
         "lab05_slow": ("large_2m.bin", 2097152, 6),
         "lab06_serverpaced": ("large_2m.bin", 2097152, 6)}
CLIENT = "172.31.50.161"
SERVER = "172.31.60.10"


def tcp_groups(path: Path) -> list[list[dict]]:
    """Le somente a captura ja aceita por audit_pcap; nao e extrator de features."""
    data = path.read_bytes()
    endian = "<" if data[:4] == b"\xd4\xc3\xb2\xa1" else ">"
    position, groups = 24, {}
    while position < len(data):
        sec, usec, captured, _ = struct.unpack_from(endian + "IIII", data, position)
        position += 16
        ip = data[position + 14:position + captured]
        position += captured
        ihl, total = (ip[0] & 15) * 4, int.from_bytes(ip[2:4], "big")
        tcp = ip[ihl:total]
        src = (socket.inet_ntoa(ip[12:16]), int.from_bytes(tcp[:2], "big"))
        dst = (socket.inet_ntoa(ip[16:20]), int.from_bytes(tcp[2:4], "big"))
        if {src[0], dst[0]} != {CLIENT, SERVER} or (SERVER, 8000) not in (src, dst):
            raise ValueError("Pacote fora dos endpoints/porta planejados.")
        packet = {"time_us": sec * 1_000_000 + usec, "src": src, "dst": dst,
                  "seq": int.from_bytes(tcp[4:8], "big"), "ack": int.from_bytes(tcp[8:12], "big"),
                  "flags": tcp[13], "payload": tcp[(tcp[12] >> 4) * 4:]}
        groups.setdefault(tuple(sorted((src, dst))), []).append(packet)
    return sorted(groups.values(), key=lambda group: group[0]["time_us"])


def reassemble(group: list[dict], endpoint: tuple) -> tuple[bytes, int]:
    """Reconstroi bytes em ordem de sequencia; valida sobreposicoes e lacunas."""
    syns = [p for p in group if p["src"] == endpoint and p["flags"] & 2]
    if len(syns) != 1:
        raise ValueError("Este ensaio exige um SYN por direcao e 5-tupla sem reutilizacao.")
    origin = (syns[0]["seq"] + 1) & 0xFFFFFFFF
    segments = sorted((((p["seq"] - origin) & 0xFFFFFFFF), p["payload"])
                      for p in group if p["src"] == endpoint and p["payload"])
    assembled, duplicates = bytearray(), 0
    for offset, payload in segments:
        if offset > len(assembled):
            raise ValueError("Lacuna de bytes TCP: captura incompleta ou formato fora do ensaio.")
        overlap = min(len(payload), len(assembled) - offset)
        if assembled[offset:offset + overlap] != payload[:overlap]:
            raise ValueError("Sobreposicao TCP com bytes conflitantes.")
        duplicates += overlap
        assembled.extend(payload[overlap:])
    return bytes(assembled), duplicates


def validate_server_logs(manifest_path: Path, requests_path: Path) -> dict:
    """Confere configuracao e eventos do servidor, sem executar codigo recebido."""
    from lab_tools import lab06_server as profile

    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    rows = [json.loads(line) for line in requests_path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]
    if (manifest.get("status") != "stopped" or manifest.get("attempted_gets") != 6
            or manifest.get("successful_gets") != 6 or manifest.get("plan") != profile.plan()
            or manifest.get("server_script_sha256") != sha256(Path(profile.__file__))):
        raise ValueError("Identidade, plano ou encerramento do servidor LAB06 diverge do perfil.")
    gets = [row for row in rows if row["method"] == "GET"]
    if len(gets) != 6 or [p.get("get_attempt") for p in gets] != list(range(1, 7)):
        raise ValueError("Quantidade/sequencia dos GETs do servidor diverge.")
    for row in gets:
        if (row.get("success") is not True or row.get("status") != 200 or row.get("error") is not None
                or row.get("client_ip") != CLIENT or row.get("path") != profile.DATA_PATH
                or row.get("pacing_marker") != profile.MARKER
                or row.get("body_bytes_written") != 2097152 or row.get("chunks_written") != 128):
            raise ValueError("Um GET do servidor nao corresponde ao LAB06.")
        events = row.get("chunk_events", [])
        if len(events) != 128:
            raise ValueError("Trace de blocos do servidor incompleto.")
        times = [p["elapsed_seconds"] for p in events]
        if (not all(math.isfinite(t) and t >= 0 for t in times)
                or times[-1] - times[0] < 12
                or any(b - a < 0.10 for a, b in zip(times, times[1:]))
                or any(p["chunk"] != i or p["body_bytes_cumulative"] != i * 16384
                       for i, p in enumerate(events, 1))):
            raise ValueError("Trace nao demonstra as pausas/blocos esperados no servidor.")
    return {"server_script_sha256": manifest["server_script_sha256"], "successful_gets": 6,
            "chunks_per_get": 128, "server_write_pacing_trace_validated": True,
            "clock_note": "Server elapsed times are not assumed synchronized to capture timestamps."}


def validate(*, archive: Path, client_manifest: Path, requests: Path,
             output_dir: Path, scenario: str, repetition: int = 1,
             server_manifest: Path | None = None, server_requests: Path | None = None) -> dict:
    if output_dir.exists():
        raise FileExistsError("A pasta da sessao deve ser nova para nao sobrescrever evidencias.")
    filename, body_size, count = PLANS[scenario]
    sources = [archive, client_manifest, requests]
    server_evidence = None
    if scenario == "lab06_serverpaced":
        if server_manifest is None or server_requests is None:
            raise ValueError("LAB06 exige --server-manifest e --server-requests.")
        sources.extend((server_manifest, server_requests))
        server_evidence = validate_server_logs(server_manifest, server_requests)
    before = {str(p.resolve()): sha256(p) for p in sources}
    manifest = json.loads(client_manifest.read_text(encoding="utf-8-sig"))
    logs = [json.loads(line) for line in requests.read_text(encoding="utf-8-sig").splitlines() if line.strip()]
    definition = manifest["definition"]
    url = f"http://{SERVER}:8000/benign-v1/{filename}"
    expected = {"scenario": scenario, "repetition": repetition, "source_ip": CLIENT, "target_ip": SERVER,
                "url": url, "requests": count, "expected_bytes_per_request": body_size,
                "expected_total_body_bytes": count * body_size, "concurrency": 1, "http_version": "1.0",
                "redirects": False, "retries": 0}
    if any(definition.get(key) != value for key, value in expected.items()):
        raise ValueError("Plano do cliente difere do cenario solicitado.")
    if scenario == "lab06_serverpaced" and (
        definition.get("pacing_location") != "server" or definition.get("maximum_transfer_rate") is not None
        or definition.get("required_server_marker") != "server-128k-v1"
    ):
        raise ValueError("LAB06 deve usar pacing no servidor e nao limitar a leitura no cliente.")
    if manifest["status"] != "completed" or manifest["attempted_requests"] != count or manifest["successful_requests"] != count:
        raise ValueError("Sessao do cliente nao foi concluida integralmente.")
    if len(logs) != count or [p["request_number"] for p in logs] != list(range(1, count + 1)):
        raise ValueError("Numeracao ou quantidade de registros do cliente incorreta.")
    for row in logs:
        if (row["success"] is not True or row["error"] is not None or row["curl_exit_code"] != 0
                or row["http_status"] != 200 or row["body_bytes"] != body_size
                or row["url"] != url or row["local_ip"] != CLIENT or row["remote_ip"] != SERVER):
            raise ValueError("Uma tentativa do cliente difere do planejado.")
        if scenario == "lab06_serverpaced" and row.get("server_marker_verified") is not True:
            raise ValueError("Cliente nao confirmou o marcador do servidor LAB06.")
    with zipfile.ZipFile(archive) as source_zip:
        entries = source_zip.infolist()
        if len(entries) != 2 or any(p.is_dir() or Path(p.filename).name != p.filename
                                   or "/" in p.filename or "\\" in p.filename
                                   or p.file_size > 128 * 1024 * 1024 for p in entries):
            raise ValueError("ZIP deve conter apenas JSON e PCAP pequenos, sem subdiretorios.")
        pcaps = [p for p in entries if p.filename.endswith(".pcap")]
        configs = [p for p in entries if p.filename.endswith(".json")]
        if len(pcaps) != 1 or len(configs) != 1 or source_zip.testzip() is not None:
            raise ValueError("Conteudo/CRC do ZIP invalido.")
        config = json.loads(source_zip.read(configs[0]).decode("utf-8-sig"))
        if (config["description"] != f"{scenario}_r{repetition}" or config["interface"] != "hn2"
                or config["fam"] != "ip" or config["protocol"] != "TCP"
                or config["host"] != CLIENT or config["port"] != "8000"
                or config["protocol_not"] != "0" or config["port_not"] != "0"
                or int(config["snaplen"]) < 65535):
            raise ValueError("Filtro da captura difere do plano.")
        incoming, client = output_dir / "input", output_dir / "client_logs"
        incoming.mkdir(parents=True, exist_ok=False)
        client.mkdir()
        shutil.copy2(archive, incoming / archive.name)
        shutil.copy2(client_manifest, client / "run_manifest.json")
        shutil.copy2(requests, client / "requests.jsonl")
        if server_evidence is not None:
            server_dir = output_dir / "server_logs"
            server_dir.mkdir()
            shutil.copy2(server_manifest, server_dir / "server_manifest.json")
            shutil.copy2(server_requests, server_dir / "server_requests.jsonl")
        for entry in entries:
            with (incoming / entry.filename).open("xb") as target:
                target.write(source_zip.read(entry))
        pcap = incoming / pcaps[0].filename
    independent = audit_pcap(pcap)
    if int(config["count"]) and independent["packets"] >= int(config["count"]):
        raise ValueError("A captura atingiu o teto de pacotes; conferir possivel corte.")
    groups = tcp_groups(pcap)
    if len(groups) != count:
        raise ValueError("Quantidade de conexoes TCP nao corresponde aos logs.")
    pattern = b"TCC2026-BENIGN-HTTP-DATA\n"
    expected_body = (pattern * ((body_size + len(pattern) - 1) // len(pattern)))[:body_size]
    details = []
    for group, log in zip(groups, logs):
        first = group[0]
        if first["src"][0] != CLIENT or first["flags"] & 0x12 != 2 or any(p["flags"] & 4 for p in group):
            raise ValueError("Inicio TCP inesperado ou reset observado.")
        source, destination = first["src"], first["dst"]
        synack = [p for p in group if p["src"] == destination and p["flags"] & 0x12 == 0x12]
        if len(synack) != 1 or synack[0]["ack"] != (first["seq"] + 1) & 0xFFFFFFFF:
            raise ValueError("Handshake SYN/SYN-ACK nao confirmado.")
        if not any(p["src"] == source and p["flags"] & 16 and
                   p["ack"] == (synack[0]["seq"] + 1) & 0xFFFFFFFF for p in group):
            raise ValueError("ACK do handshake nao observado.")
        for endpoint in (source, destination):
            fins = [p for p in group if p["src"] == endpoint and p["flags"] & 1]
            if not fins or not any(p["dst"] == endpoint and p["flags"] & 16 and
                                  p["ack"] == (fins[-1]["seq"] + len(fins[-1]["payload"]) + 1) & 0xFFFFFFFF
                                  for p in group):
                raise ValueError("FIN e respectivo ACK nao confirmados nas duas direcoes.")
        request_stream, duplicate_request = reassemble(group, source)
        response_stream, duplicate_response = reassemble(group, destination)
        expected_request = f"GET /benign-v1/{filename} HTTP/1.0".encode()
        request_head, request_separator, request_body = request_stream.partition(b"\r\n\r\n")
        head, separator, body = response_stream.partition(b"\r\n\r\n")
        if request_head.split(b"\r\n")[0] != expected_request or not request_separator or request_body:
            raise ValueError("Requisicao HTTP inesperada.")
        headers = {k.lower(): v.strip() for line in head.split(b"\r\n")[1:]
                   for k, _, v in [line.partition(b":")]}
        if (not separator or head.split(b"\r\n")[0].split()[:2] != [b"HTTP/1.0", b"200"]
                or headers.get(b"content-length") != str(body_size).encode() or body != expected_body):
            raise ValueError("Resposta HTTP, tamanho ou conteudo do corpo diverge.")
        if scenario == "lab06_serverpaced" and headers.get(b"x-tcc-pacing") != b"server-128k-v1":
            raise ValueError("O PCAP nao contem o marcador HTTP do servidor LAB06.")
        server_payload = [p for p in group if p["src"] == destination and p["payload"]]
        payload_span = (server_payload[-1]["time_us"] - server_payload[0]["time_us"]) / 1e6
        start = datetime.fromtimestamp(first["time_us"] / 1e6, timezone.utc)
        log_start = datetime.fromisoformat(log["started_at_utc"].replace("Z", "+00:00"))
        log_end = datetime.fromisoformat(log["completed_at_utc"].replace("Z", "+00:00"))
        if not -0.25 <= (start - log_start).total_seconds() or (start - log_end).total_seconds() > 0.25:
            raise ValueError("Horario inicial da conexao nao se alinha ao log (tolerancia 250ms).")
        details.append({"request_number": log["request_number"], "source_port": source[1],
                        "packets": len(group), "started_at_utc": start.isoformat(),
                        "http_status": 200, "body_bytes": len(body),
                        "body_sha256": hashlib.sha256(body).hexdigest(),
                        "server_payload_span_seconds": payload_span,
                        "duplicate_payload_bytes": duplicate_request + duplicate_response,
                        "handshake_and_bidirectional_close_observed": True})
    starts = [group[0]["time_us"] / 1e6 for group in groups]
    intervals = [b - a for a, b in zip(starts, starts[1:])]
    after = {str(p.resolve()): sha256(p) for p in sources}
    if after != before:
        raise ValueError("Arquivo de origem mudou durante a validacao.")
    report = {"status": "validated_for_exploratory_v4_extraction", "scenario": scenario,
              "repetition": repetition, "source_files_unchanged": True, "source_sha256": before,
              "pcap_sha256": independent["sha256"], "packets": independent["packets"],
              "connections": count, "successful_http_responses": count,
              "total_http_body_bytes": body_size * count, "truncated_packet_records": 0,
              "tcp_rst_packets": 0, "capture_drop_counter_available": False,
              "capture_span_seconds": (groups[-1][-1]["time_us"] - groups[0][0]["time_us"]) / 1e6,
              "connection_start_interval_seconds": {"min": min(intervals), "median": statistics.median(intervals),
                                                     "max": max(intervals)},
              "details": details, "pcap": str(pcap.resolve()),
              "limitations": ["Only filtered traffic was examined; no claim about all VM traffic.",
                              "No packet-drop counter was supplied; do not claim zero capture drops.",
                              "Parser restricted to one HTTP/1.0 GET per distinct TCP 5-tuple.",
                              "Planned activity does not create independent ground-truth labels."]}
    if server_evidence is not None:
        report["server_evidence"] = server_evidence
        observed = all(row["server_payload_span_seconds"] >= 12.0 for row in details)
        report["server_pacing_observed_at_capture"] = observed
        report["minimum_required_payload_span_seconds"] = 12.0
        if not observed:
            report["status"] = "validated_http_but_server_pacing_not_observed"
    with (output_dir / "capture_validation.json").open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, allow_nan=False)
        stream.write("\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("archive", "client-manifest", "requests", "output-dir"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--scenario", choices=PLANS, required=True)
    parser.add_argument("--repetition", type=int, default=1)
    parser.add_argument("--server-manifest", type=Path)
    parser.add_argument("--server-requests", type=Path)
    result = validate(**vars(parser.parse_args()))
    print(json.dumps({key: result[key] for key in ("status", "packets", "connections", "total_http_body_bytes",
                                                   "capture_span_seconds", "connection_start_interval_seconds")}, indent=2))
