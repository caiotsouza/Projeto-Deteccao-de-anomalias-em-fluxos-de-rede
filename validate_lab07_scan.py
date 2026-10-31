"""Preserva e audita o piloto LAB07 offline; nao executa Nmap ou modelos."""
from __future__ import annotations

import argparse
import json
import re
import shlex
import shutil
import socket
import stat
import struct
import xml.etree.ElementTree as ET
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from src.lab_flow_audit import audit_pcap, sha256

SOURCE = "172.31.60.10"
TARGET = "172.31.50.161"
PORTS = {21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3389, 5985, 8000, 8080}


def expand_ports(value: str) -> set[int]:
    result = []
    for token in value.split(","):
        if not re.fullmatch(r"\d+(?:-\d+)?", token):
            raise ValueError("Lista de portas invalida.")
        ends = list(map(int, token.split("-")))
        low, high = ends[0], ends[-1]
        if not 1 <= low <= high <= 65535 or high - low > 16:
            raise ValueError("Intervalo de portas fora do piloto.")
        result.extend(range(low, high + 1))
    if not result or len(result) > 16 or len(set(result)) != len(result) or not set(result) <= PORTS:
        raise ValueError("Portas fora do escopo ou repetidas.")
    return set(result)


def parse_scanner(xml: bytes, normal: str, grepable: str, *, profile: str = "pilot") -> dict:
    if len(xml) > 1024 * 1024 or b"<!ENTITY" in xml.upper() or re.search(rb"<!DOCTYPE[^>]*(?:SYSTEM|PUBLIC)", xml, re.I):
        raise ValueError("XML excessivo ou com declaracao externa.")
    root = ET.fromstring(xml)
    if root.tag != "nmaprun" or root.get("scanner") != "nmap":
        raise ValueError("XML nao e uma execucao Nmap.")
    args = root.get("args", "")
    tokens = shlex.split(args)
    if not tokens or Path(tokens[0]).name != "nmap":
        raise ValueError("Comando difere da estrutura delimitada.")
    expected = {1: "-n", 2: "-Pn", 3: "-sT", 4: "-p", 6: "--max-rate", 7: "10",
                8: "--scan-delay", 9: "100ms", 10: "--max-retries", 11: "1",
                12: "--host-timeout", 13: "120s", 14: "-oA", 15: "/tmp/lab07-r1/scan",
                16: TARGET}
    planned = PORTS
    token_count = 17
    if profile == "diag135_r2":
        expected = {1: "-n", 2: "-Pn", 3: "-sT", 4: "-p", 6: "--max-rate", 7: "1",
                    8: "--max-retries", 9: "0", 10: "--host-timeout", 11: "20s",
                    12: "-oA", 13: "/tmp/lab07-diag135-r2/scan", 14: TARGET}
        planned, token_count = {135}, 15
    elif profile == "lab08_r1":
        expected[15] = "/tmp/lab08-r1/scan"
    elif profile != "pilot":
        raise ValueError("Perfil do scanner desconhecido.")
    # Perfis fechados, definidos pelo codigo local; nunca executar os argumentos.
    if len(tokens) != token_count:
        raise ValueError("Quantidade de argumentos inesperada.")
    if any(tokens[i] != value for i, value in expected.items()):
        raise ValueError("Parametros ou alvo fora do plano.")
    selected = expand_ports(tokens[5])
    if not selected <= planned:
        raise ValueError("Porta fora do perfil solicitado.")
    if profile == "lab08_r1" and selected != planned:
        raise ValueError("LAB08 exige as 16 portas planejadas.")
    info = root.find("scaninfo")
    hosts = root.findall("host")
    finished = root.find("runstats/finished")
    if (info is None or info.get("type") != "connect" or info.get("protocol") != "tcp"
            or int(info.get("numservices", "0")) != len(selected)
            or expand_ports(info.get("services", "")) != selected
            or len(hosts) != 1 or finished is None or finished.get("exit") != "success"):
        raise ValueError("Tipo, portas, quantidade de alvos ou encerramento inesperados.")
    addresses = hosts[0].findall("address")
    if len(addresses) != 1 or addresses[0].get("addr") != TARGET or addresses[0].get("addrtype") != "ipv4":
        raise ValueError("Endereco de destino divergente.")
    states = {}
    for port in hosts[0].findall("ports/port"):
        number = int(port.get("portid", "0"))
        state = port.find("state")
        if number in states or number not in selected or port.get("protocol") != "tcp" or state is None:
            raise ValueError("Portas/resultados XML inconsistentes.")
        states[number] = {"state": state.get("state"), "reason": state.get("reason")}
    if set(states) != selected:
        raise ValueError("Resultado incompleto por porta.")
    expected_states = {p: row["state"] for p, row in states.items()}
    for text, pattern in ((normal, r"^(\d+)/tcp\s+(\S+)"), (grepable, r"(\d+)/([^/]+)/tcp/")):
        if not text.strip():
            raise ValueError("Log do scanner vazio.")
        if len(text) > 1024 * 1024 or {int(p): s for p, s in re.findall(pattern, text, re.M)} != expected_states:
            raise ValueError("Os formatos de resultado divergem.")
        if " as: " not in text.splitlines()[0] or text.splitlines()[0].split(" as: ", 1)[1] != args:
            raise ValueError("Comando dos arquivos de texto diverge do XML.")
    status = hosts[0].find("status")
    return {"args": args, "nmap_version": root.get("version"), "scan_type": "connect",
            "target": TARGET, "actual_ports": sorted(selected), "planned_ports": sorted(planned),
            "missing_planned_ports": sorted(planned - selected), "unexpected_ports": [],
            "port_results": {str(p): row for p, row in sorted(states.items())},
            "host_status_reason": status.get("reason") if status is not None else None,
            "host_reachability_proven_by_scanner_status": False,
            "start_epoch_seconds": int(root.get("start", "0")),
            "finish_epoch_seconds": int(finished.get("time", "0")),
            "scanner_elapsed_seconds": float(finished.get("elapsed", "nan"))}


def scan_packets(path: Path, scanner: dict) -> dict:
    independent = audit_pcap(path)  # Valida cabecalhos, truncamentos e ordem antes da leitura abaixo.
    data = path.read_bytes()
    endian = "<" if data[:4] == b"\xd4\xc3\xb2\xa1" else ">"
    offset, packets = 24, []
    while offset < len(data):
        sec, usec, captured, _ = struct.unpack_from(endian + "IIII", data, offset)
        offset += 16
        ip = data[offset + 14:offset + captured]
        offset += captured
        ihl, total = (ip[0] & 15) * 4, int.from_bytes(ip[2:4], "big")
        tcp = ip[ihl:total]
        source, dest = socket.inet_ntoa(ip[12:16]), socket.inet_ntoa(ip[16:20])
        sport, dport = struct.unpack_from("!HH", tcp)
        if (source, dest) == (SOURCE, TARGET):
            direction, target_port = "kali_to_windows", dport
        elif (source, dest) == (TARGET, SOURCE):
            direction, target_port = "windows_to_kali", sport
        else:
            raise ValueError("Pacotes fora dos endpoints do piloto.")
        if target_port not in scanner["actual_ports"]:
            raise ValueError("PCAP contem porta fora do comando executado.")
        timestamp = sec + usec / 1e6
        if not scanner["start_epoch_seconds"] - 1 <= timestamp <= scanner["finish_epoch_seconds"] + 1:
            raise ValueError("PCAP fora da janela Nmap (tolerancia 1 s para timestamps inteiros).")
        packets.append({"time_us": sec * 1000000 + usec, "direction": direction,
                        "target_port": target_port, "flags": tcp[13], "source_port": sport,
                        "payload_bytes": len(tcp) - (tcp[12] >> 4) * 4})
    observed = {p["target_port"] for p in packets}
    if observed != set(scanner["actual_ports"]):
        raise ValueError("Nem todas as portas executadas aparecem na captura.")
    return {"packets": len(packets), "direction_counts": dict(Counter(p["direction"] for p in packets)),
            "tcp_flags_counts": dict(Counter(str(p["flags"]) for p in packets)),
            "packets_by_target_port": dict(sorted(Counter(p["target_port"] for p in packets).items())),
            "payload_bytes": sum(p["payload_bytes"] for p in packets),
            "endpoint_groups": independent["endpoint_groups"],
            "first_packet_utc": datetime.fromtimestamp(packets[0]["time_us"] / 1e6, timezone.utc).isoformat(),
            "last_packet_utc": datetime.fromtimestamp(packets[-1]["time_us"] / 1e6, timezone.utc).isoformat(),
            "capture_span_seconds": (packets[-1]["time_us"] - packets[0]["time_us"]) / 1e6,
            "reverse_packets_observed": any(p["direction"] == "windows_to_kali" for p in packets),
            "capture_drop_counter_available": False, "truncated_packet_records": 0}


def validate(archive: Path, normal: Path, grepable: Path, xml: Path, output: Path,
             *, profile: str = "pilot") -> dict:
    if profile not in ("pilot", "lab08_r1"):
        raise ValueError("Perfil de importacao desconhecido.")
    if output.exists():
        raise FileExistsError("Use uma pasta nova para preservar tentativas.")
    sources = [archive, normal, grepable, xml]
    before = {str(p.resolve()): sha256(p) for p in sources}
    scanner = parse_scanner(xml.read_bytes(), normal.read_text(encoding="utf-8-sig"),
                           grepable.read_text(encoding="utf-8-sig"), profile=profile)
    with zipfile.ZipFile(archive) as z:
        entries = z.infolist()
        if len(entries) != 2 or any(e.is_dir() or e.file_size > 128 * 1024 * 1024
                                   or Path(e.filename).name != e.filename or "/" in e.filename or "\\" in e.filename
                                   or stat.S_ISLNK(e.external_attr >> 16) for e in entries):
            raise ValueError("ZIP inseguro ou fora do contrato.")
        pcaps = [e for e in entries if e.filename.endswith(".pcap")]
        configs = [e for e in entries if e.filename.endswith(".json")]
        if len(pcaps) != 1 or len(configs) != 1 or z.testzip() is not None:
            raise ValueError("ZIP deve conter um PCAP e um JSON com CRC valido.")
        config = json.loads(z.read(configs[0]).decode("utf-8-sig"))
        expected = {"description": "lab07_tcp_connect_r1", "interface": "hn2", "fam": "ip",
                    "protocol": "TCP", "host": TARGET, "port": "", "snaplen": "65535", "count": "10000",
                    "promiscuous": "0", "protocol_not": "0", "port_not": "0"}
        if profile == "lab08_r1":
            expected["description"] = "lab08_tcp_responsive_r1"
        if any(config.get(k) != value for k, value in expected.items()):
            raise ValueError("Configuracao da captura difere do LAB07.")
        output.mkdir(parents=True)
        (output / "input").mkdir()
        (output / "scanner_logs").mkdir()
        for source in sources:
            dest = output / ("input" if source == archive else "scanner_logs") / source.name
            shutil.copyfile(source, dest)
            if sha256(dest) != before[str(source.resolve())]:
                raise ValueError("Copia diverge do hash de recepcao.")
        for entry in entries:
            with (output / "input" / entry.filename).open("xb") as stream:
                stream.write(z.read(entry))
    pcap = output / "input" / pcaps[0].filename
    capture = scan_packets(pcap, scanner)
    if before != {str(p.resolve()): sha256(p) for p in sources}:
        raise ValueError("Fontes mudaram durante a importacao.")
    result = {"status": "captured_scan_with_plan_deviation" if scanner["missing_planned_ports"] else "captured_scan_scope_validated",
              "scenario": "lab08_tcp_responsive_r1" if profile == "lab08_r1" else "lab07_tcp_connect_r1",
              "scanner": scanner, "capture": capture,
              "source_sha256": before, "pcap": str(pcap.resolve()), "pcap_sha256": sha256(pcap),
              "source_files_unchanged_at_import": True, "saved_copies_match_import_hashes": True,
              "planned_activity": "port_scan", "ground_truth_labels_generated": False,
              "windows_reachability_established": False, "filtering_location_established": False,
              "models_loaded": False, "database_written": False,
              "limitations": ["hn2 observations do not establish filtering location for unresponsive ports.",
                              "-Pn host status is user-set, not a host response.",
                              "Services named by port tables do not prove services are installed.",
                              "Missing planned ports are preserved, not silently repaired."]}
    with (output / "scan_validation.json").open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, ensure_ascii=False, allow_nan=False)
        stream.write("\n")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for arg in ("archive", "normal", "grepable", "xml", "output"):
        parser.add_argument("--" + arg, type=Path, required=True)
    parser.add_argument("--profile", choices=("pilot", "lab08_r1"), default="pilot")
    result = validate(**vars(parser.parse_args()))
    print(json.dumps({k: result[k] for k in ("status", "scanner", "capture")}, indent=2))
