"""Preserva evidencias do diagnostico de uma porta, sem sondagens ou inferencia."""
import argparse
import json
import re
import shutil
import stat
import struct
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from validate_lab07_scan import SOURCE, TARGET, parse_scanner, scan_packets
from src.lab_flow_audit import sha256


def decode_windows_text(raw: bytes) -> str:
    return raw.decode('utf-16' if raw.startswith((b'\xff\xfe', b'\xfe\xff')) else 'utf-8-sig')


def trace_metadata(text: str) -> dict:
    start = re.search(r'\bStartTime: (\d+)', text)
    end = re.search(r'\bEndTime: (\d+)', text)
    if start is None or end is None:
        raise ValueError("Cabecalho ETL com FILETIME inicial/final ausente.")
    epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
    beginning = epoch + timedelta(microseconds=int(start[1]) // 10)
    finish = epoch + timedelta(microseconds=int(end[1]) // 10)
    if finish < beginning:
        raise ValueError("Janela de trace invertida.")
    return {"start_utc": beginning.isoformat(), "finish_utc": finish.isoformat(),
            "duration_seconds": (finish - beginning).total_seconds(),
            "filetime_precision_note": "100 ns FILETIME truncated to microseconds for display",
            "text_nonempty_lines": len([line for line in text.splitlines() if line.strip()]),
            "pktmon_provider_lines": len(re.findall(r'\[[^\]]*PktMon[^\]]*\]', text, re.I)),
            "inbound_packet_observation_proven": False,
            "limitation": "Trace window and no provider lines do not prove a valid NIC/filter capture."}


def window_covers(trace: dict, scanner: dict) -> bool:
    start = datetime.fromisoformat(trace["start_utc"]).timestamp()
    end = datetime.fromisoformat(trace["finish_utc"]).timestamp()
    return start <= scanner["start_epoch_seconds"] <= scanner["finish_epoch_seconds"] <= end


def run(archive: Path, etl: Path, text: Path, normal: Path, xml: Path, grepable: Path, output: Path):
    if output.exists():
        raise FileExistsError("Use pasta nova; nao sobrescrever diagnosticos.")
    sources = [archive, etl, text, normal, xml, grepable]
    before = {str(p.resolve()): sha256(p) for p in sources}
    scanner = parse_scanner(xml.read_bytes(), normal.read_text(encoding="utf-8-sig"),
                           grepable.read_text(encoding="utf-8-sig"), profile="diag135_r2")
    trace = trace_metadata(decode_windows_text(text.read_bytes()))
    with zipfile.ZipFile(archive) as z:
        entries = z.infolist()
        if len(entries) != 2 or any(e.is_dir() or e.file_size > 128 * 1024 * 1024
                                   or Path(e.filename).name != e.filename or '/' in e.filename or '\\' in e.filename
                                   or stat.S_ISLNK(e.external_attr >> 16) for e in entries):
            raise ValueError("ZIP inseguro.")
        pcaps = [e for e in entries if e.filename.endswith('.pcap')]
        configs = [e for e in entries if e.filename.endswith('.json')]
        if len(pcaps) != 1 or len(configs) != 1 or z.testzip() is not None:
            raise ValueError("ZIP/CRC invalido.")
        config = json.loads(z.read(configs[0]).decode('utf-8-sig'))
        expected = {"interface": "hn1", "description": "lab07_diag135_r2_lan", "fam": "ip", "protocol": "TCP",
                    "host": SOURCE, "port": "135", "snaplen": "65535", "count": "1000",
                    "promiscuous": "0", "port_not": "0", "protocol_not": "0"}
        if any(config.get(k) != v for k, v in expected.items()):
            raise ValueError("Filtro LAN difere do diagnostico.")
        output.mkdir(parents=True)
        (output / 'input').mkdir()
        (output / 'scanner_logs').mkdir()
        (output / 'windows_logs').mkdir()
        for p in sources:
            folder = 'input' if p == archive else ('windows_logs' if p in (etl, text) else 'scanner_logs')
            dest = output / folder / p.name
            shutil.copyfile(p, dest)
            if sha256(dest) != before[str(p.resolve())]:
                raise ValueError("Copia diverge da fonte.")
        for entry in entries:
            with (output / 'input' / entry.filename).open('xb') as stream:
                stream.write(z.read(entry))
    pcap = output / 'input' / pcaps[0].filename
    capture = scan_packets(pcap, scanner)
    data = pcap.read_bytes()
    endian = '<' if data[:4] == bytes.fromhex('d4c3b2a1') else '>'
    offset, ethernet = 24, []
    mac = lambda value: ':'.join(f'{b:02x}' for b in value)
    while offset < len(data):
        _, _, length, _ = struct.unpack_from(endian + 'IIII', data, offset)
        offset += 16
        frame = data[offset:offset + length]
        offset += length
        ethernet.append({"source_mac": mac(frame[6:12]), "destination_mac": mac(frame[:6])})
    if before != {str(p.resolve()): sha256(p) for p in sources}:
        raise ValueError("Uma fonte mudou durante a importacao.")
    result = {"status": "lan_syn_observed_windows_capture_inconclusive", "scenario": "lab07_diag135_r2",
              "scanner": scanner, "lan_capture": capture, "ethernet_frames": ethernet,
              "windows_text_metadata": trace, "trace_declared_window_contains_scan": window_covers(trace, scanner),
              "source_sha256": before, "source_files_unchanged_at_import": True,
              "pcap_sha256": sha256(pcap), "windows_packet_reception_established": False,
              "windows_firewall_drop_established": False, "inference_executed": False,
              "database_written": False,
              "limitations": ["Packet addressed to a MAC does not prove delivery to that guest NIC.",
                              "No Pktmon provider lines in supplied TXT; capture setup not independently confirmed.",
                              "FILETIME covers scan, but this is not independent clock synchronization proof.",
                              "ETL preserved for independent offline decoding; original files not executed."]}
    with (output / 'diagnostic_audit.json').open('x', encoding='utf-8') as stream:
        json.dump(result, stream, indent=2, allow_nan=False)
        stream.write('\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('archive', 'etl', 'text', 'normal', 'xml', 'grepable', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    result = run(**vars(parser.parse_args()))
    print(json.dumps({k: result[k] for k in ('status', 'lan_capture', 'ethernet_frames',
                                          'windows_text_metadata', 'trace_declared_window_contains_scan')}, indent=2))
