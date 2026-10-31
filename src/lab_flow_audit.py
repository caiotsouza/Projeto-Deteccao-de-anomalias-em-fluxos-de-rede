"""Auditoria offline: compara extratores, sem produzir entradas de inferencia.

O leitor PCAP e deliberadamente restrito a Ethernet/IPv4/TCP nao fragmentado,
com timestamp em microssegundos. Nao substitui um extrator de features.
"""

from __future__ import annotations

import csv
import hashlib
import json
import socket
import struct
from collections import Counter
from pathlib import Path

import pandas as pd

from src.data_split import align_features_to_manifest
from src.utils import normalize_columns


COMMITS = {
    "v4": "98a5ebad0df579cc8b43eedd3421b3ae87699901",
    "legacy_pre2019": "99dc82768a0ebbf2be63a506b185113f52ab1edf",
}
FLAGS = [f"{name}_flag_count" for name in ("fin", "syn", "rst", "psh", "ack", "urg", "ece")]
V4_ALIASES = {
    "dst_port": "destination_port",
    "total_fwd_packet": "total_fwd_packets",
    "total_bwd_packets": "total_backward_packets",
    "total_length_of_fwd_packet": "total_length_of_fwd_packets",
    "total_length_of_bwd_packet": "total_length_of_bwd_packets",
    "packet_length_min": "min_packet_length",
    "packet_length_max": "max_packet_length",
    "fwd_init_win_bytes": "init_win_bytes_forward",
    "bwd_init_win_bytes": "init_win_bytes_backward",
    "fwd_act_data_pkts": "act_data_pkt_fwd",
    "fwd_seg_size_min": "min_seg_size_forward",
}
LEGACY_ALIASES = {
    "dst_port": "destination_port",
    "tot_fwd_pkts": "total_fwd_packets",
    "tot_bwd_pkts": "total_backward_packets",
    "totlen_fwd_pkts": "total_length_of_fwd_packets",
    "totlen_bwd_pkts": "total_length_of_bwd_packets",
    "flow_byts_s": "flow_bytes_s", "flow_pkts_s": "flow_packets_s",
    "fwd_iat_tot": "fwd_iat_total", "bwd_iat_tot": "bwd_iat_total",
    "fwd_header_len": "fwd_header_length", "bwd_header_len": "bwd_header_length",
    "fwd_pkts_s": "fwd_packets_s", "bwd_pkts_s": "bwd_packets_s",
    "pkt_len_min": "min_packet_length", "pkt_len_max": "max_packet_length",
    "pkt_len_mean": "packet_length_mean", "pkt_len_std": "packet_length_std",
    "pkt_size_avg": "average_packet_size",
    "init_fwd_win_byts": "init_win_bytes_forward",
    "init_bwd_win_byts": "init_win_bytes_backward",
    "fwd_act_data_pkts": "act_data_pkt_fwd",
    "fwd_seg_size_min": "min_seg_size_forward",
}
for _direction in ("fwd", "bwd"):
    for _stat in ("min", "max", "mean", "std"):
        LEGACY_ALIASES[f"{_direction}_pkt_len_{_stat}"] = f"{_direction}_packet_length_{_stat}"
for _flag in FLAGS:
    LEGACY_ALIASES[_flag.replace("_count", "_cnt")] = _flag
ALIASES = {"v4": V4_ALIASES, "legacy_pre2019": LEGACY_ALIASES}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def audit_pcap(path: Path) -> dict:
    """Conta bytes/pacotes de forma independente; agrupa por par de endpoints.

    Uma reutilizacao da mesma 5-tupla fica no mesmo grupo. Este agrupamento
    nao implementa timeouts nem a segmentacao do CICFlowMeter.
    """
    packets = []
    with path.open("rb") as stream:
        header = stream.read(24)
        endian = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">"}.get(header[:4])
        if len(header) != 24 or endian is None:
            raise ValueError("PCAP classico com timestamps em microssegundos obrigatorio.")
        major, minor, _, _, _, linktype = struct.unpack(endian + "HHiIII", header[4:])
        if (major, minor, linktype) != (2, 4, 1):
            raise ValueError("A auditoria suporta somente PCAP 2.4/Ethernet.")
        while record := stream.read(16):
            if len(record) != 16:
                raise ValueError("Cabecalho de pacote truncado.")
            sec, usec, captured, original = struct.unpack(endian + "IIII", record)
            if usec >= 1_000_000 or captured != original or captured > 16_777_216:
                raise ValueError("Timestamp invalido, snaplen truncado ou tamanho excessivo.")
            frame = stream.read(captured)
            if len(frame) != captured or len(frame) < 54 or frame[12:14] != b"\x08\x00":
                raise ValueError("Frame truncado ou fora do escopo Ethernet/IPv4/TCP.")
            ip = frame[14:]
            ihl = (ip[0] & 15) * 4
            total = int.from_bytes(ip[2:4], "big")
            fragment = int.from_bytes(ip[6:8], "big")
            if ip[0] >> 4 != 4 or ihl < 20 or total > len(ip) or total < ihl + 20:
                raise ValueError("Cabecalho IPv4 invalido.")
            if ip[9] != 6 or fragment & 0x3FFF:
                raise ValueError("Somente TCP/IPv4 sem fragmentacao e suportado.")
            tcp = ip[ihl:total]
            thl = (tcp[12] >> 4) * 4
            if thl < 20 or thl > len(tcp):
                raise ValueError("Cabecalho TCP invalido.")
            packets.append({
                "time_us": sec * 1_000_000 + usec,
                "src": (socket.inet_ntoa(ip[12:16]), int.from_bytes(tcp[:2], "big")),
                "dst": (socket.inet_ntoa(ip[16:20]), int.from_bytes(tcp[2:4], "big")),
                "window": int.from_bytes(tcp[14:16], "big"),
                "flags": tcp[13], "payload": len(tcp) - thl,
            })
    if not packets:
        raise ValueError("PCAP vazio.")
    if any(b["time_us"] < a["time_us"] for a, b in zip(packets, packets[1:])):
        raise ValueError("Timestamps fora de ordem.")
    groups = {}
    for packet in packets:
        key = tuple(sorted((packet["src"], packet["dst"])))
        groups.setdefault(key, []).append(packet)
    connections = []
    for group in groups.values():
        first = group[0]
        forward = [p for p in group if p["src"] == first["src"]]
        backward = [p for p in group if p["src"] != first["src"]]
        fin_index = next((i for i, p in enumerate(group) if p["flags"] & 1), None)
        prefix = group if fin_index is None else group[:fin_index + 1]
        connections.append({
            "source": list(first["src"]), "destination": list(first["dst"]),
            "packets": len(group), "forward_packets": len(forward), "backward_packets": len(backward),
            "payload_bytes": sum(p["payload"] for p in group),
            "duration_us": group[-1]["time_us"] - first["time_us"],
            "first_fin_prefix_packets": len(prefix),
            "first_fin_prefix_forward_packets": sum(p["src"] == first["src"] for p in prefix),
            "first_fin_prefix_backward_packets": sum(p["src"] != first["src"] for p in prefix),
            "first_fin_prefix_duration_us": prefix[-1]["time_us"] - first["time_us"],
            "forward_initial_window_raw": forward[0]["window"],
            "backward_initial_window_raw": backward[0]["window"] if backward else None,
            "backward_last_window_raw": backward[-1]["window"] if backward else None,
        })
    return {
        "sha256": sha256(path), "packets": len(packets),
        "payload_bytes": sum(p["payload"] for p in packets),
        "endpoint_groups": len(groups), "connections": connections,
        "grouping_limitation": "same 5-tuple reuse is not separated; no flow timeout applied",
    }


def map_columns(columns: list, profile: str) -> list[str]:
    if profile not in ALIASES:
        raise ValueError("Perfil desconhecido.")
    names = [ALIASES[profile].get(name, name) for name in normalize_columns(columns)]
    if len(set(names)) != len(names):
        raise ValueError("Aliases geraram colunas duplicadas.")
    return names


def audit_extraction(directory: Path, profile: str, pcap: Path, selection: dict, split: dict) -> dict:
    run = json.loads((directory / "extraction_run.json").read_text(encoding="utf-8-sig"))
    expected_hash = sha256(pcap)
    if run["source_commit"] != COMMITS[profile] or any(
        run[key] != expected_hash for key in ("pcap_sha256_before", "pcap_sha256_after")
    ):
        raise ValueError("Proveniencia diverge do perfil ou do PCAP.")
    if len(run["csv_files"]) != 1:
        raise ValueError("A comparacao exige exatamente um CSV por extracao.")
    entry = run["csv_files"][0]
    name = entry["name"]
    if Path(name).name != name or "/" in name or "\\" in name:
        raise ValueError("Nome de CSV deve ser um basename local.")
    path = directory / name
    if sha256(path) != entry["sha256"]:
        raise ValueError("O hash do CSV diverge do manifesto de extracao.")
    with path.open(encoding="utf-8-sig", newline="") as stream:
        columns = map_columns(next(csv.reader(stream)), profile)
    frame = pd.read_csv(path)
    frame.columns = columns
    if frame.empty:
        raise ValueError("CSV vazio.")
    # Label e metadados nunca entram no alinhamento das features.
    features = align_features_to_manifest(frame, selection)
    schema = "\n".join(f"{col}:{features[col].dtype}" for col in features)
    fingerprint = hashlib.sha256(schema.encode()).hexdigest()
    if fingerprint != split["model_input_schema_sha256"] or list(features) != split["feature_columns"]:
        raise ValueError("Contrato de features difere dos splits congelados.")
    pairs = Counter(zip(features.total_fwd_packets, features.total_backward_packets))
    payload = features.total_length_of_fwd_packets + features.total_length_of_bwd_packets
    principal = frame.loc[payload > 0, [
        "flow_duration", "total_fwd_packets", "total_backward_packets",
        "init_win_bytes_forward", "init_win_bytes_backward", "min_seg_size_forward",
        "packet_length_mean", "average_packet_size",
    ]]
    return {
        "profile": profile, "source_commit": run["source_commit"], "image_id": run["image_id"],
        "csv_sha256": entry["sha256"], "rows": len(frame), "raw_columns": len(columns),
        "feature_count": len(features.columns), "schema_sha256": fingerprint,
        "dtypes": dict(Counter(str(t) for t in features.dtypes)),
        "packet_count_sum": int((features.total_fwd_packets + features.total_backward_packets).sum()),
        "payload_bytes_sum": int(payload.sum()),
        "packet_count_pairs": [{"forward": int(f), "backward": int(b), "rows": count}
                               for (f, b), count in sorted(pairs.items())],
        "flag_values": {flag: sorted(int(v) for v in features[flag].unique()) for flag in FLAGS},
        "payload_rows": principal.to_dict(orient="records"),
        "label_ignored": True, "structural_validation": "passed",
        "semantic_compatibility": "not_established", "automatic_inference_allowed": False,
    }


def audit_original_flags(paths: list[Path]) -> list[dict]:
    """Le as sete flags em todas as linhas, sem amostragem ou alteracao do CSV."""
    output = []
    for path in paths:
        values = {flag: set() for flag in FLAGS}
        rows = 0
        with pd.read_csv(path, encoding="latin-1", chunksize=100_000,
                         usecols=lambda name: normalize_columns([name])[0] in FLAGS) as chunks:
            for chunk in chunks:
                chunk.columns = normalize_columns(list(chunk.columns))
                if set(chunk.columns) != set(FLAGS):
                    raise ValueError(f"Flags incompletas em {path.name}")
                rows += len(chunk)
                for flag in FLAGS:
                    series = pd.to_numeric(chunk[flag], errors="raise")
                    if series.isna().any() or not series.isin([0, 1]).all():
                        raise ValueError(f"Flag fora de 0/1 em {path.name}: {flag}")
                    values[flag].update(int(v) for v in series.unique())
        if rows == 0:
            raise ValueError(f"CSV original vazio: {path.name}")
        output.append({"file": path.name, "rows": rows,
                       "flag_values": {flag: sorted(v) for flag, v in values.items()}})
    return output
