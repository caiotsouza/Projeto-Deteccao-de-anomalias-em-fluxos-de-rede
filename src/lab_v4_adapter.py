"""CICFlowMeter V4 -> entrada estruturada, somente para inferencia exploratoria.

Nao corrige calculos do Java, nao infere rotulos e nao aprende transformacoes.
Usa o contrato congelado e conserva todos os segmentos exportados.
"""

from __future__ import annotations

import csv
import hashlib
import ipaddress
import json
import re
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from src.data_split import align_features_to_manifest
from src.lab_flow_audit import COMMITS, audit_extraction, map_columns, sha256


ADAPTER_VERSION = "lab-v4-exploratory-v1"
LIMITATIONS = [
    "Exact feature-calculation equivalence with CIC-IDS2017 is not established.",
    "Environment shift and extractor changes are confounded in this experiment.",
    "Exported segments are not independent connections or requests.",
    "CSV timestamps have second precision and refer to exported flow starts in UTC.",
    "Scores are not probabilities; signal rate is not precision, recall or FPR.",
    "Endpoint grouping does not separate reuse of the same TCP 5-tuple.",
    "No ground-truth labels are inferred from the extractor Label column.",
]


def parse_v4_timestamp(value: str) -> str:
    """Interpreta o formato observado sem depender do locale AM/PM do Windows."""
    match = re.fullmatch(r"(\d{2})/(\d{2})/(\d{4}) (\d{2}):(\d{2}):(\d{2}) (AM|PM)", value)
    if not match:
        raise ValueError(f"Timestamp V4 fora do formato auditado: {value!r}")
    day, month, year, hour, minute, second = map(int, match.groups()[:6])
    if not 1 <= hour <= 12:
        raise ValueError("Hora V4 deve estar entre 01 e 12.")
    hour = hour % 12 + (12 if match[7] == "PM" else 0)
    return datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc).isoformat()


def _port(value: object) -> int:
    if isinstance(value, bool):
        raise ValueError("Porta booleana invalida.")
    numeric = float(value)
    if not 0 <= numeric <= 65535 or not numeric.is_integer():
        raise ValueError("Porta deve ser um inteiro entre 0 e 65535.")
    return int(numeric)


def prepare_v4_records(
    *, pcap: Path, extraction_dir: Path, selection: dict, split: dict,
    accept_experimental_v4: bool = False, scenario: str = "controlled_lab_capture",
) -> tuple[list[dict], dict]:
    """Valida antes de carregar qualquer modelo; devolve features e procedencia."""
    if not accept_experimental_v4:
        raise ValueError("Uso somente exploratorio: informe --accept-experimental-v4.")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", scenario):
        raise ValueError("scenario deve ser um identificador de 1 a 100 caracteres.")
    manifest_path = extraction_dir / "extraction_run.json"
    run = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    if run.get("status") != "extraction_completed" or run.get("timezone") != "UTC":
        raise ValueError("Extracao deve estar concluida e declarar timezone UTC.")
    if run.get("source_repository") != "https://github.com/ahlashkari/CICFlowMeter":
        raise ValueError("Repositorio de extracao inesperado.")
    pcap_hash = str(run["pcap_sha256_before"])
    # audit_extraction verifica commit, PCAP, CSV e contrato, sem aprovar semantica.
    audit = audit_extraction(extraction_dir, "v4", pcap, selection, split)
    csv_path = extraction_dir / run["csv_files"][0]["name"]
    with csv_path.open(encoding="utf-8-sig", newline="") as stream:
        names = map_columns(next(csv.reader(stream)), "v4")
    frame = pd.read_csv(csv_path)
    frame.columns = names
    required = {"src_ip", "dst_ip", "src_port", "destination_port", "protocol", "timestamp", "flow_id"}
    if missing := required - set(frame.columns):
        raise ValueError(f"Metadados obrigatorios ausentes: {sorted(missing)}")
    if any(pd.api.types.is_bool_dtype(frame[name]) for name in selection["selected_features"]):
        raise ValueError("Features booleanas nao sao aceitas.")
    features = align_features_to_manifest(frame, selection)
    records = []
    for index, numeric in enumerate(features.to_dict(orient="records")):
        row = frame.iloc[index]
        src = str(ipaddress.IPv4Address(str(row["src_ip"])))
        dst = str(ipaddress.IPv4Address(str(row["dst_ip"])))
        src_port, dst_port = _port(row["src_port"]), _port(row["destination_port"])
        if float(row["protocol"]) != 6:
            raise ValueError("Este perfil experimental aceita somente TCP (protocolo 6).")
        observed_at = parse_v4_timestamp(str(row["timestamp"]))
        endpoints = sorted(((src, src_port), (dst, dst_port)))
        group_key = hashlib.sha256(json.dumps([6, endpoints], separators=(",", ":")).encode()).hexdigest()
        identity = [ADAPTER_VERSION, audit["source_commit"], pcap_hash, audit["csv_sha256"], index + 1]
        event_id = "lab-v4-" + hashlib.sha256(json.dumps(identity, separators=(",", ":")).encode()).hexdigest()
        payload = int(numeric["total_length_of_fwd_packets"] + numeric["total_length_of_bwd_packets"])
        records.append({
            "event_id": event_id, "observed_at": observed_at,
            "source": "lab_pcap_v4_exploratory", "features": numeric,
            "context": {
                "experimental": True, "production_approved": False,
                "semantic_compatibility": "not_established", "ground_truth_available": False,
                "adapter_version": ADAPTER_VERSION, "scenario": scenario,
                "extractor_commit": COMMITS["v4"], "extractor_image_id": run["image_id"],
                "pcap_sha256": pcap_hash, "csv_sha256": audit["csv_sha256"],
                "csv_data_row": index + 1, "csv_timestamp_raw": str(row["timestamp"]),
                "timestamp_precision": "second", "timestamp_timezone": "UTC",
                "observed_at_semantics": "exported_flow_start",
                "src_ip": src, "dst_ip": dst, "src_port": src_port, "dst_port": dst_port,
                "protocol": "TCP", "protocol_number": 6, "flow_id": str(row["flow_id"]),
                "endpoint_group_id": group_key,
                "packet_count": int(numeric["total_fwd_packets"] + numeric["total_backward_packets"]),
                "payload_bytes": payload,
                "payload_group": "with_payload" if payload > 0 else "zero_payload",
                "label_column_ignored": True,
            },
        })
    # Detecta alteracoes entre a auditoria e a montagem das entradas.
    if sha256(csv_path) != audit["csv_sha256"] or sha256(pcap) != pcap_hash:
        raise ValueError("Entrada mudou durante a adaptacao.")
    return records, {
        "adapter_version": ADAPTER_VERSION, "scenario": scenario,
        "experimental_v4_accepted": True, "structural_audit": audit,
        "label_used": False, "rows_dropped": 0, "features_imputed": False,
        "flags_clipped": False, "segments_merged": False,
        "timestamp_timezone": "UTC", "timestamp_precision": "second",
        "semantic_compatibility": "not_established", "limitations": LIMITATIONS,
    }


def summarize_predictions(predictions: list[dict]) -> dict:
    """Estatisticas descritivas por modelo; nao calcula metricas supervisionadas."""
    if not predictions:
        raise ValueError("Nenhuma predicao para resumir.")
    summary = {}
    for name, subset in (
        ("all_segments", predictions),
        ("with_payload", [p for p in predictions if p["context"]["payload_group"] == "with_payload"]),
        ("zero_payload", [p for p in predictions if p["context"]["payload_group"] == "zero_payload"]),
    ):
        scores = pd.Series([p["prediction"]["anomaly_score"] for p in subset], dtype="float64")
        signaled = sum(p["prediction"]["predicted_anomaly"] for p in subset)
        summary[name] = {
            "segments": len(subset), "signaled_segments": signaled,
            "not_signaled_segments": len(subset) - signaled,
            "signal_rate": signaled / len(subset) if subset else None,
            "native_signaled_segments": sum(p["prediction"]["native_predicted_anomaly"] for p in subset),
            "score_min": float(scores.min()) if subset else None,
            "score_median": float(scores.median()) if subset else None,
            "score_max": float(scores.max()) if subset else None,
        }
    groups = {}
    for result in predictions:
        key = result["context"]["endpoint_group_id"]
        groups[key] = groups.get(key, False) or bool(result["prediction"]["predicted_anomaly"])
    summary["endpoint_groups"] = {"total": len(groups), "with_any_signaled_segment": sum(groups.values())}
    summary["supervised_metrics_computed"] = False
    summary["ground_truth_available"] = False
    return summary
