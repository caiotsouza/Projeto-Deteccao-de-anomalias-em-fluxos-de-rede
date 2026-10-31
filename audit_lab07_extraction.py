"""Audita cobertura da V4 no LAB07; nao carrega modelos ou corrige features."""
import argparse
import json
from pathlib import Path

import pandas as pd

from src.config import PROJECT_ROOT
from src.lab_flow_audit import audit_extraction, audit_pcap, map_columns, sha256


def compare_groups(frame: pd.DataFrame, independent: dict) -> dict:
    groups = {}
    for group in independent["connections"]:
        key = (tuple(group["source"]), tuple(group["destination"]))
        if key in groups:
            raise ValueError("Grupo independente duplicado.")
        groups[key] = group
    represented = set()
    for _, row in frame.iterrows():
        key = ((str(row.src_ip), int(row.src_port)), (str(row.dst_ip), int(row.destination_port)))
        if key not in groups or key in represented:
            raise ValueError("Segmento CSV sem grupo independente unico.")
        group = groups[key]
        if (int(row.total_fwd_packets) != group["forward_packets"]
                or int(row.total_backward_packets) != group["backward_packets"]
                or int(row.flow_duration) != group["duration_us"]):
            raise ValueError("Contagens ou duracao do segmento divergem do PCAP.")
        represented.add(key)
    missing = [g for key, g in groups.items() if key not in represented]
    packets = sum(g["packets"] for key, g in groups.items() if key in represented)
    return {"captured_packets": independent["packets"], "represented_packets": packets,
            "unrepresented_packets": independent["packets"] - packets,
            "captured_endpoint_groups": len(groups), "represented_endpoint_groups": len(represented),
            "unrepresented_endpoint_groups": len(missing),
            "all_unrepresented_groups_are_single_packet": bool(missing) and all(g["packets"] == 1 for g in missing),
            "full_packet_coverage": packets == independent["packets"],
            "unrepresented_groups": missing}


def run(session: Path):
    output = session / "extraction_audit.json"
    if output.exists():
        raise FileExistsError("Preserve a auditoria anterior.")
    receipt = json.loads((session / "scan_validation.json").read_text(encoding="utf-8"))
    pcap = Path(receipt["pcap"])
    extraction = session / "extracted"
    manifest = json.loads((extraction / "extraction_run.json").read_text(encoding="utf-8"))
    csv = extraction / manifest["csv_files"][0]["name"]
    if csv.resolve().parent != extraction.resolve() or sha256(pcap) != receipt["pcap_sha256"]:
        raise ValueError("Procedencia insegura ou PCAP alterado.")
    protected = [pcap, csv, session / "scan_validation.json", extraction / "extraction_run.json",
                 PROJECT_ROOT / "data/processed/monday_feature_manifest.json",
                 PROJECT_ROOT / "experiments/scale_100k/data/splits/split_manifest.json"]
    before = {str(p.resolve()): sha256(p) for p in protected}
    selection = json.loads(protected[-2].read_text(encoding="utf-8"))
    split = json.loads(protected[-1].read_text(encoding="utf-8"))
    structural = audit_extraction(extraction, "v4", pcap, selection, split)
    frame = pd.read_csv(csv)
    frame.columns = map_columns(frame.columns.tolist(), "v4")
    coverage = compare_groups(frame, audit_pcap(pcap))
    result = {"status": "partial_extraction_inference_not_performed" if not coverage["full_packet_coverage"]
              else "coverage_audited_manual_review_required",
              "structural_audit": structural, "coverage": coverage,
              "scanner_plan_deviation": receipt["scanner"]["missing_planned_ports"],
              "windows_reachability_established": False,
              "inference_executed": False, "automatic_inference_allowed": False,
              "models_loaded": False, "models_retrained": False, "thresholds_recalibrated": False,
              "database_written": False, "protected_sha256": before,
              "reason": "Do not score a partial subset as though it represented the complete scan.",
              "limitations": ["Finite features for exported rows do not establish full packet coverage.",
                              "One-packet groups remain in PCAP; no synthetic replacement rows were generated."]}
    if before != {str(p.resolve()): sha256(p) for p in protected}:
        raise ValueError("Uma entrada mudou durante a auditoria.")
    with output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, allow_nan=False)
        stream.write("\n")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--session", type=Path, required=True)
    result = run(parser.parse_args().session)
    print(json.dumps({"status": result["status"], "coverage": {k: v for k, v in result["coverage"].items()
                                                              if k != "unrepresented_groups"}}, indent=2))
