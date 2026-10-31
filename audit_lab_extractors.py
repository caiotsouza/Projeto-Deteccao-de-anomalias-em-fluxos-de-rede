"""Compara os perfis sobre a mesma captura; nao carrega modelos nem grava no banco."""

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from src.lab_flow_audit import audit_extraction, audit_original_flags, audit_pcap, sha256


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", type=Path, required=True)
    parser.add_argument("--v4-dir", type=Path, required=True)
    parser.add_argument("--legacy-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--scan-original-flags", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    report_path = args.report.resolve()
    protected_inputs = [args.pcap.resolve()]
    for directory in (args.v4_dir, args.legacy_dir):
        protected_inputs.extend(p.resolve() for p in directory.iterdir() if p.is_file())
    frozen = [root / name for name in (
        "experiments/scale_100k/models/isolation_forest.joblib",
        "experiments/scale_100k/models/lof.joblib",
        "reports/operational/model_registry_operational.json",
        "data/processed/monday_feature_manifest.json",
        "experiments/scale_100k/data/splits/split_manifest.json",
    )]
    protected_inputs.extend(frozen)
    originals = sorted((root / "data/raw").glob("*.csv")) if args.scan_original_flags else []
    if args.scan_original_flags and not originals:
        raise ValueError("Nenhum CSV original encontrado.")
    if report_path.exists() or report_path in protected_inputs or report_path in originals:
        raise ValueError("Use um caminho novo para o relatorio; entradas nao podem ser sobrescritas.")
    before = {str(p): sha256(p) for p in protected_inputs}
    selection = json.loads(frozen[3].read_text(encoding="utf-8"))
    split = json.loads(frozen[4].read_text(encoding="utf-8"))
    pcap = audit_pcap(args.pcap)
    profiles = [audit_extraction(directory, profile, args.pcap, selection, split)
                for directory, profile in ((args.v4_dir, "v4"), (args.legacy_dir, "legacy_pre2019"))]
    for profile in profiles:
        profile["packets_not_accounted_by_exported_counts"] = pcap["packets"] - profile["packet_count_sum"]
    flags = audit_original_flags(originals) if originals else []
    after = {str(p): sha256(p) for p in protected_inputs}
    if after != before:
        raise ValueError("Um arquivo protegido mudou durante a auditoria.")
    result = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "comparison_completed_not_approved_for_inference",
        "pcap": pcap, "profiles": profiles, "original_dataset_flags": flags,
        "protected_files_unchanged": True,
        "frozen_artifacts": {str(p.relative_to(root)): before[str(p)] for p in frozen},
        "models_loaded": False, "models_retrained": False, "database_written": False,
        "decision": "Neither tested profile establishes exact CIC-IDS2017 extraction compatibility.",
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive creation also prevents accidental replacement between preflight and write.
    with report_path.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write("\n")
    print(json.dumps({"status": result["status"], "report": str(report_path),
                      "pcap_packets": pcap["packets"],
                      "profiles": [{k: p[k] for k in ("profile", "rows", "packet_count_sum", "feature_count")}
                                   for p in profiles]}, indent=2))


if __name__ == "__main__":
    main()
