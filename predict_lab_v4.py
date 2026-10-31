"""Executa IF/LOF congelados sobre CSV V4, somente em experimento offline."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import platform
from datetime import datetime, timezone
from pathlib import Path

from src.config import PROJECT_ROOT
from src.inference_service import AnomalyInferenceService, ModelSelection
from src.lab_flow_audit import audit_pcap, sha256
from src.lab_export_scope import validate_export_scope
from src.lab_v4_adapter import prepare_v4_records, summarize_predictions


def run_experiment(
    *, pcap: Path, extraction_dir: Path, output_dir: Path,
    accept_experimental_v4: bool = False, scenario: str = "controlled_lab_capture",
    batch_size: int = 256, project_root: Path = PROJECT_ROOT,
    coverage_audit: Path | None = None, accept_partial_export: bool = False,
) -> dict:
    if not accept_experimental_v4:
        raise ValueError("Informe --accept-experimental-v4 para reconhecer as limitacoes.")
    if accept_partial_export and coverage_audit is None:
        raise ValueError("Analise parcial exige --coverage-audit.")
    if not 1 <= batch_size <= 1000:
        raise ValueError("batch-size deve estar entre 1 e 1000.")
    output_dir = output_dir.resolve()
    if output_dir.exists():
        raise FileExistsError("Use uma pasta de saida nova; resultados anteriores nao sao sobrescritos.")
    root = project_root.resolve()
    registry_path = root / "reports/operational/model_registry_operational.json"
    selection_path = root / "data/processed/monday_feature_manifest.json"
    split_path = root / "experiments/scale_100k/data/splits/split_manifest.json"
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    model_paths, registered_artifacts = [], {}
    model_keys = ("isolation_forest", "lof")
    for name in model_keys:
        entry = registry["experiments"]["expanded_100k"]["models"][name]
        for reference in ("model_artifact", "metadata_artifact"):
            path = (root / entry[reference]["relative_path"]).resolve()
            if not path.is_relative_to(root):
                raise ValueError("Artefato fora da raiz do projeto.")
            actual_hash = sha256(path)
            matches = actual_hash == entry[reference]["sha256"]
            registered_artifacts[f"{name}/{reference}"] = {
                "registered_sha256": entry[reference]["sha256"], "actual_sha256": actual_hash,
                "matches_registry": matches, "used_for_inference": reference == "model_artifact",
            }
            # Somente o .joblib e desserializado; o JSON auxiliar nao fornece
            # features ou limiares. Sua divergencia fica explicita, nunca ocultada.
            if reference == "model_artifact" and not matches:
                raise ValueError(f"Hash divergente em {name}/{reference}.")
            model_paths.append(path)
    protected = list(dict.fromkeys([
        pcap.resolve(), selection_path, split_path, registry_path, *model_paths,
        *(p.resolve() for p in extraction_dir.iterdir() if p.is_file()),
        *([coverage_audit.resolve()] if coverage_audit is not None else []),
    ]))
    # Mesmo uma pasta inexistente nao pode ser criada dentro de uma entrada.
    if output_dir.is_relative_to(extraction_dir.resolve()) or output_dir == pcap.resolve():
        raise ValueError("Separe a pasta de saida das entradas originais.")
    before = {str(p): sha256(p) for p in protected}
    records, methodology = prepare_v4_records(
        pcap=pcap, extraction_dir=extraction_dir,
        selection=json.loads(selection_path.read_text(encoding="utf-8")),
        split=json.loads(split_path.read_text(encoding="utf-8")),
        accept_experimental_v4=True, scenario=scenario,
    )
    if coverage_audit is not None:
        scope = validate_export_scope(
            json.loads(coverage_audit.read_text(encoding="utf-8-sig")),
            methodology['structural_audit'], records, audit_pcap(pcap),
            accept_partial_export=accept_partial_export,
        )
        methodology['evaluation_scope'] = scope
        methodology['coverage_audit_sha256'] = before[str(coverage_audit.resolve())]
        for record in records:
            record['context'].update({
                'evaluation_population': scope['population'],
                'full_capture_packet_coverage': scope['coverage']['full_packet_coverage'],
                'whole_scan_detection_measured': False,
            })
    predictions, model_reports = {}, {}
    for name in model_keys:
        service = AnomalyInferenceService.from_registry(
            project_root=root, registry_path=registry_path,
            selection=ModelSelection(experiment="expanded_100k", model=name,
                                     operating_point="validation_fpr_operational"),
            max_batch_size=batch_size,
        )
        if list(service.feature_columns) != list(records[0]["features"]):
            raise ValueError("Ordem das features diverge do bundle carregado.")
        predictions[name] = []
        for offset in range(0, len(records), batch_size):
            predictions[name].extend(service.predict_many(records[offset:offset + batch_size]))
        model_reports[name] = {
            "model_sha256": service.model_sha256, "operating_point": service.selection.operating_point,
            "threshold": service.threshold, "summary": summarize_predictions(predictions[name]),
        }
    if {str(p): sha256(p) for p in protected} != before:
        raise ValueError("Uma entrada ou artefato congelado mudou durante a inferencia.")
    first, second = (predictions[name] for name in model_keys)
    if [r["event_id"] for r in first] != [r["event_id"] for r in second]:
        raise ValueError("Os modelos nao classificaram os mesmos registros na mesma ordem.")
    agreements = sum(a["prediction"]["predicted_anomaly"] == b["prediction"]["predicted_anomaly"]
                     for a, b in zip(first, second))
    report = {
        "schema_version": 1, "status": "exploratory_inference_completed",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "methodology": methodology, "models": model_reports,
        "decision_agreement": {"segments": len(records), "agree": agreements,
                               "disagree": len(records) - agreements,
                               "is_accuracy_measure": False},
        "integrity": {"protected_files_unchanged": True, "sha256": before,
                      "registered_artifacts": registered_artifacts,
                      "auxiliary_metadata_used_for_inference": False,
                      "warnings": [f"Registered hash mismatch: {name}; auxiliary JSON not used for inference."
                                   for name, entry in registered_artifacts.items() if not entry["matches_registry"]]},
        "runtime": {"python": platform.python_version(),
                    **{name: importlib.metadata.version(name) for name in
                       ("scikit-learn", "numpy", "pandas", "scipy", "joblib")}},
        "implementation_sha256": {name: sha256(PROJECT_ROOT / name) for name in (
            "predict_lab_v4.py", "src/lab_v4_adapter.py", "src/lab_flow_audit.py",
            "src/inference_service.py", "src/data_split.py",
            "src/lab_export_scope.py",
        )},
        "models_retrained": False, "thresholds_recalibrated": False,
        "database_written": False, "production_approved": False,
    }
    # Toda a validacao e inferencia termina antes de criar arquivos de saida.
    output_dir.mkdir(parents=True, exist_ok=False)
    artifacts = {"model_inputs.json": records,
                 **{f"{name}_predictions.json": predictions[name] for name in model_keys}}
    for filename, payload in artifacts.items():
        with (output_dir / filename).open("x", encoding="utf-8") as stream:
            json.dump(payload, stream, ensure_ascii=False, indent=2, allow_nan=False)
            stream.write("\n")
    report["output_sha256"] = {name: sha256(output_dir / name) for name in artifacts}
    with (output_dir / "run_manifest.json").open("x", encoding="utf-8") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write("\n")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", type=Path, required=True)
    parser.add_argument("--extraction-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--accept-experimental-v4", action="store_true")
    parser.add_argument("--scenario", default="controlled_lab_capture")
    parser.add_argument("--batch-size", type=int, default=256)
    parser.add_argument("--coverage-audit", type=Path)
    parser.add_argument("--accept-partial-export", action="store_true")
    args = parser.parse_args()
    try:
        report = run_experiment(**vars(args))
    except (OSError, ValueError, KeyError, TypeError, RuntimeError) as exc:
        parser.exit(1, f"Erro: {exc}\n")
    print(json.dumps({"status": report["status"], "models": report["models"],
                      "output_dir": str(args.output_dir.resolve()),
                      "production_approved": False}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
