"""Compara as 60 features do laboratorio com X_train, preservando os modelos."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

from src.config import PROJECT_ROOT
from src.inference_service import AnomalyInferenceService, ModelSelection
from src.isolation_forest import validate_feature_frame
from src.lab_feature_diagnostics import compare_features, reference_profile, squared_distance_diagnostics
from src.lab_flow_audit import sha256
from summarize_lab_captures import RUNS


def draw_figure(report: dict, path: Path):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    sessions = list(report["sessions"])
    short = ["LAB02", "LAB03", "LAB04", "LAB05", "LAB06"]
    labels = [short[i] if i < len(short) else name for i, name in enumerate(sessions)]
    fig, axes = plt.subplots(1, 2, figsize=(13, 5.5))
    x = np.arange(len(sessions))
    ack = {}
    for group in ("with_payload", "zero_payload"):
        ack[group] = [next(f["sample"]["median"] for f in report["sessions"][s][group]["features"]
                           if f["feature"] == "ack_flag_count") for s in sessions]
    for offset, group, color, label in ((-.18, "with_payload", "#2864b0", "Com payload"),
                                       (.18, "zero_payload", "#dc8b27", "Sem payload")):
        bars = axes[0].bar(x + offset, ack[group], width=.35, color=color, label=label)
        axes[0].bar_label(bars, labels=[f"{v:g}" for v in ack[group]], fontsize=8, padding=3)
    axes[0].axhline(report["reference"]["features"]["ack_flag_count"]["maximum"],
                   color="#a12525", linestyle="--", linewidth=1.4, label="Máximo no treino: 1")
    axes[0].set_yscale("symlog", linthresh=1)
    axes[0].set_ylim(0, max(max(values) for values in ack.values()) * 3)
    axes[0].set_xticks(x, labels)
    axes[0].set_ylabel("Mediana de ACK Flag Count (escala symlog)")
    axes[0].set_title("Valores observados: flags históricas × V4")
    axes[0].legend(fontsize=8, loc="upper left")
    axes[0].grid(axis="y", alpha=.2)
    selected = [("ack_flag_count", "ACK", "#2864b0"), ("psh_flag_count", "PSH", "#dc8b27"),
                ("syn_flag_count", "SYN", "#39956c")]
    left = np.zeros(len(sessions))
    for name, label, color in selected:
        values = [100 * next(f["pooled_squared_distance_share"] for f in
                            report["sessions"][s]["with_payload"]["lof_geometry"]["features"]
                            if f["feature"] == name) for s in sessions]
        axes[1].barh(x, values, left=left, color=color, label=label)
        left += np.asarray(values)
    axes[1].barh(x, np.maximum(100 - left, 0), left=left, color="#a0a5ad", label="Outras features")
    axes[1].set_yticks(x, labels)
    axes[1].invert_yaxis()
    axes[1].set_xlim(0, 100)
    axes[1].set_xlabel("Participação na distância quadrática agrupada (%)")
    axes[1].set_title("Geometria dos 20 vizinhos do LOF — com payload")
    axes[1].legend(fontsize=8, loc="lower right")
    fig.text(.5, .025, "Diagnóstico descritivo: não é importância causal, fração do score ou métrica de detecção.",
             ha="center", fontsize=9)
    fig.tight_layout(rect=(0, .07, 1, 1))
    fig.savefig(path, dpi=170)
    plt.close(fig)


def run(output_dir: Path) -> dict:
    if output_dir.exists():
        raise FileExistsError("Escolha uma pasta nova para preservar diagnosticos anteriores.")
    root = PROJECT_ROOT
    train_path = root / "experiments/scale_100k/data/splits/X_train.parquet"
    split_path = train_path.with_name("split_manifest.json")
    registry_path = root / "reports/operational/model_registry_operational.json"
    registry = json.loads(registry_path.read_text())
    split = json.loads(split_path.read_text())
    protected = [train_path, split_path, registry_path, root / "data/processed/monday_feature_manifest.json"]
    for entry in registry["experiments"]["expanded_100k"]["models"].values():
        for key in ("model_artifact", "metadata_artifact"):
            p = (root / entry[key]["relative_path"]).resolve()
            if not p.is_relative_to(root.resolve()):
                raise ValueError("Artefato fora da raiz.")
            if key == "model_artifact" and sha256(p) != entry[key]["sha256"]:
                raise ValueError("Hash do modelo diverge do registro.")
            protected.append(p)
    runs = {}
    for name, relative in RUNS.items():
        directory = root / relative
        manifest_path = directory / "run_manifest.json"
        manifest = json.loads(manifest_path.read_text())
        if manifest["status"] != "exploratory_inference_completed":
            raise ValueError("Rodada de laboratorio incompleta.")
        for filename, expected in manifest["output_sha256"].items():
            path = directory / filename
            if path.resolve().parent != directory.resolve() or sha256(path) != expected:
                raise ValueError("Artefato de laboratorio inseguro ou alterado.")
            protected.append(path)
        protected.append(manifest_path)
        runs[name] = (directory, manifest)
    protected = list(dict.fromkeys(protected))
    before = {str(p.relative_to(root)): sha256(p) for p in protected}
    train = pd.read_parquet(train_path)
    columns = list(split["feature_columns"])
    validate_feature_frame(train, "diagnostic_reference", columns, split["model_input_schema_sha256"])
    service = AnomalyInferenceService.from_registry(selection=ModelSelection(model="lof"))
    scaler, lof = service.estimator.named_steps["scaler"], service.estimator.named_steps["lof"]
    if list(service.feature_columns) != columns or lof.effective_metric_ != "euclidean":
        raise ValueError("Contrato ou metrica do pipeline inesperada.")
    scaled_train = scaler.transform(train)
    fitted = np.asarray(lof._fit_X)  # Somente leitura, versao e hash do artefato registrados.
    if scaled_train.shape != fitted.shape or not np.allclose(scaled_train, fitted, rtol=1e-12, atol=1e-12):
        raise ValueError("X_train nao coincide com a referencia ajustada dentro do LOF.")
    profile, ordered = reference_profile(train)
    sessions = {}
    warnings = set()
    for name, (directory, manifest) in runs.items():
        records = json.loads((directory / "model_inputs.json").read_text())
        predictions = {model: json.loads((directory / f"{model}_predictions.json").read_text())
                       for model in ("isolation_forest", "lof")}
        for model, rows in predictions.items():
            frozen = registry["experiments"]["expanded_100k"]["models"][model]
            if [r["event_id"] for r in rows] != [r["event_id"] for r in records]:
                raise ValueError("IDs/ordem das predicoes nao correspondem as entradas.")
            if any(r["model"]["sha256"] != frozen["model_artifact"]["sha256"]
                   or r["model"]["operating_point"] != "validation_fpr_operational"
                   or r["model"]["threshold"] != frozen["thresholds"]["validation_fpr_operational"]["threshold"]
                   or r["prediction"]["predicted_anomaly"] != int(r["prediction"]["anomaly_score"] >= r["model"]["threshold"])
                   for r in rows):
                raise ValueError("Identidade, limiar ou decisao divergente na rodada.")
        warnings.update(manifest["integrity"].get("warnings", []))
        sessions[name] = {}
        for group in ("with_payload", "zero_payload"):
            indexes = [i for i, r in enumerate(records) if r["context"]["payload_group"] == group]
            frame = pd.DataFrame([records[i]["features"] for i in indexes]).loc[:, columns]
            comparisons = compare_features(frame, profile, ordered)
            query = scaler.transform(frame)
            distances, neighbors = lof.kneighbors(query, n_neighbors=int(lof.n_neighbors_))
            geometry = squared_distance_diagnostics(query, fitted, distances, neighbors, columns)
            for position, index in enumerate(indexes):
                geometry["records"][position].update(
                    event_id=records[index]["event_id"],
                    stored_scores={model: predictions[model][index]["prediction"]["anomaly_score"] for model in predictions})
            sessions[name][group] = {
                "segments": len(indexes), "features": comparisons, "lof_geometry": geometry,
                "stored_signaled_segments": {model: sum(rows[i]["prediction"]["predicted_anomaly"] for i in indexes)
                                             for model, rows in predictions.items()},
                "interpretation": "Exploratory correlated sample, no causal attribution or supervised metric.",
            }
    if {str(p.relative_to(root)): sha256(p) for p in protected} != before:
        raise ValueError("Arquivo protegido mudou durante o diagnostico.")
    result = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(), "status": "descriptive_diagnostics_completed",
        "reference": {"records": len(train), "feature_count": len(columns),
                      "schema_sha256": split["model_input_schema_sha256"], "features": profile,
                      "transformed_reference_matches_fitted_lof": True,
                      "maximum_absolute_reference_difference": float(np.max(np.abs(scaled_train - fitted)))},
        "lof": {"model_sha256": service.model_sha256, "neighbors": int(lof.n_neighbors_),
                "metric": lof.effective_metric_, "scaler_fitted_now": False},
        "sessions": sessions,
        "integrity": {"protected_files_unchanged": True, "sha256": before, "warnings": sorted(warnings)},
        "models_fitted": False, "thresholds_recalibrated": False, "predictions_recomputed": False,
        "labels_loaded": False, "validation_or_test_loaded": False, "database_written": False,
        "limitations": [
            "Out-of-range and p01/p99 counts are descriptive, not statistical drift tests or alert rules.",
            "Percentile bounds around a median describe ties, not a confidence interval.",
            "Standardized Euclidean distance shares are not LOF-score or IF-feature attribution.",
            "Pooled distance shares weight faraway samples more heavily; per-record medians are also supplied.",
            "Mixed training traffic and a small correlated HTTP-only lab sample are not comparable populations.",
            "No clipping, feature replacement, row deletion, retraining or calibration is performed.",
        ],
    }
    output_dir.mkdir(parents=True, exist_ok=False)
    with (output_dir / "diagnostics.json").open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, ensure_ascii=False, allow_nan=False)
        stream.write("\n")
    draw_figure(result, output_dir / "flags_and_lof_geometry.png")
    text = ["# Comparacao descritiva das 60 features", "",
            f"Referencia: {len(train):,} registros; {len(columns)} features; referencia LOF confirmada.", "",
            "Participacao geometrica abaixo NAO e importancia causal ou fracao do score.", "",
            "| Sessao | Grupo | Segmentos | Mediana ACK | Maximo ACK no treino | ACK: parcela geometrica |",
            "| --- | --- | ---: | ---: | ---: | ---: |"]
    for name, groups in sessions.items():
        for group, entry in groups.items():
            ack = next(f for f in entry["features"] if f["feature"] == "ack_flag_count")
            share = next(f for f in entry["lof_geometry"]["features"] if f["feature"] == "ack_flag_count")
            text.append(f"| {name} | {group} | {entry['segments']} | {ack['sample']['median']:g} | "
                        f"{ack['training']['maximum']:g} | {100*share['pooled_squared_distance_share']:.2f}% |")
    text.extend(["", "Os 60 campos por grupo estao em diagnostics.json. Nenhum limiar/modelo foi alterado."])
    (output_dir / "SUMMARY.md").write_text("\n".join(text) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    result = run(parser.parse_args().output_dir)
    print(json.dumps({"status": result["status"], "training_records": result["reference"]["records"],
                      "features": result["reference"]["feature_count"], "sessions": len(result["sessions"]),
                      "reference_matches_fitted_lof": result["reference"]["transformed_reference_matches_fitted_lof"]}, indent=2))
