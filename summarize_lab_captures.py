"""Consolida rodadas exploratorias existentes, sem carregar ou ajustar modelos."""

import argparse
import json
import statistics
from pathlib import Path

from src.config import PROJECT_ROOT
from src.lab_flow_audit import audit_pcap, sha256
from validate_benign_http_capture import SERVER, reassemble, tcp_groups


RUNS = {
    "lab02_http": "data/lab/lab02_http/inference_v4_run1",
    "lab03_small_r1": "data/lab/lab03_small/r1/inference",
    "lab04_medium_r1": "data/lab/lab04_medium/r1/inference",
    "lab05_slow_r1": "data/lab/lab05_slow/r1/inference",
    "lab06_serverpaced_r1": "data/lab/lab06_serverpaced/r1/inference",
}


def stats(values):
    return {"min": min(values), "median": statistics.median(values), "max": max(values)}


def include_runs(specifications, root: Path = PROJECT_ROOT) -> dict:
    """Acrescenta sessoes explicitamente, sem alterar o conjunto historico."""
    runs = dict(RUNS)
    for spec in specifications:
        name, separator, relative = spec.partition("=")
        if not separator or not name.strip() or name in runs or not relative.strip():
            raise ValueError("Use nome_unico=caminho_relativo para cada sessao adicional.")
        path = Path(relative)
        if path.is_absolute() or not (root / path).resolve().is_relative_to(root.resolve()):
            raise ValueError("A sessao adicional deve estar dentro do projeto.")
        runs[name] = relative
    return runs


def summarize(root: Path = PROJECT_ROOT, *, runs: dict | None = None) -> dict:
    sessions, identity = {}, None
    for name, relative in (RUNS if runs is None else runs).items():
        directory = root / relative
        path = directory / "run_manifest.json"
        report = json.loads(path.read_text(encoding="utf-8"))
        if report["status"] != "exploratory_inference_completed":
            raise ValueError(f"Rodada incompleta: {name}")
        current_identity = {
            model: {key: value[key] for key in ("model_sha256", "operating_point", "threshold")}
            for model, value in report["models"].items()
        }
        if identity is None:
            identity = current_identity
        elif current_identity != identity:
            raise ValueError("Modelos/limiares diferentes impedem esta comparacao congelada.")
        for filename, expected in report["output_sha256"].items():
            if sha256(directory / filename) != expected:
                raise ValueError(f"Saida alterada em {name}: {filename}")
        inputs = json.loads((directory / "model_inputs.json").read_text())
        # Identifica o PCAP declarado e confere seu hash, sem inferir novo contexto.
        pcaps = [Path(p) for p in report["integrity"]["sha256"] if p.endswith(".pcap")]
        if len(pcaps) != 1 or sha256(pcaps[0]) != inputs[0]["context"]["pcap_sha256"]:
            raise ValueError("PCAP ausente ou divergente.")
        independent = audit_pcap(pcaps[0])
        groups = tcp_groups(pcaps[0])
        full_durations, payload_spans, body_sizes = [], [], []
        for group in groups:
            full_durations.append((group[-1]["time_us"] - group[0]["time_us"]) / 1e6)
            payload = [p for p in group if p["src"][0] == SERVER and p["payload"]]
            payload_spans.append((payload[-1]["time_us"] - payload[0]["time_us"]) / 1e6)
            response, _ = reassemble(group, payload[0]["src"])
            head, separator, body = response.partition(b"\r\n\r\n")
            if not separator or head.split(b"\r\n")[0].split()[:2] != [b"HTTP/1.0", b"200"]:
                raise ValueError("Resposta HTTP inesperada na consolidacao.")
            body_sizes.append(len(body))
        by_payload = {}
        for label in ("with_payload", "zero_payload"):
            by_payload[label] = stats([r["features"]["flow_duration"] / 1e6 for r in inputs
                                       if r["context"]["payload_group"] == label])
        sessions[name] = {
            "run_manifest_relative_path": str(path.relative_to(root)), "run_manifest_sha256": sha256(path),
            "connections": len(groups), "packets": independent["packets"], "segments": len(inputs),
            "observed_http_body_sizes_bytes": sorted(set(body_sizes)), "total_http_body_bytes": sum(body_sizes),
            "tcp_connection_duration_seconds": stats(full_durations),
            "server_payload_packet_span_seconds": stats(payload_spans),
            "v4_segment_duration_seconds": by_payload,
            "models": {model: entry["summary"] for model, entry in report["models"].items()},
        }
    return {
        "status": "descriptive_comparison_completed", "fixed_model_identity": identity, "sessions": sessions,
        "limitations": ["Descriptive results, not precision, recall, FPR or accuracy.",
                        "Correlated segments and differing capture conditions; no causal feature attribution.",
                        "Long client transfer does not imply sustained packet transmission at the capture point.",
                        "No model load, training, threshold change or database write performed by this summary."],
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--include-run", action="append", default=[], metavar="NAME=RELATIVE_PATH")
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError("Escolha uma saida nova para preservar comparacoes anteriores.")
    result = summarize(runs=include_runs(args.include_run))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, allow_nan=False)
        stream.write("\n")
    print(json.dumps({name: {key: row[key] for key in (
        "connections", "packets", "segments", "observed_http_body_sizes_bytes",
        "tcp_connection_duration_seconds", "server_payload_packet_span_seconds")}
        for name, row in result["sessions"].items()}, indent=2))
