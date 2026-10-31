"""Recreate article Figures 1–3 from frozen reports, without running models."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter


def generate(root: Path, output: Path) -> None:
    paths = [output / name for name in (
        "figura1_metricas_percentuais.png", "figura2_tempos.png",
        "figura3_compromisso_fpr_recall.png")]
    if any(path.exists() for path in paths):
        raise FileExistsError("Use a new output directory; published figures are not overwritten")
    read = lambda relative: json.loads((root / relative).read_text(encoding="utf-8"))
    comparison = read("experiments/scale_100k/metrics/model_comparison.json")
    initial = read("reports/metrics/model_comparison.json")
    operational = read("reports/operational/operational_calibration.json")
    output.mkdir(parents=True, exist_ok=True)
    pt = lambda value, digits=2: f"{value:.{digits}f}".replace(".", ",")
    metrics = ["precision", "recall_tpr", "f1_score", "false_positive_rate"]
    models = [("isolation_forest", "Isolation Forest", "#2864a5"),
              ("lof", "LOF", "#c83e4d")]
    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 10,
                         "axes.spines.top": False, "axes.spines.right": False})
    fmt = FuncFormatter(lambda x, pos: pt(x, 0))
    fig, axes = plt.subplots(1, 2, figsize=(10.8, 4.7), constrained_layout=True)
    for ax, point, title in zip(axes, ["native", "validation_f1_calibrated"],
                                ["Limiar nativo", "Calibrado por F1"]):
        for j, (name, label, color) in enumerate(models):
            block = comparison["models"][name]["splits"]["test"]["operating_points"][point]
            values = [block[key] * 100 for key in metrics]
            bars = ax.bar([i + (j - .5) * .36 for i in range(4)], values, .36,
                          label=label, color=color)
            for i, bar in enumerate(bars):
                ax.text(bar.get_x() + .18, bar.get_height() + 1.2,
                        pt(values[i], 3 if i == 3 else 2), ha="center", fontsize=8)
        ax.set(xticks=range(4), xticklabels=["Precisão", "Recall", "F1", "FPR"],
               ylim=(0, 110), title=title, ylabel="Percentual (%)")
        ax.yaxis.set_major_formatter(fmt)
        ax.legend(loc="upper left", fontsize=8)
        ax.grid(axis="y", alpha=.15)
        ax.set_axisbelow(True)
    fig.savefig(paths[0], dpi=220)
    plt.close(fig)

    fig, axes = plt.subplots(1, 2, figsize=(10.8, 5), constrained_layout=True)
    for ax, (name, label, _) in zip(axes, models):
        for j, (data, legend, color) in enumerate([
                (initial, "20 mil", "#818181"), (comparison, "100 mil", "#2e8a56")]):
            timing = data["timing"]["by_model_seconds"][name]
            values = [timing[key] for key in ["fit", "inference_validation", "inference_test"]]
            bars = ax.bar([i + (j - .5) * .36 for i in range(3)], values, .36,
                          label=legend, color=color)
            for value, bar in zip(values, bars):
                ax.text(bar.get_x() + .18, value * 1.12, pt(value), ha="center", fontsize=9)
        ax.set(yscale="log", ylim=(.05, 25), xticks=range(3),
               xticklabels=["Treino", "Inferência\nvalidação", "Inferência\nteste"],
               title=label, ylabel="Segundos (escala logarítmica)")
        ax.yaxis.set_major_formatter(FuncFormatter(lambda x, pos: pt(x, 2)))
        ax.legend(fontsize=9)
        ax.grid(axis="y", alpha=.15)
        ax.set_axisbelow(True)
    fig.savefig(paths[1], dpi=220)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(10.8, 5.6), constrained_layout=True)
    for name, label, color in models:
        budgets = operational["models"][name]["budgets"]
        values = sorted((point["test_metrics"]["false_positive_rate"] * 100,
                         point["test_metrics"]["recall_tpr"] * 100)
                        for point in budgets.values())
        ax.plot([value[0] for value in values], [value[1] for value in values],
                "o-", label=label, color=color)
    ax.axvline(1, linestyle="--", color="black", label="Referência de FPR de 1%")
    ax.set(xlabel="FPR observada no teste (%)", ylabel="Recall dos ataques no teste (%)",
           ylim=(0, 45))
    ax.xaxis.set_major_formatter(fmt)
    ax.yaxis.set_major_formatter(fmt)
    ax.legend()
    ax.grid(alpha=.15)
    fig.savefig(paths[2], dpi=220)
    plt.close(fig)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    generate(Path(__file__).resolve().parents[1], args.output_dir.resolve())
    print("Three figures generated from frozen JSON reports; models were not executed.")
