"""
Research Figure Generator
AI-Augmented SOC — Swarm Intelligence for Automated Threat Modeling

Reads experiment results and generates publication-quality matplotlib figures.

Usage:
    python generate_figures.py experiments/EXP-20250322_120000/
    python generate_figures.py experiments/EXP-20250322_120000/ --format pdf
"""

import argparse
import json
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")  # non-interactive backend
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import numpy as np

# Paper-quality defaults
plt.rcParams.update({
    "figure.dpi": 150,
    "savefig.dpi": 300,
    "font.size": 11,
    "axes.titlesize": 13,
    "axes.labelsize": 12,
    "xtick.labelsize": 10,
    "ytick.labelsize": 10,
    "legend.fontsize": 10,
    "figure.figsize": (8, 5),
    "axes.grid": True,
    "grid.alpha": 0.3,
    "axes.spines.top": False,
    "axes.spines.right": False,
})

COLORS = {
    "primary": "#2563eb",
    "secondary": "#dc2626",
    "tertiary": "#059669",
    "quaternary": "#d97706",
    "light_blue": "#93c5fd",
    "light_red": "#fca5a5",
    "light_green": "#86efac",
    "gray": "#6b7280",
}

ARCHETYPE_COLORS = {
    "opportunist": "#2563eb",
    "apt": "#dc2626",
    "ransomware": "#7c3aed",
    "insider": "#d97706",
}


def load_results(exp_dir: Path) -> dict:
    """Load all experiment results from directory."""
    results = {}
    all_file = exp_dir / "all_results.json"
    if all_file.exists():
        with open(all_file) as f:
            results = json.load(f)
    else:
        # Load individual files
        for i in range(1, 5):
            f = exp_dir / f"exp{i}_results.json"
            if f.exists():
                with open(f) as fh:
                    results.setdefault("experiments", {})[f"exp{i}"] = json.load(fh)
    return results


# ---------------------------------------------------------------------------
# Figure 1: Scale vs Discovery (Experiment 1)
# ---------------------------------------------------------------------------

def fig1_scale_vs_discovery(exp1: dict, fig_dir: Path, fmt: str):
    """Line plot: swarm size vs unique paths + emergent discoveries."""
    results = exp1.get("results", [])
    if not results:
        print("  [SKIP] Fig 1: No Experiment 1 data")
        return

    sizes = [r["swarm_size"] for r in results]
    paths = [r["unique_paths"] for r in results]
    emergent = [r["emergent_discoveries"] for r in results]

    fig, ax1 = plt.subplots(figsize=(8, 5))

    # Unique paths (left axis)
    line1 = ax1.plot(sizes, paths, "o-", color=COLORS["primary"],
                     linewidth=2, markersize=8, label="Unique Attack Paths")
    ax1.set_xlabel("Swarm Size (followers per archetype)")
    ax1.set_ylabel("Unique Attack Paths Discovered", color=COLORS["primary"])
    ax1.tick_params(axis="y", labelcolor=COLORS["primary"])

    # Emergent discoveries (right axis)
    ax2 = ax1.twinx()
    line2 = ax2.plot(sizes, emergent, "s--", color=COLORS["secondary"],
                     linewidth=2, markersize=8, label="Emergent Discoveries")
    ax2.set_ylabel("Emergent Discoveries", color=COLORS["secondary"])
    ax2.tick_params(axis="y", labelcolor=COLORS["secondary"])

    # Mark convergence points
    for r in results:
        if r["convergence_achieved"]:
            ax1.axvline(x=r["swarm_size"], color=COLORS["tertiary"],
                       linestyle=":", alpha=0.5)
            ax1.annotate("converged", xy=(r["swarm_size"], paths[sizes.index(r["swarm_size"])]),
                        textcoords="offset points", xytext=(10, 10),
                        fontsize=8, color=COLORS["tertiary"])

    # Combined legend
    lines = line1 + line2
    labels = [l.get_label() for l in lines]
    ax1.legend(lines, labels, loc="upper left")

    ax1.set_title("Experiment 1: Scale vs Discovery Rate")
    fig.tight_layout()
    fig.savefig(fig_dir / f"fig1_scale_vs_discovery.{fmt}", bbox_inches="tight")
    plt.close(fig)
    print(f"  Fig 1: Scale vs Discovery saved")


# ---------------------------------------------------------------------------
# Figure 2: Host Risk Heatmap (from largest scale)
# ---------------------------------------------------------------------------

def fig2_host_risk_heatmap(exp1: dict, fig_dir: Path, fmt: str):
    """Bar chart with error bars: per-host compromise rate at largest scale."""
    results = exp1.get("results", [])
    if not results:
        print("  [SKIP] Fig 2: No data")
        return

    # Use the largest scale
    largest = results[-1]
    rates = largest.get("host_compromise_rates", {})
    cis = largest.get("host_confidence_intervals", {})

    if not rates:
        print("  [SKIP] Fig 2: No host rates")
        return

    hosts = sorted(rates.keys())
    values = [rates[h] for h in hosts]
    ci_low = [cis.get(h, [0, 0])[0] for h in hosts]
    ci_high = [cis.get(h, [0, 0])[1] for h in hosts]
    errors_low = [v - cl for v, cl in zip(values, ci_low)]
    errors_high = [ch - v for v, ch in zip(values, ci_high)]

    # Short labels
    labels = [h.split(".")[-1] for h in hosts]
    full_labels = hosts

    fig, ax = plt.subplots(figsize=(10, 5))
    bars = ax.bar(range(len(hosts)), values, yerr=[errors_low, errors_high],
                  capsize=5, color=COLORS["primary"], alpha=0.8,
                  edgecolor="white", linewidth=0.5)

    # Color by criticality threshold
    for i, v in enumerate(values):
        if v > 0.5:
            bars[i].set_color(COLORS["secondary"])
        elif v > 0.3:
            bars[i].set_color(COLORS["quaternary"])

    ax.set_xticks(range(len(hosts)))
    ax.set_xticklabels(full_labels, rotation=30, ha="right", fontsize=9)
    ax.set_ylabel("Compromise Rate")
    ax.set_title(f"Experiment 1: Host Risk Heatmap (n={largest['swarm_size']} followers)")
    ax.set_ylim(0, 1.0)
    ax.yaxis.set_major_formatter(mticker.PercentFormatter(1.0))

    # Threshold line
    ax.axhline(y=0.3, color=COLORS["gray"], linestyle="--", alpha=0.5, label="30% threshold")
    ax.legend()

    fig.tight_layout()
    fig.savefig(fig_dir / f"fig2_host_risk_heatmap.{fmt}", bbox_inches="tight")
    plt.close(fig)
    print(f"  Fig 2: Host Risk Heatmap saved")


# ---------------------------------------------------------------------------
# Figure 3: Prediction Confusion Matrix (Experiment 2)
# ---------------------------------------------------------------------------

def fig3_prediction_accuracy(exp2: dict, fig_dir: Path, fmt: str):
    """Confusion matrix + per-host prediction table."""
    best = exp2.get("best_results", {})
    cm = best.get("confusion_matrix", {})
    if not cm:
        print("  [SKIP] Fig 3: No Experiment 2 data")
        return

    matrix = np.array([
        [cm.get("tp", 0), cm.get("fp", 0)],
        [cm.get("fn", 0), cm.get("tn", 0)],
    ])

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5),
                                     gridspec_kw={"width_ratios": [1, 1.5]})

    # Confusion matrix
    im = ax1.imshow(matrix, cmap="Blues", aspect="auto")
    ax1.set_xticks([0, 1])
    ax1.set_yticks([0, 1])
    ax1.set_xticklabels(["Predicted\nVulnerable", "Predicted\nSecure"])
    ax1.set_yticklabels(["Actually\nVulnerable", "Actually\nSecure"])

    for i in range(2):
        for j in range(2):
            label = ["TP", "FP", "FN", "TN"][i * 2 + j]
            ax1.text(j, i, f"{label}\n{matrix[i, j]}",
                    ha="center", va="center", fontsize=14, fontweight="bold",
                    color="white" if matrix[i, j] > matrix.max() / 2 else "black")

    ax1.set_title(f"Confusion Matrix (threshold={exp2.get('best_threshold', 0.3)})")

    # Metrics bar
    metrics = {
        "Accuracy": best.get("accuracy", 0),
        "Precision": best.get("precision", 0),
        "Recall": best.get("recall", 0),
        "F1 Score": best.get("f1_score", 0),
    }
    bars = ax2.barh(list(metrics.keys()), list(metrics.values()),
                    color=[COLORS["primary"], COLORS["tertiary"],
                           COLORS["quaternary"], COLORS["secondary"]],
                    height=0.5)
    ax2.set_xlim(0, 1.05)
    for bar, val in zip(bars, metrics.values()):
        ax2.text(bar.get_width() + 0.02, bar.get_y() + bar.get_height() / 2,
                f"{val:.0%}", va="center", fontweight="bold")
    ax2.set_title("Prediction Metrics")
    ax2.xaxis.set_major_formatter(mticker.PercentFormatter(1.0))

    fig.suptitle("Experiment 2: Swarm Prediction Accuracy vs Expert Ground Truth",
                 fontsize=14, fontweight="bold")
    fig.tight_layout()
    fig.savefig(fig_dir / f"fig3_prediction_accuracy.{fmt}", bbox_inches="tight")
    plt.close(fig)
    print(f"  Fig 3: Prediction Accuracy saved")


# ---------------------------------------------------------------------------
# Figure 4: Single-Run vs Swarm (Experiment 3)
# ---------------------------------------------------------------------------

def fig4_single_vs_swarm(exp3: dict, fig_dir: Path, fmt: str):
    """Grouped bar chart comparing single-run vs swarm per host."""
    comparison = exp3.get("host_comparison", [])
    if not comparison:
        print("  [SKIP] Fig 4: No Experiment 3 data")
        return

    hosts = [c["hostname"] for c in comparison]
    single_rates = [1.0 if c["single_run_compromised"] else 0.0 for c in comparison]
    swarm_rates = [c["swarm_compromise_rate"] for c in comparison]
    ground_truth = [c.get("ground_truth", None) for c in comparison]

    x = np.arange(len(hosts))
    width = 0.35

    fig, ax = plt.subplots(figsize=(10, 6))
    bars1 = ax.bar(x - width / 2, single_rates, width, label="Single Run (4 agents)",
                   color=COLORS["light_blue"], edgecolor=COLORS["primary"], linewidth=1)
    bars2 = ax.bar(x + width / 2, swarm_rates, width, label="Swarm (statistical)",
                   color=COLORS["light_red"], edgecolor=COLORS["secondary"], linewidth=1)

    # Add CI whiskers for swarm
    for i, c in enumerate(comparison):
        ci = c.get("swarm_ci_95", [0, 0])
        if ci and ci != [0, 0]:
            ax.plot([x[i] + width / 2, x[i] + width / 2], ci,
                    color=COLORS["secondary"], linewidth=2)

    # Ground truth markers
    for i, gt in enumerate(ground_truth):
        if gt is True:
            ax.plot(x[i], -0.05, "^", color=COLORS["tertiary"], markersize=10)
        elif gt is False:
            ax.plot(x[i], -0.05, "v", color=COLORS["gray"], markersize=10)

    ax.set_ylabel("Compromise Rate")
    ax.set_title("Experiment 3: Single-Run vs Swarm Predictions")
    ax.set_xticks(x)
    ax.set_xticklabels(hosts, rotation=30, ha="right")
    ax.set_ylim(-0.1, 1.1)
    ax.yaxis.set_major_formatter(mticker.PercentFormatter(1.0))
    ax.legend()

    # Ground truth legend
    ax.plot([], [], "^", color=COLORS["tertiary"], markersize=8, label="Ground truth: vulnerable")
    ax.plot([], [], "v", color=COLORS["gray"], markersize=8, label="Ground truth: secure")
    ax.legend(loc="upper right")

    fig.tight_layout()
    fig.savefig(fig_dir / f"fig4_single_vs_swarm.{fmt}", bbox_inches="tight")
    plt.close(fig)
    print(f"  Fig 4: Single vs Swarm saved")


# ---------------------------------------------------------------------------
# Figure 5: Defender Impact (Experiment 4)
# ---------------------------------------------------------------------------

def fig5_defender_impact(exp4: dict, fig_dir: Path, fmt: str):
    """Side-by-side bar chart: compromise rates with/without defenders."""
    comparison = exp4.get("host_comparison", [])
    if not comparison:
        print("  [SKIP] Fig 5: No Experiment 4 data")
        return

    hosts = [c["hostname"] for c in comparison]
    with_def = [c["rate_with_defenders"] for c in comparison]
    without_def = [c["rate_without_defenders"] for c in comparison]

    x = np.arange(len(hosts))
    width = 0.35

    fig, ax = plt.subplots(figsize=(10, 6))
    bars1 = ax.bar(x - width / 2, without_def, width,
                   label="Without Defenders",
                   color=COLORS["light_red"], edgecolor=COLORS["secondary"], linewidth=1)
    bars2 = ax.bar(x + width / 2, with_def, width,
                   label="With LLM Defenders",
                   color=COLORS["light_green"], edgecolor=COLORS["tertiary"], linewidth=1)

    # Reduction arrows
    for i in range(len(hosts)):
        if without_def[i] > with_def[i]:
            reduction_pct = comparison[i]["relative_reduction_pct"]
            mid_y = (without_def[i] + with_def[i]) / 2
            ax.annotate(
                f"-{reduction_pct:.0f}%",
                xy=(x[i], mid_y),
                fontsize=8, fontweight="bold",
                color=COLORS["tertiary"],
                ha="center",
            )

    ax.set_ylabel("Compromise Rate")
    ax.set_title("Experiment 4: Impact of LLM-Powered Defenders")
    ax.set_xticks(x)
    ax.set_xticklabels(hosts, rotation=30, ha="right")
    ax.set_ylim(0, 1.0)
    ax.yaxis.set_major_formatter(mticker.PercentFormatter(1.0))
    ax.legend()

    # Overall stats
    overall_text = (
        f"Overall: {exp4.get('overall_compromise_without_defenders', 0):.0%} -> "
        f"{exp4.get('overall_compromise_with_defenders', 0):.0%} "
        f"({exp4.get('overall_reduction_pct', 0):.0f}% reduction)"
    )
    ax.text(0.5, 0.95, overall_text, transform=ax.transAxes,
            ha="center", fontsize=10, fontstyle="italic",
            bbox=dict(boxstyle="round,pad=0.3", facecolor="lightyellow", alpha=0.8))

    fig.tight_layout()
    fig.savefig(fig_dir / f"fig5_defender_impact.{fmt}", bbox_inches="tight")
    plt.close(fig)
    print(f"  Fig 5: Defender Impact saved")


# ---------------------------------------------------------------------------
# Figure 6: Archetype Comparison
# ---------------------------------------------------------------------------

def fig6_archetype_comparison(exp1: dict, fig_dir: Path, fmt: str):
    """Grouped bar chart: attacker archetype effectiveness at largest scale."""
    results = exp1.get("results", [])
    if not results:
        print("  [SKIP] Fig 6: No data")
        return

    largest = results[-1]
    arch_stats = largest.get("archetype_stats", {})
    if not arch_stats:
        print("  [SKIP] Fig 6: No archetype data")
        return

    archetypes = sorted(arch_stats.keys())
    success_rates = [arch_stats[a].get("success_rate_mean", 0) for a in archetypes]
    compromised = [arch_stats[a].get("hosts_compromised_mean", 0) for a in archetypes]

    x = np.arange(len(archetypes))
    width = 0.35

    fig, ax1 = plt.subplots(figsize=(8, 5))

    bars1 = ax1.bar(x - width / 2, success_rates, width,
                    color=[ARCHETYPE_COLORS.get(a, COLORS["gray"]) for a in archetypes],
                    alpha=0.7, label="Success Rate")
    ax1.set_ylabel("Action Success Rate")
    ax1.set_ylim(0, 1.0)
    ax1.yaxis.set_major_formatter(mticker.PercentFormatter(1.0))

    ax2 = ax1.twinx()
    bars2 = ax2.bar(x + width / 2, compromised, width,
                    color=[ARCHETYPE_COLORS.get(a, COLORS["gray"]) for a in archetypes],
                    alpha=0.3, hatch="//", label="Hosts Compromised (mean)")
    ax2.set_ylabel("Mean Hosts Compromised")

    ax1.set_xticks(x)
    ax1.set_xticklabels([a.replace("_", " ").title() for a in archetypes])
    ax1.set_title(f"Attacker Archetype Effectiveness (n={largest['swarm_size']})")

    # Combined legend
    ax1.legend(loc="upper left")
    ax2.legend(loc="upper right")

    fig.tight_layout()
    fig.savefig(fig_dir / f"fig6_archetype_comparison.{fmt}", bbox_inches="tight")
    plt.close(fig)
    print(f"  Fig 6: Archetype Comparison saved")


# ---------------------------------------------------------------------------
# Figure 7: Convergence Analysis
# ---------------------------------------------------------------------------

def fig7_convergence(exp1: dict, fig_dir: Path, fmt: str):
    """Line plot: compromise rate stabilization across scales."""
    results = exp1.get("results", [])
    if not results:
        print("  [SKIP] Fig 7: No data")
        return

    fig, ax = plt.subplots(figsize=(8, 5))

    for r in results:
        batch_evo = r.get("batch_evolution", [])
        if batch_evo:
            batches = [b["batch"] for b in batch_evo]
            success = [b["success_rate"] for b in batch_evo]
            ax.plot(batches, success, "o-", label=f"n={r['swarm_size']}",
                    alpha=0.7, markersize=5)

    ax.set_xlabel("Monte Carlo Batch")
    ax.set_ylabel("Attacker Success Rate")
    ax.set_title("Experiment 1: Convergence Across Scales")
    ax.yaxis.set_major_formatter(mticker.PercentFormatter(1.0))
    ax.legend(title="Swarm Size")

    fig.tight_layout()
    fig.savefig(fig_dir / f"fig7_convergence.{fmt}", bbox_inches="tight")
    plt.close(fig)
    print(f"  Fig 7: Convergence saved")


# ---------------------------------------------------------------------------
# Figure 8: Discovery Rate per Agent
# ---------------------------------------------------------------------------

def fig8_discovery_efficiency(exp1: dict, fig_dir: Path, fmt: str):
    """Bar chart: emergent discoveries per 1000 agent runs."""
    results = exp1.get("results", [])
    if not results:
        print("  [SKIP] Fig 8: No data")
        return

    sizes = [r["swarm_size"] for r in results]
    efficiency = [
        (r["emergent_discoveries"] / max(r["total_agents"], 1)) * 1000
        for r in results
    ]

    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.bar(range(len(sizes)), efficiency, color=COLORS["primary"], alpha=0.8)
    ax.set_xticks(range(len(sizes)))
    ax.set_xticklabels([str(s) for s in sizes])
    ax.set_xlabel("Swarm Size (followers per archetype)")
    ax.set_ylabel("Emergent Discoveries per 1000 Agent Runs")
    ax.set_title("Discovery Efficiency: Does Scaling Help?")

    # Annotate values
    for bar, val in zip(bars, efficiency):
        if val > 0:
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.1,
                    f"{val:.1f}", ha="center", fontsize=9)

    fig.tight_layout()
    fig.savefig(fig_dir / f"fig8_discovery_efficiency.{fmt}", bbox_inches="tight")
    plt.close(fig)
    print(f"  Fig 8: Discovery Efficiency saved")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def generate_all_figures(exp_dir: Path, fmt: str = "png"):
    """Generate all figures from experiment results."""
    fig_dir = exp_dir / "figures"
    fig_dir.mkdir(exist_ok=True)

    results = load_results(exp_dir)
    experiments = results.get("experiments", {})

    print(f"\nGenerating figures in: {fig_dir}")
    print(f"Format: {fmt}")
    print("-" * 40)

    # Find experiment data by key pattern
    exp1 = None
    exp2 = None
    exp3 = None
    exp4 = None

    for key, data in experiments.items():
        if "scale" in key or "1_" in key:
            exp1 = data
        elif "prediction" in key or "2_" in key:
            exp2 = data
        elif "single" in key or "3_" in key:
            exp3 = data
        elif "defender" in key or "4_" in key:
            exp4 = data

    if exp1:
        fig1_scale_vs_discovery(exp1, fig_dir, fmt)
        fig2_host_risk_heatmap(exp1, fig_dir, fmt)
        fig6_archetype_comparison(exp1, fig_dir, fmt)
        fig7_convergence(exp1, fig_dir, fmt)
        fig8_discovery_efficiency(exp1, fig_dir, fmt)

    if exp2:
        fig3_prediction_accuracy(exp2, fig_dir, fmt)

    if exp3:
        fig4_single_vs_swarm(exp3, fig_dir, fmt)

    if exp4:
        fig5_defender_impact(exp4, fig_dir, fmt)

    print(f"\nDone. {len(list(fig_dir.glob(f'*.{fmt}')))} figures generated.")


def main():
    parser = argparse.ArgumentParser(description="Generate research paper figures")
    parser.add_argument("exp_dir", help="Path to experiment results directory")
    parser.add_argument("--format", default="png", choices=["png", "pdf", "svg"],
                        help="Output format")
    args = parser.parse_args()

    exp_dir = Path(args.exp_dir)
    if not exp_dir.exists():
        print(f"Error: {exp_dir} does not exist")
        sys.exit(1)

    generate_all_figures(exp_dir, args.format)


if __name__ == "__main__":
    main()
