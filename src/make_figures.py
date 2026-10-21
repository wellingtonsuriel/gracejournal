from __future__ import annotations

import argparse
import io
import os
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.colors import LinearSegmentedColormap


ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"
COLORS = ["#16324f", "#137f89", "#c78a20", "#8b466a", "#6a747e"]
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 10, "axes.labelsize": 11,
                     "axes.spines.top": False, "axes.spines.right": False,
                     "axes.grid": True, "grid.color": "#dfe4e8", "grid.linewidth": .6,
                     "grid.alpha": .65, "legend.frameon": False, "figure.dpi": 150,
                     "savefig.dpi": 350, "lines.linewidth": 2})


def save(fig, path):
    buffer = io.BytesIO()
    fig.savefig(buffer, format="png", bbox_inches="tight", facecolor="white")
    temporary = path.with_suffix(".png.tmp")
    with temporary.open("wb") as f:
        f.write(buffer.getvalue())
        f.flush()
        os.fsync(f.fileno())
    os.replace(temporary, path)
    plt.close(fig)


def main(destination: Path):
    destination.mkdir(parents=True, exist_ok=True)
    op = pd.read_csv(RESULTS / "optimization.csv")
    av = pd.read_csv(RESULTS / "availability.csv")
    pub = pd.read_csv(RESULTS / "public_replay.csv")
    diag = pd.read_csv(RESULTS / "diagnostics.csv")
    sc = pd.read_csv(RESULTS / "scaling.csv")
    rt = pd.read_csv(RESULTS / "runtime.csv")
    out = pd.read_csv(RESULTS / "targeted_outages.csv")
    copies = pd.read_csv(RESULTS / "copy_study.csv")

    names = ["Financial Data", "Financial Harm", "Physical Harm", "Data Security Harm", "Physical Data", "Others"]
    labels = ["Financial data", "Financial harm", "Physical harm", "Data security harm", "Physical data", "Other data"]
    counts = pub[pub.stage == "first"].attack_type.value_counts()
    fig, ax = plt.subplots(figsize=(6.9, 3.4), layout="constrained")
    bars = ax.barh(labels, [counts[x] for x in names], color=[COLORS[2], COLORS[2], COLORS[0], COLORS[0], COLORS[1], COLORS[1]], height=.64)
    ax.bar_label(bars, padding=5, fontsize=10)
    ax.set(xlabel="Public benchmark records", xlim=(0, 285))
    ax.grid(axis="y", visible=False)
    save(fig, destination / "dataset_composition.png")

    cases = ["untrusted_argument", "record_mixing", "missing_role", "wrong_scope", "stale_evidence",
             "descriptor_change", "erased_lineage", "state_change_at_commit", "permit_replay"]
    case_labels = ["Untrusted argument", "Mixed records", "Missing evidence role", "Different task scope",
                   "Stale evidence", "Changed descriptor", "Erased lineage", "Changed commit state", "Permit reuse"]
    methods = ["Tool allowlist", "Lineage only", "Single cover", "GRACE-R", "Without scope", "Without join", "Without freshness", "Without nonce"]
    display = ["Tool only", "Lineage", "Single cover", "GRACE-R", "Scope\nremoved", "Relation\nremoved", "Freshness\nremoved", "Nonce\nremoved"]
    matrix = diag.pivot_table(index="case", columns="method", values="admitted", aggfunc="sum").loc[cases, methods].to_numpy()
    fig, ax = plt.subplots(figsize=(7.0, 4.65), layout="constrained")
    cmap = LinearSegmentedColormap.from_list("violations", ["#eef4f7", "#b0524d"])
    img = ax.imshow(matrix, cmap=cmap, vmin=0, vmax=17, aspect="auto")
    ax.set_xticks(range(len(methods)), display, rotation=35, ha="right", fontsize=9)
    ax.set_yticks(range(len(cases)), case_labels, fontsize=9)
    ax.grid(False)
    for y in range(len(cases)):
        for x in range(len(methods)):
            ax.text(x, y, str(int(matrix[y, x])), va="center", ha="center", fontsize=10,
                    color="white" if matrix[y, x] > 8 else COLORS[0])
    cb = fig.colorbar(img, ax=ax, fraction=.035, pad=.03, ticks=[0, 17])
    cb.set_label("Unauthorized requests admitted / 17", fontsize=10)
    save(fig, destination / "diagnostic_ablation.png")

    fig, ax = plt.subplots(figsize=(6.9, 3.5), layout="constrained")
    labels_t = ["No loss tolerance", "One-domain tolerance", "Two-domain tolerance"]
    for t in range(3):
        exact = op.query("method=='Exact' and tolerance==@t").fraction_bytes.to_numpy() * 100
        greedy = op.query("method=='Greedy' and tolerance==@t").fraction_bytes.to_numpy() * 100
        pos = np.array([t * 3 + 1, t * 3 + 2])
        bx = ax.boxplot([exact, greedy], positions=pos, widths=.55, patch_artist=True, showfliers=False,
                        medianprops={"color": "white", "linewidth": 1.5})
        for patch, color in zip(bx["boxes"], [COLORS[0], COLORS[1]]):
            patch.set_facecolor(color)
        ax.text(pos.mean(), .97, labels_t[t], transform=ax.get_xaxis_transform(), ha="center", va="top", fontsize=9,
                bbox={"facecolor": "white", "edgecolor": "none", "pad": 2})
    ax.set_xticks([1, 2, 4, 5, 7, 8], ["Exact", "Greedy"] * 3)
    ax.set(ylabel="Eligible evidence bytes retained (%)", ylim=(0, 43), xlim=(.35, 8.65))
    ax.grid(axis="x", visible=False)
    save(fig, destination / "witness_bytes.png")

    fig, ax = plt.subplots(figsize=(6.9, 3.4), layout="constrained")
    wide = op.pivot(index=["case_id", "tolerance"], columns="method", values="cost_bytes").reset_index()
    for t in range(3):
        vals = np.sort((wide[wide.tolerance == t].Greedy / wide[wide.tolerance == t].Exact - 1) * 100)
        ax.step(vals, np.arange(1, len(vals) + 1) / len(vals), where="post", color=COLORS[t], label=labels_t[t])
    ax.set(xlabel="Greedy evidence cost above the exact optimum (%)", ylabel="Cumulative share of workloads", ylim=(0, 1.02), xlim=(-.8, 46))
    ax.legend(loc="lower right", fontsize=9)
    save(fig, destination / "greedy_gap.png")

    fig, ax = plt.subplots(figsize=(6.9, 3.5), layout="constrained")
    selected_methods = ["Exact t=0", "Exact t=1", "Exact t=2", "All sources"]
    display = ["Ordinary minimum witness", "One-domain tolerance", "Two-domain tolerance", "All eligible sources"]
    for m, label, color in zip(selected_methods, display, COLORS):
        mean = av[av.method == m].groupby("loss_probability").availability.mean()
        ax.plot(mean.index, mean.to_numpy() * 100, color=color, marker="o", markersize=3.5,
                linestyle="--" if m == "All sources" else "-", label=label)
    ax.axvline(.2, color="#87939c", linewidth=.8, linestyle=":", zorder=0)
    for m, color, label_y in zip(selected_methods[:3], COLORS[:3], [59, 87, 103.5]):
        value = av[(av.method == m) & np.isclose(av.loss_probability, .2)].availability.mean() * 100
        ax.annotate(f"{value:.2f}%", xy=(.2, value), xytext=(.235, label_y), color=color, fontsize=9,
                    arrowprops={"arrowstyle": "-", "color": color, "linewidth": .7}, va="center",
                    bbox={"facecolor": "white", "edgecolor": "none", "alpha": .95, "pad": .4})
    ax.set(xlabel="Independent loss probability per source domain", ylabel="Modeled evidence availability (%)",
           xlim=(0, .5), ylim=(20, 106))
    ax.legend(loc="lower left", fontsize=9)
    save(fig, destination / "evidence_availability.png")

    fig, ax = plt.subplots(figsize=(6.9, 3.4), layout="constrained")
    for m, label, color in zip(selected_methods, display, COLORS):
        data = out[out.method == m].groupby("lost_domains").worst_case_available.mean()
        ax.step(data.index, data.to_numpy() * 100, where="post", color=color, marker="o", markersize=4,
                label=label, linestyle="--" if m == "All sources" else "-")
    ax.set(xlabel="Number of source domains removed by a worst-case outage", ylabel="Workloads retaining every role (%)",
           xlim=(-.05, 5.05), ylim=(-3, 103), xticks=range(6))
    ax.legend(loc="center right", fontsize=9)
    save(fig, destination / "targeted_outages.png")

    fig, axes = plt.subplots(1, 2, figsize=(7.1, 3.4), sharey=True, layout="constrained")
    for tolerance, ax in zip((1, 2), axes):
        for method, color, marker in (("GRACE-R", COLORS[1], "s"), ("Copy counting", "#b0524d", "o")):
            data = copies[(copies.method == method) & (copies.tolerance == tolerance)]
            means = data.groupby("copies").budget_survives.mean() * 100
            ax.plot(means.index, means, color=color, marker=marker, label=method, markersize=5)
            for x, y in means.items():
                if method == "Copy counting" and x > 1:
                    ax.annotate(f"{y:.2f}%", (x, y), xytext=(0, 9), textcoords="offset points",
                                ha="center", fontsize=9, color=color)
        ax.set(xlabel="Copies per source domain", xticks=[1, 2, 3], xlim=(.85, 3.15), ylim=(-3, 115))
        ax.set_title("(a) One-domain loss budget" if tolerance == 1 else "(b) Two-domain loss budget", fontsize=10, pad=10)
        ax.grid(axis="x", visible=False)
    axes[0].set_ylabel("Witnesses satisfying loss budget (%)")
    axes[1].legend(loc="center right", fontsize=9)
    save(fig, destination / "correlated_copies.png")

    fig, axes = plt.subplots(1, 2, figsize=(7.0, 3.45), layout="constrained")
    for t in range(3):
        data = sc.query("roles==6 and tolerance==@t").groupby("domains").latency_ms
        med = data.median()
        axes[0].plot(med.index, med, color=COLORS[t], marker="o", label=labels_t[t])
        axes[0].fill_between(med.index, data.quantile(.25), data.quantile(.75), color=COLORS[t], alpha=.15)
        data2 = sc.query("domains==64 and tolerance==@t").groupby("roles").latency_ms
        med2 = data2.median()
        axes[1].plot(med2.index, med2, color=COLORS[t], marker="o")
        axes[1].fill_between(med2.index, data2.quantile(.25), data2.quantile(.75), color=COLORS[t], alpha=.15)
    axes[0].set(xlabel="Source domains (six roles)", ylabel="Exact solver time (ms)", yscale="log", xticks=[16, 32, 64])
    axes[1].set(xlabel="Evidence roles (64 domains)", ylabel="Exact solver time (ms)", yscale="log", xticks=[3, 4, 5, 6])
    axes[0].legend(fontsize=8, loc="upper left")
    save(fig, destination / "solver_scaling.png")

    fig, ax = plt.subplots(figsize=(6.9, 3.4), layout="constrained")
    stages = ["certificate_verification_ms", "optimization_ms", "permit_issue_ms", "local_commit_ms"]
    names = ["Verify certificates", "Solve witness", "Issue permit", "Revalidate and commit"]
    values = [rt[s].to_numpy() for s in stages]
    bp = ax.boxplot(values, tick_labels=names, patch_artist=True, showfliers=False, widths=.5,
                    medianprops={"color": "white", "linewidth": 1.5})
    for patch, color in zip(bp["boxes"], COLORS):
        patch.set_facecolor(color)
    ax.set(ylabel="Local processing time (ms)", yscale="log", ylim=(.04, 8))
    ax.grid(axis="x", visible=False)
    save(fig, destination / "runtime_stages.png")

    fig, ax = plt.subplots(figsize=(6.9, 3.4), layout="constrained")
    for t, color, label in zip(range(3), COLORS, labels_t):
        vals = op.query("method=='Exact' and tolerance==@t").fraction_bytes.to_numpy()
        budgets = np.linspace(.03, .4, 100)
        achieved = [np.mean(vals <= b) * 100 for b in budgets]
        ax.plot(budgets * 100, achieved, color=color, label=label)
    ax.set(xlabel="Witness budget as a share of all eligible evidence bytes (%)", ylabel="Workloads with a feasible witness (%)",
           ylim=(-2, 102), xlim=(3, 40))
    ax.legend(loc="lower right", fontsize=9)
    save(fig, destination / "budget_frontier.png")

    fig, ax = plt.subplots(figsize=(6.9, 3.4), layout="constrained")
    data = pub[pub.stage == "first"]
    attack_names = ["Physical Harm", "Financial Harm", "Data Security Harm", "Physical Data", "Financial Data", "Others"]
    box = ax.boxplot([data[data.attack_type == t].instruction_chars for t in attack_names], patch_artist=True,
                     tick_labels=["Physical\nharm", "Financial\nharm", "Data security\nharm", "Physical\ndata", "Financial\ndata", "Other\ndata"],
                     widths=.55, showfliers=False, medianprops={"color": "white"})
    for patch, color in zip(box["boxes"], [COLORS[0]] * 3 + [COLORS[1]] * 3):
        patch.set_facecolor(color)
    ax.set(ylabel="Attacker instruction length (characters)")
    ax.grid(axis="x", visible=False)
    save(fig, destination / "instruction_lengths.png")

    fig, ax = plt.subplots(figsize=(6.9, 3.4), layout="constrained")
    exact = op[op.method == "Exact"]
    for t in range(3):
        sizes = exact[exact.tolerance == t].groupby("selected_domains").size()
        ax.bar(sizes.index + (t - 1) * .23, sizes / 340 * 100, width=.22, color=COLORS[t], label=labels_t[t])
    ax.set(xlabel="Source domains retained in the exact witness", ylabel="Share of constructed workloads (%)", xticks=range(2, 9))
    ax.legend(fontsize=9)
    ax.grid(axis="x", visible=False)
    save(fig, destination / "witness_domain_counts.png")

    fig, ax = plt.subplots(figsize=(6.9, 3.6), layout="constrained")
    for t in range(3):
        o = op.query("method=='Exact' and tolerance==@t")
        a = av[(av.method == "Exact t=" + str(t)) & np.isclose(av.loss_probability, .2)]
        joined = o.merge(a[["case_id", "availability"]], on="case_id")
        ax.scatter(joined.fraction_bytes * 100, joined.availability * 100, s=18, alpha=.35, color=COLORS[t], label=labels_t[t])
    ax.set(xlabel="Eligible evidence bytes retained (%)", ylabel="Modeled availability at 20% domain loss (%)", ylim=(50, 101))
    ax.legend(fontsize=9, loc="lower right")
    save(fig, destination / "cost_availability.png")
    print("Created 13 scientific graphs at 350 dpi in", destination)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "figures")
    args = parser.parse_args()
    main(args.output.resolve())
