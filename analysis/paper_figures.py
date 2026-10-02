"""Publication figures, LaTeX tables, and a key-numbers sheet for the journal
paper -- every number quoted in the text should come from paper/key_numbers.md
so the prose, the tables, and the figures can never drift apart.

Unlike analysis/figures.py (a quick look at whatever is on disk), this script
is strict about provenance:

  * The concurrency figures/tables use only the sweep(s) named by
    --concurrency-run-id. Without one, they fall back to the legacy rows
    (no run_id column -- the original 2026-08-22 sweep) and every output is
    stamped PROVISIONAL, because that sweep has no Full PQC leg and several of
    its repetition files were later overwritten by smoke tests.
  * Latency is end-to-end (total_ms = handshake + protected request), the only
    latency directly comparable to control's single request.
  * Streaming results use one named run (--streaming-run-id, default the
    10-repetition real Llama-3.2-3B sweep), never a pool of runs.

Figures are sized for IEEE two-column layout (3.5 in single / 7.16 in double
column), serif type at 8 pt, and saved as vector PDF (for LaTeX) plus 300-dpi
PNG (for Word / slides). Config identity is carried by color AND hatch/marker,
so every figure survives grayscale printing.

Usage:
    python -m analysis.paper_figures                                  # provisional
    python -m analysis.paper_figures --concurrency-run-id 2026XXXXTXXXXXX
"""

from __future__ import annotations

import argparse
import glob
import json
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.ticker import FuncFormatter, LogLocator, NullFormatter
from scipy import stats

from analysis.aggregate import discard_warmup, load_raw, mann_whitney_vs_control
from analysis.tradeoff_matrix import WEIGHTINGS, build_matrix
from webapp.colors import CONFIG_COLORS, STRATEGY_COLORS

COL_W, DBL_W = 3.5, 7.16  # IEEE column widths (inches)

CONFIGS = ["control", "control_2rt", "classical", "classical_ecdhe", "hybrid", "hybrid_kex", "full_pqc", "hybrid_kex_pq"]
PROTECTED = ["classical", "classical_ecdhe", "hybrid", "hybrid_kex", "full_pqc", "hybrid_kex_pq"]
LABEL = {"control": "Control", "control_2rt": "Control-2RT", "classical": "Classical-RSA", "classical_ecdhe": "Classical-ECDHE",
         "hybrid": "Hybrid", "hybrid_kex": "Hybrid-KEX", "full_pqc": "Full PQC", "hybrid_kex_pq": "Hybrid-KEX-PQ"}
LABEL_LONG = {
    "control": "Control (no crypto)",
    "control_2rt": "Control-2RT (no crypto, two requests)",
    "classical": "Classical-RSA (RSA-2048 + ECDSA P-256, legacy)",
    "classical_ecdhe": "Classical-ECDHE (X25519 + ECDSA P-256)",
    "hybrid_kex": "Hybrid-KEX (X25519MLKEM768 + ECDSA P-256)",
    "hybrid": "Hybrid (ML-KEM-768 + ECDSA P-256)",
    "full_pqc": "Full PQC (ML-KEM-768 + ML-DSA-65)",
    "hybrid_kex_pq": "Hybrid-KEX-PQ (X25519MLKEM768 + ML-DSA-65)",
}
HATCH = {"control": "", "control_2rt": "", "classical": "", "classical_ecdhe": "....", "hybrid": "////", "hybrid_kex": "\\\\\\\\",
         "full_pqc": "xxxx", "hybrid_kex_pq": "++++"}
MARKER = {"control": "o", "control_2rt": "h", "classical": "s", "classical_ecdhe": "v", "hybrid": "^", "hybrid_kex": "P",
          "full_pqc": "D", "hybrid_kex_pq": "X"}
LINESTYLE = {"control": ":", "control_2rt": (0, (1, 2)), "classical": "-", "classical_ecdhe": (0, (5, 1.5, 1, 1.5, 1, 1.5)),
             "hybrid": "--", "hybrid_kex": (0, (1, 1)), "full_pqc": "-.", "hybrid_kex_pq": (0, (3, 1, 1, 1, 1, 1))}
STRATS = ["buffer_and_sign", "per_chunk", "hash_chain"]
STRAT_LABEL = {"buffer_and_sign": "Buffer-and-sign", "per_chunk": "Per-chunk", "hash_chain": "Hash-chain"}

INK, INK_2, GRID = "#1a1a1a", "#555555", "#e6e6e6"
DEFAULT_STREAMING_RUN = "20260908T180055"  # real Llama-3.2-3B (Q4_K_M), M3, 10 reps, 0 errors


def _style() -> None:
    plt.rcParams.update({
        "font.family": "serif",
        "font.serif": ["Times New Roman", "Times", "STIXGeneral", "DejaVu Serif"],
        "mathtext.fontset": "stix",
        "font.size": 8, "axes.titlesize": 8, "axes.labelsize": 8,
        "xtick.labelsize": 7, "ytick.labelsize": 7, "legend.fontsize": 7,
        "axes.edgecolor": INK_2, "axes.labelcolor": INK, "text.color": INK,
        "xtick.color": INK_2, "ytick.color": INK_2,
        "axes.spines.top": False, "axes.spines.right": False,
        "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.5, "axes.axisbelow": True,
        "lines.linewidth": 1.4, "lines.markersize": 4.5,
        "hatch.linewidth": 0.5, "hatch.color": "white",
        "legend.frameon": False,
        "pdf.fonttype": 42, "ps.fonttype": 42,  # embed TrueType: IEEE PDF eXpress requirement
        "savefig.dpi": 300, "savefig.bbox": "tight", "savefig.pad_inches": 0.02,
    })


class Out:
    """Collects outputs and the key-number sheet."""

    def __init__(self, root: str, provisional: bool):
        self.root = root
        self.fig_dir = os.path.join(root, "figures")
        self.tab_dir = os.path.join(root, "tables")
        os.makedirs(self.fig_dir, exist_ok=True)
        os.makedirs(self.tab_dir, exist_ok=True)
        self.provisional = provisional
        self.numbers: list[tuple[str, str, str]] = []  # (section, claim, value)
        self.notes: list[str] = []

    def fig(self, fig, name: str, provisional: bool = False) -> None:
        if provisional:
            fig.text(0.5, 0.5, "PROVISIONAL", fontsize=30, color="#d0d0d0", alpha=0.45,
                     ha="center", va="center", rotation=20, zorder=0)
        for ext in ("pdf", "png"):
            fig.savefig(os.path.join(self.fig_dir, f"{name}.{ext}"))
        plt.close(fig)
        print(f"  figure  {name}.pdf/.png" + ("  [PROVISIONAL]" if provisional else ""))

    def table(self, name: str, latex: str, provisional: bool = False) -> None:
        if provisional:
            latex = "% PROVISIONAL -- regenerate from a clean --concurrency-run-id before submission\n" + latex
        with open(os.path.join(self.tab_dir, f"{name}.tex"), "w") as f:
            f.write(latex)
        print(f"  table   {name}.tex" + ("  [PROVISIONAL]" if provisional else ""))

    def num(self, section: str, claim: str, value: str) -> None:
        self.numbers.append((section, claim, value))

    def write_numbers(self, provenance: dict) -> None:
        lines = ["# Key numbers for the paper", "",
                 "Generated by `python -m analysis.paper_figures` -- quote numbers from here, not by hand.", ""]
        lines += ["## Provenance", ""] + [f"- **{k}:** {v}" for k, v in provenance.items()] + [""]
        if self.notes:
            lines += ["## Data caveats", ""] + [f"- {n}" for n in self.notes] + [""]
        section = None
        for sec, claim, value in self.numbers:
            if sec != section:
                lines += ["", f"## {sec}", "", "| Claim | Value |", "|---|---|"]
                section = sec
            lines.append(f"| {claim} | {value} |")
        with open(os.path.join(self.root, "key_numbers.md"), "w") as f:
            f.write("\n".join(lines) + "\n")
        print("  numbers key_numbers.md")


# --------------------------------------------------------------------------- helpers

def _ok(df: pd.DataFrame) -> pd.DataFrame:
    return df[df["error"].isna() | (df["error"] == "")]


def _fmt_ms(v: float) -> str:
    if v is None or (isinstance(v, float) and np.isnan(v)):
        return "--"
    return f"{v / 1000:,.2f}\\,s" if v >= 10_000 else f"{v:,.1f}"


def _pct(v) -> str:
    # None = not applicable (e.g. buffer-and-sign has a single envelope, so a
    # "drop one chunk" attack has nothing to act on).
    return "n/a" if v is None else f"{v * 100:.0f}\\%"


def _fmt_p(p: float) -> str:
    if p is None or np.isnan(p):
        return "--"
    if p < 1e-3:
        return "$<10^{%d}$" % int(np.floor(np.log10(max(p, 1e-300))) + 1)
    return f"{p:.3f}"


def _log_axis(ax, axis: str = "y") -> None:
    target = ax.yaxis if axis == "y" else ax.xaxis
    target.set_major_locator(LogLocator(base=10))
    target.set_minor_formatter(NullFormatter())
    target.set_major_formatter(FuncFormatter(
        lambda v, _: f"{v:,.0f}" if v >= 1 else f"{v:g}"))


def _bar_label(ax, rect, text: str, inside: bool = False, fontsize: float = 6.0, horizontal: bool = False) -> None:
    if horizontal:
        x = rect.get_x() + rect.get_width()
        ax.annotate(text, (x, rect.get_y() + rect.get_height() / 2), xytext=(2, 0),
                    textcoords="offset points", ha="left", va="center", fontsize=fontsize, color=INK)
    else:
        y = rect.get_y() + rect.get_height()
        ax.annotate(text, (rect.get_x() + rect.get_width() / 2, y), xytext=(0, 1.5),
                    textcoords="offset points", ha="center", va="bottom", fontsize=fontsize, color=INK)


def _bar_kw(config: str) -> dict:
    return dict(color=CONFIG_COLORS[config], hatch=HATCH[config], edgecolor="white", linewidth=0.6)


# --------------------------------------------------------------------------- concurrency

def _latest_run_per_cell(df: pd.DataFrame) -> pd.DataFrame:
    """When the same configuration (under the same payload/network/session
    settings) appears in several runs, keep only its most recent run. run_ids
    are timestamps, so the lexically largest is the latest. This is how a
    corrective re-run supersedes earlier data -- e.g. the Control re-run
    after the async-endpoint fix -- without pooling the two."""
    if "run_id" not in df.columns or df["run_id"].isna().all():
        return df
    keys = ["config"] + [c for c in ("payload_profile", "network_profile", "requests_per_handshake")
                         if c in df.columns]
    # Rows from runs that predate a column carry NaN there; give them the value
    # that column defaults to, so an old run and its re-run compare as the same cell.
    defaults = {"payload_profile": "tabular_small", "network_profile": "localhost", "requests_per_handshake": 1}
    df = df.assign(**{c: df[c].fillna(defaults[c]) for c in keys if c in defaults})
    if "requests_per_handshake" in df.columns:
        df["requests_per_handshake"] = df["requests_per_handshake"].astype(int)
    # map, not astype(str): newer pandas keeps NaN as missing under astype(str),
    # which breaks the join for rows that predate a column (e.g. requests_per_handshake).
    k = df[keys].apply(lambda col: col.map(lambda v: "-" if pd.isna(v) else str(v))).agg("|".join, axis=1)
    latest = df.groupby(k)["run_id"].transform(lambda r: r.astype(str).max())
    return df[df["run_id"].astype(str) == latest]


def load_concurrency(results_dir: str, run_ids: list[str] | None, warmup: float):
    raw = load_raw(os.path.join(results_dir, "raw"))
    if run_ids:
        df = _latest_run_per_cell(raw[raw["run_id"].astype(str).isin(run_ids)])
        provisional = False
        label = ", ".join(run_ids)
    else:
        # Legacy rows: the original full sweep, written before run_id existed.
        df = raw[raw["run_id"].isna()] if "run_id" in raw.columns else raw
        provisional = True
        label = "legacy (pre-run_id) rows -- original 2026-08-22 sweep, partially overwritten"
    if df.empty:
        raise SystemExit("No concurrency rows selected.")
    # A cell where every request got HTTP 404 hit the wrong server (harness
    # misconfiguration -- e.g. a smoke test against a stale port), so it says
    # nothing about the configuration under test. Drop it rather than count
    # it as 100% failure.
    err = df["error"].fillna("").astype(str)
    keys = [k for k in ("run_id", "config", "concurrency", "repetition") if k in df.columns]
    all_404 = err.str.contains("404").groupby([df[k].fillna("-") for k in keys]).transform("all")
    df = df[~all_404]
    return discard_warmup(df.reset_index(drop=True), warmup), provisional, label


def concurrency_stats(df: pd.DataFrame) -> pd.DataFrame:
    is_err = df["error"].notna() & (df["error"] != "")
    rows = []
    for (cfg, conc), g in df.groupby(["config", "concurrency"]):
        okg = g[~is_err.loc[g.index]]
        ok = okg["total_ms"].dropna()
        rep_med = okg.groupby("repetition")["total_ms"].median()
        rows.append({
            "config": cfg, "concurrency": int(conc),
            "n_attempted": len(g), "n_ok": len(ok), "n_reps": g["repetition"].nunique(),
            "error_rate": float(is_err.loc[g.index].mean()),
            "median": ok.median() if len(ok) else np.nan,
            "q25": ok.quantile(0.25) if len(ok) else np.nan,
            "q75": ok.quantile(0.75) if len(ok) else np.nan,
            "p95": ok.quantile(0.95) if len(ok) else np.nan,
            "p99": ok.quantile(0.99) if len(ok) else np.nan,
            "rep_min": rep_med.min() if len(rep_med) else np.nan,
            "rep_max": rep_med.max() if len(rep_med) else np.nan,
        })
    return pd.DataFrame(rows)


def fig_concurrency(out: Out, st: pd.DataFrame, provisional: bool, res: pd.DataFrame | None = None) -> None:
    fig, (ax, axe) = plt.subplots(1, 2, figsize=(DBL_W, 2.35), gridspec_kw={"width_ratios": [1.35, 1]})
    levels = sorted(st["concurrency"].unique())
    for cfg in CONFIGS:
        s = st[st["config"] == cfg].sort_values("concurrency")
        if s.empty:
            continue
        good = s[s["error_rate"] < 0.5]
        ax.errorbar(good["concurrency"], good["median"],
                    yerr=[good["median"] - good["q25"], good["q75"] - good["median"]],
                    color=CONFIG_COLORS[cfg], marker=MARKER[cfg], ls=LINESTYLE[cfg],
                    capsize=2, elinewidth=0.8, label=LABEL[cfg], zorder=3)
        ax.plot(good["concurrency"], good["p95"], color=CONFIG_COLORS[cfg], marker=MARKER[cfg],
                ls="none", mfc="white", ms=3.5, zorder=3)
        for _, r in s[s["error_rate"] >= 0.5].iterrows():
            # Failed cell: an x on the top edge plus a label set off to the left,
            # clear of any surviving configs' points at the same level.
            ax.plot([r["concurrency"]], [1.0], transform=ax.get_xaxis_transform(), marker="X", ms=6,
                    color=CONFIG_COLORS[cfg], clip_on=False, ls="none", zorder=4)
            ax.annotate(f"{LABEL[cfg]}: {r['error_rate']:.0%} of\nrequests failed", (r["concurrency"], 1.0),
                        xycoords=("data", "axes fraction"), xytext=(-8, -3), textcoords="offset points",
                        ha="right", va="top", fontsize=6, color=CONFIG_COLORS[cfg], fontweight="bold")
    ax.set_xscale("log")
    ax.set_yscale("log")
    _log_axis(ax, "y")
    ax.set_xticks(levels)
    ax.set_xticklabels([f"{c:,}" for c in levels])
    ax.set_xlabel("Concurrent connections")
    ax.set_ylabel("End-to-end latency (ms)")
    ax.set_title("(a) Latency: median with IQR; hollow marker = p95", loc="left")
    ax.legend(loc="upper left", ncol=2, handlelength=2.2)

    present = [c for c in CONFIGS if c in set(st["config"])]
    width = 0.8 / len(present)
    x = np.arange(len(levels))
    if res is not None and not res.empty:
        # Server CPU in cores (100% = one core): failures are rare once the
        # baseline is fixed, but RSA key generation's CPU appetite is not.
        cpu = res.groupby(["concurrency", "config"])["cpu_percent_mean"].mean() / 100
        for i, cfg in enumerate(present):
            vals = [cpu.get((c, cfg), np.nan) for c in levels]
            rects = axe.bar(x + (i - (len(present) - 1) / 2) * width, vals, width, label=LABEL[cfg], **_bar_kw(cfg))
            for rect, v in zip(rects, vals):
                if not np.isnan(v) and v >= 1.5:
                    _bar_label(axe, rect, f"{v:.1f}", fontsize=5.5)
        top = np.nanmax(cpu.values)
        axe.set_ylim(0, top * 1.75)  # headroom so the legend clears the bars
        axe.set_yticks(np.arange(0, top + 0.5, 1))  # no ticks under the legend
        axe.set_ylabel("Mean server CPU (cores)")
        axe.set_title("(b) Server CPU use", loc="left")
    else:
        for i, cfg in enumerate(present):
            s_ = st[st["config"] == cfg].set_index("concurrency")
            vals = [s_["error_rate"].get(c, np.nan) * 100 for c in levels]
            axe.bar(x + (i - (len(present) - 1) / 2) * width, vals, width, label=LABEL[cfg], **_bar_kw(cfg))
        axe.set_ylabel("Failed requests (%)")
        axe.set_title("(b) Request failure rate", loc="left")
    axe.set_xticks(x)
    axe.set_xticklabels([f"{c:,}" for c in levels])
    axe.set_xlabel("Concurrent connections")
    axe.grid(axis="x", visible=False)
    axe.legend(loc="upper center", bbox_to_anchor=(0.53, 1.0), ncol=4, fontsize=5.5, handlelength=1.2,
               columnspacing=0.6)
    fig.tight_layout(w_pad=1.5)
    out.fig(fig, "fig_concurrency_latency", provisional)


def fig_decomposition(out: Out, df: pd.DataFrame, provisional: bool, concurrency: int) -> None:
    ok = _ok(df[df["concurrency"] == concurrency])
    if ok.empty:
        return
    parts = [("handshake_ms", "Handshake round trip", "#9aa5b1"),
             ("server_crypto_ms", "Server crypto (decaps + sign)", "#2f5d8a"),
             ("server_inference_ms", "Model inference", "#7fb27f"),
             ("_transport", "Transport, queueing & framework", "#d9d9d9"),
             ("verify_ms", "Client signature verify", "#c9822b")]
    fig, ax = plt.subplots(figsize=(COL_W, 1.75))
    cfgs = [c for c in CONFIGS if c in ok["config"].unique()]
    for yi, cfg in enumerate(cfgs):
        g = ok[ok["config"] == cfg]
        mean = {c: g[c].mean() if c in g and g[c].notna().any() else 0.0
                for c in ["handshake_ms", "server_crypto_ms", "server_inference_ms", "verify_ms", "rtt_ms"]}
        mean["_transport"] = max(mean["rtt_ms"] - mean["server_crypto_ms"] - mean["server_inference_ms"], 0.0)
        left = 0.0
        for col, _, color in parts:
            w = mean[col]
            ax.barh(yi, w, left=left, color=color, edgecolor="white", linewidth=0.6, height=0.62)
            left += w
        ax.annotate(f"{left:,.0f} ms", (left, yi), xytext=(3, 0), textcoords="offset points",
                    va="center", fontsize=6.5)
    ax.set_yticks(range(len(cfgs)))
    ax.set_yticklabels([LABEL[c] for c in cfgs])
    ax.invert_yaxis()
    ax.set_xlabel(f"Mean time per transaction at {concurrency} connections (ms)")
    ax.grid(axis="y", visible=False)
    handles = [plt.Rectangle((0, 0), 1, 1, color=c) for _, _, c in parts]
    ax.legend(handles, [l for _, l, _ in parts], loc="upper center", bbox_to_anchor=(0.45, -0.32),
              ncol=2, fontsize=6, columnspacing=1.0, handlelength=1.2)
    ax.set_xlim(0, ax.get_xlim()[1] * 1.12)
    out.fig(fig, "fig_latency_decomposition", provisional)


# --- inference: repetition is the statistical unit ----------------------------------------
#
# Requests within one repetition share a server process, warm-up state, and
# queue, so they are not independent observations; treating thousands of them
# as independent is what produced p-values like 1e-299. Significance is
# therefore tested on the five per-repetition medians, effect sizes and
# uncertainty come from a two-stage (repetition, then request) bootstrap, and
# p-values are Holm-corrected across the family of comparisons reported.

BOOT_B = 1000
BOOT_CAP = 3000  # max requests drawn per repetition per bootstrap draw (speed; preserves the distribution)


def _rep_arrays(ok: pd.DataFrame, cfg: str, conc: int) -> list[np.ndarray]:
    g = ok[(ok["config"] == cfg) & (ok["concurrency"] == conc)]
    return [r["total_ms"].dropna().to_numpy() for _, r in g.groupby("repetition")]


def _hboot_diff(a: list[np.ndarray], b: list[np.ndarray], rng: np.random.Generator) -> np.ndarray:
    """Bootstrap distribution of median(a) - median(b): resample repetitions,
    then requests within each chosen repetition."""
    out = np.empty(BOOT_B)

    def draw(reps):
        picks = rng.integers(0, len(reps), len(reps))
        return np.concatenate([rng.choice(reps[k], size=min(len(reps[k]), BOOT_CAP)) for k in picks])

    for t in range(BOOT_B):
        out[t] = np.median(draw(a)) - np.median(draw(b))
    return out


def _cliffs_delta(x: np.ndarray, y: np.ndarray) -> float:
    """P(X>Y) - P(X<Y), via the Mann-Whitney U statistic (request level, descriptive)."""
    u = stats.mannwhitneyu(x, y, alternative="two-sided").statistic
    return 2 * u / (len(x) * len(y)) - 1


def _holm(pvals: list[float]) -> list[float]:
    order = np.argsort(pvals)
    m = len(pvals)
    adj = np.empty(m)
    running = 0.0
    for rank, idx in enumerate(order):
        running = max(running, (m - rank) * pvals[idx])
        adj[idx] = min(1.0, running)
    return list(adj)


def comparison_stats(df: pd.DataFrame, pairs: list[tuple[str, str]], seed: int = 7) -> pd.DataFrame:
    """For each (config, reference) pair at each concurrency: median difference
    (ms and % of the reference median), 95% and 90% two-stage bootstrap CIs,
    Mann-Whitney U on per-repetition medians (Holm-corrected over all rows
    returned), and Cliff's delta on requests."""
    ok = _ok(df)
    rng = np.random.default_rng(seed)
    rows = []
    for conc in sorted(ok["concurrency"].unique()):
        for cfg, ref in pairs:
            a, b = _rep_arrays(ok, cfg, conc), _rep_arrays(ok, ref, conc)
            if len(a) < 2 or len(b) < 2:
                continue
            ref_med = np.median(np.concatenate(b))
            diff = np.median(np.concatenate(a)) - ref_med
            boot = _hboot_diff(a, b, rng)
            p_rep = stats.mannwhitneyu([np.median(x) for x in a], [np.median(x) for x in b],
                                       alternative="two-sided", method="exact").pvalue
            rows.append({
                "concurrency": int(conc), "config": cfg, "reference": ref,
                "diff_ms": diff, "ci95_lo": np.percentile(boot, 2.5), "ci95_hi": np.percentile(boot, 97.5),
                "ci90_lo": np.percentile(boot, 5), "ci90_hi": np.percentile(boot, 95),
                "ref_median": ref_med, "diff_pct": 100 * diff / ref_med,
                "p_rep": p_rep, "cliffs_delta": _cliffs_delta(np.concatenate(a), np.concatenate(b)),
                "n_reps": (len(a), len(b)),
            })
    res = pd.DataFrame(rows)
    if not res.empty:
        # Holm family = all configurations compared with one reference at one
        # concurrency level (the question "which configs differ from X here?").
        res["p_holm"] = np.nan
        for _, idx in res.groupby(["concurrency", "reference"]).groups.items():
            res.loc[idx, "p_holm"] = _holm(res.loc[idx, "p_rep"].tolist())
    return res


def _fmt_ci(v: float, lo: float, hi: float) -> str:
    big = max(abs(v), abs(lo), abs(hi)) >= 1000
    f = (lambda x: f"{x / 1000:+.2f}") if big else (lambda x: f"{x:+.1f}")
    unit = r"\,s" if big else ""
    return f"{f(v)} [{f(lo)}, {f(hi)}]{unit}"


def table_concurrency(out: Out, st: pd.DataFrame, cmp: pd.DataFrame, provisional: bool) -> None:
    ctl = cmp[cmp["reference"] == "control"].set_index(["concurrency", "config"])
    rt2 = cmp[cmp["reference"] == "control_2rt"].set_index(["concurrency", "config"])
    has_2rt = not rt2.empty
    lines = [r"\begin{table*}[t]", r"\centering",
             r"\caption{End-to-end latency (handshake + protected request) by configuration and concurrency, over "
             r"successful requests after 5\% warm-up trimming. ``Rep.\ range'': spread of the five per-repetition "
             r"medians. $\Delta$: difference in medians (ms) with a 95\% two-stage bootstrap CI (repetitions, then "
             r"requests), versus Control and"
             + (r" versus Control-2RT, the matched no-crypto protocol (making $\Delta_{2RT}$ the cryptographic "
                r"overhead alone)" if has_2rt else "")
             + r". $\delta$: Cliff's delta versus Control. $p$: two-sided Mann--Whitney $U$ on per-repetition "
               r"medians (5 vs.\ 5; smallest attainable 0.008), Holm-corrected within each concurrency level.}",
             r"\label{tab:concurrency}", r"\setlength{\tabcolsep}{2pt}", r"\footnotesize",
             r"\begin{tabular}{@{}rlrrrr" + ("rr" if has_2rt else "r") + r"rr@{}}", r"\toprule",
             r"Conc. & Configuration & Median (ms) & Rep.\ range (ms) & p95 (ms) & Fail & "
             r"$\Delta$ vs.\ Control & " + (r"$\Delta_{2RT}$ (crypto) & " if has_2rt else "")
             + r"$\delta$ & $p_{\mathrm{Holm}}$ \\",
             r"\midrule"]
    for conc in sorted(st["concurrency"].unique()):
        sub = st[st["concurrency"] == conc].set_index("config")
        first = True
        for cfg in CONFIGS:
            if cfg not in sub.index:
                continue
            r = sub.loc[cfg]
            key = (conc, cfg)
            if key in ctl.index:
                c = ctl.loc[key]
                d_ctl = _fmt_ci(c["diff_ms"], c["ci95_lo"], c["ci95_hi"])
                delta, p = f"{c['cliffs_delta']:+.2f}", f"{c['p_holm']:.3f}"
            else:
                d_ctl, delta, p = ("ref." if cfg == "control" else "--"), "--", "--"
            cells = [d_ctl]
            if has_2rt:
                cells.append(_fmt_ci(rt2.loc[key, "diff_ms"], rt2.loc[key, "ci95_lo"], rt2.loc[key, "ci95_hi"])
                             if key in rt2.index else ("ref." if cfg == "control_2rt" else "--"))
            lines.append(
                f"{f'{conc:,}' if first else ''} & {LABEL[cfg]} & {_fmt_ms(r['median'])} & "
                f"{_fmt_ms(r['rep_min'])}--{_fmt_ms(r['rep_max'])} & {_fmt_ms(r['p95'])} & "
                f"{r['error_rate'] * 100:.1f}\\% & " + " & ".join(cells) + f" & {delta} & {p} \\\\")
            first = False
        lines.append(r"\addlinespace")
    lines[-1] = r"\bottomrule"
    lines += [r"\end{tabular}", r"\end{table*}", ""]
    out.table("tab_concurrency", "\n".join(lines), provisional)


EQUIV_MARGIN_PCT = 5.0


def table_equivalence(out: Out, cmp: pd.DataFrame) -> None:
    """TOST-style equivalence: the ML-KEM configurations are declared
    equivalent to Classical-ECDHE at a concurrency level if the 90% bootstrap
    CI of the median difference lies within +/- EQUIV_MARGIN_PCT of the
    Classical-ECDHE median."""
    eq = cmp[cmp["reference"] == "classical_ecdhe"]
    if eq.empty:
        return
    lines = [r"\begin{table}[t]", r"\centering",
             fr"\caption{{Equivalence of ML-KEM-based key establishment to the X25519 baseline (Classical-ECDHE): "
             fr"median end-to-end difference with its 90\% two-stage bootstrap CI, as a percentage of the "
             fr"Classical-ECDHE median. ``Equiv.'': the CI lies within $\pm${EQUIV_MARGIN_PCT:.0f}\% "
             fr"(two one-sided tests at $\alpha=0.05$). A verdict is given only at 10 connections. At 100 connections the "
             fr"protected configurations are bimodal, and at 1,000 client--server contention on the shared host dominates "
             fr"(the protected configurations are faster than the no-crypto Control-2RT), so differences there are shown "
             fr"for completeness and are not interpreted as equivalence or difference.}}",
             r"\label{tab:equivalence}", r"\setlength{\tabcolsep}{3pt}", r"\footnotesize",
             r"\begin{tabular}{@{}rlrl@{}}", r"\toprule",
             r"Conc. & Configuration & $\Delta$ (\%) [90\% CI] & Equiv. \\", r"\midrule"]
    # "n/i" = not interpreted (see caption)
    verdict_level = int(eq["concurrency"].min())  # the only level not dominated by single-host contention
    for conc in sorted(eq["concurrency"].unique()):
        first = True
        for _, r in eq[eq["concurrency"] == conc].iterrows():
            lo, hi = 100 * r["ci90_lo"] / r["ref_median"], 100 * r["ci90_hi"] / r["ref_median"]
            ok_ = -EQUIV_MARGIN_PCT < lo and hi < EQUIV_MARGIN_PCT
            verdict = ("yes" if ok_ else "no") if conc == verdict_level else "n/i"
            lines.append(f"{f'{conc:,}' if first else ''} & {LABEL[r['config']]} & "
                         f"{r['diff_pct']:+.1f} [{lo:+.1f}, {hi:+.1f}] & {verdict} \\\\")
            out.num("Equivalence vs Classical-ECDHE (90% CI, +/-5% margin)",
                    f"{LABEL[r['config']]} @ {conc:,}",
                    f"{r['diff_pct']:+.1f}% [{lo:+.1f}, {hi:+.1f}] -> {'equivalent' if ok_ else 'not shown equivalent'}")
            first = False
        lines.append(r"\addlinespace")
    lines[-1] = r"\bottomrule"
    lines += [r"\end{tabular}", r"\end{table}", ""]
    out.table("tab_equivalence", "\n".join(lines))


# --------------------------------------------------------------------------- primitives

PRIM_SIZES = {  # FIPS 203/204 sizes, and the DER sizes this harness puts on the wire
    "ML-KEM-768": "pk 1,184 B / ct 1,088 B",
    "RSA-2048 OAEP": "ct 256 B",
    "ML-DSA-65": "sig 3,309 B",
    "ECDSA P-256": "sig $\\approx$71 B (DER)",
}


def fig_primitives(out: Out, bench: dict) -> None:
    kem, dsa, cl = bench["ml_kem_768"], bench["ml_dsa_65"], bench["classical"]
    ops = lambda d: 1e6 / d["median_us"]
    panels = [
        ("(a) Key establishment", [
            ("RSA-2048 keygen", ops(cl["rsa2048_keygen"]), "classical"),
            ("RSA-OAEP encrypt", ops(cl["rsa2048_oaep_encrypt"]), "classical"),
            ("RSA-OAEP decrypt", ops(cl["rsa2048_oaep_decrypt"]), "classical"),
            *([("X25519 keygen", ops(cl["x25519_keygen"]), "classical_ecdhe"),
               ("X25519 exchange", ops(cl["x25519_exchange"]), "classical_ecdhe")] if "x25519_keygen" in cl else []),
            ("ML-KEM-768 keygen", ops(kem["keygen"]), "full_pqc"),
            ("ML-KEM-768 encaps", ops(kem["encaps"]), "full_pqc"),
            ("ML-KEM-768 decaps", ops(kem["decaps"]), "full_pqc"),
        ]),
        ("(b) Signatures", [
            ("ECDSA P-256 sign", ops(cl["ecdsa_p256_sign"]), "classical"),
            ("ECDSA P-256 verify", ops(cl["ecdsa_p256_verify"]), "classical"),
            ("ML-DSA-65 sign", ops(dsa["sign"]), "full_pqc"),
            ("ML-DSA-65 verify", ops(dsa["verify"]), "full_pqc"),
        ]),
    ]
    fig, axes = plt.subplots(1, 2, figsize=(DBL_W, 1.9), gridspec_kw={"width_ratios": [1.5, 1]})
    for ax, (title, items) in zip(axes, panels):
        y = np.arange(len(items))
        for yi, (name, v, fam) in zip(y, items):
            rect = ax.barh(yi, v, color=CONFIG_COLORS[fam], hatch=HATCH[fam], edgecolor="white", height=0.62)[0]
            _bar_label(ax, rect, f"{v:,.0f}", horizontal=True, fontsize=6)
        ax.set_yticks(y)
        ax.set_yticklabels([n for n, _, _ in items])
        ax.invert_yaxis()
        ax.set_xscale("log")
        _log_axis(ax, "x")
        ax.set_xlim(1 if "Key" in title else 1e3, max(v for _, v, _ in items) * 6)
        ax.set_xlabel("Operations per second (median-based, log scale)")
        ax.set_title(title, loc="left")
        ax.grid(axis="y", visible=False)
    fams = [("classical", "RSA / ECDSA"), ("classical_ecdhe", "X25519 (ECDHE)"),
            ("full_pqc", "Post-quantum (liboqs)")]
    fams = [f for f in fams if any(fam == f[0] for _, items in panels for _, _, fam in items)]
    handles = [plt.Rectangle((0, 0), 1, 1, facecolor=CONFIG_COLORS[f], hatch=HATCH[f], edgecolor="white")
               for f, _ in fams]
    fig.legend(handles, [l for _, l in fams], loc="lower center", ncol=len(fams), bbox_to_anchor=(0.5, -0.06))
    fig.tight_layout(rect=(0, 0.06, 1, 1), w_pad=2)
    out.fig(fig, "fig_primitive_throughput")

    ratio_med = cl["rsa2048_keygen"]["median_us"] / kem["keygen"]["median_us"]
    ratio_mean = cl["rsa2048_keygen"]["mean_us"] / kem["keygen"]["mean_us"]
    n_rsa = cl["rsa2048_keygen"]["iterations"]
    out.num("Primitive micro-benchmark", "RSA-2048 keygen / ML-KEM-768 keygen (median ratio)", f"{ratio_med:,.0f}x")
    out.num("Primitive micro-benchmark", "RSA-2048 keygen / ML-KEM-768 keygen (mean ratio)", f"{ratio_mean:,.0f}x")
    out.num("Primitive micro-benchmark", "RSA-2048 keygen samples", f"{n_rsa}")
    if "x25519_keygen" in cl:
        out.num("Primitive micro-benchmark", "X25519 keygen vs ML-KEM-768 keygen (median, us)",
                f"{cl['x25519_keygen']['median_us']:.1f} vs {kem['keygen']['median_us']:.1f}")
        out.num("Primitive micro-benchmark", "Server-side handshake work: X25519 keygen+exchange vs ML-KEM keygen+decaps (median, us)",
                f"{cl['x25519_keygen']['median_us'] + cl['x25519_exchange']['median_us']:.1f} vs "
                f"{kem['keygen']['median_us'] + kem['decaps']['median_us']:.1f}")
    else:
        out.notes.append("primitive_bench.json predates the X25519 rows; re-run validation.primitive_bench.")
    out.num("Primitive micro-benchmark", "RSA-2048 keygen median / range",
            f"{cl['rsa2048_keygen']['median_us'] / 1000:.1f} ms ({cl['rsa2048_keygen']['min_us'] / 1000:.1f}-{cl['rsa2048_keygen']['max_us'] / 1000:.1f} ms)")
    out.num("Primitive micro-benchmark", "ML-DSA-65 verify vs ECDSA P-256 verify (ops/s, median-based)",
            f"{ops(dsa['verify']):,.0f} vs {ops(cl['ecdsa_p256_verify']):,.0f} ({ops(dsa['verify']) / ops(cl['ecdsa_p256_verify']):.2f}x)")
    out.num("Primitive micro-benchmark", "ML-DSA-65 sign p99/median (rejection-sampling skew)",
            f"{dsa['sign']['p99_us'] / dsa['sign']['median_us']:.2f}x")
    if n_rsa < 30:
        out.notes.append(f"RSA-2048 keygen was timed over only {n_rsa} samples; re-run "
                         "`python -m validation.primitive_bench --output results/validation/primitive_bench.json` "
                         "(now >=50 samples by default) before citing the keygen ratio.")

    rows = [
        ("ML-KEM-768", "KeyGen", kem["keygen"]), ("ML-KEM-768", "Encaps", kem["encaps"]),
        ("ML-KEM-768", "Decaps", kem["decaps"]),
        ("RSA-2048", "KeyGen", cl["rsa2048_keygen"]), ("RSA-2048 OAEP", "Encrypt", cl["rsa2048_oaep_encrypt"]),
        ("RSA-2048 OAEP", "Decrypt", cl["rsa2048_oaep_decrypt"]),
        ("ML-DSA-65", "KeyGen", dsa["keygen"]), ("ML-DSA-65", "Sign", dsa["sign"]),
        ("ML-DSA-65", "Verify", dsa["verify"]),
        ("ECDSA P-256", "KeyGen", cl["ecdsa_p256_keygen"]), ("ECDSA P-256", "Sign", cl["ecdsa_p256_sign"]),
        ("ECDSA P-256", "Verify", cl["ecdsa_p256_verify"]),
    ]
    if "x25519_keygen" in cl:
        rows[3:3] = [("X25519", "KeyGen", cl["x25519_keygen"]), ("X25519", "Exchange", cl["x25519_exchange"])]
    lines = [r"\begin{table}[t]", r"\centering",
             r"\caption{Primitive-level micro-benchmark (single process, warm loop). $n$ = timed iterations.}",
             r"\label{tab:primitives}", r"\setlength{\tabcolsep}{3pt}", r"\footnotesize",
             r"\begin{tabular}{@{}llrrrr@{}}", r"\toprule",
             r"Algorithm & Op. & $n$ & Median ($\mu$s) & p99 ($\mu$s) & ops/s \\", r"\midrule"]
    prev = None
    for alg, op, d in rows:
        if prev and alg.split()[0] != prev.split()[0]:
            lines.append(r"\addlinespace")
        lines.append(f"{alg} & {op} & {d['iterations']} & {d['median_us']:,.1f} & {d['p99_us']:,.1f} & "
                     f"{1e6 / d['median_us']:,.0f} \\\\")
        prev = alg
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}", ""]
    out.table("tab_primitives", "\n".join(lines))


# --------------------------------------------------------------------------- bytes / HNDL / MITM

def _read_json_glob(pattern: str) -> list[dict]:
    out = []
    for p in sorted(glob.glob(pattern)):
        with open(p) as f:
            out.append(json.load(f))
    return out


def fig_wire_bytes(out: Out, results_dir: str) -> None:
    hndl = {d["config"]: d for d in _read_json_glob(os.path.join(results_dir, "hndl", "*-hndl-summary.json"))}
    cfgs = [c for c in PROTECTED if c in hndl]
    if not cfgs:
        return
    parts = [("kex", "Key-establishment blob", "#2f5d8a"), ("ct", "AEAD ciphertext + tag", "#9aa5b1"),
             ("sig", "Signature", "#c9822b")]
    fig, ax = plt.subplots(figsize=(COL_W, 1.45))
    for yi, cfg in enumerate(cfgs):
        d = hndl[cfg]
        vals = {"kex": d["kex_bytes_per_request"], "sig": d["signature_bytes_per_request"]}
        vals["ct"] = d["bytes_per_request_mean"] - vals["kex"] - vals["sig"]
        left = 0
        for key, _, color in parts:
            ax.barh(yi, vals[key], left=left, color=color, edgecolor="white", linewidth=0.6, height=0.6)
            left += vals[key]
        tag = "CRQC-decryptable" if d["kex_decryptable_under_future_crqc"] else "not CRQC-decryptable"
        ax.annotate(f"{left:,.0f} B  ({tag})", (left, yi), xytext=(3, 0), textcoords="offset points",
                    va="center", fontsize=6.3)
        out.num("Harvest-now-decrypt-later (single transaction)", f"{LABEL[cfg]}: harvestable bytes per transaction",
                f"{left:,.0f} B (kex {vals['kex']:,}, ciphertext {vals['ct']:,.0f}, signature {vals['sig']:,}); "
                f"KEX CRQC-decryptable: {d['kex_decryptable_under_future_crqc']}")
    ax.set_yticks(range(len(cfgs)))
    ax.set_yticklabels([LABEL[c] for c in cfgs])
    ax.invert_yaxis()
    ax.set_xlim(0, max(hndl[c]["bytes_per_request_mean"] for c in cfgs) * 1.75)
    ax.set_xlabel("Bytes captured per transaction by a passive adversary")
    ax.grid(axis="y", visible=False)
    handles = [plt.Rectangle((0, 0), 1, 1, color=c) for _, _, c in parts]
    ax.legend(handles, [l for _, l, _ in parts], loc="upper center", bbox_to_anchor=(0.45, -0.38), ncol=3,
              fontsize=6, handlelength=1.2, columnspacing=0.8)
    out.fig(fig, "fig_wire_bytes")


def fig_streaming_hndl(out: Out, results_dir: str) -> None:
    paths = sorted(glob.glob(os.path.join(results_dir, "hndl", "streaming", "*-streaming-hndl.csv")))
    if not paths:
        return
    df = pd.concat([pd.read_csv(p) for p in paths], ignore_index=True)
    df = df[df["error"].isna()]
    # x = tokens actually generated: a real model may stop (EOS) before max_tokens.
    df["tokens"] = df["n_chunks"] * df["chunk_size_tokens"]
    fig, ax = plt.subplots(figsize=(COL_W, 2.1))
    for cfg in PROTECTED:
        s = df[df["config"] == cfg].sort_values("tokens")
        if s.empty:
            continue
        ax.plot(s["tokens"], s["decryptable_bytes_under_future_crqc"], color=CONFIG_COLORS[cfg],
                marker=MARKER[cfg], ls=LINESTYLE[cfg], label=LABEL[cfg], zorder=3)
        if bool(s["kex_decryptable_under_future_crqc"].iloc[0]) and len(s) >= 2:
            fit = stats.linregress(s["tokens"], s["decryptable_bytes_under_future_crqc"])
            if cfg == "classical":
                ax.text(0.97, 0.30, f"Classical-RSA/-ECDHE: {fit.slope:.1f} B/token\n$R^2$ = {fit.rvalue ** 2:.4f}",
                        transform=ax.transAxes, ha="right", va="bottom", fontsize=6.3, color=INK)
            out.num("Streaming HNDL exposure", f"{LABEL[cfg]} decryptable bytes vs generated tokens (linear fit)",
                    f"{fit.slope:.2f} B/token, R^2 = {fit.rvalue ** 2:.4f}, n = {len(s)} lengths, "
                    f"{int(s['tokens'].min())}-{int(s['tokens'].max())} tokens")
            # Decryptable volume counts whole AEAD records (12 B nonce + ciphertext + 16 B GCM tag);
            # the plaintext a CRQC would actually recover excludes those 28 B of framing per chunk.
            plain = s["decryptable_bytes_under_future_crqc"] - 28 * s["n_chunks"]
            pfit = stats.linregress(s["tokens"], plain)
            out.num("Streaming HNDL exposure", f"{LABEL[cfg]} recoverable plaintext vs generated tokens (linear fit)",
                    f"{pfit.slope:.2f} B/token, R^2 = {pfit.rvalue ** 2:.4f} (records minus 28 B framing per chunk)")
            out.num("Streaming HNDL exposure", f"{LABEL[cfg]} decryptable bytes at each length",
                    ", ".join(f"{int(t)} tok -> {int(b):,} B" for t, b in
                              zip(s["tokens"], s["decryptable_bytes_under_future_crqc"])))
        else:
            out.num("Streaming HNDL exposure", f"{LABEL[cfg]} decryptable bytes (all lengths)",
                    f"{int(s['decryptable_bytes_under_future_crqc'].max())} B; raw harvestable "
                    f"{int(s['total_bytes_harvestable'].min()):,}-{int(s['total_bytes_harvestable'].max()):,} B")
    fp = df[df["config"] == "full_pqc"].sort_values("tokens")
    if not fp.empty:
        ax.plot(fp["tokens"], fp["total_bytes_harvestable"], color=INK_2, lw=0.9, ls=(0, (1, 1.5)),
                label="Full PQC: bytes harvested")
    ax.set_xlabel("Tokens generated in the stream")
    ax.set_ylabel("Bytes a future CRQC could decrypt")
    ax.text(0.97, 0.11, "All ML-KEM configurations: 0 B", transform=ax.transAxes, ha="right",
            va="bottom", fontsize=6, color=INK_2)
    ax.legend(loc="upper left", fontsize=6)
    if (df["n_chunks"] * df["chunk_size_tokens"] < df["max_tokens"]).any():
        out.notes.append("Streaming HNDL: the real model ended some streams (EOS) before max_tokens, so the "
                         "x-axis is tokens actually generated (n_chunks x chunk size), not the requested length.")
    out.fig(fig, "fig_streaming_hndl")


def table_threats(out: Out, results_dir: str) -> None:
    """Single-response tampering. Streaming sequence attacks are in the
    campaign table (table_attack_campaign), which supersedes the earlier
    10-trial streaming summaries."""
    mitm = _read_json_glob(os.path.join(results_dir, "mitm", "*-mitm-*-summary.json"))
    lines = [r"\begin{table}[t]", r"\centering",
             r"\caption{Tampering with single responses: one flipped bit per response, in the AEAD ciphertext or in "
             r"the signature. Detection time is the rejecting check alone (median).}",
             r"\label{tab:threats}", r"\setlength{\tabcolsep}{4pt}", r"\footnotesize",
             r"\begin{tabular}{@{}llrrr@{}}", r"\toprule",
             r"Config. & Target & $n$ & Detected & Detection (ms) \\", r"\midrule"]
    for d in sorted(mitm, key=lambda d: (CONFIGS.index(d["config"]), d["tamper_target"])):
        t = d.get("detection_ms_median", d.get("detection_ms_mean"))
        lines.append(f"{LABEL[d['config']]} & {d['tamper_target']} & {d['n_requests']} & "
                     f"{d['detection_rate'] * 100:.0f}\\% & {t:.3f} \\\\")
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}", ""]
    out.table("tab_threats", "\n".join(lines))


# --------------------------------------------------------------------------- streaming

def load_streaming(results_dir: str, run_id: str) -> pd.DataFrame:
    paths = sorted(glob.glob(os.path.join(results_dir, "streaming", f"*-streaming-{run_id}.csv")))
    if not paths:
        raise SystemExit(f"No streaming CSVs for run_id {run_id}")
    return _ok(pd.concat([pd.read_csv(p) for p in paths], ignore_index=True))


def fig_streaming(out: Out, df: pd.DataFrame, run_id: str) -> None:
    lengths = sorted(df["max_tokens"].unique())
    chunk = int(df["chunk_size_tokens"].mode()[0])
    df = df[df["chunk_size_tokens"] == chunk]
    present = [c for c in PROTECTED if c in set(df["config"])]  # older runs predate classical_ecdhe
    fig, axes = plt.subplots(len(lengths), 2, figsize=(DBL_W, 1.85 * len(lengths)), squeeze=False)
    width = 0.8 / len(present)
    x = np.arange(len(STRATS))
    for row, n_tok in enumerate(lengths):
        sub = df[df["max_tokens"] == n_tok]
        for col, (metric, ylabel) in enumerate([("ttft_ms", "Time to first token (ms)"),
                                                 ("total_signature_bytes", "Signature bytes per response")]):
            ax = axes[row, col]
            for i, cfg in enumerate(present):
                med, lo, hi = [], [], []
                for s in STRATS:
                    v = sub[(sub["config"] == cfg) & (sub["strategy"] == s)][metric]
                    med.append(v.median())
                    lo.append(v.median() - v.quantile(0.25))
                    hi.append(v.quantile(0.75) - v.median())
                kw = dict(yerr=[lo, hi], capsize=1.5, error_kw={"elinewidth": 0.7}) if metric == "ttft_ms" else {}
                rects = ax.bar(x + (i - (len(present) - 1) / 2) * width, med, width, label=LABEL[cfg],
                               **_bar_kw(cfg), **kw)
                tops = [m + (h if metric == "ttft_ms" else 0) for m, h in zip(med, hi)]
                for rect, v, top in zip(rects, med, tops):
                    txt = f"{v / 1000:.1f}k" if v >= 10_000 else f"{v:,.0f}"
                    # above the whisker, not on it
                    ax.annotate(txt, (rect.get_x() + rect.get_width() / 2, top), xytext=(0, 1.5),
                                textcoords="offset points", ha="center", va="bottom", fontsize=5,
                                rotation=90, color=INK)
            ax.set_yscale("log")
            _log_axis(ax, "y")
            # Floor one decade below the smallest bar so short bars stay visible.
            ax.set_ylim(10, ax.get_ylim()[1] * 12)  # headroom for the vertical labels
            ax.set_xticks(x)
            ax.set_xticklabels([STRAT_LABEL[s] for s in STRATS])
            ax.set_ylabel(ylabel)
            ax.grid(axis="x", visible=False)
            letter = "abcd"[row * 2 + col]
            ax.set_title(f"({letter}) {ylabel.split(' (')[0].split(' per')[0]}: {n_tok}-token response", loc="left")
    handles, labels = axes[0, 0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="upper center", ncol=len(labels), bbox_to_anchor=(0.5, 1.03))
    fig.tight_layout(h_pad=1.2, w_pad=2, rect=(0, 0, 1, 0.96))
    out.fig(fig, "fig_streaming_strategies")

    # key numbers at the longest length, Full PQC
    n_tok = lengths[-1]
    for cfg in present:
        s = df[(df["config"] == cfg) & (df["max_tokens"] == n_tok)].groupby("strategy")
        ttft, sig, total = s["ttft_ms"].median(), s["total_signature_bytes"].median(), s["total_ms"].median()
        out.num(f"Streaming strategies (run {run_id}, {n_tok} tokens, chunk {chunk})",
                f"{LABEL[cfg]}: TTFT buffer / per-chunk / hash-chain (median)",
                f"{ttft['buffer_and_sign']:,.1f} / {ttft['per_chunk']:,.1f} / {ttft['hash_chain']:,.1f} ms "
                f"(hash-chain {ttft['buffer_and_sign'] / ttft['hash_chain']:.1f}x faster than buffer)")
        out.num(f"Streaming strategies (run {run_id}, {n_tok} tokens, chunk {chunk})",
                f"{LABEL[cfg]}: signature bytes buffer / per-chunk / hash-chain",
                f"{sig['buffer_and_sign']:,.0f} / {sig['per_chunk']:,.0f} / {sig['hash_chain']:,.0f} B")
        out.num(f"Streaming strategies (run {run_id}, {n_tok} tokens, chunk {chunk})",
                f"{LABEL[cfg]}: total stream time buffer / per-chunk / hash-chain",
                f"{total['buffer_and_sign']:,.0f} / {total['per_chunk']:,.0f} / {total['hash_chain']:,.0f} ms")
    # flag order-confounded cells: same generation, wildly different time
    for n_tok in lengths:
        b = df[(df["strategy"] == "buffer_and_sign") & (df["max_tokens"] == n_tok)].groupby("config")["total_ms"].median()
        if len(b) > 1 and b.max() / b.median() > 2:
            worst = b.idxmax()
            out.notes.append(
                f"Streaming run {run_id}: {LABEL[worst]} buffer-and-sign at {n_tok} tokens took "
                f"{b.max() / 1000:.1f} s vs a {b.median() / 1000:.1f} s median across configs for the same "
                "generation. It was the first cell after the server (and model) started -- a cold-start ordering "
                "artifact, not crypto cost. Re-run bench.streaming_runner (now with a warm-up transaction) "
                "before citing buffer-and-sign TTFT for that config.")


def table_streaming(out: Out, df: pd.DataFrame, run_id: str) -> None:
    lengths = sorted(df["max_tokens"].unique())
    reps = int(df["repetition"].max())
    lines = [r"\begin{table*}[t]", r"\centering",
             r"\caption{Streaming signature strategies on a real Llama-3.2-3B-Instruct backend "
             fr"({reps} repetitions per cell; median, with interquartile range for TTFT). "
             r"Signing and verification times are summed over the whole stream and given as wall-clock / "
             r"thread-CPU time; Section~\ref{sec:timing} explains why per-signature cost in a stream exceeds "
             r"the back-to-back microbenchmark. Generation slowed over the sweep (thermal), so compare "
             r"times within a configuration, not across.}",
             r"\label{tab:streaming}", r"\setlength{\tabcolsep}{2.4pt}", r"\footnotesize",
             r"\begin{tabular}{@{}rllrrrrrr@{}}", r"\toprule",
             r"Tokens & Config. & Strategy & TTFT (ms) & Total (ms) & Sigs & Sig. bytes & Sign wall/CPU (ms) "
             r"& Verify wall/CPU (ms) \\",
             r"\midrule"]
    for n_tok in lengths:
        first_len = True
        for cfg in PROTECTED:
            first_cfg = True
            for s in STRATS:
                v = df[(df["max_tokens"] == n_tok) & (df["config"] == cfg) & (df["strategy"] == s)]
                if v.empty:
                    continue
                n_sigs = int(v["n_signatures"].median()) if "n_signatures" in v else \
                    {"buffer_and_sign": 1, "hash_chain": 1}.get(s, int(v["n_chunks"].median()))
                cpu = "total_signing_cpu_ms" in v and v["total_signing_cpu_ms"].notna().any()
                sign = f"{v['total_signing_ms'].median():.2f}" + (f" / {v['total_signing_cpu_ms'].median():.2f}" if cpu else "")
                ver = f"{v['total_verify_ms'].median():.2f}" + (f" / {v['total_verify_cpu_ms'].median():.2f}" if cpu else "")
                lines.append(
                    f"{n_tok if first_len else ''} & {LABEL[cfg] if first_cfg else ''} & {STRAT_LABEL[s]} & "
                    f"{v['ttft_ms'].median():,.1f} [{v['ttft_ms'].quantile(.25):,.0f}--{v['ttft_ms'].quantile(.75):,.0f}] & "
                    f"{v['total_ms'].median():,.0f} & {n_sigs} & {v['total_signature_bytes'].median():,.0f} & "
                    f"{sign} & {ver} \\\\")
                first_len = first_cfg = False
            lines.append(r"\addlinespace[1pt]")
        lines.append(r"\midrule")
    lines[-1] = r"\bottomrule"
    lines += [r"\end{tabular}", r"\end{table*}", ""]
    out.table("tab_streaming", "\n".join(lines))


# --------------------------------------------------------------------------- trade-off matrix

def table_tradeoff(out: Out, df: pd.DataFrame, provisional: bool) -> None:
    m = build_matrix(df)
    if m.empty:
        return
    levels = sorted(m["concurrency"].unique())
    names = list(WEIGHTINGS)
    lines = [r"\begin{table*}[t]", r"\centering",
             r"\caption{Weighted composite score $w_{sec}\cdot S - w_{perf}\cdot O$ (higher is better), where $S$ is "
             r"the security score (Classical 0, Hybrid 0.8, Full PQC 1.0) and $O$ the end-to-end latency overhead "
             r"versus Control. Bold: best at that weighting and concurrency; fail: every request failed; n/a: not measured.}",
             r"\label{tab:tradeoff}", r"\setlength{\tabcolsep}{4pt}",
             r"\begin{tabular}{@{}l" + "r" * (len(levels) * len(names)) + r"@{}}", r"\toprule",
             " & " + " & ".join(
                 fr"\multicolumn{{{len(levels)}}}{{c}}{{{n.split('_')[0].capitalize()} ($w_{{sec}}{{=}}{WEIGHTINGS[n]['w_sec']}$)}}"
                 for n in names) + r" \\"]
    rule_cols = []
    for i in range(len(names)):
        a = 2 + i * len(levels)
        rule_cols.append(fr"\cmidrule(lr){{{a}-{a + len(levels) - 1}}}")
    lines.append("".join(rule_cols))
    lines.append("Config. & " + " & ".join(f"{c:,}" for _ in names for c in levels) + r" \\")
    lines.append(r"\midrule")
    for cfg in [c for c in PROTECTED if c in set(m["config"])]:
        cells = []
        for n in names:
            for c in levels:
                sub = m[(m["weighting"] == n) & (m["concurrency"] == c)]
                r = sub[sub["config"] == cfg]
                if r.empty:
                    cells.append("n/a")  # not measured
                    continue
                if not bool(r["available"].iloc[0]):
                    cells.append("fail")  # every request failed
                    continue
                v = r["composite_score"].iloc[0]
                best = sub[sub["available"]]["composite_score"].max()
                cells.append(fr"$\mathbf{{{v:+.2f}}}$" if np.isclose(v, best) else f"${v:+.2f}$")
        lines.append(f"{LABEL[cfg]} & " + " & ".join(cells) + r" \\")
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table*}", ""]
    out.table("tab_tradeoff", "\n".join(lines), provisional)



# --------------------------------------------------------------------------- payload profiles

PROFILE_ORDER = ["tabular_small", "image_cnn", "embedding", "llm_completion"]
PROFILE_LABEL = {"tabular_small": "Tabular\n(RandomForest)", "image_cnn": "Image\n(CNN)",
                 "embedding": "Embedding\n(768-d)", "llm_completion": "LLM\ncompletion"}
NET_ORDER = ["localhost", "metro", "wan", "mobile"]


def _load_runs(results_dir: str, run_ids: list[str], warmup: float) -> pd.DataFrame:
    df = _latest_run_per_cell(load_raw(os.path.join(results_dir, "raw"), run_ids=run_ids))
    return discard_warmup(df, warmup)


def fig_payload_profiles(out: Out, df: pd.DataFrame) -> None:
    ok = _ok(df)
    profiles = [p for p in PROFILE_ORDER if p in set(ok["payload_profile"])]
    present = [c for c in CONFIGS if c in set(ok["config"])]
    if not profiles:
        return
    med = ok.groupby(["payload_profile", "config"])["total_ms"].median()
    fig, (ax, axo) = plt.subplots(1, 2, figsize=(DBL_W, 2.2))
    x = np.arange(len(profiles))
    width = 0.8 / len(present)
    for i, cfg in enumerate(present):
        vals = [med.get((p, cfg), np.nan) for p in profiles]
        ax.bar(x + (i - (len(present) - 1) / 2) * width, vals, width, label=LABEL[cfg], **_bar_kw(cfg))
    ax.set_xticks(x)
    ax.set_xticklabels([PROFILE_LABEL[p] for p in profiles])
    ax.set_ylabel("Median end-to-end latency (ms)")
    ax.set_title("(a) End-to-end latency at 10 connections", loc="left")
    ax.grid(axis="x", visible=False)
    ax.legend(loc="upper right", ncol=2, fontsize=6)
    prot = [c for c in present if c != "control"]
    width = 0.8 / max(len(prot), 1)
    for i, cfg in enumerate(prot):
        vals = [med.get((p, cfg), np.nan) - med.get((p, "control"), np.nan) for p in profiles]
        rects = axo.bar(x + (i - (len(prot) - 1) / 2) * width, vals, width, label=LABEL[cfg], **_bar_kw(cfg))
        for rect, v in zip(rects, vals):
            if not np.isnan(v):
                axo.annotate(f"{v:+.0f}", (rect.get_x() + rect.get_width() / 2, max(v, 0)), xytext=(0, 1.5),
                             textcoords="offset points", ha="center", va="bottom", fontsize=5)
    axo.axhline(0, color=INK_2, lw=0.6)
    axo.set_xticks(x)
    axo.set_xticklabels([PROFILE_LABEL[p] for p in profiles])
    axo.set_ylabel("Added latency vs. Control (ms)")
    axo.set_title("(b) Cryptographic overhead (median difference)", loc="left")
    axo.grid(axis="x", visible=False)
    fig.tight_layout(w_pad=2)
    out.fig(fig, "fig_payload_profiles")


def table_payload_profiles(out: Out, df: pd.DataFrame) -> None:
    ok = _ok(df)
    profiles = [p for p in PROFILE_ORDER if p in set(ok["payload_profile"])]
    present = [c for c in PROTECTED if c in set(ok["config"])]
    if not profiles:
        return
    lines = [r"\begin{table*}[t]", r"\centering",
             r"\caption{Payload-shape sensitivity at 10 connections (5 repetitions per cell). Request/response "
             r"sizes are plaintext medians; each cell gives median end-to-end latency (ms) and the added latency "
             r"versus Control, with Mann--Whitney $U$ significance (* $p<0.05$).}",
             r"\label{tab:payload}", r"\setlength{\tabcolsep}{4pt}",
             r"\begin{tabular}{@{}lrrr" + "r" * len(present) + r"@{}}", r"\toprule",
             r"Profile & Req. (B) & Resp. (B) & Control & " + " & ".join(LABEL[c] for c in present) + r" \\",
             r"\midrule"]
    for prof in profiles:
        sub = ok[ok["payload_profile"] == prof]
        ctrl = sub[sub["config"] == "control"]["total_ms"].dropna()
        prot_rows = sub[sub["config"] != "control"]
        req = prot_rows["request_plaintext_bytes"].median()
        resp = prot_rows["response_plaintext_bytes"].median()
        cells = []
        for cfg in present:
            v = sub[sub["config"] == cfg]["total_ms"].dropna()
            if v.empty or ctrl.empty:
                cells.append("--")
                continue
            p = stats.mannwhitneyu(v, ctrl, alternative="two-sided").pvalue
            d = v.median() - ctrl.median()
            cells.append(f"{v.median():,.1f} ({d:+.1f}{'*' if p < 0.05 else ''})")
            out.num("Payload-shape sensitivity (10 connections)", f"{prof} / {LABEL[cfg]}",
                    f"median {v.median():,.1f} ms, {d:+.1f} ms vs Control ({d / ctrl.median():+.1%}, p = {p:.2g})")
        lines.append(f"{prof.replace('_', chr(92) + '_')} & {req:,.0f} & {resp:,.0f} & "
                     f"{ctrl.median():,.1f} & " + " & ".join(cells) + r" \\")
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table*}", ""]
    out.table("tab_payload_profiles", "\n".join(lines))


# --------------------------------------------------------------------------- network conditions

def _rep_medians(ok: pd.DataFrame, by: list[str], metric: str) -> pd.DataFrame:
    """Median of `metric` within each repetition, then mean and SD of those
    per-repetition medians across repetitions. Variability BETWEEN
    repetitions -- not the within-run IQR -- is what decides whether a
    difference between configurations is resolvable."""
    rm = ok.groupby(by + ["repetition"])[metric].median()
    return rm.groupby(by).agg(["mean", "std", "count"])


def fig_network(out: Out, df: pd.DataFrame) -> None:
    """Plots the handshake leg: it is where key-establishment bytes cross the
    emulated link, and it carries no model-inference queueing, so the cost of
    PQC message size is resolvable there. End-to-end differences are reported
    in key_numbers.md with their between-repetition SD."""
    ok = _ok(df)
    if "network_profile" not in ok:
        return
    ok = ok.assign(network_profile=ok["network_profile"].fillna("localhost"))
    nets = [n for n in NET_ORDER if n in set(ok["network_profile"])]
    present = [c for c in PROTECTED if c in set(ok["config"])]
    if len(nets) < 2 or not present:
        return
    from bench.netem_proxy import NETWORK_PROFILES
    tick = [n if NETWORK_PROFILES[n] is None else
            f"{n}\n{NETWORK_PROFILES[n]['rtt_ms']} ms, {NETWORK_PROFILES[n]['bandwidth_mbps']} Mb/s" for n in nets]
    hs = _rep_medians(ok, ["network_profile", "config"], "handshake_ms")
    tot = _rep_medians(ok, ["network_profile", "config"], "total_ms")
    fig, (ax, axd) = plt.subplots(1, 2, figsize=(DBL_W, 2.2))
    x = np.arange(len(nets))
    for cfg in present:
        m = [hs["mean"].get((n, cfg), np.nan) for n in nets]
        e = [hs["std"].get((n, cfg), np.nan) for n in nets]
        ax.errorbar(x, m, yerr=e, color=CONFIG_COLORS[cfg], marker=MARKER[cfg], ls=LINESTYLE[cfg],
                    capsize=2, elinewidth=0.8, label=LABEL[cfg])
    ax.set_xticks(x)
    ax.set_xticklabels(tick, fontsize=6)
    ax.set_ylabel("Handshake round trip (ms)")
    ax.set_title("(a) Handshake leg under emulated network paths", loc="left")
    ax.legend(fontsize=6, loc="upper left")
    base = "classical_ecdhe" if "classical_ecdhe" in present else None
    if base:
        others = [c for c in present if c not in (base, "classical")]
        width = 0.8 / max(len(others), 1)
        for i, cfg in enumerate(others):
            d = [hs["mean"].get((n, cfg), np.nan) - hs["mean"].get((n, base), np.nan) for n in nets]
            e = [np.hypot(hs["std"].get((n, cfg), np.nan), hs["std"].get((n, base), np.nan)) for n in nets]
            rects = axd.bar(x + (i - (len(others) - 1) / 2) * width, d, width, yerr=e, capsize=1.5,
                            error_kw={"elinewidth": 0.7}, label=LABEL[cfg], **_bar_kw(cfg))
            for rect, v, ev in zip(rects, d, e):
                if not np.isnan(v):
                    axd.annotate(f"{v:+.1f}", (rect.get_x() + rect.get_width() / 2, max(v, 0) + (ev or 0)),
                                 xytext=(0, 1.5), textcoords="offset points", ha="center", va="bottom", fontsize=5)
            for n, dv, ev in zip(nets, d, e):
                td = tot["mean"].get((n, cfg), np.nan) - tot["mean"].get((n, base), np.nan)
                te = np.hypot(tot["std"].get((n, cfg), np.nan), tot["std"].get((n, base), np.nan))
                out.num("Network emulation (10 connections; mean of 5 per-repetition medians +/- SD)",
                        f"{LABEL[cfg]} vs {LABEL[base]} on {n}",
                        f"handshake {dv:+.1f} +/- {ev:.1f} ms; end-to-end {td:+.1f} +/- {te:.1f} ms")
        axd.axhline(0, color=INK_2, lw=0.6)
        axd.set_xticks(x)
        axd.set_xticklabels(tick, fontsize=6)
        axd.set_ylabel("Added handshake time (ms)")
        axd.set_title(f"(b) PQC key-exchange cost vs. {LABEL[base]}", loc="left")
        axd.grid(axis="x", visible=False)
        axd.legend(fontsize=6, loc="upper left")
    if "classical" in present:
        for n in nets:
            out.num("Network emulation (10 connections; mean of 5 per-repetition medians +/- SD)",
                    f"Classical-RSA handshake on {n}",
                    f"{hs['mean'].get((n, 'classical'), np.nan):.1f} +/- {hs['std'].get((n, 'classical'), np.nan):.1f} ms "
                    f"(Classical-ECDHE {hs['mean'].get((n, 'classical_ecdhe'), np.nan):.1f} ms)")
    fig.tight_layout(w_pad=2)
    out.fig(fig, "fig_network_conditions")


# --------------------------------------------------------------------------- resources

def _resource_cells(results_dir: str, run_ids: list[str]) -> pd.DataFrame:
    """Per-cell server CPU/RSS samples for the given sweeps, keeping each
    config's latest run only (as for latency -- see _latest_run_per_cell)."""
    cells = []
    for rid in run_ids:
        path = os.path.join(results_dir, "sweep_summaries", f"{rid}.json")
        if os.path.isfile(path):
            with open(path) as f:
                cells += [c for c in json.load(f) if c.get("run_type") == "concurrency"]
    if not cells:
        return pd.DataFrame()
    rs = pd.DataFrame(cells)
    rs["config"] = rs["config"].str.replace("-", "_")
    latest = rs.groupby("config")["run_id"].transform("max")
    return rs[rs["run_id"] == latest]


def table_resources(out: Out, results_dir: str, run_ids: list[str], provisional: bool) -> None:
    rs = _resource_cells(results_dir, run_ids)
    if rs.empty:
        out.notes.append("No server CPU/RSS samples for the selected concurrency run(s); the resource table "
                         "needs a sweep run with the current bench.orchestrator.")
        return
    agg = rs.groupby(["concurrency", "config"]).agg(
        cpu_mean=("cpu_percent_mean", "mean"), cpu_max=("cpu_percent_max", "max"),
        rss_mean=("rss_mb_mean", "mean"), rss_max=("rss_mb_max", "max"),
        rps=("throughput_rps", "mean")).reset_index()
    host = rs.iloc[0]
    lines = [r"\begin{table}[t]", r"\centering",
             r"\caption{Server-process resource use, sampled every 0.25\,s during each cell and averaged over "
             fr"repetitions; RSS is mean resident memory (macOS, Apple M3, "
             fr"{host.get('host_cpu_count', '?')} logical CPUs; 100\% = one core).}}",
             r"\label{tab:resources}", r"\setlength{\tabcolsep}{2.5pt}", r"\footnotesize",
             r"\begin{tabular}{@{}rlrrrr@{}}", r"\toprule",
             r"Conc. & Config. & CPU mean & CPU max & RSS & Req/s \\",
             r" & & (\%) & (\%) & (MB) & \\", r"\midrule"]
    for conc in sorted(agg["concurrency"].unique()):
        sub = agg[agg["concurrency"] == conc].set_index("config")
        first = True
        for cfg in CONFIGS:
            if cfg not in sub.index:
                continue
            r = sub.loc[cfg]
            f = lambda v, fmt: "--" if pd.isna(v) else format(v, fmt)
            lines.append(f"{f'{conc:,}' if first else ''} & {LABEL[cfg]} & {f(r['cpu_mean'], '.0f')} & "
                         f"{f(r['cpu_max'], '.0f')} & {f(r['rss_mean'], '.0f')} & "
                         f"{f(r['rps'], ',.1f')} \\\\")
            out.num("Server resources" + (" -- PROVISIONAL" if provisional else ""), f"{LABEL[cfg]} @ {conc:,}",
                    f"CPU mean {f(r['cpu_mean'], '.0f')}% (max {f(r['cpu_max'], '.0f')}%), "
                    f"RSS mean {f(r['rss_mean'], '.0f')} MB (max {f(r['rss_max'], '.0f')} MB), {f(r['rps'], ',.1f')} req/s")
            first = False
        lines.append(r"\addlinespace")
    lines[-1] = r"\bottomrule"
    lines += [r"\end{tabular}", r"\end{table}", ""]
    out.table("tab_resources", "\n".join(lines), provisional)



# --------------------------------------------------------------------------- checkpoint frontier

def fig_checkpoint_frontier(out: Out, df: pd.DataFrame, run_id: str, attacks: list[dict]) -> None:
    """Bytes vs. exposure for checkpointed hash-chain signing. k = signature
    every k chunks; k = infinity is plain hash-chain, k = 1 signs every chunk."""
    hc = df[df["strategy"] == "hash_chain"].copy()
    if hc.empty or "checkpoint_interval" not in hc:
        return
    hc["k"] = hc["checkpoint_interval"].fillna(0).astype(int)  # 0 = terminal signature only
    chunk = int(hc["chunk_size_tokens"].mode()[0])
    present = [c for c in PROTECTED if c in set(hc["config"])]
    fig, (ax, axd) = plt.subplots(1, 2, figsize=(DBL_W, 2.35), gridspec_kw={"width_ratios": [1.25, 1]})
    for cfg in present:
        g = hc[hc["config"] == cfg].groupby("k").agg(
            sig=("total_signature_bytes", "median"), exp=("max_unverified_chunks", "median"),
            n=("n_chunks", "median"), nsig=("n_signatures", "median"), lag=("max_verification_lag_ms", "median"))
        order = sorted(g.index, key=lambda k: (k == 0, k))  # 1, 2, ..., then 0 (= infinity) last
        g = g.loc[order]
        ax.plot(g["exp"] * chunk, g["sig"], color=CONFIG_COLORS[cfg], marker=MARKER[cfg], ls=LINESTYLE[cfg],
                label=f"{LABEL[cfg]} (measured)", zorder=3)
        # analytic model: ceil(n/k) checkpoint signatures + 1 terminal signature, |sigma| from the k=inf row
        sig_size = g.loc[0, "sig"] if 0 in g.index else np.nan
        n = g["n"].median()
        ks = [k for k in order if k > 0]
        model_bytes = [(np.floor(n / k) + 1) * sig_size for k in ks] + ([sig_size] if 0 in g.index else [])
        model_exp = [k * chunk for k in ks] + ([n * chunk] if 0 in g.index else [])
        ax.plot(model_exp, model_bytes, color=CONFIG_COLORS[cfg], lw=0.8, ls=":", zorder=2)
        for k, row in g.iterrows():
            ax.annotate("k=∞" if k == 0 else f"k={k}", (row["exp"] * chunk, row["sig"]), xytext=(3, 2),
                        textcoords="offset points", fontsize=5.5, color=INK_2)
            out.num(f"Checkpoint frontier (run {run_id}, chunk {chunk} tokens)",
                    f"{LABEL[cfg]} k={'inf' if k == 0 else k}",
                    f"{row['sig']:,.0f} B signatures ({row['nsig']:.0f} sigs), max exposure "
                    f"{row['exp'] * chunk:.0f} tokens, max verification lag {row['lag']:,.0f} ms")
    ax.set_xscale("log")
    ax.set_yscale("log")
    _log_axis(ax, "y")
    ax.xaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v:,.0f}"))
    ax.set_xlabel("Max tokens shown before verification (exposure)")
    ax.set_ylabel("Signature bytes per response")
    ax.plot([], [], color=INK_2, lw=0.8, ls=":", label="Analytic model")
    ax.set_title("(a) Signature bytes vs. exposure", loc="left")
    ax.legend(fontsize=6, loc="lower left")

    camp = pd.DataFrame(attacks)
    if not camp.empty and "unverified_at_detection_mean" in camp:
        # Detection depends on where checkpoints fall, not on the signature
        # scheme, so pool configurations: one line per attack.
        camp = camp[camp["strategy"] == "hash_chain"].copy()
        camp["k"] = camp["checkpoint_interval"].fillna(0).astype(int)
        n_chunks = camp["n_chunks_mean"].median()
        inf_x = 2 * camp.loc[camp["k"] > 0, "k"].max()  # where k = infinity is drawn
        camp["x"] = np.where(camp["k"] == 0, inf_x, camp["k"])
        styles = {"drop": ("-", "o", INK, "Drop one chunk"), "reorder": ("--", "s", "white", "Reorder two chunks"),
                  "duplicate": ("-.", "D", "white", "Duplicate a chunk"),
                  "drop_after_ckpt": ((0, (1, 1)), "v", INK, "Drop just after a checkpoint"),
                  "truncate": (":", "^", INK_2, "Truncate (terminal record lost)")}
        for attack, (ls, mk, mfc, name) in styles.items():
            g = camp[camp["attack"] == attack]
            if g.empty:
                continue
            g = g.assign(w=g["unverified_at_detection_mean"] * g["n"]).groupby("x")[["w", "n"]].sum()
            axd.plot(g.index, g["w"] / g["n"] * chunk, color=INK, marker=mk, ls=ls, mfc=mfc, label=name)
        axd.axhline(n_chunks * chunk, color=INK_2, lw=0.6, ls=":")
        axd.text(ticks_min := camp.loc[camp["k"] > 0, "k"].min(), n_chunks * chunk * 1.015,
                 f"whole {n_chunks * chunk:.0f}-token stream", fontsize=5.5, color=INK_2, va="bottom")
        axd.set_xscale("log")
        ticks = sorted(camp["x"].unique())
        axd.set_xticks(ticks)
        axd.set_xticklabels(["∞" if t == inf_x else f"{t:g}" for t in ticks])
        axd.xaxis.set_minor_formatter(NullFormatter())
        axd.set_xlabel("Checkpoint interval k (chunks)")
        axd.set_ylabel("Unverified tokens shown at rejection")
        axd.set_ylim(0, n_chunks * chunk * 1.15)
        axd.set_title("(b) Exposure when an attack is caught", loc="left")
        axd.legend(fontsize=5.5, loc="center left", bbox_to_anchor=(0.0, 0.55))
    else:
        axd.axis("off")
    fig.tight_layout(w_pad=2)
    out.fig(fig, "fig_checkpoint_frontier")


def table_checkpoint(out: Out, df: pd.DataFrame) -> None:
    hc = df[df["strategy"] == "hash_chain"].copy()
    if hc.empty:
        return
    hc["k"] = hc["checkpoint_interval"].fillna(0).astype(int)
    chunk = int(hc["chunk_size_tokens"].mode()[0])
    lines = [r"\begin{table}[t]", r"\centering",
             r"\caption{Checkpointed hash-chain signing on Llama-3.2-3B (200-token responses, "
             fr"{chunk}-token chunks): a signature every $k$ chunks plus the terminal one. Exposure = most "
             r"tokens a client displays before a signature covers them; lag = longest wait for that coverage. "
             r"Signing time summed over the stream, wall-clock / thread-CPU (median over repetitions).}",
             r"\label{tab:checkpoint}", r"\setlength{\tabcolsep}{1.8pt}", r"\footnotesize",
             r"\begin{tabular}{@{}llrrrrr@{}}", r"\toprule",
             r"Config. & $k$ & Sigs & Bytes & Exp.\ (tok) & Lag (ms) & Sign (ms) \\", r"\midrule"]
    for cfg in [c for c in PROTECTED if c in set(hc["config"])]:
        g = hc[hc["config"] == cfg]
        first = True
        for k in sorted(g["k"].unique(), key=lambda k: (k == 0, k)):
            v = g[g["k"] == k]
            lines.append(f"{LABEL[cfg] if first else ''} & {'$\\infty$' if k == 0 else k} & "
                         f"{v['n_signatures'].median():.0f} & {v['total_signature_bytes'].median():,.0f} & "
                         f"{v['max_unverified_chunks'].median() * chunk:.0f} & "
                         f"{v['max_verification_lag_ms'].median():,.0f} & "
                         f"{v['total_signing_ms'].median():.1f}"
                         + (f"/{v['total_signing_cpu_ms'].median():.1f}" if "total_signing_cpu_ms" in v
                            and v["total_signing_cpu_ms"].notna().any() else "") + r" \\")
            first = False
        lines.append(r"\addlinespace")
    lines[-1] = r"\bottomrule"
    lines += [r"\end{tabular}", r"\end{table}", ""]
    out.table("tab_checkpoint", "\n".join(lines))


# --------------------------------------------------------------------------- handshake amortization

def fig_amortization(out: Out, df: pd.DataFrame) -> None:
    ok = _ok(df)
    if "requests_per_handshake" not in ok:
        return
    ok = ok.assign(rph=ok["requests_per_handshake"].fillna(1).astype(int))
    levels = sorted(ok["rph"].unique())
    if len(levels) < 2:
        return
    # Overhead per repetition: config's per-repetition median vs Control's
    # median in the same sweep (each N is its own sweep with its own Control).
    rep = ok.groupby(["rph", "config", "repetition"])["total_ms"].median()
    ctrl = ok[ok["config"] == "control"].groupby("rph")["total_ms"].median()
    present = [c for c in PROTECTED if c in set(ok["config"])]
    fig, (ax, axz) = plt.subplots(1, 2, figsize=(DBL_W, 2.2))
    for cfg in present:
        mean, sd = [], []
        for n in levels:
            v = 100 * (rep.loc[(n, cfg)] - ctrl[n]) / ctrl[n] if (n, cfg) in rep.index else pd.Series(dtype=float)
            mean.append(v.mean())
            sd.append(v.std())
            out.num("Handshake amortization (10 connections; mean +/- SD over 5 repetitions)",
                    f"{LABEL[cfg]}, {n} request(s) per key exchange",
                    f"{v.mean():+.1f} +/- {v.std():.1f}% end-to-end vs Control")
        for a_ in ([ax] if cfg == "classical" else [ax, axz]):
            a_.errorbar(levels, mean, yerr=sd, color=CONFIG_COLORS[cfg], marker=MARKER[cfg], ls=LINESTYLE[cfg],
                        capsize=2, elinewidth=0.8, label=LABEL[cfg])
    for a_, title in ((ax, "(a) All configurations"), (axz, "(b) Zoom: excluding Classical-RSA")):
        a_.axhline(0, color=INK_2, lw=0.6)
        a_.set_xscale("log")
        a_.set_xticks(levels)
        a_.set_xticklabels([str(n) for n in levels])
        a_.set_xlabel("Requests served per key exchange (session reuse)")
        a_.set_title(title, loc="left")
    ax.set_ylabel("End-to-end overhead vs. Control (%)")
    ax.legend(fontsize=6, ncol=2, loc="upper right")
    fig.tight_layout(w_pad=2)
    out.fig(fig, "fig_handshake_amortization")


# --------------------------------------------------------------------------- environment

def table_environment(out: Out, env_path: str) -> None:
    if not os.path.isfile(env_path):
        out.notes.append("paper/environment.json missing: run bench.paper_runs to capture versions.")
        return
    with open(env_path) as f:
        env = json.load(f)
    pk = env.get("packages", {})
    osname = env.get("os", "").replace("Darwin", "macOS")
    rows = [
        ("Host", f"{env.get('cpu')}, {env.get('cpu_count')} cores, {env.get('memory_gb'):g}\\,GB"),
        ("OS", osname),
        ("Python", env.get("python")),
        ("FastAPI / Uvicorn / httpx", f"{pk.get('fastapi')} / {pk.get('uvicorn')} / {pk.get('httpx')}"),
        ("cryptography / OpenSSL", f"{pk.get('cryptography')} / {(env.get('openssl') or '').replace('OpenSSL ', '').split(' ')[0]}"),
        ("liboqs (commit)", (env.get("liboqs_commit") or "")[:12]),
        ("NumPy / SciPy / pandas", f"{pk.get('numpy')} / {pk.get('scipy')} / {pk.get('pandas')}"),
        ("scikit-learn", pk.get("scikit-learn")),
        ("llama-cpp-python (Metal)", pk.get("llama_cpp_python")),
        ("LLM file", (env.get("llama_model_file") or "").replace("_", "\\_")),
        ("LLM SHA-256 (prefix)", (env.get("llama_model_sha256") or "")[:16]),
        ("Classifier SHA-256 (prefix)", (env.get("classifier_model_sha256") or "")[:16]),
    ]
    lines = [r"\begin{table}[t]", r"\centering",
             r"\caption{Software and hardware environment, captured automatically at run time.}",
             r"\label{tab:environment}", r"\footnotesize", r"\setlength{\tabcolsep}{3pt}", r"\begin{tabular}{@{}ll@{}}", r"\toprule",
             r"Component & Version \\", r"\midrule"]
    lines += [f"{a} & {b} \\\\" for a, b in rows]
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}", ""]
    out.table("tab_environment", "\n".join(lines))


# --------------------------------------------------------------------------- main

# --------------------------------------------------------------------------- second review round

CLIENT_TIMEOUT_MS = 30_000  # bench.runner's httpx timeout; no failed request can have been faster to fail than this


def _err_kind(e) -> str:
    e = str(e)
    for key, kind in (("Timeout", "timeout"), ("ReadError", "reset"), ("RemoteProtocolError", "reset"),
                      ("ConnectError", "refused"), ("HTTP 5", "HTTP 5xx"), ("HTTP 4", "HTTP 4xx")):
        if key in e:
            return kind
    return "other"


def _equiv(r, margin: float = EQUIV_MARGIN_PCT) -> bool:
    lo, hi = 100 * r["ci90_lo"] / r["ref_median"], 100 * r["ci90_hi"] / r["ref_median"]
    return -margin < lo and hi < margin


def table_failures(out: Out, df: pd.DataFrame, cmp: pd.DataFrame) -> None:
    """Where requests failed: by stage and cause, and whether excluding them
    changes the comparisons. The sensitivity re-analysis counts every failed
    request at the client timeout (30 s) -- slower than any successful
    request -- and recomputes each median and each difference versus
    Classical-ECDHE. No equivalence verdict is drawn here: the levels with
    failures are dominated by single-host contention (Section VI-H)."""
    is_err = df["error"].notna() & (df["error"] != "")
    rate = is_err.groupby([df["config"], df["concurrency"]]).mean()
    # only levels where some configuration lost a non-trivial share (>= 0.5%) of requests
    levels = sorted({c for (_, c), r in rate.items() if r >= 0.005})
    if not levels:
        return
    imp = df[df["concurrency"].isin(levels)].copy()
    e = imp["error"].notna() & (imp["error"] != "")
    imp.loc[e, "total_ms"] = CLIENT_TIMEOUT_MS
    imp.loc[e, "error"] = np.nan
    present = set(imp["config"])
    pairs = [(c, "classical_ecdhe") for c in PROTECTED if c in present and c != "classical_ecdhe"]
    cmp0 = comparison_stats(df[df["concurrency"].isin(levels)], pairs, seed=11)
    cmp1 = comparison_stats(imp, pairs, seed=11)

    def get(c, cfg, conc):
        r = c[(c["config"] == cfg) & (c["reference"] == "classical_ecdhe") & (c["concurrency"] == conc)]
        return None if r.empty else r.iloc[0]

    def pct(r):
        if r is None:
            return "--"
        f = lambda v: 100 * v / r["ref_median"]
        return f"{r['diff_pct']:+.1f} [{f(r['ci95_lo']):+.1f}, {f(r['ci95_hi']):+.1f}]"

    lines = [r"\begin{table*}[t]", r"\centering",
             r"\caption{Failed requests and their effect on the comparisons. All failures were connection resets "
             r"(httpx \texttt{ReadError}): no timeouts and no HTTP errors. ``At handshake'': the first request of the "
             r"transaction failed. Sensitivity: every failed request re-counted at the 30\,s client timeout (slower than "
             r"any successful request) and the statistics recomputed. $\Delta$: difference in medians versus "
             r"Classical-ECDHE, \% of its median, with 95\% CI. These levels are dominated by single-host contention, "
             r"so the table tests only whether excluding failures changes the comparisons; it draws no equivalence "
             r"verdicts.}",
             r"\label{tab:failures}", r"\setlength{\tabcolsep}{3pt}", r"\footnotesize",
             r"\begin{tabular}{@{}rlrrrrrll@{}}", r"\toprule",
             r" & & & \multicolumn{2}{c}{Failed at} & \multicolumn{2}{c}{Median (s)} & "
             r"\multicolumn{2}{c}{$\Delta$ vs.\ Classical-ECDHE (\%)} \\",
             r"\cmidrule(lr){4-5}\cmidrule(lr){6-7}\cmidrule(lr){8-9}",
             r"Conc. & Configuration & Failed & handshake & request & succ.\ only & fail.\ at 30\,s & "
             r"successful only & failures at 30\,s \\",
             r"\midrule"]
    for conc in levels:
        first = True
        for cfg in CONFIGS:
            g = df[(df["config"] == cfg) & (df["concurrency"] == conc)]
            if g.empty:
                continue
            ge = g[g["error"].notna() & (g["error"] != "")]
            n_hs = int(ge["handshake_ms"].isna().sum()) if cfg != "control" else 0
            kinds = ge["error"].map(_err_kind).value_counts().to_dict()
            ok = g[~(g["error"].notna() & (g["error"] != ""))]
            m0 = ok["total_ms"].median()
            m1 = imp[(imp["config"] == cfg) & (imp["concurrency"] == conc)]["total_ms"].median()
            q0, q1 = get(cmp0, cfg, conc), get(cmp1, cfg, conc)
            lines.append(f"{f'{conc:,}' if first else ''} & {LABEL[cfg]} & {100 * len(ge) / len(g):.1f}\\% & "
                         f"{n_hs if cfg != 'control' else '--'} & {len(ge) - n_hs} & {m0 / 1000:.2f} & {m1 / 1000:.2f} & "
                         f"{'ref.' if cfg == 'classical_ecdhe' else pct(q0)} & "
                         f"{'ref.' if cfg == 'classical_ecdhe' else pct(q1)} \\\\")
            out.num(f"Failures at {conc:,} connections (stage, cause, sensitivity)", LABEL[cfg],
                    f"{len(ge)}/{len(g)} failed ({len(ge) / len(g):.2%}); at handshake {n_hs}, at request "
                    f"{len(ge) - n_hs}; causes {kinds}; median {m0:,.0f} -> {m1:,.0f} ms with failures at 30 s"
                    + (f"; vs ECDHE {q0['diff_pct']:+.1f}% -> {q1['diff_pct']:+.1f}%" if q0 is not None and q1 is not None else ""))
            first = False
        lines.append(r"\addlinespace")
    lines[-1] = r"\bottomrule"
    lines += [r"\end{tabular}", r"\end{table*}", ""]
    out.table("tab_failures", "\n".join(lines))


# Security properties, stated rather than scored. Each is a yes/no fact about
# the construction (Section III); none is weighted against latency.
CODE = {"classical": "A", "classical_ecdhe": "A$'$", "hybrid": "B", "hybrid_kex": "B$'$", "full_pqc": "C",
        "hybrid_kex_pq": "C$'$"}
SEC_AXES = [
    ("KEX vs.\\ CRQC", {"classical": 0, "classical_ecdhe": 0, "hybrid": 1, "hybrid_kex": 1, "full_pqc": 1, "hybrid_kex_pq": 1}),
    ("KEX if ML-KEM breaks", {"classical": 1, "classical_ecdhe": 1, "hybrid": 0, "hybrid_kex": 1, "full_pqc": 0, "hybrid_kex_pq": 1}),
    ("Sig.\\ vs.\\ CRQC", {"classical": 0, "classical_ecdhe": 0, "hybrid": 0, "hybrid_kex": 0, "full_pqc": 1, "hybrid_kex_pq": 1}),
]


def dominance_frame(df: pd.DataFrame, sdf: pd.DataFrame | None, results_dir: str) -> dict:
    """Replaces the weighted composite score. A configuration is dominated if
    another is at least as secure on every stated property and no worse on
    every cost -- latency 'no worse' meaning the 90% CI of the difference lies
    below +5% (the equivalence margin) -- and strictly better somewhere. The
    non-dominated set is what any weighting of these axes could select, so no
    weights are needed. Only the 10- and 1,000-connection levels are used: the
    100-connection level is bimodal (Section VI-A) and is not ranked."""
    present = [c for c in PROTECTED if c in set(df["config"])]
    # Latency is compared at 10 connections only: at 100 the protected configurations are
    # bimodal, and at 1,000 single-host contention makes the matched-protocol subtraction
    # meaningless (protected configurations come out faster than the no-crypto control).
    levels = [c for c in (10,) if c in set(df["concurrency"])]
    pairs = [(a, b) for i, a in enumerate(present) for b in present[i + 1:]]
    pw = comparison_stats(df[df["concurrency"].isin(levels)], pairs, seed=13)
    ov = comparison_stats(df[df["concurrency"].isin(levels)], [(c, "control_2rt") for c in present], seed=17) \
        if "control_2rt" in set(df["config"]) else pd.DataFrame()

    def lat_not_worse(a, b, conc):  # is a no worse than b?
        r = pw[(pw["concurrency"] == conc) & (((pw["config"] == a) & (pw["reference"] == b)) |
                                              ((pw["config"] == b) & (pw["reference"] == a)))]
        if r.empty:
            return True, False
        r = r.iloc[0]
        if r["config"] == a:  # diff = a - b, relative to b
            hi, lo, ref = r["ci90_hi"], r["ci90_lo"], r["ref_median"]
        else:  # diff = b - a; flip
            hi, lo, ref = -r["ci90_lo"], -r["ci90_hi"], r["ref_median"] + r["diff_ms"]
        return 100 * hi / ref < EQUIV_MARGIN_PCT, 100 * hi / ref < -EQUIV_MARGIN_PCT

    hndl = {d["config"]: d for d in _read_json_glob(os.path.join(results_dir, "hndl", "*-hndl-summary.json"))}
    hs_bytes = {c: hndl[c]["kex_bytes_per_request"] + hndl[c]["signature_bytes_per_request"] for c in present if c in hndl}
    pc_bytes = {}
    if sdf is not None and not sdf.empty:
        n_max = sdf["max_tokens"].max()
        for c in present:
            v = sdf[(sdf["config"] == c) & (sdf["strategy"] == "per_chunk") & (sdf["max_tokens"] == n_max)]
            if not v.empty:  # a streamed response also pays for its handshake
                pc_bytes[c] = v["total_signature_bytes"].median() + hs_bytes.get(c, 0)

    def dominates(a, b, byte_map):
        sec_ge = all(ax[a] >= ax[b] for _, ax in SEC_AXES)
        sec_gt = any(ax[a] > ax[b] for _, ax in SEC_AXES)
        lat = [lat_not_worse(a, b, c) for c in levels]
        lat_ok, lat_better = all(x[0] for x in lat), any(x[1] for x in lat)
        by_ok = a not in byte_map or b not in byte_map or byte_map[a] <= byte_map[b]
        by_better = a in byte_map and b in byte_map and byte_map[a] < byte_map[b]
        return sec_ge and lat_ok and by_ok and (sec_gt or lat_better or by_better)

    workloads = {"API / hash-chain": hs_bytes, "Per-chunk streaming": pc_bytes}
    dominated_by = {w: {c: [o for o in present if o != c and dominates(o, c, bm)] for c in present}
                    for w, bm in workloads.items()}
    return {"present": present, "levels": levels, "overhead": ov, "pairwise": pw, "hs_bytes": hs_bytes,
            "pc_bytes": pc_bytes, "workloads": workloads, "dominated_by": dominated_by}


def table_dominance(out: Out, df: pd.DataFrame, sdf: pd.DataFrame | None, results_dir: str) -> None:
    """LaTeX rendering of dominance_frame (the weight-free decision summary)."""
    d = dominance_frame(df, sdf, results_dir)
    present, levels, ov = d["present"], d["levels"], d["overhead"]
    hs_bytes, pc_bytes, workloads, dominated_by = d["hs_bytes"], d["pc_bytes"], d["workloads"], d["dominated_by"]
    lines = [r"\begin{table*}[t]", r"\centering",
             r"\caption{Decision summary without weights. Security columns are properties of the construction "
             r"(\checkmark = holds): key establishment resists a CRQC (KEX-Q); key establishment survives a break of "
             r"ML-KEM (KEX-H); signatures resist a CRQC (Sig-Q). $\Delta_{2RT}$: cryptographic overhead versus "
             r"Control-2RT (median, 95\% CI). Bytes: key-establishment blob + one signature per transaction (API), "
             r"and key-establishment blob + signatures on a 200-token per-chunk stream. A configuration is \emph{dominated} if another is at "
             r"least as secure on every property, no worse on latency at 10 connections (90\% CI of the "
             r"difference below $+5$\%), no larger in the workload's bytes, and strictly better somewhere; the last two "
             r"columns name the dominating configurations (codes as in Table~\ref{tab:configs}), or ``--'' if none. "
             r"The 100- and 1,000-connection levels are not used: the first is bimodal and the second dominated by "
             r"single-host contention (Section~\ref{sec:res-concurrency}).}",
             r"\label{tab:dominance}", r"\setlength{\tabcolsep}{3.5pt}", r"\footnotesize",
             r"\begin{tabular}{@{}l" + "c" * len(SEC_AXES) + "r" * len(levels) + r"rrcc@{}}", r"\toprule",
             r" & \multicolumn{3}{c}{Security} & $\Delta_{2RT}$ & \multicolumn{2}{c}{Bytes} "
             r"& \multicolumn{2}{c}{Dominated by} \\",
             r"\cmidrule(lr){2-4}\cmidrule(lr){5-5}\cmidrule(lr){6-7}\cmidrule(lr){8-9}",
             "Configuration & KEX-Q & KEX-H & Sig-Q & "
             + " & ".join(f"@{c:,} ({'s' if c >= 1000 else 'ms'})" for c in levels)
             + r" & API & Per-chunk & API & Per-chunk \\", r"\midrule"]
    for c in present:
        cells = [r"\checkmark" if ax[c] else "--" for _, ax in SEC_AXES]
        for conc in levels:
            r = ov[(ov["config"] == c) & (ov["concurrency"] == conc)] if not ov.empty else ov
            if r.empty:
                cells.append("--")
                continue
            r = r.iloc[0]
            k = 1000 if conc >= 1000 else 1
            cells.append(f"{r['diff_ms'] / k:+.{2 if k > 1 else 1}f} [{r['ci95_lo'] / k:+.{2 if k > 1 else 1}f}, "
                         f"{r['ci95_hi'] / k:+.{2 if k > 1 else 1}f}]")
        cells.append(f"{hs_bytes[c]:,.0f}" if c in hs_bytes else "--")
        cells.append(f"{pc_bytes[c]:,.0f}" if c in pc_bytes else "--")
        for w in workloads:
            d = dominated_by[w][c]
            cells.append(", ".join(CODE[o] for o in d) if d else "--")
        lines.append(f"{CODE[c]}: {LABEL[c]} & " + " & ".join(cells) + r" \\")
        for w in workloads:
            out.num("Decision summary (non-dominated configurations)", f"{LABEL[c]} -- {w}",
                    "Pareto-optimal" if not dominated_by[w][c] else
                    "dominated by " + ", ".join(LABEL[o] for o in dominated_by[w][c]))
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table*}", ""]
    out.table("tab_dominance", "\n".join(lines))


def table_timing(out: Out, results_dir: str, sdf: pd.DataFrame | None, cdf: pd.DataFrame | None) -> None:
    """Reconciles per-signature cost in streams with the microbenchmark:
    validation.contention_check measures sign/verify back-to-back and spaced
    one chunk interval apart (idle, and while Llama generates), in wall and
    thread-CPU time; the streaming runs give per-signature cost in situ."""
    path = os.path.join(results_dir, "validation", "contention_check.csv")
    if not os.path.isfile(path):
        out.notes.append("No signing-cost diagnostic (results/validation/contention_check.csv); run validation.contention_check.")
        return
    cc = pd.read_csv(path)
    scheme = {"hybrid": "ECDSA P-256", "full_pqc": "ML-DSA-65"}
    phases = [("idle", "Back-to-back, idle"), ("llama_generating", "Back-to-back, during generation"),
              ("ecores", "Back-to-back, efficiency cores"),
              ("idle_spaced", "One per 125\\,ms, idle"), ("busy_spaced", "One per 125\\,ms, core kept busy"),
              ("llama_spaced", "One per 125\\,ms, during generation")]
    lines = [r"\begin{table}[t]", r"\centering",
             r"\caption{Per-call signing and verification cost ($\mu$s, median; wall-clock / thread-CPU) by calling "
             r"pattern, and per signature inside real Llama streams (CPU time; range of per-cell medians over all "
             r"streaming and checkpoint cells). CPU time rises with wall time, so the extra cost after an idle gap "
             r"is executed work (the core has clocked down), not waiting.}",
             r"\label{tab:timing}", r"\setlength{\tabcolsep}{2.5pt}", r"\footnotesize",
             r"\begin{tabular}{@{}L{2.9cm}rrrr@{}}", r"\toprule",
             r" & \multicolumn{2}{c}{Sign} & \multicolumn{2}{c}{Verify} \\", r"\cmidrule(lr){2-3}\cmidrule(lr){4-5}",
             r"Pattern & ECDSA & ML-DSA & ECDSA & ML-DSA \\", r"\midrule"]

    def cell(sel, op):
        return f"{sel[f'{op}_wall_ms'].median() * 1000:,.0f}/{sel[f'{op}_cpu_ms'].median() * 1000:,.0f}"

    for ph, name in phases:
        cells = []
        for op in ("sign", "verify"):
            for cfg in ("hybrid", "full_pqc"):
                sel = cc[(cc["phase"] == ph) & (cc["config"] == cfg)]
                cells.append("--" if sel.empty else cell(sel, op))
                if not sel.empty:
                    out.num("Signing-cost diagnostic (us, median wall/CPU)", f"{scheme[cfg]} {op}, {name.replace(chr(92) + ',', ' ')}",
                            f"{sel[f'{op}_wall_ms'].median() * 1000:,.1f} / {sel[f'{op}_cpu_ms'].median() * 1000:,.1f} "
                            f"(mean wall {sel[f'{op}_wall_ms'].mean() * 1000:,.1f}, n={len(sel)})")
        lines.append(f"{name} & " + " & ".join(cells) + r" \\")
    # In situ: per-signature cost in every streaming and checkpoint cell (median over
    # repetitions), as a range per scheme, checked against the back-to-back (lower)
    # and spaced-idle (upper) bounds measured above.
    frames = [d for d in (sdf, cdf) if d is not None and "total_signing_cpu_ms" in d]
    if frames:
        allc = pd.concat(frames, ignore_index=True)
        allc = allc[allc["n_signatures"] > 0].assign(
            scheme=lambda d: np.where(d["config"].isin(["full_pqc", "hybrid_kex_pq"]), "full_pqc", "hybrid"),
            k=lambda d: d["checkpoint_interval"].fillna(0) if "checkpoint_interval" in d else 0)
        cells = []
        for op, col in (("sign", "total_signing"), ("verify", "total_verify")):
            for cfg in ("hybrid", "full_pqc"):
                v = allc[allc["scheme"] == cfg]
                per = v.assign(c=v[f"{col}_cpu_ms"] / v["n_signatures"] * 1000).groupby(
                    ["config", "strategy", "max_tokens", "k"])["c"].median()
                lo_b = cc[(cc["phase"] == "idle") & (cc["config"] == cfg)][f"{op}_cpu_ms"].median() * 1000
                hi_b = cc[(cc["phase"] == "idle_spaced") & (cc["config"] == cfg)][f"{op}_cpu_ms"].median() * 1000
                inside = ((per >= 0.8 * lo_b) & (per <= 1.2 * hi_b)).mean()
                cells.append(f"{per.min():,.0f}--{per.max():,.0f}")
                out.num("Signing-cost diagnostic (us, median wall/CPU)", f"{scheme[cfg]} {op} CPU per signature in streams",
                        f"{per.min():,.1f}-{per.max():,.1f} over {len(per)} cells; {inside:.0%} of cells within "
                        f"[back-to-back {lo_b:,.1f}, spaced {hi_b:,.1f}] (+/-20%)")
        lines.append(r"In streams (CPU, range of cells) & " + " & ".join(cells) + r" \\")
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}", ""]
    out.table("tab_timing", "\n".join(lines))


CAMPAIGN_CELLS = [("per_chunk", None, "Per-chunk"), ("hash_chain", None, "Chain $k{=}\\infty$"),
                  ("hash_chain", 10, "$k{=}10$"), ("hash_chain", 5, "$k{=}5$"), ("hash_chain", 2, "$k{=}2$")]
CAMPAIGN_ATTACKS = [("drop", "Drop one chunk"), ("reorder", "Reorder two chunks"), ("duplicate", "Duplicate a chunk"),
                    ("replay", "Replay a foreign chunk"), ("session_replay", "Replay a whole session"),
                    ("truncate", "Truncate"), ("checkpoint_strip", "Strip all checkpoints"),
                    ("checkpoint_strip_v2client", "\\quad v2 client (no schedule check)"),
                    ("checkpoint_move", "Move a checkpoint"), ("drop_before_ckpt", "Drop chunk before checkpoint"),
                    ("drop_after_ckpt", "Drop chunk after checkpoint"), ("reorder_across", "Reorder across checkpoint")]


def table_attack_campaign(out: Out, results_dir: str) -> None:
    path = os.path.join(results_dir, "streaming", "mitm", "campaign.json")
    if not os.path.isfile(path):
        return
    with open(path) as f:
        doc = json.load(f)
    df = pd.DataFrame(doc["rows"])
    df["k"] = df["checkpoint_interval"].fillna(0).astype(int)
    configs = [c for c in PROTECTED if c in set(df["config"])]
    chunk = 5
    # Trials within one captured stream are not independent (they differ only in attack
    # position), so the defensible unit is the stream: each entry pools pool x configs
    # distinct streams. Every stream in every all-detected entry was detected at every
    # sampled position, so the stream-level bound is Clopper-Pearson on n_streams/n_streams.
    n_streams = int(doc["pool"]) * len(configs)
    n_trials = int(doc["trials"]) * len(configs)
    s_lo = clopper_pearson_ci(n_streams, n_streams)[0]
    t_lo = clopper_pearson_ci(n_trials, n_trials)[0]
    out.num("Stream attack campaign: confidence bounds", "Stream-level (cluster) 95% bound, all-detected entry",
            f"{n_streams}/{n_streams} streams -> lower bound {s_lo:.1%} (trial-level, assuming independence: "
            f"{n_trials}/{n_trials} -> {t_lo:.2%})")
    lines = [r"\begin{table*}[t]", r"\centering",
             fr"\caption{{Stream-integrity campaign on real Llama streams ({doc['max_tokens']} tokens, {chunk}-token chunks), "
             fr"pooled over {len(configs)} configurations: {doc['trials']} trials per configuration and cell, each on a random "
             fr"one of {doc['pool']} captured streams at a random position ({n_trials:,} trials and {n_streams} distinct streams "
             fr"per entry). Each entry: \% detected / \% detected before the stream ended / mean chunks shown with no "
             r"verified signature covering them when the client rejected. Trials on the same stream differ only in attack "
             r"position and are not independent, so we take the stream as the unit: 100\% detected means the attack was "
             fr"detected at every sampled position on all {n_streams} streams (exact 95\% lower bound "
             fr"{100 * s_lo:.1f}\% of streams); 0\% means it was detected on none (upper bound {100 * (1 - s_lo):.1f}\%). "
             fr"Treating trials as independent would give {100 * t_lo:.2f}\%, which the design does not support. "
             r"Benign: unmodified streams rejected (false rejections).}",
             r"\label{tab:campaign}", r"\setlength{\tabcolsep}{2.5pt}", r"\scriptsize",
             r"\begin{tabular}{@{}l" + "r" * len(CAMPAIGN_CELLS) + r"@{}}", r"\toprule",
             "Attack & " + " & ".join(n for _, _, n in CAMPAIGN_CELLS) + r" \\", r"\midrule"]
    benign = []
    for s, k, _ in CAMPAIGN_CELLS:
        g = df[(df["strategy"] == s) & (df["k"] == (k or 0)) & (df["attack"] == "benign")]
        n, d = int(g["n"].sum()), int(g["detected"].sum())
        hi = 1 - 0.05 ** (1 / n) if d == 0 and n else np.nan  # exact one-sided-ish bound for 0 events
        benign.append(f"{d}/{n}" + (f" ($<${hi:.1%})".replace("%", r"\%") if d == 0 and n else ""))
    lines.append(r"Benign (false rejections) & " + " & ".join(benign) + r" \\")
    lines.append(r"\midrule")
    for a, name in CAMPAIGN_ATTACKS:
        cells, any_row = [], False
        for s, k, _ in CAMPAIGN_CELLS:
            g = df[(df["strategy"] == s) & (df["k"] == (k or 0)) & (df["attack"] == a)]
            if g.empty or g["n"].sum() == 0:
                cells.append("--")
                continue
            any_row = True
            n, d, mid = int(g["n"].sum()), int(g["detected"].sum()), int(g["mid_stream"].fillna(0).sum())
            unv = (g["unverified_at_detection_mean"] * g["n"]).sum() / n if g["unverified_at_detection_mean"].notna().any() else np.nan
            cells.append(f"{100 * d / n:.0f} / {100 * mid / n:.0f} / {unv:.1f}")
            lo, hi = clopper_pearson_ci(d, n)
            out.num("Stream attack campaign (pooled over configurations)",
                    f"{name.replace(chr(92) + 'quad ', '').strip()} -- {s} k={k or 'inf'}",
                    f"detected {d}/{n} (95% CI {lo:.4f}-{hi:.4f}), mid-stream {mid / n:.1%}, mean unverified chunks "
                    f"at rejection {unv:.2f}, mean attacker-influenced chunks shown "
                    f"{(g['exposure_chunks_mean'] * g['n']).sum() / n if g['exposure_chunks_mean'].notna().any() else float('nan'):.2f}")
        if any_row:
            lines.append(f"{name} & " + " & ".join(cells) + r" \\")
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table*}", ""]
    out.table("tab_campaign", "\n".join(lines))
    per_cfg = df[df["attack"] != "benign"].groupby("config").apply(
        lambda g: f"{int(g['detected'].sum())}/{int(g['n'].sum())}", include_groups=False)
    for c, v in per_cfg.items():
        out.num("Stream attack campaign (per configuration, all attacks and cells)", LABEL[c], v)


def clopper_pearson_ci(k: int, n: int, alpha: float = 0.05) -> tuple[float, float]:
    lo = 0.0 if k == 0 else stats.beta.ppf(alpha / 2, k, n - k + 1)
    hi = 1.0 if k == n else stats.beta.ppf(1 - alpha / 2, k + 1, n - k)
    return float(lo), float(hi)


def table_key_substitution(out: Out, results_dir: str) -> None:
    path = os.path.join(results_dir, "mitm", "key_substitution.json")
    if not os.path.isfile(path):
        return
    with open(path) as f:
        rows = pd.DataFrame(json.load(f))
    configs = [c for c in PROTECTED if c in set(rows["config"])]
    names = {"benign": "None", "substitute": "Substitute", "substitute_resign": "Subst.\\ + re-sign",
             "relay_tamper": "Relay + bit flip"}
    lines = [r"\begin{table}[t]", r"\centering",
             fr"\caption{{Full man-in-the-middle (key substitution) against a live server, pooled over {len(configs)} "
             r"configurations (results were identical in each). Accepted: the client accepted the response; Read: the "
             r"attacker decrypted the request; Forged: the client accepted an attacker-chosen prediction. Pinned: the "
             r"client checks the handshake transcript signature under a pinned server identity key "
             r"(Section~\ref{sec:auth}). Counts out of 1,800 trials per row (300 per configuration).}",
             r"\label{tab:keysub}", r"\setlength{\tabcolsep}{1.6pt}", r"\footnotesize",
             r"\begin{tabular}{@{}llrrrl@{}}", r"\toprule",
             r"Client & Attack & Accepted & Read & Forged & Rejected \\", r"\midrule"]
    for mode in ("unauthenticated", "pinned"):
        first = True
        for v in ("benign", "substitute", "substitute_resign", "relay_tamper"):
            g = rows[(rows["mode"] == mode) & (rows["variant"] == v)]
            if g.empty:
                continue
            n = int(g["n_valid"].sum())
            acc, rd, fg = int(g["accepted"].sum()), int(g["attacker_read_request"].sum()), int(g["forged_response_accepted"].sum())
            rej = {}
            for d in g["rejected_at"]:
                for k2, c2 in (d or {}).items():
                    rej[k2] = rej.get(k2, 0) + c2
            rej_s = ", ".join((k2.upper() if k2 == 'aead' else k2) + ('' if c2 == n else f' ({c2:,})') for k2, c2 in rej.items()) or "--"
            lines.append(f"{('Unauth.' if mode == 'unauthenticated' else 'Pinned') if first else ''} & "
                         f"{names[v]} & {acc:,} & {rd:,} & {fg:,} & {rej_s} \\\\")
            out.num("Key substitution (full MITM), pooled", f"{mode}: {names[v]}",
                    f"accepted {acc}/{n}, attacker read request {rd}/{n}, forged response accepted {fg}/{n}, rejected at {rej}")
            first = False
        lines.append(r"\addlinespace")
    lines[-1] = r"\bottomrule"
    lines += [r"\end{tabular}", r"\end{table}", ""]
    out.table("tab_keysub", "\n".join(lines))


def table_auth_cost(out: Out, results_dir: str, entries: list[dict], warmup: float) -> None:
    """Cost of authenticating the handshake: each config with and without a
    transcript signature under a pinned identity key, run back to back."""
    if not entries:
        return
    raw = load_raw(os.path.join(results_dir, "raw"))
    ids = {e["run_id"] for e in entries}
    df = discard_warmup(raw[raw["run_id"].astype(str).isin(ids)].reset_index(drop=True), warmup)
    auth = df["auth_handshake"].fillna(False).astype(str).str.lower().isin(["true", "1"])
    df = df.assign(config=np.where(auth, df["config"] + "+auth", df["config"]))
    present = [c for c in PROTECTED if c in set(df["config"]) and f"{c}+auth" in set(df["config"])]
    cmp = comparison_stats(df, [(f"{c}+auth", c) for c in present], seed=19)
    ok = _ok(df)
    lines = [r"\begin{table}[t]", r"\centering",
             r"\caption{Cost of authenticating the handshake (10 connections, 5 repetitions each, run back to back "
             r"with the unauthenticated configuration). The identity key uses the configuration's signature scheme "
             r"(ML-DSA-65 for Full PQC and Hybrid-KEX-PQ, ECDSA P-256 otherwise). +B: bytes added per handshake; "
             r"verify: client transcript check; $\Delta$: end-to-end median difference with 95\% CI.}",
             r"\label{tab:authcost}", r"\setlength{\tabcolsep}{3pt}", r"\footnotesize",
             r"\begin{tabular}{@{}lrrr@{}}", r"\toprule",
             r"Configuration & +B & Verify ($\mu$s) & $\Delta$ (ms) \\", r"\midrule"]
    for c in present:
        r = cmp[(cmp["config"] == f"{c}+auth") & (cmp["concurrency"] == 10)]
        v = ok[ok["config"] == f"{c}+auth"]["handshake_auth_verify_ms"].median() * 1000
        ident = "ML-DSA-65" if c in ("full_pqc", "hybrid_kex_pq") else "ECDSA P-256"
        extra = 3309 if ident == "ML-DSA-65" else 71
        d = "--" if r.empty else _fmt_ci(r.iloc[0]["diff_ms"], r.iloc[0]["ci95_lo"], r.iloc[0]["ci95_hi"])
        lines.append(f"{LABEL[c]} & {extra:,} & {v:,.0f} & {d} \\\\")
        if not r.empty:
            out.num("Authenticated handshake cost (c=10)", LABEL[c],
                    f"Delta {r.iloc[0]['diff_ms']:+.2f} ms [{r.iloc[0]['ci95_lo']:+.2f}, {r.iloc[0]['ci95_hi']:+.2f}] "
                    f"({r.iloc[0]['diff_pct']:+.1f}%), client transcript verify {v:,.0f} us, +{extra} B")
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}", ""]
    out.table("tab_authcost", "\n".join(lines))


def main() -> None:
    ap = argparse.ArgumentParser(description="PQ-Shield paper figures / tables / key numbers")
    ap.add_argument("--results-dir", default="results")
    ap.add_argument("--output-dir", default="paper")
    ap.add_argument("--concurrency-run-id", action="append", default=None)
    ap.add_argument("--streaming-run-id", default=DEFAULT_STREAMING_RUN)
    ap.add_argument("--decomposition-concurrency", type=int, default=10)
    ap.add_argument("--warmup-fraction", type=float, default=0.05)
    ap.add_argument("--payload-run-id", action="append", default=None,
                    help="Payload-profile sweep run_id(s) (one per profile)")
    ap.add_argument("--network-run-id", action="append", default=None,
                    help="Network-emulation sweep run_id(s) (one per network profile)")
    ap.add_argument("--checkpoint-run-id", default=None, help="Checkpointed hash-chain streaming run_id")
    ap.add_argument("--amortization-run-id", action="append", default=None,
                    help="Session-reuse sweep run_id(s), one per requests-per-handshake value")
    ap.add_argument("--manifest", default=None,
                    help="JSON written by bench.paper_runs; fills any run-id option not given explicitly "
                         "(default: <results-dir>/paper_runs.json if it exists)")
    args = ap.parse_args()

    manifest_path = args.manifest or os.path.join(args.results_dir, "paper_runs.json")
    manifest = None
    if os.path.isfile(manifest_path):
        with open(manifest_path) as f:
            manifest = json.load(f)
        args.concurrency_run_id = args.concurrency_run_id or (
            [r for r in (manifest.get("concurrency"), manifest.get("concurrency_supplement"),
                         manifest.get("concurrency_control_2rt"), manifest.get("concurrency_hybrid_kex_pq")) if r]
            or None)
        args.payload_run_id = args.payload_run_id or manifest.get("payload") or None
        args.network_run_id = args.network_run_id or (
            (manifest.get("network") or []) + (manifest.get("network_supplement") or []) or None)
        args.checkpoint_run_id = args.checkpoint_run_id or manifest.get("checkpoint")
        args.amortization_run_id = args.amortization_run_id or manifest.get("amortization") or None
        if manifest.get("streaming") and args.streaming_run_id == DEFAULT_STREAMING_RUN:
            args.streaming_run_id = manifest["streaming"]
        print(f"Using run ids from {manifest_path}")

    _style()
    conc_df, provisional, conc_label = load_concurrency(args.results_dir, args.concurrency_run_id, args.warmup_fraction)
    out = Out(args.output_dir, provisional)
    print(f"Writing to {args.output_dir}/ (concurrency data: {conc_label})")

    st = concurrency_stats(conc_df)
    sig = pd.concat([mann_whitney_vs_control(conc_df, metric=m) for m in ("total_ms", "rtt_ms")], ignore_index=True)
    present_cfgs = set(conc_df["config"])
    pairs = [(c, "control") for c in CONFIGS if c != "control" and c in present_cfgs]
    if "control_2rt" in present_cfgs:
        pairs += [(c, "control_2rt") for c in PROTECTED if c in present_cfgs]
    if "classical_ecdhe" in present_cfgs:
        pairs += [(c, "classical_ecdhe") for c in ("hybrid", "hybrid_kex", "full_pqc", "hybrid_kex_pq")
                  if c in present_cfgs]
    cmp = comparison_stats(conc_df, pairs)
    fig_concurrency(out, st, provisional,
                    _resource_cells(args.results_dir, args.concurrency_run_id) if args.concurrency_run_id else None)
    fig_decomposition(out, conc_df, provisional, args.decomposition_concurrency)
    table_concurrency(out, st, cmp, provisional)
    table_equivalence(out, cmp)
    table_failures(out, conc_df, cmp)
    missing = [c for c in CONFIGS if c not in set(st["config"])]
    if missing:
        out.notes.append(f"Concurrency data has no rows for: {', '.join(LABEL[c] for c in missing)}.")
    thin = st[(st["n_reps"] < 5) & (st["config"].isin(CONFIGS))]
    for _, r in thin.iterrows():
        out.notes.append(f"Concurrency cell {LABEL[r['config']]} @ {r['concurrency']:,} has only {r['n_reps']} repetition(s).")
    for _, r in st.iterrows():
        sec = "Concurrency (end-to-end latency)" + (" -- PROVISIONAL" if provisional else "")
        out.num(sec, f"{LABEL[r['config']]} @ {r['concurrency']:,}: median [rep range] / p95 / failed",
                f"{r['median']:,.0f} [{r['rep_min']:,.0f}-{r['rep_max']:,.0f}] / {r['p95']:,.0f} ms / {r['error_rate']:.1%} "
                f"({int(r['n_attempted']):,} attempted, {int(r['n_reps'])} reps)")
    for _, r in cmp[cmp["reference"].isin(["control", "control_2rt"])].iterrows():
        out.num(f"Difference vs {LABEL[r['reference']]} (median, 95% two-stage bootstrap CI; "
                f"p: rep-level Mann-Whitney, Holm)" + (" -- PROVISIONAL" if provisional else ""),
                f"{LABEL[r['config']]} @ {int(r['concurrency']):,}",
                f"{r['diff_ms']:+.1f} ms [{r['ci95_lo']:+.1f}, {r['ci95_hi']:+.1f}] ({r['diff_pct']:+.1f}%), "
                f"Cliff's delta {r['cliffs_delta']:+.2f}, p_Holm = {r['p_holm']:.3f}")

    with open(os.path.join(args.results_dir, "validation", "primitive_bench.json")) as f:
        bench = json.load(f)
    fig_primitives(out, bench)
    fig_wire_bytes(out, args.results_dir)
    fig_streaming_hndl(out, args.results_dir)
    table_threats(out, args.results_dir)

    sdf = load_streaming(args.results_dir, args.streaming_run_id)
    if "checkpoint_interval" in sdf:
        sdf = sdf[sdf["checkpoint_interval"].isna()]  # plain strategies only; checkpoints have their own figure
    fig_streaming(out, sdf, args.streaming_run_id)
    table_streaming(out, sdf, args.streaming_run_id)
    table_dominance(out, conc_df, sdf, args.results_dir)
    table_attack_campaign(out, args.results_dir)
    table_key_substitution(out, args.results_dir)
    table_auth_cost(out, args.results_dir, manifest.get("auth_cost", []) if manifest else [], args.warmup_fraction)

    if args.concurrency_run_id:
        table_resources(out, args.results_dir, args.concurrency_run_id, provisional)
    else:
        out.notes.append("No CPU/RSS table: the legacy concurrency data predates resource sampling.")
    if args.payload_run_id:
        pdf_ = _load_runs(args.results_dir, args.payload_run_id, args.warmup_fraction)
        fig_payload_profiles(out, pdf_)
        table_payload_profiles(out, pdf_)
    else:
        out.notes.append("No payload-profile sweep given (--payload-run-id); Table II in the draft is n=1 per profile.")
    if args.checkpoint_run_id:
        cdf = load_streaming(args.results_dir, args.checkpoint_run_id)
        camp_path = os.path.join(args.results_dir, "streaming", "mitm", "campaign.json")
        attacks = json.load(open(camp_path))["rows"] if os.path.isfile(camp_path) else []
        fig_checkpoint_frontier(out, cdf, args.checkpoint_run_id, attacks)
        table_checkpoint(out, cdf)
    table_timing(out, args.results_dir, sdf, cdf if args.checkpoint_run_id else None)
    if args.amortization_run_id:
        fig_amortization(out, _load_runs(args.results_dir, args.amortization_run_id, args.warmup_fraction))
    if args.network_run_id:
        fig_network(out, _load_runs(args.results_dir, args.network_run_id, args.warmup_fraction))
    else:
        out.notes.append("No network-emulation sweep given (--network-run-id); all latency is over loopback.")

    table_environment(out, os.path.join(args.output_dir, "environment.json"))
    out.write_numbers({
        "Concurrency sweep": conc_label + ("  **(PROVISIONAL)**" if provisional else ""),
        "Streaming sweep": f"{args.streaming_run_id} ({sdf['backend'].iloc[0] if 'backend' in sdf else 'backend not recorded'}; "
                           f"{int(sdf['repetition'].max())} reps, {len(sdf)} successful transactions)",
        "Primitive benchmark": f"results/validation/primitive_bench.json (host: {bench.get('host', 'not recorded')})",
        "Latency metric": "total_ms = handshake round trip + protected request (end-to-end)",
        "Payload-profile sweeps": ", ".join(args.payload_run_id or []) or "none",
        "Network-emulation sweeps": ", ".join(args.network_run_id or []) or "none",
        "Checkpoint frontier run": args.checkpoint_run_id or "none",
        "Amortization sweeps": ", ".join(args.amortization_run_id or []) or "none",
    })


if __name__ == "__main__":
    main()
