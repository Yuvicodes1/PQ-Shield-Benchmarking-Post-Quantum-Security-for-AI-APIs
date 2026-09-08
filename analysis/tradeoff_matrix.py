"""Builds the composite security/performance trade-off matrix (design doc
Phase 6, "Layer 6"). The composite score formula is:

    composite_score(config, concurrency) =
        w_sec * security_score(config) - w_perf * normalized_latency_overhead(config, concurrency)

security_score is an explicit, defended ordinal mapping (NOT hand-waved):
    classical = 0.0   -- no quantum resistance on either axis
    hybrid    = 0.8    -- ML-KEM-768 closes the HNDL/confidentiality threat
                          entirely (the axis with the long, currently-accruing
                          exposure window); ECDSA signing remains classically
                          vulnerable, but signatures only protect real-time
                          integrity, not the confidentiality of already-
                          harvested traffic, so this is a materially smaller
                          residual risk than full classical exposure
    full_pqc  = 1.0    -- quantum-resistant on both confidentiality and
                          integrity/authenticity axes

normalized_latency_overhead(config, concurrency) =
    (median_rtt_ms[config, concurrency] - median_rtt_ms[baseline, concurrency])
    / median_rtt_ms[baseline, concurrency]

`baseline` is `control` whenever it's present in the data -- every
already-validated concurrency-sweep number to date is computed this way --
falling back to `classical` when it isn't, which is every streaming run
(bench/streaming_runner.py has no unprotected control leg at all). See
`analysis.aggregate.resolve_baseline_config` for the resolution logic, and
the `baseline_config` column this module's output always carries so
callers never have to guess, or silently mix, which baseline a given number
is relative to.

Reported at three weightings (security-priority, performance-priority,
balanced) rather than a single arbitrary weighting, per the design doc's
explicit recommendation -- this is more defensible to reviewers than one
hard-coded number and lets a reader apply their own organizational risk
tolerance. build_matrix_at() computes the same formula at any single
(w_sec, w_perf) pair, for callers (e.g. the Results Dashboard's weighting
slider) that need an arbitrary weighting rather than these three presets;
build_matrix() itself calls build_matrix_at() three times so there is only
one implementation of the score formula in the codebase.

Usage:
    python -m analysis.tradeoff_matrix --raw-dir results/raw --output results/tradeoff_matrix.csv
"""

from __future__ import annotations

import argparse
import os

import pandas as pd

from analysis.aggregate import discard_warmup, load_raw, resolve_baseline_config

SECURITY_SCORES = {
    "control": None,   # excluded from the matrix -- it is the zero-overhead reference, not a real option
    "classical": 0.0,
    "hybrid": 0.8,
    "full_pqc": 1.0,
}

# Default split for streaming_security_score() below: how much of the
# blended score comes from the measured sequence-integrity exposure window
# vs. the categorical SECURITY_SCORES mapping. See streaming_security_score's
# docstring and docs/DESIGN.md's "Streaming security score" note for the
# justification -- 0.3 mirrors that note's stated default.
DEFAULT_EXPOSURE_SHARE = 0.3


def sequence_integrity_resistance(
    streaming_mitm_summaries: list[dict], config: str, strategy: str
) -> float | None:
    """1 - (mean fraction of the response delivered before detection),
    averaged across attack types (drop/reorder) when both exist for this
    (config, strategy) -- the Threat Scenarios page's 🌊 Streaming Sequence
    Attack tab already presents drop and reorder side by side as two trials
    of the same sequence-integrity threat, not two distinct threats, so
    averaging them here is consistent with that framing rather than an
    arbitrary choice.

    `buffer_and_sign` is hardcoded to 1.0 (no exposure window by
    construction: nothing is delivered before the single terminating
    signature) rather than read from its summary rows -- those rows exist
    on disk (`results/streaming/mitm/*-buffer_and_sign-*-summary.json`) but
    carry `fraction_delivered_before_detection_mean=None` with
    `n_valid_trials=0`, since the drop/reorder attack can't be meaningfully
    constructed against a single terminal blob (see
    `threats/streaming_mitm_experiment.py`) -- reading them as-is would
    read as "no data" rather than the true "zero exposure by construction".

    Returns None (never a fabricated 0.0 or 1.0) if no valid trial data
    exists yet for this (config, strategy) pair among per_chunk/hash_chain."""
    if strategy == "buffer_and_sign":
        return 1.0
    fractions = [
        s["fraction_delivered_before_detection_mean"]
        for s in streaming_mitm_summaries
        if s.get("config") == config and s.get("strategy") == strategy
        and s.get("fraction_delivered_before_detection_mean") is not None
    ]
    if not fractions:
        return None
    return 1.0 - (sum(fractions) / len(fractions))


def streaming_security_score(
    config: str,
    strategy: str,
    streaming_mitm_summaries: list[dict],
    exposure_share: float = DEFAULT_EXPOSURE_SHARE,
) -> float | None:
    """Blends the existing categorical SECURITY_SCORES[config]
    (quantum-resistance on the confidentiality/authenticity axes) with the
    newly-measured sequence_integrity_resistance(config, strategy) into one
    score, still on SECURITY_SCORES' own [0, 1] scale -- so it can be fed
    straight into build_matrix_at's existing `w_sec * security_score` term
    unchanged, rather than adding a third weighted term to the composite
    formula. This keeps the Results Dashboard's existing w_sec/w_perf slider
    pair (which already sums to 1) intact for both run types; only what
    "security_score" *means* changes for a streaming call. See
    docs/DESIGN.md's "Streaming security score" note for the reasoning.

    exposure_share=0 reproduces plain SECURITY_SCORES[config] exactly --
    this function is only ever called for streaming runs, so the
    concurrency sweep's composite score is completely unaffected either way.

    Returns None if SECURITY_SCORES[config] is undefined (`control` --
    excluded the same way it always has been) or if
    sequence_integrity_resistance has no data yet for this (config,
    strategy) pair -- never fabricates a score for an untested combination."""
    sec_score = SECURITY_SCORES.get(config)
    if sec_score is None:
        return None
    exposure_resistance = sequence_integrity_resistance(streaming_mitm_summaries, config, strategy)
    if exposure_resistance is None:
        return None
    return (1 - exposure_share) * sec_score + exposure_share * exposure_resistance

WEIGHTINGS = {
    "security_priority": {"w_sec": 0.8, "w_perf": 0.2},
    "balanced": {"w_sec": 0.5, "w_perf": 0.5},
    "performance_priority": {"w_sec": 0.2, "w_perf": 0.8},
}


def build_matrix_at(
    df: pd.DataFrame,
    w_sec: float,
    w_perf: float,
    baseline_config: str | None = None,
    scale_col: str = "concurrency",
    metric_col: str = "rtt_ms",
    security_scores: dict[str, float | None] | None = None,
) -> pd.DataFrame:
    """The one place composite_score is actually computed, for a single
    (w_sec, w_perf) pair -- everything else in this module (build_matrix's
    three fixed weightings, the Results Dashboard's arbitrary-weighting
    slider) calls through this rather than reimplementing the formula.
    Rows are keyed by (config, scale_col); config is restricted to whichever
    configs have a defined SECURITY_SCORES entry and are present in the data
    (control is excluded -- it's the historical zero-overhead reference, not
    a real option; every other scored config, including the baseline itself
    if it isn't control, gets a row).

    baseline_config=None (default) auto-resolves per
    analysis.aggregate.resolve_baseline_config: "control" when present in
    the data, else "classical" -- the streaming sweep has no control leg.
    The resolved value is always in the output's "baseline_config" column.

    scale_col/metric_col default to the concurrency sweep's "concurrency"/
    "rtt_ms" -- passing scale_col="max_tokens", metric_col="ttft_ms" (say)
    computes the same formula for a streaming run, keyed by response length
    instead of concurrency. Output column names for the scale/metric/
    baseline values track whichever columns were requested (e.g.
    "median_ttft_ms"/"baseline_median_ttft_ms" for that streaming call) so
    two different scales/metrics are never silently conflated in one frame;
    for the default (scale_col="concurrency", metric_col="rtt_ms") call --
    every concurrency-sweep caller today -- these are "median_rtt_ms" and
    "baseline_median_rtt_ms", identical values to before this function
    gained these parameters (only the second column's name changed, from
    "control_median_rtt_ms", to stop implying it's always literally
    `control`; nothing reads that column by name elsewhere in the codebase).

    security_scores=None (default) uses the module-level SECURITY_SCORES
    dict, exactly as before this parameter existed. A caller building a
    streaming-strategy-aware matrix passes a dict of
    {config: streaming_security_score(config, strategy, ...)} instead --
    see that function -- so the composite-score *formula* below never
    changes, only which per-config number "security_score" resolves to."""
    ok = df[df["error"].isna() | (df["error"] == "")]
    available_configs = set(ok["config"].unique())
    baseline_config = resolve_baseline_config(available_configs, baseline_config)
    median_metric = ok.groupby(["config", scale_col])[metric_col].median()
    scores = security_scores if security_scores is not None else SECURITY_SCORES
    scored_configs = [c for c, s in scores.items() if s is not None and c in available_configs]

    median_col = f"median_{metric_col}"
    baseline_col = f"baseline_median_{metric_col}"

    rows = []
    for scale_val in sorted(ok[scale_col].unique()):
        try:
            baseline_val = median_metric[(baseline_config, scale_val)]
        except KeyError:
            continue
        for config in scored_configs:
            try:
                config_val = median_metric[(config, scale_val)]
            except KeyError:
                continue
            overhead_pct = (config_val - baseline_val) / baseline_val if baseline_val > 0 else None
            sec_score = scores[config]
            score = w_sec * sec_score - w_perf * (overhead_pct or 0.0)
            rows.append({
                "config": config,
                scale_col: int(scale_val),
                "baseline_config": baseline_config,
                "w_sec": w_sec,
                "w_perf": w_perf,
                "security_score": sec_score,
                median_col: config_val,
                baseline_col: baseline_val,
                "normalized_latency_overhead": overhead_pct,
                "composite_score": score,
            })
    return pd.DataFrame(rows)


def build_matrix(df: pd.DataFrame, baseline_config: str | None = None) -> pd.DataFrame:
    """All three standard weightings (design doc's recommended headline
    view), each computed via build_matrix_at so there is exactly one
    implementation of the scoring formula in the codebase."""
    frames = []
    for weighting_name, w in WEIGHTINGS.items():
        at = build_matrix_at(df, w["w_sec"], w["w_perf"], baseline_config=baseline_config)
        at.insert(2, "weighting", weighting_name)
        frames.append(at)
    if not frames:
        return pd.DataFrame()
    return pd.concat(frames, ignore_index=True)


def main():
    parser = argparse.ArgumentParser(description="PQ-Shield weighted trade-off matrix builder")
    parser.add_argument("--raw-dir", default="results/raw")
    parser.add_argument("--warmup-fraction", type=float, default=0.05)
    parser.add_argument("--output", default="results/tradeoff_matrix.csv")
    parser.add_argument("--baseline-config", default=None,
                         help="Config to normalize overhead against; default auto-resolves to 'control' "
                              "if present, else 'classical' (see resolve_baseline_config).")
    args = parser.parse_args()

    df = load_raw(args.raw_dir)
    df = discard_warmup(df, args.warmup_fraction)

    matrix = build_matrix(df, baseline_config=args.baseline_config)
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    matrix.to_csv(args.output, index=False)
    print(f"Wrote trade-off matrix ({len(matrix)} rows) to {args.output}")

    for weighting_name in WEIGHTINGS:
        sub = matrix[matrix["weighting"] == weighting_name]
        print(f"\n=== {weighting_name} (w_sec={WEIGHTINGS[weighting_name]['w_sec']}, "
              f"w_perf={WEIGHTINGS[weighting_name]['w_perf']}) ===")
        for concurrency in sorted(sub["concurrency"].unique()):
            cs = sub[sub["concurrency"] == concurrency].sort_values("composite_score", ascending=False)
            best = cs.iloc[0]
            print(f"  concurrency={concurrency}: best = {best['config']} "
                  f"(score={best['composite_score']:.3f}, overhead={best['normalized_latency_overhead']:.1%})")


if __name__ == "__main__":
    main()
