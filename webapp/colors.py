"""Single source of truth for every color used across the benchmark figures
(analysis/figures.py, analysis/plot_metrics.py) and the Results Dashboard
(pages/3_Results_Dashboard.py). Previously CONFIG_COLORS was independently
redefined in all three places (identical values, but no guarantee a future
edit stays that way), and STRATEGY_COLORS reused CONFIG_COLORS' exact hex
values, making a bar "red" mean either a config or a signing strategy
depending on which chart was on screen. Fixed here: two visually distinct
palettes, one per dimension, defined once.
"""

from __future__ import annotations

# Per-configuration colors (control/classical/hybrid/full_pqc) -- the
# gray/red/orange/blue mapping used in the paper's own matplotlib figures.
# Every config-colored chart across the app uses this exact dict.
CONFIG_COLORS = {
    "control": "#888888",
    "control_2rt": "#4d4d4d",  # matched-protocol control: control's gray, darker
    "classical": "#c0392b",
    # Teal: validated all-pairs against red/orange/blue (worst normal-vision
    # dE 16.3, CVD 11.0). It sits close to STRATEGY_COLORS["per_chunk"] green,
    # but config and strategy palettes never share a chart, and the paper
    # figures use config colors only.
    "classical_ecdhe": "#16a085",
    # Raspberry: validated against its neighbours in config order (orange hybrid,
    # blue full_pqc); figures add hatch/marker as the secondary cue.
    "hybrid_kex": "#ad1457",
    # Deep violet: the best sixth hue left (deutan dE 6.5 vs full_pqc blue, in
    # the 6-8 band), so figures always pair it with its own hatch and marker.
    "hybrid_kex_pq": "#6c3fa0",
    "hybrid": "#e67e22",
    "full_pqc": "#2471a3",
}

# bench.orchestrator writes resource-summary JSON keyed by its own hyphenated
# "full-pqc" rather than "full_pqc" -- same colors, just the other key form,
# so callers reading that data don't need a translation step.
CONFIG_COLORS_HYPHENATED = {**CONFIG_COLORS, "full-pqc": CONFIG_COLORS["full_pqc"],
                            "classical-ecdhe": CONFIG_COLORS["classical_ecdhe"],
                            "hybrid-kex": CONFIG_COLORS["hybrid_kex"],
                            "hybrid-kex-pq": CONFIG_COLORS["hybrid_kex_pq"],
                            "control-2rt": CONFIG_COLORS["control_2rt"]}

# Per-signing-strategy colors (buffer_and_sign/per_chunk/hash_chain) --
# purple/green/magenta, deliberately non-overlapping with CONFIG_COLORS'
# gray/red/orange/blue hues (including full_pqc's blue) so a reader never
# has to ask "is this color a config or a strategy" when both chart
# families appear on the same page.
STRATEGY_COLORS = {
    "buffer_and_sign": "#8e44ad",  # purple
    "per_chunk": "#27ae60",        # green
    "hash_chain": "#d63384",       # magenta
}

STRATEGY_ORDER = ["buffer_and_sign", "per_chunk", "hash_chain"]
