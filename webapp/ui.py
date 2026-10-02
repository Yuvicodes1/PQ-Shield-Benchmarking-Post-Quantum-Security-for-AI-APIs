"""Shared look and feel for the dashboard: one stylesheet, a page header,
KPI cards, configuration chips, and a Plotly styling helper. Pages call
`ui.page_header(...)` first; everything else is optional.

Colours that carry data (configurations, strategies) come from
webapp/colors.py; the stylesheet only adds neutral surfaces, so it reads
correctly in both the light and the dark theme (.streamlit/config.toml).
"""

from __future__ import annotations

import html

import plotly.graph_objects as go
import streamlit as st

from webapp.colors import CONFIG_COLORS

# Short names, codes, and construction facts, shared by every page.
CONFIG_ORDER = ["control", "control_2rt", "classical", "classical_ecdhe", "hybrid", "hybrid_kex", "full_pqc",
                "hybrid_kex_pq"]
PROTECTED = ["classical", "classical_ecdhe", "hybrid", "hybrid_kex", "full_pqc", "hybrid_kex_pq"]
SHORT = {"control": "Control", "control_2rt": "Control-2RT", "classical": "Classical-RSA",
         "classical_ecdhe": "Classical-ECDHE", "hybrid": "Hybrid", "hybrid_kex": "Hybrid-KEX",
         "full_pqc": "Full PQC", "hybrid_kex_pq": "Hybrid-KEX-PQ"}
CODE = {"control": "—", "control_2rt": "—", "classical": "A", "classical_ecdhe": "A′", "hybrid": "B",
        "hybrid_kex": "B′", "full_pqc": "C", "hybrid_kex_pq": "C′"}
KEX = {"control": "none", "control_2rt": "none (2 requests)", "classical": "RSA-2048-OAEP",
       "classical_ecdhe": "X25519", "hybrid": "ML-KEM-768", "hybrid_kex": "X25519MLKEM768",
       "full_pqc": "ML-KEM-768", "hybrid_kex_pq": "X25519MLKEM768"}
SIG = {"control": "none", "control_2rt": "none", "classical": "ECDSA P-256", "classical_ecdhe": "ECDSA P-256",
       "hybrid": "ECDSA P-256", "hybrid_kex": "ECDSA P-256", "full_pqc": "ML-DSA-65", "hybrid_kex_pq": "ML-DSA-65"}
# Security properties of the construction (same three as the paper's decision table).
KEX_PQ = {"classical": False, "classical_ecdhe": False, "hybrid": True, "hybrid_kex": True, "full_pqc": True,
          "hybrid_kex_pq": True}
KEX_HEDGED = {"classical": True, "classical_ecdhe": True, "hybrid": False, "hybrid_kex": True, "full_pqc": False,
              "hybrid_kex_pq": True}
SIG_PQ = {"classical": False, "classical_ecdhe": False, "hybrid": False, "hybrid_kex": False, "full_pqc": True,
          "hybrid_kex_pq": True}

_CSS = """
<style>
/* layout rhythm */
.block-container {padding-top: 2.2rem; padding-bottom: 4rem; max-width: 1320px;}
h1, h2, h3 {letter-spacing: -0.015em;}
[data-testid="stMetric"] {padding: 0.9rem 1rem;}
[data-testid="stMetricValue"] {font-weight: 650; letter-spacing: -0.02em;}

/* hero */
.pq-hero {padding: 1.6rem 1.8rem; border-radius: 1rem; margin-bottom: 1.4rem;
  background: linear-gradient(135deg, rgba(79,70,229,0.12) 0%, rgba(36,113,163,0.08) 45%, rgba(22,160,133,0.06) 100%);
  border: 1px solid rgba(127,127,127,0.18);}
.pq-eyebrow {font-size: 0.78rem; font-weight: 600; letter-spacing: 0.09em; text-transform: uppercase;
  opacity: 0.68; margin-bottom: 0.35rem;}
.pq-hero h1 {font-size: 2.05rem; margin: 0 0 0.35rem 0; padding: 0; line-height: 1.15;}
.pq-hero p {font-size: 1.02rem; opacity: 0.82; margin: 0; max-width: 62rem; line-height: 1.55;}

/* cards */
.pq-grid {display: grid; gap: 0.85rem; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));}
.pq-card {border: 1px solid rgba(127,127,127,0.2); border-radius: 0.85rem; padding: 1rem 1.1rem;
  background: rgba(127,127,127,0.035); transition: border-color .15s ease, transform .15s ease;}
.pq-card:hover {border-color: rgba(79,70,229,0.45); transform: translateY(-1px);}
.pq-kpi-label {font-size: 0.8rem; font-weight: 550; opacity: 0.7; margin-bottom: 0.25rem;}
.pq-kpi-value {font-size: 1.6rem; font-weight: 700; letter-spacing: -0.02em; line-height: 1.15;}
.pq-kpi-sub {font-size: 0.82rem; opacity: 0.68; margin-top: 0.3rem; line-height: 1.4;}
.pq-accent {display: inline-block; width: 0.55rem; height: 0.55rem; border-radius: 50%; margin-right: 0.45rem;
  vertical-align: middle;}

/* configuration chips */
.pq-chip {display: inline-flex; align-items: center; gap: 0.35rem; padding: 0.14rem 0.55rem;
  border-radius: 999px; font-size: 0.78rem; font-weight: 600; border: 1px solid rgba(127,127,127,0.25);
  margin: 0 0.3rem 0.3rem 0; white-space: nowrap;}
.pq-dot {width: 0.5rem; height: 0.5rem; border-radius: 50%; display: inline-block;}
.pq-prop {display: inline-block; font-size: 0.72rem; font-weight: 600; padding: 0.08rem 0.45rem;
  border-radius: 0.35rem; margin: 0.15rem 0.25rem 0 0;}
.pq-yes {background: rgba(22,160,133,0.14); color: inherit;}
.pq-no {background: rgba(127,127,127,0.12); opacity: 0.75;}

/* streamed text with verification state */
.pq-stream {font-size: 1.02rem; line-height: 1.75; padding: 0.9rem 1.1rem; border-radius: 0.75rem;
  border: 1px solid rgba(127,127,127,0.22); min-height: 6rem;}
.pq-tok-verified {}
.pq-tok-pending {opacity: 0.55; text-decoration: underline dotted rgba(127,127,127,0.8); text-underline-offset: 3px;}
.pq-tok-rejected {color: #c0392b; text-decoration: line-through;}
.pq-legend {font-size: 0.8rem; opacity: 0.75; margin-top: 0.4rem;}

/* section header */
.pq-section {margin: 1.6rem 0 0.6rem 0;}
.pq-section h3 {margin: 0; padding: 0;}
.pq-section p {margin: 0.2rem 0 0 0; opacity: 0.72; font-size: 0.92rem;}
</style>
"""


_THEME_JS = """
<script>
(function () {
  // Streamlit remembers the viewer's theme in localStorage under a key that
  // includes the page path it was loaded at, so store the choice for every
  // page of the app, then reload to apply it.
  const mode = %(mode)s, slugs = %(slugs)s;
  const path = window.location.pathname.replace(/\\/+$/, "");
  const last = path.split("/").pop();
  const base = (last && slugs.includes(last)) ? path.slice(0, -last.length - 1) : path;
  for (const s of slugs) {
    const p = ((base + "/" + s).replace(/\\/+$/, "")) || "/";
    for (const k of new Set(p === "/" ? ["/"] : [p, p + "/"])) {
      window.localStorage.setItem("stActiveTheme-" + k + "-v2", JSON.stringify(mode));
    }
  }
  window.location.reload();
})();
</script>
"""


def theme_toggle(slugs: list[str]) -> None:
    """Sidebar light/dark switch. Reflects the theme the browser is showing
    (st.context.theme) and, when flipped, stores the opposite choice the way
    Streamlit's own settings menu does and reloads."""
    import json

    current = getattr(st.context.theme, "type", None) or "light"
    dark = st.toggle("Dark mode", value=current == "dark", key="pq_dark_mode")
    if dark != (current == "dark"):
        st.html(_THEME_JS % {"mode": json.dumps("Dark" if dark else "Light"), "slugs": json.dumps(slugs)},
                unsafe_allow_javascript=True)


def inject_css() -> None:
    st.html(_CSS)


def page_header(title: str, subtitle: str = "", eyebrow: str = "PQ-Shield") -> None:
    inject_css()
    st.html(
        f'<div class="pq-hero"><div class="pq-eyebrow">{html.escape(eyebrow)}</div>'
        f"<h1>{html.escape(title)}</h1>"
        + (f"<p>{subtitle}</p>" if subtitle else "")
        + "</div>"
    )


def section(title: str, caption: str = "") -> None:
    st.html(f'<div class="pq-section"><h3>{html.escape(title)}</h3>'
            + (f"<p>{caption}</p>" if caption else "") + "</div>")


def kpi_cards(cards: list[dict]) -> None:
    """cards: [{"label", "value", "sub"?, "color"?}] rendered as a responsive grid."""
    items = []
    for c in cards:
        dot = f'<span class="pq-accent" style="background:{c["color"]}"></span>' if c.get("color") else ""
        items.append(
            f'<div class="pq-card"><div class="pq-kpi-label">{dot}{html.escape(c["label"])}</div>'
            f'<div class="pq-kpi-value">{html.escape(str(c["value"]))}</div>'
            + (f'<div class="pq-kpi-sub">{c["sub"]}</div>' if c.get("sub") else "")
            + "</div>"
        )
    st.html(f'<div class="pq-grid">{"".join(items)}</div>')


def chip(cfg: str) -> str:
    color = CONFIG_COLORS.get(cfg, "#888888")
    code = CODE.get(cfg, "")
    label = f"{code} · {SHORT.get(cfg, cfg)}" if code and code != "—" else SHORT.get(cfg, cfg)
    return f'<span class="pq-chip"><span class="pq-dot" style="background:{color}"></span>{html.escape(label)}</span>'


def config_cards(configs: list[str]) -> None:
    items = []
    for c in configs:
        props = ""
        if c in KEX_PQ:
            for name, d in (("KEX vs CRQC", KEX_PQ), ("KEX hedged", KEX_HEDGED), ("Sig vs CRQC", SIG_PQ)):
                props += f'<span class="pq-prop {"pq-yes" if d[c] else "pq-no"}">{"✓" if d[c] else "✗"} {name}</span>'
        items.append(
            f'<div class="pq-card">{chip(c)}'
            f'<div class="pq-kpi-sub" style="margin-top:.5rem"><b>Key exchange</b> {html.escape(KEX[c])}<br>'
            f'<b>Signature</b> {html.escape(SIG[c])}</div><div>{props}</div></div>'
        )
    st.html(f'<div class="pq-grid">{"".join(items)}</div>')


def label(cfg: str) -> str:
    code = CODE.get(cfg, "")
    return f"{code}: {SHORT.get(cfg, cfg)}" if code and code != "—" else SHORT.get(cfg, cfg)


def style_fig(fig: go.Figure, height: int = 420, legend: str = "top", **layout) -> go.Figure:
    """Consistent Plotly styling: compact margins, horizontal legend, unified
    hover where it helps. Colours stay per-trace (config/strategy palettes)."""
    leg = dict(orientation="h", yanchor="bottom", y=1.02, xanchor="left", x=0, title_text="")
    if legend == "bottom":
        leg.update(y=-0.22, yanchor="top")
    fig.update_layout(
        height=height, margin=dict(l=8, r=8, t=36 if legend == "top" else 16, b=8),
        legend=leg if legend else dict(visible=False), hoverlabel=dict(font_size=12),
        font=dict(family="Inter, -apple-system, Segoe UI, sans-serif", size=13),
        bargap=0.25, bargroupgap=0.06, **layout,
    )
    fig.update_xaxes(showline=False, zeroline=False)
    fig.update_yaxes(zeroline=False)
    # log axes: label powers of ten only (Plotly's default minor labels clutter)
    for ax in (fig.layout.xaxis, fig.layout.yaxis):
        if ax.type == "log":
            ax.dtick = 1
            ax.minor = dict(showgrid=True, gridcolor="rgba(127,127,127,0.08)")
    return fig


def chart(fig: go.Figure, key: str | None = None) -> None:
    st.plotly_chart(fig, width="stretch", theme="streamlit", key=key,
                    config={"displaylogo": False, "modeBarButtonsToRemove": ["lasso2d", "select2d"]})


def empty_state(message: str, hint: str = "") -> None:
    st.info(message + (f"\n\n{hint}" if hint else ""), icon=":material/info:")
