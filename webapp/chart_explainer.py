"""Per-chart "Explain this chart" button, shared by every chart on the
Results Dashboard and Threat Scenarios pages -- one component instead of a
dozen ad hoc inline implementations. Distinct from webapp/ai_summary.py's
page-level "🤖 AI Summary" button: this explains one chart's *current* data
on demand, scoped to exactly what's plotted, not the whole page's scope.

Uses st.session_state to cache a generated explanation across reruns (both
pages rerun on every widget interaction, and nothing else on either page is
`@st.cache_data`-cached today) so switching back to a chart you've already
asked about doesn't re-call the API. See render_explain_button's docstring
for the cache-key design.
"""

from __future__ import annotations

import hashlib
import json

import numpy as np
import streamlit as st

from webapp import ai_summary

_STATE_PREFIX = "chart_explainer:"


def _json_safe(obj):
    """Recursively converts numpy/pandas scalar types (int64, float64,
    bool_, ndarray, ...) into native Python types. chart_data is built at
    each call site directly from pandas Series/DataFrame values (`.median()`,
    `.tolist()` on a numeric column, dict(zip(configs, numpy_array)), ...),
    which routinely carry numpy scalars that plain json.dumps() can't
    serialize -- sanitizing once here, centrally, is far less error-prone
    than requiring every call site to remember to cast every value by hand."""
    if isinstance(obj, dict):
        return {str(k): _json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_json_safe(v) for v in obj]
    if isinstance(obj, np.integer):
        return int(obj)
    if isinstance(obj, np.floating):
        return float(obj)
    if isinstance(obj, np.bool_):
        return bool(obj)
    if isinstance(obj, np.ndarray):
        return _json_safe(obj.tolist())
    return obj


def render_explain_button(
    chart_key: str, chart_title: str, chart_data: dict, caveats: list[str] | None = None
) -> None:
    """Renders a small "Explain this chart" button, and the cached
    explanation (once one exists) directly below it.

    chart_key must identify which chart this is AND fold in whatever
    selector/slider state changes what's plotted (run_id, concurrency
    level, response length, chunk size, strategy, weighting, ...) --
    callers build this from the panel's own identity plus the current
    values of every widget that affects `chart_data`. As a defensive
    backstop (not a substitute for the above -- a stale chart_key that
    still forgot a relevant widget would otherwise cache silently wrong
    data), a short hash of `chart_data` itself is folded into the actual
    cache key too, so any change to the plotted data invalidates the cache
    even if a caller's chart_key under-specifies it -- this also covers
    pages with no explicit run selector at all (e.g. Threat Scenarios,
    where the "selector state" is really just "whatever's on disk right
    now," which changes when a new capture/trial is saved).

    Calling this repeatedly for the same chart_key + chart_data is cheap
    (no API call) -- the explanation is generated once per unique
    (chart_key, chart_data) pair and displayed from session_state on every
    subsequent rerun, until either changes. Clicking the button again after
    a cached explanation exists regenerates it (fresh API call, same cache
    slot). The API is called only on the literal rerun triggered by that
    click -- st.button's own semantics already guarantee it isn't called on
    an unrelated widget's rerun.

    Respects the same ANTHROPIC_API_KEY-unset gating as the page-level AI
    Summary feature: shows the same "unset API key" message rather than a
    disabled or hidden button.
    """
    if not ai_summary.api_key_present():
        st.caption("Set `ANTHROPIC_API_KEY` in `.env` (repo root) to enable chart explanations.")
        return

    # Sanitize once, here -- chart_data is built at each call site directly from
    # pandas/numpy values, and both the hash below and ai_summary._call_claude's
    # json.dumps(..., indent=2) (no `default=` fallback there) need plain types.
    chart_data = _json_safe(chart_data)
    caveats = _json_safe(caveats) if caveats is not None else None

    fingerprint = hashlib.sha256(json.dumps(chart_data, sort_keys=True, default=str).encode()).hexdigest()[:12]
    state_key = f"{_STATE_PREFIX}{chart_key}:{fingerprint}"

    has_cached = state_key in st.session_state
    label = "🔄 Regenerate explanation" if has_cached else "💬 Explain this chart"
    clicked = st.button(label, key=f"{state_key}:button", type="secondary")

    if clicked:
        with st.spinner("Asking Claude..."):
            try:
                st.session_state[state_key] = ai_summary.generate_chart_explanation(
                    chart_title, chart_data, caveats=caveats
                )
            except Exception as exc:
                st.warning(f"Chart explanation failed: {exc}")
                return

    if state_key in st.session_state:
        st.info(st.session_state[state_key])
