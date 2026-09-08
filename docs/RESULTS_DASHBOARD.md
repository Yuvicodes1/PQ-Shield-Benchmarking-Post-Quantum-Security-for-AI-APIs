# Results Dashboard — current layout

Describes what `pages/3_📊_Results_Dashboard.py` actually shows today, top to
bottom, as one long scrolling page (not tabs). Every number on the page comes
from `webapp/data_loader.py`, which wraps `analysis/aggregate.py`,
`analysis/tradeoff_matrix.py`, and `analysis/streaming_analysis.py` so
nothing here is computed independently of the CLI tools — see those modules
for the underlying math. Colors are imported from `webapp/colors.py`, the one
place `CONFIG_COLORS`/`STRATEGY_COLORS` are defined (also imported by
`analysis/figures.py` and `analysis/plot_metrics.py` for the paper's own
matplotlib figures) — no chart on this page redefines them locally.

## 1. Header

Title (`📊 Results Dashboard`), a **🔄 Refresh data** button (its return
value isn't read anywhere — clicking it just triggers Streamlit's normal
rerun, which re-reads every file from disk fresh since nothing on this page
is `@st.cache_data`-cached, so any widget interaction has the same
refreshing effect), and a 2–3 sentence plain-language explainer of what
RQ1/RQ3/"Layer 6" mean, so a first-time reader isn't required to have read
`docs/DESIGN.md` first.

## 2. Unified data-source selector

One **"Data source"** dropdown (`dl.get_unified_runs()`) covering *both*
experiment types in a single chronologically-sorted list, most-recent-first,
interleaved rather than grouped by type — every `run_id` from
`results/raw/*.csv` (concurrency sweep) and every `run_id` from
`results/streaming/*.csv` (streaming sweep). Both sweeps share the same
`run_id` generator (`bench.runner.new_run_id`, a sortable
`YYYYMMDDTHHMMSS` timestamp), so a plain string sort is already
chronological across both. Each entry's label states its type at a glance,
e.g. `2026-09-05 14:32 — Concurrency Sweep` / `2026-09-05 15:10 — Streaming
Sweep`. There are two **"All ... runs combined"** pseudo-entries (one per
type, always listed first) rather than one, since the two schemas (RTT vs.
time-to-first-token) can't be combined into one meaningful aggregate. Rows
written before `run_id` tracking existed are bucketed under a `"legacy"`
pseudo-run per type, same as before. Defaults to whichever type's most
recent run is chronologically newest.

Whatever is selected, every panel below auto-detects its type
(`selected["type"]`, `"concurrency"` or `"streaming"`) and renders the
matching content — there is no separate mode toggle and no second selector.

## 3. Top-line metrics

Four `st.metric` tiles, same layout both modes, different labels/values:
- **Concurrency sweep**: total requests (post warm-up trim), successful
  requests, error count + rate, number of distinct configurations present.
- **Streaming**: transaction count, error count + rate, end-to-end
  verification rate (fraction of successful transactions with
  `stream_fully_verified == True`), number of distinct configurations
  present.

Selecting a concurrency run calls `dl.get_trimmed_and_summary(warmup_fraction
=0.05, run_id=...)`, which discards the first 5% of requests in each
`(config, concurrency, repetition)` cell as connection-pool/JIT warm-up, then
computes per-cell aggregate stats (`analysis.aggregate.summarize`). If the
selected run has no data after trimming, the page stops here with a warning.
A streaming run calls `dl.load_streaming_df(run_id=...)` with no warm-up
trim, then `analysis.streaming_analysis.summarize`.

## 4. Latency vs. Scale

Same chart family (Plotly line chart, log-x where the x-range warrants it)
both modes:
- **Concurrency sweep (RQ1)**: median and p95 RTT per configuration across
  every concurrency level present, log-x. Colored by `CONFIG_COLORS`.
- **Streaming**: for a chosen configuration (`st.selectbox`) and chunk size
  (`st.select_slider`), TTFT (solid) and total duration (dashed) per signing
  strategy across every response length (max tokens) present — x-axis swaps
  from concurrency to response length. Colored by `STRATEGY_COLORS`.

## 5. Where the Overhead Comes From

Same chart family (grouped bar chart) both modes:
- **Concurrency sweep**: a concurrency-level `st.select_slider` (defaulting
  to the middle available level), then median time decomposed into
  handshake, server-side decapsulate, server-side sign, and client-side
  verify, for whichever protected configs have data at that concurrency.
  `control` is excluded (it has none of these steps).
- **Streaming**: a response-length `st.select_slider` (reusing the chunk
  size fixed in §4), then median signing time per delivery unit
  (`total_signing_ms_mean / n_chunks_mean`) grouped by signing strategy, one
  bar-group per configuration — categories swap from protocol-phase to
  signing-strategy. `buffer_and_sign` never emits per-chunk events
  client-side (`api/secure_streaming_client.py` only increments `n_chunks`
  for `per_chunk`/`hash_chain`), so its `n_chunks_mean` is always 0; the
  divisor is clamped to 1 for it rather than dividing by zero, which is the
  correct semantics (it performs exactly one signing operation over the
  whole response) as well as what keeps its bar from silently vanishing
  from the chart.

## 6. Wire Bytes per Request / Transaction (RQ3)

- **Concurrency sweep**: a stacked bar chart of median key-establishment-blob
  bytes and median signature bytes per protected config (`kex_blob_bytes` and
  `signature_bytes`) — two genuinely additive components of one request's
  total. Response-ciphertext bytes aren't shown even though a
  `response_ciphertext_bytes` field exists in the current `bench/runner.py`
  CSV schema — the historical sweep files on disk predate that column.
- **Streaming**: only one wire-bytes component exists in this sweep's schema
  (`total_signature_bytes`) — there's nothing to stack, and the three
  strategies are alternative choices for the same transaction rather than
  additive parts, so they're shown as a grouped (not stacked) bar chart
  instead, with a caption explaining why, at the same (response length,
  chunk size) slice as §5.

## 7. Server Resource Usage

One code path both modes now (`dl.load_resource_summaries(mode, run_id=...)`):
CPU%/RSS sampled every 0.25s (`crypto.instrumentation.ResourceSampler`) —
per `(config, concurrency, repetition)` cell for the concurrency sweep
(wired into `bench.orchestrator.run_full_sweep`), per streaming transaction
`(config, strategy, max_tokens, chunk_size_tokens, repetition)` for the
streaming sweep (wired into `bench.streaming_runner.run_sweep`). Both write
into `results/sweep_summaries/*.json`, tagged with a `"run_type"` field
("concurrency"/"streaming") so `load_resource_summaries()` can scope to just
one; files written before that tag existed (every pre-fix concurrency-sweep
file) are treated as `"concurrency"` rather than dropped, so no historical
number changes. A combo chart: CPU% as bars (primary y-axis), RSS as a
markers+line trace (secondary y-axis). If the selected run predates
resource-sampling instrumentation *for its sweep type*, or every cell/
transaction was too short to catch a 0.25s sample, shows an info message
instead of an empty chart — this is the normal state for every streaming
run collected before this feature was added. Config keys here are matched
against `bench.orchestrator`/`bench.streaming_runner`'s shared hyphenated
`full-pqc` convention.

## 8. Aggregate Statistics

- **Concurrency sweep**: the full per-`(config, concurrency)` aggregate
  stats table (`summary`) as a plain dataframe, followed by a Mann-Whitney U
  significance table (`dl.get_significance`) comparing each protected config
  against `control` at matching concurrency levels — needs at least 2
  samples in both groups to produce a row.
- **Streaming**: the equivalent per-`(config, strategy, max_tokens,
  chunk_size_tokens)` summary table, followed by a Mann-Whitney U
  significance table (`dl.get_streaming_significance`, metric `ttft_ms`)
  comparing each other config against a baseline within each
  `(strategy, max_tokens, chunk_size_tokens)` group — there is no
  `concurrency` column in this sweep's schema, so the grouping columns
  differ from the concurrency sweep's, and the baseline is `classical`
  (auto-resolved by `analysis.aggregate.resolve_baseline_config`, since the
  streaming sweep has no `control` leg), never silently `control`. The
  subheading changes to *"Mann-Whitney U Test vs. Classical (TTFT)"* with a
  caption explaining the baseline difference, so it's never confused with
  the concurrency sweep's control-relative table above. A collapsed
  expander below it holds the configuration/response-length/chunk-size
  "strategy comparison" table (`analysis.streaming_analysis.strategy_comparison_at`)
  showing TTFT speedup and signature-byte reduction relative to
  `buffer_and_sign`/`per_chunk` respectively (a different, strategy-relative
  comparison, unrelated to the baseline-config question above).

Cryptographic Validation (NIST ACVP known-answer tests, streaming
signature-cost model validation) is no longer a section of this page — it
lives on its own page, `pages/5_🔬_Cryptographic_Validation.py`, since it
validates the *measurement instrument* itself rather than any one sweep's
results, and having it inside a run-selector-scoped page implied a
dependency on that selector it never actually had. The dashboard page
carries a one-line pointer to it in its place. See that page's own header
for what it checks.

## 9. Security / Performance Trade-off Matrix (Layer 6)

Same panel both modes now. A `st.slider` for the security weight `w_sec`
(performance weight is `1 - w_sec`, always sums to 1), driving
`dl.build_custom_tradeoff` — a thin call-through into
`analysis.tradeoff_matrix.build_matrix_at(df, w_sec, w_perf, scale_col=...,
metric_col=...)`, the same single-weighting scoring function `build_matrix()`'s
three fixed presets call internally, so the CLI and the dashboard never
compute `composite_score = w_sec * security_score - w_perf *
normalized_latency_overhead` two different ways.

- **Concurrency sweep**: `scale_col="concurrency"`, `metric_col="rtt_ms"`,
  baseline auto-resolves to `control`. Config × concurrency heatmap (Plotly
  `imshow`, red↔green) plus a "recommended configuration per concurrency
  level" table.
- **Streaming**: `scale_col="max_tokens"`, `metric_col="ttft_ms"`, baseline
  auto-resolves to `classical` (no `control` leg exists). Config × response-
  length heatmap; `classical` itself now appears as a scored row (overhead
  0%, since it's its own baseline) rather than being excluded the way
  `control` is — it's a real, deployable option here, unlike the
  concurrency sweep's zero-overhead reference. Two extra controls appear:
  a **Signing strategy** selectbox and an **Exposure-window share of the
  security score** slider (default 0.3). Together they drive
  `security_score` for this call: instead of the plain `SECURITY_SCORES`
  mapping, it's `analysis.tradeoff_matrix.streaming_security_score(config,
  strategy, streaming_mitm_summaries, exposure_share)` — a blend of that
  same categorical mapping with the *measured* sequence-integrity exposure
  window from the 🌊 Streaming Sequence Attack tab (Threat Scenarios page):
  `1 - ` mean fraction of the response delivered before a drop/reorder
  attack is caught, for that `(config, strategy)`. `buffer_and_sign` scores
  a fixed 1.0 (no exposure window by construction); `per_chunk`/`hash_chain`
  read real data, or the config is simply excluded from that call's
  heatmap if no data exists yet for it. `streaming_df` is pre-filtered to
  the selected strategy before scoring. A caption states the baseline and
  the blend explicitly: *"Overhead relative to Classical (no unprotected
  control leg in the streaming sweep) — not the same baseline as the
  concurrency sweep's heatmap. security_score blends the categorical
  mapping above with `per_chunk`'s measured sequence-integrity exposure
  window (exposure share = 0.30)..."*

Directly below the heatmap, one stated sentence names the config the
composite score favors at the selected weighting and the concurrency/
response-length level currently selected in §5 (or the best across all
levels, if that level has no row), with the baseline and (for streaming)
the selected strategy named explicitly — e.g. *"At this weighting
(w_sec=0.50) and concurrency=50, C: Full PQC gives the best balance of
quantum resistance and latency overhead (composite score 0.528, -5.5%
latency overhead vs. control)"* for a concurrency-sweep run, or *"...with
`per_chunk` signing,... relative to the Classical baseline"* for a
streaming run. For streaming, a second sentence is appended when the
winning config's exposure resistance would differ under the *other*
attackable strategy — e.g. *"Note: `hash_chain` would give C: Full PQC a
larger sequence-attack exposure window than `per_chunk` does."* — so the
recommendation never hides the trade-off the exposure term exists to
surface.

## 10. 🤖 AI Summary

**Concurrency-sweep runs only** — this section summarizes the RTT,
overhead-decomposition, and trade-off-matrix data computed for a
concurrency-sweep selection, none of which exists in the same shape for a
streaming run, so a streaming selection shows a guard message instead. A
button-triggered (not automatic) call to `webapp/ai_summary.py`, which sends
the current scope's aggregate stats, significance table, trade-off matrix,
and resource data (not raw per-request rows) to Claude for a plain-language
report. Hidden behind an "unset `ANTHROPIC_API_KEY`" message if no key is
configured.

---

## Known gaps (not fixed here, just documented)

- **`response_ciphertext_bytes`** is a live column in `bench/runner.py`'s
  schema but absent from every concurrency-sweep file currently on disk
  (§6) — will appear automatically once a new sweep is run, no code change
  needed.
- **`bench.orchestrator`'s `ResourceSampler` is never `.stop()`-ed** — each
  cell's background sampling thread just keeps running (daemon thread,
  harmless to each cell's own numbers since every `ResourceSampler` has its
  own sample list) until its target process dies. `bench.streaming_runner`'s
  new resource sampling (§7) mirrors this exactly rather than fixing it in
  only one place — a real, pre-existing quirk, not introduced by either fix.
- **No `control` leg for the streaming sweep at all**: `bench/streaming_runner.py`
  only exercises `classical`/`hybrid`/`full-pqc`. This is why §8 and §9's
  streaming baseline is `classical`, not `control` — see `docs/DESIGN.md`
  §5's "A note on baselines" and `docs/STREAMING.md` §8. Not something
  either fix changes; would need an unprotected streaming config added to
  `bench/streaming_runner.py` to close.
