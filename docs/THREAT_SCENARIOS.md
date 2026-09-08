# Threat Scenarios — current layout

Describes what `pages/4_🛡️_Threat_Scenarios.py` actually shows today: four
tabs, each independent of the others and of the Results Dashboard's run
selector, plus one page-level AI summary at the bottom. Every tab follows
the same shape — a plain-language explanation of the threat, a chart/table
of whatever results already exist on disk, a small form to run a new trial
live from the browser, and a save step that writes one JSON (or CSV+JSON)
file per configuration (or per `(configuration, parameter)` combination).
Unlike `results/raw/*.csv` and `results/streaming/*.csv`, none of these
output files are `run_id`-tagged or accumulate history — each new run
**overwrites** the file for its exact `(config, ...)` key, and the page
says so ("Refresh the page to see it in the chart above") rather than
implying otherwise. Nothing on this page is `@st.cache_data`-cached, same
as the Results Dashboard.

Every "run a new ..." action first calls `server_manager.ensure_server(config)`,
which starts that configuration's API server on demand if it isn't already
running and reuses it if it is — a different lifecycle from
`bench/orchestrator.py`/`bench/streaming_runner.py`'s CLI sweeps, which
start and stop a fresh server process per config every time.

## 1. Header and tabs

Title (`🛡️ Threat Scenarios`), no refresh button (unlike the Results
Dashboard — every widget interaction already reruns and re-reads disk).
Four `st.tabs`:

1. Harvest-Now-Decrypt-Later (HNDL)
2. Man-in-the-Middle (MITM)
3. 🌊 Streaming Sequence Attack
4. 🌊 Streaming HNDL Exposure

## 2. Harvest-Now-Decrypt-Later (HNDL)

**What it simulates**: a passive adversary archiving every cryptographic
artifact (key-establishment blob, response ciphertext, signature) flowing
over a protected connection, to decrypt it retroactively once a
cryptographically relevant quantum computer (CRQC) exists. The page
explicitly distinguishes **bytes stored** from **bytes eventually
decryptable** — Configuration A's RSA/ECDSA key-establishment blob is
eventually decryptable (broken by Shor's algorithm); B/C's ML-KEM-768
ciphertext is not (lattice-based).

**Existing results** (`dl.load_hndl_summaries()`, reading
`results/hndl/*-summary.json`): a bar chart of projected bytes stored per
1,000 requests per config, colored red if that config's key-establishment
is decryptable under a future CRQC (classical) or blue if not (hybrid,
full_pqc), followed by the raw summaries as a dataframe. Shows an info
message if no HNDL results exist yet.

**Run a new capture**: pick a configuration, a request count (10–2,000,
default 200), click "Run HNDL capture". Calls
`threats.hndl_capture.capture`/`summarize` against that config's live
server. Shows three metrics (mean bytes stored/request, projected
bytes/1,000 requests, whether the key exchange is decryptable under a
future CRQC) plus a collapsed full-JSON expander, then writes
`results/hndl/{config}-hndl-summary.json` (overwriting any prior capture
for that config).

## 3. Man-in-the-Middle (MITM)

**What it simulates**: injects a tamper into the response — corrupting
either the AES-GCM ciphertext (caught at the authenticated-encryption
layer, before signature verification is even reached) or the signature
field specifically (isolating ECDSA vs. ML-DSA-65 tamper-detection
behavior) — and measures detection rate and latency. This reuses the same
tamper function as `threats/mitm_harness.py`'s network proxy, applied
locally in-process for a fast in-browser demo; the CLI script
(`scripts/run_threat_experiments.sh`) runs the full network-proxy version
that produced the paper's reported numbers — **this tab's numbers are not
those numbers**, just a live sanity-check of the same tamper logic.

**Existing results** (`dl.load_mitm_summaries()`, reading
`results/mitm/*-summary.json`): two side-by-side bar charts — detection
rate (%) and mean detection latency (ms) — one bar per
`(config, tamper_target)` combination, followed by the raw summaries as a
dataframe.

**Run a new demo**: pick a configuration, tamper target
(`ciphertext`/`signature`), and trial count (5–200, default 25), click "Run
tamper-detection demo". Runs `mitm_n` tampered transactions in-process via
`webapp.demo_transaction.run_secure_transaction(..., tamper_target=...)`
against that config's live server. Shows detection rate and mean detection
latency, writes `results/mitm/{config}-mitm-{tamper_target}-summary.json`,
and offers a collapsed expander with the raw per-trial JSON records.

## 4. 🌊 Streaming Sequence Attack

**What it simulates**: byte-corruption (the MITM tab, above) is caught
**immediately** by AES-GCM authentication in every streaming strategy the
instant a tampered chunk arrives — not strategy-dependent, so it isn't
re-tested here. What *is* strategy-dependent is a **sequence-integrity
attack**: an attacker silently drops or reorders a chunk without touching
any single chunk's bytes.
- `per_chunk` signs each chunk's position, so a client catches this on the
  very next chunk.
- `hash_chain` deliberately defers its sequence guarantee to the
  *terminating* signature (to amortize signing cost), so this measures how
  much of the response a client would already have received — and, in a
  real chat UI, likely already shown the user — before the tamper is caught.
- `buffer_and_sign` delivers nothing before the stream ends regardless, so
  it has no such exposure window and is excluded from the strategy picker
  entirely (not given a fabricated number).

**Existing results** (`dl.load_streaming_mitm_summaries()`, reading
`results/streaming/mitm/*-summary.json`): two side-by-side bar charts —
percent of the response delivered before detection, and mid-stream
detection rate — one bar per `(config, strategy, attack)` combination
(rows with no `detection_rate`, i.e. nothing attackable, are excluded from
the charts but still appear in the dataframe below), followed by the raw
summaries as a dataframe.

**Run a new demo**: pick a configuration, strategy (`per_chunk`/`hash_chain`
only — `buffer_and_sign` has no intermediate chunks to attack), attack
(`drop`/`reorder`), and trial count (3–100, default 10), click "Run
sequence-attack demo". Runs `sm_trials` trials via
`threats.streaming_mitm_experiment.run_trial`/`summarize` against that
config's live server. If every trial errored (streams too short to attack —
suggests increasing `max_tokens`), shows a warning instead of metrics.
Otherwise shows detection rate, mid-stream detection rate, and fraction of
the response delivered before detection, writes
`results/streaming/mitm/{config}-{strategy}-{attack}-summary.json`, and
offers a collapsed expander with the raw per-trial JSON records.

## 5. 🌊 Streaming HNDL Exposure

**What it simulates**: the HNDL tab above measures one small, fixed-size
response. A streamed response reuses **one handshake's session key across
every chunk of a potentially long-running stream** — so if that handshake
is later broken, an adversary who harvested the whole session recovers
*everything it ever streamed*, not one small reply. The page is explicit
that this is **not a new vulnerability class**, just the same
Shor's-algorithm-breaks-RSA/ECDH threat made worse in direct proportion to
response length. Only `kex_blob` and each chunk's `(nonce, ciphertext)`
count as *harvestable* bytes — signatures and hash-chain values protect
authenticity, not confidentiality, and are deliberately excluded here (see
the strategy-independence check below and the separate Streaming Sequence
Attack tab for what signature/chain-hash *timing metadata* exposes instead).

**Existing results** (`dl.load_streaming_hndl_summaries()`, reading
`results/hndl/streaming/*-streaming-hndl-summary.json`): a line chart of
decryptable-bytes-under-a-future-CRQC vs. response length (`max_tokens`),
one line per config, red if that config's key-establishment is decryptable
under a future CRQC (classical) or blue if not (hybrid/full_pqc — these two
lines overlap at zero regardless of length), followed by the raw summaries
as a dataframe. Below that, if a matching **strategy-independence check**
exists (`dl.load_streaming_hndl_independence()`, reading
`results/hndl/streaming/*-strategy-independence.json`) — does the choice of
signing strategy affect how many bytes are confidentiality-harvestable at a
fixed response length, which it shouldn't since strategy only changes
authenticity overhead — one line per config stating whether it was an exact
match across strategies, plus a collapsed expander with the full
byte-level detail (including the AEAD-envelope-overhead explanation for any
near-miss).

**Run a new sweep**: pick a configuration, a comma-separated list of
response lengths (default `50,200,500,2000`), and a chunk size (1–50
tokens, default 5), click "Run streaming HNDL sweep". Calls
`threats.streaming_hndl_experiment.run_one_config` against that config's
live server, fixed to strategy `per_chunk` for the sweep itself (the
strategy-independence check is what verifies the harvestable-byte count
doesn't actually depend on that choice, so any one strategy is sufficient
to run). Shows whether the key exchange is decryptable under a future
CRQC and what fraction of harvested bytes that represents, three metrics
(lengths swept, harvestable bytes at the longest length, whether harvestable
bytes grow monotonically with length), and the strategy-independence check
as inline JSON. Writes three files into `results/hndl/streaming/`: the raw
per-length sweep rows (`{config}-streaming-hndl.csv`), the sweep summary
(`{config}-streaming-hndl-summary.json`), and the strategy-independence
result (`{config}-strategy-independence.json`).

## 6. 🤖 AI Summary

Page-level, not per-tab — below all four tabs. A button-triggered (not
automatic) call to `webapp/ai_summary.py`, which sends every summary JSON
currently on disk across all four threat types (HNDL, MITM, streaming
sequence-attack, streaming HNDL — via `dl.load_hndl_summaries()`,
`dl.load_mitm_summaries()`, `dl.load_streaming_mitm_summaries()`,
`dl.load_streaming_hndl_summaries()`/`load_streaming_hndl_independence()`;
not raw per-trial records) to Claude for a plain-language security readout,
via `ai_summary.build_threat_context`/`generate_threat_summary`. Hidden
behind an "unset `ANTHROPIC_API_KEY`" message if no key is configured, same
gating as the Results Dashboard's AI summary.

---

## Known gaps / things worth knowing (not fixed here, just documented)

- **No history.** Every "run a new ..." action overwrites the one file for
  its exact key — there's no `run_id` concept here the way
  `results/raw/`, `results/streaming/`, and `results/sweep_summaries/` all
  have. Running the same `(config, ...)` combination twice silently
  discards the first result; the only way to keep both is to rename the
  file on disk before rerunning.
- **This tab's MITM numbers are not the paper's reported MITM numbers** —
  the in-browser demo (this page) and the CLI network-proxy harness
  (`threats/mitm_harness.py` via `scripts/run_threat_experiments.sh`) share
  the same tamper logic but are different code paths (in-process vs. real
  network proxy) with different measured latencies; the page's own caption
  says as much.
- **Streaming HNDL's sweep always runs `per_chunk`**, not whatever strategy
  a reader might expect to configure — this is deliberate (harvestable
  bytes shouldn't depend on signing strategy at all, which is exactly what
  the strategy-independence check verifies), not an oversight, but there's
  no UI control surfacing that choice is fixed.
- **No plain-language cross-tab explainer** at the top of the page — unlike
  the Results Dashboard (`docs/RESULTS_DASHBOARD.md` §1), there's no
  introductory text explaining how the four tabs relate to each other (e.g.
  that Streaming Sequence Attack and Streaming HNDL Exposure measure two
  genuinely different things — integrity-detection timing vs.
  confidentiality-exposure volume — despite both starting with "Streaming").
  Each tab's own markdown explains itself well in isolation, but a reader
  skimming tab titles alone could conflate the two streaming tabs.
