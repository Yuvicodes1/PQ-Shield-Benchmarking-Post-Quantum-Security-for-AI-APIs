# PQ-Shield — Live Demo Presenter Guide (Review 2)

Target: 10–12 minutes of live demo + Q&A buffer. Everything runs on
`localhost` — no internet dependency, so a flaky venue Wi-Fi cannot break
the demo. The only risk is *time* and *your own machine's CPU*, both of
which this guide is built around.

---

## 0. The one-sentence framing (say this first, before touching the laptop)

> "Every production AI inference API — OpenAI, SageMaker, a hospital's
> diagnostic endpoint — is secured today with RSA and ECDSA, both broken by
> Shor's algorithm on a future quantum computer. Anyone can record that
> encrypted traffic *right now* and decrypt it later — that's called
> harvest-now-decrypt-later. NIST standardized quantum-safe replacements in
> 2024. Nobody had measured what migrating actually *costs* an AI API
> specifically — not a generic web server — until now. That's PQ-Shield,
> and everything I'm about to show you is live, running on this laptop,
> against a real trained model."

---

## T-minus checklist (do this the morning of, not the night before)

Run the pre-flight script and read every line:

```bash
bash scripts/preflight_check.sh
```

It checks: liboqs self-test, model artifact present, all four demo ports
free, Streamlit installed, and that `results/raw/` has data for the
Results Dashboard to show. **Fix every ❌ before you leave for the venue.**

30 minutes before your slot:
- [ ] Launch the dashboard (`bash scripts/run_webapp.sh`) and leave it running.
- [ ] Click through all 4 pages once yourself, so the model/servers are
      warm and the first click in front of the panel isn't the slow one.
- [ ] Close every other application. You have a single CPU core's worth of
      margin at concurrency=100+; don't let Chrome with 40 tabs eat it.
- [ ] Confirm `results/raw/` includes `full-pqc` data (run it yourself
      beforehand if you haven't: see README "Run the full benchmark
      matrix"). Without it, Configuration C has no aggregate chart data —
      the Live Demo tab still works fine standalone, but the Results
      Dashboard's headline chart will be missing a line.
- [ ] Have a **backup**: a screen recording of one full run-through, on a
      USB stick or offline on the laptop, in case of a live failure.
      Practice the recovery line: *"Let me switch to the recorded run
      while I restart this"* — say it calmly, don't apologize repeatedly.

---

## The walkthrough (page by page, in this order)

### 1. Home page (30 seconds)

Say the framing line from §0. Point at the configuration table without
reading it aloud — the panel can read.

Click **"Run self-test"**. It runs the actual ML-KEM-768/ML-DSA-65
round-trip against the compiled liboqs library and prints the exact byte
sizes (1184B public key, 1088B ciphertext for ML-KEM-768; 1952B public
key, 3309B signature for ML-DSA-65).

> "This isn't a simulation — that's a real post-quantum cryptography
> library, built from source, running the actual FIPS 203 and FIPS 204
> algorithms."

### 2. Live Demo page (4 minutes — this is the centerpiece)

Pick a digit sample (any slider position). Run all four configurations
**in this order**, reading the RTT/handshake numbers off the screen as
they appear — don't narrate every field, just the ones below.

1. **Control** — "~10ms, no crypto. This is our zero-overhead floor."
2. **Classical (A)** — "Handshake jumps because we're generating a fresh
   RSA-2048 key pair on every single request — that's the worst-case,
   most conservative thing we could measure, and it's expensive."
3. **Hybrid (B)** — "Same AES-GCM payload encryption, but key exchange is
   now ML-KEM-768 instead of RSA. Watch the handshake time — it's faster
   than classical, not slower, because generating an ML-KEM key pair is
   cheaper than generating an RSA-2048 key pair."
4. **Full PQC (C)** — "Now the signature is ML-DSA-65 instead of ECDSA
   too. Look at sign/verify time specifically." *(If your aggregate sweep
   data confirms it — check `results/aggregate_stats.csv` yourself before
   claiming this live — point out that ML-DSA-65 sign/verify has been
   observed faster than ECDSA in single-transaction spot checks during
   development, despite a signature nearly 47x larger. Say "we're still
   validating this across the full statistical sweep" if you don't have
   the full aggregated full-pqc numbers yet — don't overclaim a
   single-shot number as a proven result in front of a panel.)*

**Then the tamper demo (the "wow" moment, don't skip this):**

On Full PQC, set the tamper dropdown to **"Corrupt ciphertext"** and send.
Point at the red rejection banner:

> "I just simulated an active man-in-the-middle attacker flipping one bit
> in the response. Watch — it's rejected at TWO independent layers: the
> AES-GCM authentication tag fails immediately, and separately, the
> ML-DSA-65 signature no longer matches because the tampered bytes don't
> match what the server signed. Defense in depth, verified live."

Switch to **"Corrupt signature"** and send again — show it's also caught,
now specifically at the signature-verification layer, isolating that
mechanism from the AEAD one.

### 3. Results Dashboard (4 minutes — the empirical rigor moment)

This page only shows what's actually in `results/raw/` — say so:

> "Everything on this page is computed live from real request logs, not
> hard-coded — the same numbers `python -m analysis.aggregate` on the
> command line would print."

**RTT vs. Concurrency chart** — point at the classical line's steep rise:

> "At concurrency 100, Classical shows a 109% latency increase over
> control — statistically significant, p < 10⁻¹⁸⁰ by a Mann-Whitney U
> test, not noise. At concurrency 1000 on this machine, Classical fails
> *completely* — every single request times out, because generating a
> fresh RSA-2048 key pair per connection can't keep up with 1000
> simultaneous connections on one CPU core. Hybrid and Full PQC don't have
> this failure mode, because ML-KEM key generation is dramatically
> cheaper. That's not a performance number, that's an availability
> finding."

**Trade-off matrix — drag the security-weight slider live.** This is your
best interactive moment:

> "This isn't one verdict — it's a formula: security score minus weighted
> latency overhead. Watch what happens as I slide from
> performance-priority to security-priority..." *(drag it)* "...the
> recommended configuration can change. A hospital and a high-frequency
> trading firm should not get the same answer, and this tool lets a
> security architect plug in their own priorities instead of trusting a
> single hard-coded number."

### 4. Threat Scenarios (2 minutes)

If you've run HNDL/MITM beforehand, show the bar charts and explain the
color coding (red = key-exchange ciphertext eventually decryptable under a
future quantum computer; blue = not). If you haven't run them yet, run one
live — HNDL with ~100 requests against Hybrid or Full PQC takes a few
seconds:

> "This measures what a passive adversary archiving today's traffic
> actually gets — not just bytes stored, but which of those bytes become
> decryptable once a quantum computer exists. That distinction is the
> paper's third contribution."

### 5. Close (30 seconds)

> "Three configurations, benchmarked under real concurrency, against real
> adversarial scenarios, on a real trained model — not a theoretical
> comparison. Happy to take questions on any number you saw."

---

## Anticipated questions

**"Why does Hybrid look faster than the unprotected control at
concurrency 100 in your data?"**
Be honest: this is a real, statistically significant result in the
current dataset (-18.3%, p < 10⁻¹³) but it's counterintuitive and the
current sweep was run on a single-core sandboxed machine — say you're
re-running the full matrix on dedicated hardware to confirm it's not a
host-specific scheduling artifact before treating it as a general claim.
Panels respect "here's what we measured, here's what we're still
verifying" far more than an overclaim.

**"Is this production-ready?"**
No — say so directly. The handshake endpoint is intentionally
unauthenticated so the benchmark can measure a fresh key exchange every
time; a real deployment would run this behind TLS with proper server
authentication. This is a measurement harness, not a shipped product.

**"Why liboqs and not a commercial library?"**
liboqs is the reference implementation used by essentially every PQC
research benchmark in the literature you reviewed (see your Review 1
literature table) — using it keeps your numbers comparable to prior work.

**"What's actually novel here versus the 15 papers you reviewed?"**
Point back to the three novelty dimensions from Review 1: AI-specific
payload profile (small asymmetric request/response, not bulk TLS), live
adversarial context (HNDL + MITM integrated into the execution pipeline,
not a separate qualitative discussion), and the empirical weighted
decision matrix replacing a theoretical claim.

---

## If something breaks live

- **A server won't start / port conflict**: the dashboard auto-picks
  ports 8100–8103, separate from anything else. If one is stuck, the page
  will just hang on "Starting server..." — refresh the browser tab, the
  session state resets and it retries.
- **A request times out during the demo**: this is *itself* consistent
  with your own findings about concurrency contention — say so, don't
  panic: "That's actually consistent with what we found about resource
  contention under load — let me pick a lower concurrency."
- **Total meltdown**: switch to the backup recording. Have the file path
  memorized, don't fumble for it.
