# What changed from the original LaTeX (`conference_101719.tex`)

The complete revised paper is `pq_shield_journal.tex` (compiled: `pq_shield_journal.pdf`, 15 pages).
For Overleaf, upload `overleaf_upload.zip` (the `.tex` plus `figures/`, `diagrams/`, `tables/`)
and compile with pdfLaTeX; no other files are needed. Every number comes from `key_numbers.md`.

## Still yours to do
- Replace the four `x@vit.com` addresses (marked `TODO(authors)` in the `.tex`).
- Confirm the Acknowledgment. Dr. Nivitha is a co-author, so she is no longer thanked there.

## Section by section

| Section | Original | Revised |
|---|---|---|
| Preamble | — | Adds `booktabs`, `url`, `array`; `\graphicspath{{figures/}{diagrams/}}` |
| Abstract | 3 configurations; "100% failure (5000/5000)"; 4,794×; synthetic 32.7×; 14.6–14.8 B/token over 40× | 6 configurations incl. X25519 baseline and X25519MLKEM768; real Llama; +3.3–7.8% vs control at 10 connections; ~5 ms on a 5 Mb/s link; 0–2% with session reuse; RSA uses 4.8 cores; checkpoint trade-off (135,669 B at k=1 vs 3,309 B at k=∞); 11.4 B/token |
| Keywords | — | + hybrid key exchange, LLM streaming, stream authentication |
| I. Introduction | One sentence cited [1]–[15] | Specific citations per claim (Shor, Mosca, Blanco-Romero, Tidjon, Song, FIPS, IETF draft, PQ-TLS benchmarks). Seven contributions instead of six: adds the X25519/hybrid-KEX baselines, network + session-reuse experiments, and the checkpoint/exposure design space; the streaming contribution is positioned as an adaptation of 1997-era stream signing |
| II-A Primitives | ML-KEM / ML-DSA sizes | + X25519MLKEM768 construction |
| Table I | Wrong titles/authors (Song, Ahmed, Schemitt), "Pote & Basode" | Corrected names and focus lines; keys point to the verified bibliography |
| II-B Related work | One paragraph | + three paragraphs: PQ-TLS under network conditions (Paquin, Sikeridis), stream authentication (Gennaro–Rohatgi, Wong–Lam, TESLA/EMSS), LLM token-length side channel (Weiss et al.) |
| III Threat model | Broken sentence in HNDL ("…pair—without CRQC-decryptable…"); claimed to distinguish configs that "rotate or ratchet" keys | HNDL rewritten (RSA-OAEP and X25519 recoverable; ML-KEM and X25519MLKEM768 not); MITM measures the rejecting check itself; ratchet claim replaced by "none rotates keys; future work" |
| IV System design | 3 configs, placeholder Fig. 1/2 | 6 processes; Fig. 1 = updated architecture (A, A′, B, B′, C); Table II = configurations; why A′ is the real classical baseline and A a legacy worst case; B vs B′ ("hybrid" naming); Llama vs RandomForest workload split; Fig. 2 = transaction sequence (decrypt before verify) |
| V-A Environment | "single-core development host" | Apple M3, 8 cores, 16 GB, on AC power, low-power mode off, one day; all endpoints (incl. control) in the thread pool; run IDs recorded |
| V-B Binding | 4 entry points; reorder fix "Section V-D" | 6 entry points; OpenSSL for RSA/X25519/ECDSA; reference fixed; hash-chain checkpoints mentioned |
| V-C Concurrency | Mann–Whitney on RTT | End-to-end `total_ms`; per-repetition range; CPU/RSS sampling |
| V-D Payload | — | Now a full sweep (6 configs × 4 profiles × 5 reps) |
| V-E Streaming | — | 10 reps; discarded warm-up generation; fixed-seed shuffled order |
| V-F (new) | — | Checkpointed hash chains and exposure (⌊n/k⌋+1 signatures, exposure ≤ k chunks) |
| V-G (new) | Warm connection "left to future work" | Session resumption (`keep_session`, N ∈ {1,10,100}) |
| V-H (new) | — | Network emulation (loopback, metro, WAN, mobile; byte-level proxy; lower bound) |
| V-I Threat injection | Signature bytes excluded from HNDL, inconsistently | Explicit harvestable vs decryptable definitions; MITM timing = rejecting step; sequence attacks |
| VI Results | c10 "no difference"; Hybrid −18.3%; 100% failure; Table II n=1 per profile; 26,247 vs 11,723; synthetic streaming; 14.6–14.8 B/token | Nine subsections: concurrency (incl. bimodality at 100), resources, payload, network, session reuse, streaming (Llama), checkpoint frontier, HNDL, MITM. 10 figures + 8 generated tables replace all placeholders |
| VII Validation | 9/9 byte predictions | + all 12 checkpoint cells match the model exactly; ACVP table restyled |
| VIII Discussion | Score on RTT; 3 configs; H1 blocked by the "Hybrid anomaly" | Score on end-to-end latency; A′ = 0.0, B′ = 0.8; Table XI matrix; H1 supported, H2 split (HNDL yes, cost no), H3 demonstrated, H4 28,202 vs 21,602 |
| IX Recommendations | "Hybrid default"; hash-chain "without qualification" | Migrate to ML-KEM now; X25519MLKEM768 to hedge (+~3 ms); no per-handshake RSA; hash-chain with checkpoints sized by tolerable exposure; buffer-and-sign only for metadata hiding; Table XII |
| X Limitations | Single-core host; Hybrid anomaly; resource sampling missing; synthetic streaming | Single host; app-layer not TLS; byte-level emulation; RSA as worst case; Hybrid-KEX concurrency from a supplementary run; synthetic profiles; bimodality at 100; timing residual |
| XI Conclusion | "Classical can fail catastrophically" | Migration is cheap where most urgent; costs lie in per-handshake RSA and per-chunk PQ signatures; checkpoints make the streaming cost a dial |
| Acknowledgment | Thanked co-author Dr. Nivitha ("Sr. Grade 1") | SCOPE faculty/staff and open-source communities |
| References | 18 entries, 8 with wrong details | 29 entries, all verified (see `reference_audit.md`) |

## Corrections behind the new numbers
These came from auditing the data and code, and they are why the results changed (see `README.md` §2):
- The draft compared RTT, which leaves out the handshake, against the control. Now end-to-end.
- The control endpoint blocked its event loop, so the baseline was ~3× too slow under load. Fixed and re-run.
- Raw result files overwrote each other across runs. Files are now tagged with a run ID.
- The client verified the signature before decrypting, and MITM timing measured the whole round trip. Both fixed.
- The streaming cold-start artifact is fixed with a warm-up generation.
- Hash-chain checkpoint signatures were sent but never verified. Now verified.
- The "warm connection" mode never worked. Replaced by real session resumption.
