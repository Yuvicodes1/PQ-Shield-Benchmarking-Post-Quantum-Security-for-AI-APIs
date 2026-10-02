# Paper: Post-Quantum Signature Schedules for Streaming LLM Inference

The manuscript is `pq_shield_journal.tex` (compiled: `pq_shield_journal.pdf`).
Everything in `figures/` and `tables/`, plus `key_numbers.md`, is generated from
the experiment results; never edit those by hand.

```
paper/
  pq_shield_journal.tex / .pdf   the manuscript (IEEEtran; port to ieeeaccess.cls for IEEE Access)
  figures/                       *.pdf (vector, for LaTeX) + *.png (for slides)
  tables/                        *.tex, \input by the manuscript
  diagrams/                      system_overview, transaction_sequence (SVG source + PDF/PNG)
  key_numbers.md                 every number the text quotes, with provenance
  environment.json               OS, packages, OpenSSL/liboqs revisions, model hashes, repo commit
  response_to_reviewers.md       point-by-point responses to the three review rounds
  CHANGES.md                     what changed in each revision
  reference_audit.md             how each reference was verified
  references.bib                 the bibliography in BibTeX form (the .tex embeds it)
  overleaf_upload.zip            local only: .tex + figures + diagrams + tables for Overleaf
```

## Regenerate and compile

```bash
python -m bench.paper_runs          # all experiments (or --steps N,M); records run IDs in results/paper_runs.json
python -m analysis.paper_figures    # reads results/paper_runs.json -> figures/, tables/, key_numbers.md
cd paper && tectonic -X compile pq_shield_journal.tex
```

`analysis.paper_figures` takes each configuration's most recent run, so a
corrective re-run supersedes earlier data without pooling. The Key findings page
of the dashboard (`streamlit run app.py`) computes the same numbers with the same
code.

## Where each output appears

| Section | Figures | Tables |
|---|---|---|
| IV System design | `system_overview`, `transaction_sequence` | configurations (in .tex) |
| VI-A Streaming strategies | `fig_streaming_strategies` | `tab_streaming` |
| VI-B Checkpointed hash chains | `fig_checkpoint_frontier` | `tab_checkpoint` |
| VI-C Signing cost in a stream | — | `tab_timing` |
| VI-D Stream integrity under attack | `fig_checkpoint_frontier` (b) | `tab_campaign` |
| VI-E Key substitution, authenticated handshakes | — | `tab_keysub`, `tab_authcost` |
| VI-F Tampering | — | `tab_threats` |
| VI-G HNDL exposure | `fig_wire_bytes`, `fig_streaming_hndl` | — |
| VI-H Key establishment under concurrency | `fig_concurrency_latency`, `fig_latency_decomposition` | `tab_concurrency`, `tab_equivalence`, `tab_failures`, `tab_resources` |
| VI-I Payload shape | `fig_payload_profiles` | `tab_payload_profiles` |
| VI-J Network conditions | `fig_network_conditions` | — |
| VI-K Session reuse | `fig_handshake_amortization` | — |
| VII Validation | `fig_primitive_throughput` | ACVP (in .tex), `tab_primitives`, `tab_environment` |
| VIII Decision summary | — | `tab_dominance` |

`results_section.tex` and `text_additions.tex` are drafts from the first revision,
kept for reference; the manuscript does not include them.

## Still to do before submission

- Replace the four `x@vit.com` author addresses (`TODO(authors)` in the .tex) and
  confirm the acknowledgment.
- Port to the IEEE Access template (`ieeeaccess.cls`, IEEE Author Center).
- Check the IEEE Access article processing charge and any institutional discount.
