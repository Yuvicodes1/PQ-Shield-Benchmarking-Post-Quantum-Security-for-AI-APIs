"""On-demand AI summary of the Results Dashboard, via the Claude API.

Generated only when the user clicks the button on the Results Dashboard page
-- not on every Streamlit rerun -- since each call costs money and the page
already reruns on every widget interaction (slider drag, refresh click, etc).

Requires ANTHROPIC_API_KEY in the environment or in the repo-root .env file
(loaded by webapp.bootstrap.load_dotenv_if_needed, which every page under
pages/*.py calls before importing anything else).
"""

from __future__ import annotations

import json
import os

MODEL = "claude-opus-5-5"


def api_key_present() -> bool:
    return bool(os.environ.get("ANTHROPIC_API_KEY"))


def build_dashboard_context(
    n_total: int,
    n_ok: int,
    n_errors: int,
    summary_df,
    significance_df,
    tradeoff_df,
    w_sec: float,
    resource_df=None,
) -> dict:
    """Condenses the dashboard's already-computed pandas frames into a small
    JSON-serializable payload, so the prompt carries the same numbers the
    user sees on screen rather than raw per-request rows."""
    return {
        "totals": {
            "n_requests_post_warmup_trim": int(n_total),
            "n_successful": int(n_ok),
            "n_errors": int(n_errors),
            "error_rate_pct": round(n_errors / n_total * 100, 2) if n_total else None,
        },
        "aggregate_stats_by_config_and_concurrency": (
            json.loads(summary_df.to_json(orient="records")) if summary_df is not None else []
        ),
        "mann_whitney_significance_vs_control": (
            json.loads(significance_df.to_json(orient="records"))
            if significance_df is not None and not significance_df.empty
            else []
        ),
        "tradeoff_matrix": {
            "security_weight_w_sec": w_sec,
            "performance_weight_w_perf": round(1.0 - w_sec, 2),
            "rows": (
                json.loads(tradeoff_df.to_json(orient="records"))
                if tradeoff_df is not None and not tradeoff_df.empty
                else []
            ),
        },
        "server_resource_usage_by_cell": (
            json.loads(
                resource_df[
                    [c for c in ["config", "concurrency", "repetition", "cpu_percent_mean",
                                 "cpu_percent_max", "rss_mb_mean", "rss_mb_max", "n_samples"]
                     if c in resource_df.columns]
                ].to_json(orient="records")
            )
            if resource_df is not None and not resource_df.empty
            else []  # empty means: no resource data available for this selection, not that usage was zero
        ),
    }


SYSTEM_PROMPT = (
    "You are a benchmarking analyst summarizing a post-quantum cryptography (PQC) "
    "performance run for a technical but non-specialist reader. You are given aggregate "
    "latency statistics by configuration and concurrency, optionally repetition-level "
    "comparisons (difference in medians with bootstrap CIs), and optionally server "
    "CPU/RSS per cell. Configurations: 'control' (no protection, one request), "
    "'control_2rt' (no protection, the same two requests as a protected transaction -- "
    "protected minus control_2rt is the cryptographic overhead), 'classical' (RSA-2048 "
    "with a key generated per handshake, a legacy worst case), 'classical_ecdhe' (X25519, "
    "the realistic classical baseline), 'hybrid' (ML-KEM-768 + ECDSA), 'hybrid_kex' "
    "(X25519MLKEM768 + ECDSA), 'full_pqc' (ML-KEM-768 + ML-DSA-65), and 'hybrid_kex_pq' "
    "(X25519MLKEM768 + ML-DSA-65). An EMPTY resource list means no data, not zero usage.\n\n"
    "Client and server share one machine, so at high concurrency (hundreds of connections "
    "and above) latency is dominated by contention: a protected configuration can even "
    "appear faster than control_2rt. Treat such differences as contention, not "
    "cryptography, and draw conclusions from low concurrency.\n\n"
    "Write a concise report (under 350 words) with these sections:\n"
    "1. Volume & data quality -- requests, error rate, repetitions per cell (flag cells "
    "with a single repetition).\n"
    "2. Cryptographic overhead -- per protected configuration at the lowest concurrency, "
    "versus control_2rt if present (else control), with CIs when given.\n"
    "3. High concurrency -- what changes, with the contention caveat.\n"
    "4. Bottom line -- latency rarely separates the non-RSA configurations; say which "
    "differences are practically meaningful, and that the choice between them depends "
    "on required security properties and bytes, not on this run's latency.\n\n"
    "Use only the numbers given; if something is missing, say so plainly."
)


def _call_claude(system_prompt: str, context: dict, context_label: str) -> str:
    """Shared call path for every AI-summary flavor in this module. Raises
    the underlying anthropic exception on failure; the caller (the Streamlit
    page) is responsible for catching and displaying it."""
    import anthropic

    client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY from the environment

    response = client.messages.create(
        model=MODEL,
        max_tokens=4000,
        output_config={"effort": "high"},
        system=system_prompt,
        messages=[{
            "role": "user",
            "content": f"Here is the current {context_label} data:\n\n{json.dumps(context, indent=2, default=str)}",
        }],
    )

    return next((b.text for b in response.content if b.type == "text"), "")


def generate_dashboard_summary(context: dict) -> str:
    return _call_claude(SYSTEM_PROMPT, context, "dashboard")


# ---------------------------------------------------------------------------
# Threat Scenarios page (HNDL + MITM)
# ---------------------------------------------------------------------------

def build_threat_context(
    hndl_summaries: list[dict], mitm_summaries: list[dict],
    streaming_mitm_summaries: list[dict] | None = None,
    streaming_hndl_summaries: list[dict] | None = None,
    streaming_hndl_independence: list[dict] | None = None,
) -> dict:
    """hndl_summaries / mitm_summaries / streaming_mitm_summaries /
    streaming_hndl_summaries / streaming_hndl_independence are exactly the
    lists returned by webapp.data_loader.load_hndl_summaries() /
    load_mitm_summaries() / load_streaming_mitm_summaries() /
    load_streaming_hndl_summaries() / load_streaming_hndl_independence() --
    already-computed per-config JSON summaries, not raw trial records."""
    return {
        "hndl_harvest_now_decrypt_later": hndl_summaries,
        "mitm_tamper_detection": mitm_summaries,
        "streaming_sequence_integrity_attack": streaming_mitm_summaries or [],
        "streaming_hndl_exposure_scaling": streaming_hndl_summaries or [],
        "streaming_hndl_strategy_independence": streaming_hndl_independence or [],
    }


SYSTEM_PROMPT_THREATS = (
    "You are a security analyst summarizing two active-adversary threat-scenario "
    "experiments against a PQC-benchmarking API, for a technical but non-specialist "
    "reader. Four server configurations exist: 'control' (no protection -- never "
    "appears in these threat experiments, they require a protected config), "
    "'classical' (RSA-2048-OAEP key exchange + ECDSA P-256 signatures), 'hybrid' "
    "(ML-KEM-768 key exchange + ECDSA P-256 signatures), and 'full_pqc' (ML-KEM-768 "
    "+ ML-DSA-65, fully quantum-resistant on both axes).\n\n"
    "You are given two independent experiments:\n"
    "- hndl_harvest_now_decrypt_later: a passive adversary that just stores every "
    "wire byte (key-establishment blob, ciphertext, signature) per config. Each "
    "entry has kex_decryptable_under_future_crqc (True only for 'classical' -- RSA "
    "is broken by Shor's algorithm; False for ML-KEM configs -- lattice-based), "
    "bytes_per_request_mean, and projected_bytes_per_1000_requests. The AES-256-GCM "
    "payload ciphertext itself is not decryptable under a future CRQC in ANY "
    "config -- only the key-establishment blob's algorithm matters for that flag.\n"
    "- mitm_tamper_detection: an active adversary tampering with either the "
    "ciphertext or the signature field in transit. Each entry has tamper_target, "
    "detection_rate (fraction of tampered responses rejected -- should be 1.0; "
    "anything less is a real finding, not noise), and detection_ms_mean.\n"
    "- streaming_sequence_integrity_attack: a DIFFERENT active adversary specific to "
    "token-by-token SSE streaming responses (see docs/STREAMING.md), who silently drops or "
    "reorders one chunk WITHOUT corrupting any chunk's own bytes -- byte corruption is caught "
    "immediately by AES-GCM in every strategy and is not what this experiment tests. Each "
    "entry has strategy ('buffer_and_sign'/'per_chunk'/'hash_chain'), attack ('drop'/'reorder'), "
    "detection_rate (was it EVER caught, including only at the very end), "
    "mid_stream_detection_rate (was it caught DURING the stream, before the client had already "
    "received the whole thing), and fraction_delivered_before_detection_mean (what fraction of "
    "the response a client would already have received -- and, in a real chat UI, likely "
    "already shown the user -- before the tamper was caught). A null detection_rate for "
    "buffer_and_sign is EXPECTED and not a gap: it delivers nothing incrementally, so this "
    "attack does not apply to it by construction. The expected, by-design finding is "
    "per_chunk catching this near-immediately (low fraction_delivered_before_detection, high "
    "mid_stream_detection_rate) while hash_chain catches it only at the terminating signature "
    "(fraction_delivered_before_detection near 1.0, mid_stream_detection_rate near 0) -- that "
    "is hash_chain's known, documented trade-off for its lower signature-byte cost, not a "
    "security failure; only flag it as concerning if detection_rate itself (not "
    "mid_stream_detection_rate) is below 1.0, since that would mean the attack went completely "
    "undetected even at the end.\n"
    "- streaming_hndl_exposure_scaling: a THIRD, separate finding -- NOT about signing strategy "
    "or tamper detection at all. It extends the plain hndl_harvest_now_decrypt_later finding "
    "above (bounded, single small response) to a streamed response, where one handshake's "
    "session key is reused across every chunk of a potentially long-running stream. Each entry "
    "has max_tokens_values (response lengths swept) and the matching "
    "decryptable_bytes_under_future_crqc_by_length list, plus "
    "harvestable_bytes_monotonic_in_length and "
    "fraction_of_harvested_bytes_eventually_decryptable (1.0 for 'classical', 0.0 for "
    "'hybrid'/'full_pqc'). This is NOT a new vulnerability class -- it is the same RSA/ECDH-"
    "broken-by-Shor threat as hndl_harvest_now_decrypt_later, made worse in direct proportion to "
    "response length, because one broken handshake now exposes an entire accumulated stream "
    "instead of one small reply. streaming_hndl_strategy_independence entries confirm (or refute) "
    "that this exposure does not depend on which signing strategy was used -- "
    "exact_match_across_strategies True means per_chunk and hash_chain produced identical "
    "confidentiality exposure; a documented, expected AEAD-envelope-count byte difference from "
    "buffer_and_sign (NOT a bug) may still show False even when the underlying finding holds -- "
    "do not describe a False here as evidence any strategy is less secure.\n\n"
    "Write a concise report (under 450 words) with these sections, in order:\n"
    "1. HNDL exposure -- which config(s) are shown as eventually decryptable under "
    "a future CRQC, what the storage cost (bytes/request) is for the protected "
    "configs, and whether classical's real weakness here is that RSA gets broken "
    "retroactively -- i.e. everything harvested from a classical connection today "
    "is already compromised the day a CRQC exists, regardless of when that happens.\n"
    "2. MITM tamper detection -- detection rate and mean detection latency per "
    "config/tamper_target. If detection_rate is 1.0 everywhere, say so plainly and "
    "briefly -- don't manufacture concern where none exists. If any entry shows "
    "detection_rate below 1.0, treat that as the most important finding in the "
    "whole report and lead with it.\n"
    "3. Streaming sequence-integrity attack -- if streaming_sequence_integrity_attack is "
    "empty, say plainly that this experiment has not been run yet and skip the rest of this "
    "section. Otherwise: for each strategy present, state detection_rate and "
    "mid_stream_detection_rate together (not just one), and name the fraction_delivered_"
    "before_detection_mean gap between per_chunk and hash_chain as the headline finding -- "
    "framed as hash_chain's documented latency/signature-cost trade-off, not a defect, unless "
    "detection_rate itself is below 1.0 for some entry (that IS a real, concerning finding -- "
    "lead with it if present).\n"
    "4. Streaming HNDL exposure scaling -- if streaming_hndl_exposure_scaling is empty, say "
    "plainly that this experiment has not been run yet and skip the rest of this section. "
    "Otherwise: state which config(s) show fraction_of_harvested_bytes_eventually_decryptable "
    "at 1.0 vs. 0.0, and name the length-dependence explicitly -- for the 1.0 config, how many "
    "bytes become decryptable at the longest response length swept, framed as 'this exposure "
    "grows with every additional token streamed,' not just a static number. State plainly that "
    "this is the same underlying weakness as section 1 above (classical's RSA/ECDH key "
    "establishment), not a new one. If streaming_hndl_strategy_independence data exists, note "
    "briefly whether it confirmed strategy-independence.\n"
    "5. Coverage gaps -- name any config, tamper_target, strategy, or attack combination that "
    "is entirely absent from the data (e.g. no full_pqc entry, only 'ciphertext' tested and "
    "never 'signature', or the streaming experiment missing entirely).\n"
    "6. Bottom line -- end with exactly one short paragraph giving a direct, "
    "plain-language verdict on which configuration is safest against these threats "
    "specifically, and note if that answer could differ from a pure "
    "performance recommendation (the Results Dashboard's separate AI summary) -- "
    "these two questions can have different answers and that's expected, not a "
    "contradiction to paper over.\n\n"
    "Use only the numbers given; if a section's data is empty, say so plainly "
    "instead of inferring it, and never state a config is safe against a threat "
    "that was never tested against it."
)


def generate_threat_summary(context: dict) -> str:
    return _call_claude(SYSTEM_PROMPT_THREATS, context, "threat-scenario")


# ---------------------------------------------------------------------------
# Per-chart "Explain this chart" button (webapp/chart_explainer.py)
# ---------------------------------------------------------------------------

SYSTEM_PROMPT_CHART = (
    "You are a benchmarking analyst explaining ONE chart from a post-quantum cryptography (PQC) "
    "benchmark dashboard to a technical but non-cryptography-expert reader. You are given "
    "chart_title and chart_data (a small structured summary of exactly what's plotted -- never "
    "the full underlying dataset).\n\n"
    "Write 1-3 short sentences describing what the chart shows and the main takeaway, in plain "
    "language -- nothing else, no extra sections.\n\n"
    "Ground every claim strictly in chart_data -- never invent a number, a trend, or a cause that "
    "isn't present in what was given. If chart_data is empty or too sparse to say anything "
    "meaningful, say so plainly instead of filling space."
)


def generate_chart_explanation(chart_title: str, chart_data: dict, caveats: list[str] | None = None) -> str:
    """chart_data is a small structured summary of exactly what's plotted --
    e.g. {"x_axis": "concurrency", "y_axis": "RTT (ms)", "series": {...}} --
    never the full underlying dataframe. `caveats` is accepted for call-site
    compatibility (webapp/chart_explainer.py's callers still pass whatever
    labels/notes are shown on screen near the chart) but is intentionally
    NOT sent to the model or echoed in the explanation -- the explanation is
    scoped to plainly describing what's plotted, nothing more."""
    context = {"chart_title": chart_title, "chart_data": chart_data}
    return _call_claude(SYSTEM_PROMPT_CHART, context, "chart")
