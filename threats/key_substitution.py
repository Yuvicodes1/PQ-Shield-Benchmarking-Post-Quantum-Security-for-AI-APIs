"""Full man-in-the-middle: key substitution against the handshake.

The bit-flip experiment (threats/mitm_experiment.py) shows that AEAD and the
response signature reject a tampered ciphertext. It does not test the
adversary an unauthenticated handshake actually invites: one who replaces the
server's key shares with its own, terminates both legs, reads the request,
and re-signs a forged response under a signing key it chose. This script runs
that attack against a real server process and records, per trial, whether
the client accepted, whether the attacker read the request plaintext, and
whether a forged response was accepted.

Attack variants (the attacker never holds the server's identity key):
  benign            no attack -- the false-rejection baseline
  substitute        replace kex and signing public keys; keep the server's
                    transcript signature (now over different keys)
  substitute_resign replace the keys and sign the new transcript with the
                    attacker's own identity key
  relay_tamper      leave the handshake intact, flip one ciphertext byte of the
                    response (and try to decrypt the request without the key)

Client modes:
  unauthenticated   the handshake as benchmarked throughout the paper
  pinned            verifies the transcript signature under an identity key
                    pinned before the experiment (crypto/handshake_auth.py)

The client side runs in-process so the attacker can sit between its messages;
the attacker's leg to the server is real HTTP to a real server process
started with PQ_SHIELD_AUTH_HANDSHAKE=1.

    python -m threats.key_substitution --trials 300
"""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import os
import time

import httpx

from api.secure_client import _b64d, _b64e, do_handshake, fetch_identity
from bench.orchestrator import REPO_ROOT, SERVER_MODULES, _start_server, _stop_server, _wait_healthy
from crypto.aead import AEADError, aead_decrypt, aead_encrypt
from crypto.handshake_auth import IdentityKey, transcript, verify_handshake
from crypto.registry import get_client_crypto, get_server_crypto
from model.profiles.registry import get_profile

CONFIGS = {"classical": "classical", "classical-ecdhe": "classical_ecdhe", "hybrid": "hybrid",
           "hybrid-kex": "hybrid_kex", "full-pqc": "full_pqc", "hybrid-kex-pq": "hybrid_kex_pq"}
VARIANTS = ["benign", "substitute", "substitute_resign", "relay_tamper"]
MODES = ["unauthenticated", "pinned"]
FORGED_PREDICTION = "attacker-chosen"


def clopper_pearson(k: int, n: int, alpha: float = 0.05) -> tuple[float, float]:
    """Exact binomial CI (no SciPy dependency at import time)."""
    from scipy.stats import beta
    lo = 0.0 if k == 0 else beta.ppf(alpha / 2, k, n - k + 1)
    hi = 1.0 if k == n else beta.ppf(1 - alpha / 2, k + 1, n - k)
    return float(lo), float(hi)


async def _trial(http: httpx.AsyncClient, base_url: str, cfg: str, variant: str, mode: str,
                 pinned: dict, attacker_identity: IdentityKey) -> dict:
    out = {"config": cfg, "variant": variant, "mode": mode, "error": None,
           "client_accepted": False, "rejected_at": None,
           "attacker_read_request": False, "forged_response_accepted": False}
    client_crypto = get_client_crypto(cfg)

    # 1. Client asks for a handshake; the attacker intercepts and fetches the real one.
    real_hs, _ = await do_handshake(http, base_url)
    hs = dict(real_hs)
    atk_server = None
    if variant in ("substitute", "substitute_resign"):
        atk_server = get_server_crypto(cfg)
        bundle = atk_server.new_handshake(real_hs["handshake_id"])
        hs["kex_public_key"] = _b64e(bundle.kex_public_key)
        hs["sig_public_key"] = _b64e(bundle.sig_public_key)
        if variant == "substitute_resign":
            sig, _ = attacker_identity.sign(transcript(
                hs["handshake_id"], hs["kex_algorithm"], hs["sig_algorithm"],
                bundle.kex_public_key, bundle.sig_public_key))
            hs["transcript_signature"] = _b64e(sig)

    # 2. Client checks the handshake (pinned mode only).
    if mode == "pinned":
        ok, _ = verify_handshake(hs, pinned, _b64d)
        if not ok:
            out["rejected_at"] = "handshake"
            return out

    # 3. Client establishes a session key with whatever key share it received.
    est = client_crypto.establish(_b64d(hs["kex_public_key"]))
    request = get_profile().sample_request()
    req = aead_encrypt(est.session_key, json.dumps(request).encode())
    client_msg = {"handshake_id": hs["handshake_id"], "kex_blob": _b64e(est.kex_blob),
                  "nonce": _b64e(req.nonce), "ciphertext": _b64e(req.ciphertext)}

    # 4. Attacker processes the client's message.
    if atk_server is not None:
        atk_key, _ = atk_server.accept(hs["handshake_id"], est.kex_blob)
        plaintext = aead_decrypt(atk_key, req.nonce, req.ciphertext)
        out["attacker_read_request"] = json.loads(plaintext) == request
        # Attacker's own session with the real server, forwarding the request.
        up_crypto = get_client_crypto(cfg)
        up_est = up_crypto.establish(_b64d(real_hs["kex_public_key"]))
        up_req = aead_encrypt(up_est.session_key, plaintext)
        r = await http.post(f"{base_url}/secure/predict", json={
            "handshake_id": real_hs["handshake_id"], "kex_blob": _b64e(up_est.kex_blob),
            "nonce": _b64e(up_req.nonce), "ciphertext": _b64e(up_req.ciphertext)})
        r.raise_for_status()
        rj = r.json()
        genuine = json.loads(aead_decrypt(up_est.session_key, _b64d(rj["nonce"]), _b64d(rj["ciphertext"])))
        forged = {**genuine, "prediction": FORGED_PREDICTION}
        resp = aead_encrypt(atk_key, json.dumps(forged).encode())
        signature, _ = atk_server.sign(hs["handshake_id"], resp.nonce + resp.ciphertext)
        resp_nonce, resp_ct = resp.nonce, resp.ciphertext
        atk_server.forget(hs["handshake_id"])
    else:
        if variant == "relay_tamper":
            try:  # without the session key the attacker cannot read the request
                aead_decrypt(os.urandom(32), req.nonce, req.ciphertext)
                out["attacker_read_request"] = True
            except AEADError:
                pass
        r = await http.post(f"{base_url}/secure/predict", json=client_msg)
        r.raise_for_status()
        rj = r.json()
        resp_nonce, resp_ct, signature = _b64d(rj["nonce"]), _b64d(rj["ciphertext"]), _b64d(rj["signature"])
        if variant == "relay_tamper":
            resp_ct = resp_ct[:-1] + bytes([resp_ct[-1] ^ 0x01])

    # 5. Client verifies the response: AEAD first, then the signature.
    try:
        body = json.loads(aead_decrypt(est.session_key, resp_nonce, resp_ct))
    except AEADError:
        out["rejected_at"] = "aead"
        return out
    valid, _ = client_crypto.verify(resp_nonce + resp_ct, signature, _b64d(hs["sig_public_key"]))
    if not valid:
        out["rejected_at"] = "signature"
        return out
    out["client_accepted"] = True
    out["forged_response_accepted"] = body.get("prediction") == FORGED_PREDICTION
    return out


def summarize(rows: list[dict]) -> dict:
    n = len(rows)
    valid = [r for r in rows if r["error"] is None]
    k_acc = sum(r["client_accepted"] for r in valid)
    k_read = sum(r["attacker_read_request"] for r in valid)
    k_forged = sum(r["forged_response_accepted"] for r in valid)
    nv = len(valid)
    at = {}
    for r in valid:
        if r["rejected_at"]:
            at[r["rejected_at"]] = at.get(r["rejected_at"], 0) + 1
    return {
        "config": rows[0]["config"], "variant": rows[0]["variant"], "mode": rows[0]["mode"],
        "n_trials": n, "n_valid": nv,
        "accepted": k_acc, "accepted_ci95": clopper_pearson(k_acc, nv) if nv else None,
        "attacker_read_request": k_read, "forged_response_accepted": k_forged,
        "forged_ci95": clopper_pearson(k_forged, nv) if nv else None,
        "rejected_at": at,
    }


async def run_config(base_url: str, cfg: str, trials: int) -> list[dict]:
    summaries = []
    async with httpx.AsyncClient(timeout=30.0) as http:
        pinned = await fetch_identity(http, base_url)
        attacker_identity = IdentityKey.generate(pinned["algorithm"])
        for mode in MODES:
            for variant in VARIANTS:
                rows = []
                for _ in range(trials):
                    try:
                        rows.append(await _trial(http, base_url, cfg, variant, mode, pinned, attacker_identity))
                    except Exception as exc:
                        rows.append({"config": cfg, "variant": variant, "mode": mode,
                                     "error": f"{type(exc).__name__}: {exc}", "client_accepted": False,
                                     "rejected_at": None, "attacker_read_request": False,
                                     "forged_response_accepted": False})
                s = summarize(rows)
                summaries.append(s)
                print(f"  {cfg:<16}{mode:<16}{variant:<18} accepted {s['accepted']}/{s['n_valid']}  "
                      f"read {s['attacker_read_request']}  forged-accepted {s['forged_response_accepted']}  "
                      f"rejected_at {s['rejected_at']}", flush=True)
    return summaries


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--configs", default=",".join(CONFIGS))
    ap.add_argument("--trials", type=int, default=300)
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--output", default=os.path.join(REPO_ROOT, "results", "mitm", "key_substitution.json"))
    ap.add_argument("--log-dir", default=os.path.join(REPO_ROOT, "results", "server_logs"))
    args = ap.parse_args()
    base_url = f"http://127.0.0.1:{args.port}"
    all_summaries = []
    for key in [c.strip() for c in args.configs.split(",") if c.strip()]:
        proc = _start_server(key, args.port, os.path.join(args.log_dir, f"keysub-server-{key}.log"),
                             extra_env={"PQ_SHIELD_AUTH_HANDSHAKE": "1"})
        try:
            _wait_healthy(base_url)
            all_summaries += asyncio.run(run_config(base_url, CONFIGS[key], args.trials))
        finally:
            _stop_server(proc)
            time.sleep(1.0)
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(all_summaries, f, indent=2)
    print(f"wrote {args.output}")


if __name__ == "__main__":
    main()
