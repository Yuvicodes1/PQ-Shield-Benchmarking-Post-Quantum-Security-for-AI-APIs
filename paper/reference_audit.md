# Reference audit (checked 2026-10-02)

Each reference in the Review-2 journal draft was checked against arXiv, the
publisher, IETF datatracker, or Crossref. **All 15 exist; none are fabricated.**
Eight have wrong bibliographic details. Corrected entries are in
`references.bib` (keys in the last column).

| # | Draft citation | Status | What to fix | bib key |
|---|---|---|---|---|
| 1 | Abbasi et al., *Cryptography* 9(1):12, 2025 | ⚠️ wrong volume/number | **vol. 9, no. 2, art. 32**, doi 10.3390/cryptography9020032 | `abbasi2025benchmark` |
| 2 | M. Demir et al., arXiv:2503.12952 | ✅ (incomplete authors) | E. D. Demir, B. Bilgin, M. C. Onbasli | `demir2025industry` |
| 3 | Egbuagha & Ikwunna, ePrint 2025/1668 | ⚠️ title truncated | full title adds "…of Protocol-Level Transitions and Readiness" | `egbuagha2025practice` |
| 4 | Pote & Bansode, JISEM **9(2):45–53, 2024** | ❌ wrong volume, pages, year, title | **vol. 10, no. 9s, pp. 548–556, 2025**; title "…: A Comprehensive Framework for Experimental Analysis" | `pote2025evaluation` |
| 5 | Shaw, arXiv:2605.17061 | ⚠️ title | real title begins "quantum-safe: Bridging the…" | `shaw2026quantumsafe` |
| 6 | Montenegro et al., FGCS 175, **pp. 108–120** | ❌ pages | FGCS uses article numbers: **art. 108062**, doi 10.1016/j.future.2025.108062 | `montenegro2026framework` |
| 7 | Chhetri et al., arXiv:2510.10436 | ✅ | (under review at ACM Computing Surveys; cite arXiv) | `chhetri2025survey` |
| 8 | Faval & Moreira, arXiv:2603.28626 | ⚠️ missing author | add **Flávio de Oliveira Silva** | `faval2026mobile` |
| 9 | Kudaloor & Aijaz, arXiv:2605.06881 | ⚠️ venue | accepted to **IEEE Communications Standards Magazine** (the Review-2 *report* lists a non-existent "IEEE Int. Conf. on 6G Networking") | `kudaloor2026sixg` |
| 10 | T. Song et al., "Analyzing privacy risks in machine learning endpoints," 2019 | ❌ wrong title and author | **L. Song, R. Shokri, P. Mittal, "Privacy Risks of Securing Machine Learning Models against Adversarial Examples," ACM CCS 2019, pp. 241–257** | `song2019privacy` |
| 11 | Tidjon & Khomh, arXiv:2207.00091 | ✅ | — | `tidjon2022threat` |
| 12 | R. Ahmed et al., "Survey of PQC support…", 2025 | ❌ wrong author initial, no venue | **N. Ahmed, L. Zhang, A. Gangopadhyay**, IEEE QCE 2025 (arXiv:2508.16078) | `ahmed2025libraries` |
| 13 | Blanco-Romero et al., arXiv:2603.01091 | ✅ (author name) | "F. Almenares Mendoza", not "F. A. Mendoza" | `blancoromero2026hndl` |
| 14 | Gómez-Cambronero et al., arXiv:2603.11006 | ✅ | (the Review-2 *report* invents "Proc. IEEE Symp. on Network Security"; cite arXiv) | `gomezcambronero2026layered` |
| 15 | Schemitt et al., "Impact of PQ digital signatures on platforms," 2025 | ❌ wrong title, no authors/venue | **A. G. Schemitt et al., "Assessing the Impact of Post-Quantum Digital Signature Algorithms on Blockchains," IEEE TrustCom 2025** | `schemitt2025blockchain` |

The Review-2 **report** (not the journal) also gives conference venues for
Faval & Moreira and Gómez-Cambronero et al. that don't exist. Both are arXiv
preprints.

## Missing prior art that reviewers will expect (all verified)

| Topic | Reference | Why it must be cited | bib key |
|---|---|---|---|
| Stream signing | Gennaro & Rohatgi, "How to Sign Digital Streams," CRYPTO '97, LNCS 1294, pp. 180–197 | Hash-chained stream signing originates here. Without it, "hash-chain" reads as a re-invention. | `gennaro1997streams` |
| Stream signing | Wong & Lam, "Digital Signatures for Flows and Multicasts," IEEE/ACM ToN 7(4):502–513, 1999 | Amortizing one signature over many packets (tree/hash chaining). | `wong1999flows` |
| Stream signing | Perrig et al., "Efficient Authentication and Signing of Multicast Streams over Lossy Channels" (TESLA/EMSS), IEEE S&P 2000, pp. 56–73 | Standard reference for amortized stream authentication and its delayed-verification trade-off, the same trade-off as your hash-chain. | `perrig2000tesla` |
| PQ-TLS benchmarking | Paquin, Stebila, Tamvada, "Benchmarking Post-quantum Cryptography in TLS," PQCrypto 2020, LNCS 12100, pp. 72–91 | The reference PQC-under-emulated-network study (Linux netem). Position your netem experiment against it. | `paquin2020benchmarking` |
| PQ-TLS benchmarking | Sikeridis, Kampanakis, Devetsikiotis, "Post-Quantum Authentication in TLS 1.3: A Performance Study," NDSS 2020 | PQ signature cost in TLS under realistic network conditions. | `sikeridis2020authentication` |
| LLM streaming side channel | Weiss et al., "What Was Your Prompt? A Remote Keylogging Attack on AI Assistants," USENIX Security 2024, pp. 3367–3384 | Token-length leakage from encrypted LLM streams. Directly supports your note that per-chunk/hash-chain leak chunk count and timing. | `weiss2024keylogging` |
| Deployed hybrid KEX | Kwiatkowski et al., draft-ietf-tls-ecdhe-mlkem-05 (X25519MLKEM768) | Justifies the Classical-ECDHE baseline and clarifies what "hybrid" means in TLS. | `ietf-ecdhe-mlkem` |
| TLS 1.3 | RFC 8446 | TLS 1.3 removed RSA key transport; that's why Classical-RSA is a legacy variant. | `rfc8446` |
| liboqs | Stebila & Mosca, SAC 2016, LNCS 10532, pp. 14–37 (published 2017) | Canonical citation for liboqs/OQS, instead of a GitHub URL. | `stebila2016oqs` |
| HNDL timeline | Mosca, IEEE S&P 16(5):38–41, 2018 | Mosca's x + y > z: the standard HNDL risk argument. | `mosca2018ready` |
| Quantum attack | Shor, SIAM J. Comput. 26(5):1484–1509, 1997 | Primary citation for "broken by Shor's algorithm". | `shor1997` |

## Citation-practice fixes

- Intro cites **[1]–[15]** for a single sentence about AI endpoints carrying sensitive
  data. None of the 15 are about that. Cite specific works per claim; drop this block.
- Drop the ACVP GitHub URL from "Weblinks" and cite it as `acvp`; likewise FIPS 203/204
  as `fips203`/`fips204`.
