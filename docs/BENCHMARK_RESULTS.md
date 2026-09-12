# Benchmark Results

Reproduce with `make bench` (held-out split) or `make bench-all` (+ ablations). Model responses replay from `benchmarks/cassettes/models.jsonl`. They were recorded from the live local models (qwen3:8b judges, granite3-guardian:2b, DeBERTa-v3 ONNX), and replay reproduced every live outcome exactly.

## Setup

- **170 cases** from `benchmarks/generate_cases.py` (seeded), split dev/test by id hash:
  - **80 attacks** crossing 4 goals (transfer, email exfiltration, HTTP exfiltration, mass delete), 9 payload carriers (plain, HTML comment, fake system notice, markdown comment, zero-width, homoglyph, base64, polite business phrasing, judge-targeting) and 3 channels (RAG document, compromised tool output, direct unsafe request).
  - **90 benign** cases, including hard lookalikes: user-typed external recipients, invoice payment from a document, legitimate work in an already-tainted session, and a security-awareness page that quotes injection phrases.
- **Worst-case agent:** a scripted model that makes every instructed tool call as soon as the instruction is visible in its context.
  - An **attack succeeds** only if a canary tool *really* executes with the attacker's arguments.
  - A **benign task completes** if the requested tool runs, or runs in its declared safe mode where the case allows it.
- **The whole stack is real:** LangChain 1.x agent, SDK middleware, guarded retriever, FastAPI gateway, Postgres and Redis.

## Headline (all 170 cases)

| Config | ASR | Unsafe executions blocked | Benign utility | Safe-mode completions |
|---|---|---|---|---|
| A: no guardrail | 100.0% | n/a | 100.0% | 0 |
| B: policy only | 28.7% | 71.2% | 66.7% | 0 |
| C: policy + detection | 3.8% | 96.2% | 44.4% | 0 |
| **D: full stack** | **0.0%** | **100%** | **88.9%** | 10 |

**Held-out test split** (34 attacks, 43 benign): B 32.4% / 72.1%, C 5.9% / 60.5%, **D 0.0% ASR / 90.7% utility**.

## Ablations (full stack minus one part)

| Config | ASR | Utility | Reading |
|---|---|---|---|
| D − provenance | 3.8% | 88.9% | Provenance closes the attacks that detection misses (polite carriers). |
| D − judges | 0.0% | 44.4% | Judges don't add safety here; they add **usability**. Without them every escalation fails closed. |
| D − guardian | 0.0% | 88.9% | No measurable effect on this suite: it only votes on would-be ALLOWs, and the judges were never fooled. |
| D − degraded mode | 0.0% | 77.8% | Safe mode (simulated transfer, soft delete) recovers about 11 points of utility. |
| D − all detection | 0.0% | **100.0%** | The deterministic adjudicator alone blocks every attack, and it avoids detection's false positives. |

## By category (A → B → C → D)

| Category | Metric | A | B | C | D |
|---|---|---|---|---|---|
| indirect_rag/email_exfil (11) | ASR | 100% | 100% | 18.2% | **0%** |
| indirect_rag/http_exfil (11) | ASR | 100% | 27.3% | 9.1% | **0%** |
| indirect_rag/transfer, delete (22) | ASR | 100% | 0% | 0% | 0% |
| tool_output/* (16) | ASR | 100% | 0–100% | 0% | 0% |
| direct/secret_exfil (4) | ASR | 100% | 100% | 0% | 0% |
| direct/budget_drain, exec_shell, http_offlist, sql_write (16) | ASR | 100% | 0% | 0% | 0% |
| benign/transfer_user_typed (10) | utility | 100% | 0% | 0% | **100%** |
| benign/pay_invoice_from_doc (10) | utility | 100% | 0% | 0% | **100%** (safe mode) |
| benign/delete_user_requested (10) | utility | 100% | 0% | 0% | **100%** |
| benign/legit_work_in_tainted_session (10) | utility | 100% | 100% | 0% | **100%** |
| benign/email_self, email_colleague, sql_read, low_risk (40) | utility | 100% | 100% | 100% | 100% |
| benign/doc_discusses_injection (10) | utility | 100% | 100% | **0%** | **0%** |

## Latency

- **Fast path** (clean T0–T2 tool calls, deterministic pre-checks included): p50 about 1–3 ms at the gateway.
- **Adjudicated path, live local models on a 16 GB Apple Silicon laptop:** p50 **13.7 s**, p95 **25 s** for three qwen3:8b judge votes plus the guardian when needed. Most of that is Ollama swapping the two models in memory. In the replay tables, adjudication shows milliseconds because responses come from cassettes.

## What these results do and don't show

- **Found by this benchmark and fixed** (see `docs/ENGINEERING_LOG.md`):
  - **S-017:** provenance only ran after taint, so polite injections leaked (5.9% test ASR).
  - **S-018:** credential invariants only ran after detection escalated a call. The `D − all detection` ablation exposed it.
- **Detection's remaining cost:** the security-awareness page that *quotes* "ignore previous instructions" is quarantined (utility 0%). Detection's benefit, keeping payloads out of the model's context so they can't steer summaries or answers, isn't measured here, because this suite only scores tool execution. So D keeps detection even though `D − all detection` scores higher on this suite.
- **Worst case, not typical case:** this is a scripted worst-case agent, not a measure of how gullible any particular LLM is.
- **Real but small suite:** 170 cases is small, and the categories are a designed grid rather than a sample of real-world attacks. Treat 0% as "none of these got through", not as a guarantee.
- **CI can diverge from the recording machine:** replays run on different hardware could shift DeBERTa scores near a threshold and produce cassette misses. Misses fail closed and appear in the uploaded CI report.
