# Engineering Log

A running, dated record of **decisions**, **tradeoffs** and **struggles** made while building the Guardrail Layer. Entries are appended as work happens, not written afterwards.

Format:
- **D-###** Decision: context → options → choice → why
- **T-###** Tradeoff: what we gave up and what we got
- **S-###** Struggle: what broke → diagnosis → fix

---

## 2026-09-12: Planning & Phase 1 (Foundation)

### D-001: No human-in-the-loop; use a fully automated adjudicator
- **Context:** The first design sent high-impact tool calls (e.g. `transfer_funds`) to a human approval queue.
- **Options:**
  1. Human approval UI.
  2. A single LLM "is this safe?" call.
  3. A multi-signal automated adjudicator.
- **Choice:** Option 3. Deterministic **argument provenance** plus **budgets/invariants**, then an **ensemble of local LLM judges** and a **tool-risk guardian model**. The result is `ALLOW`, `ALLOW_DEGRADED` or `DENY`.
- **Why:**
  - Humans don't scale, add minutes of latency and suffer approval fatigue.
  - A single LLM judge can itself be prompt-injected.
  - Deterministic checks can't be talked out of a decision, so LLM votes can only *tighten* an outcome.

### D-002: Local-first open-weight models through Ollama
- **Context:** Classification and judging run on every escalated call, which makes cloud API cost and latency the main operating expense.
- **Choice:**
  - Ollama serves the judge (Qwen3-8B class) and IBM Granite Guardian.
  - Prompt Guard 2 (86M) runs in-process as the pre-filter.
  - A cloud LLM remains an optional per-role override.
- **Why:** $0 marginal cost, no data leaves the machine, and runs are reproducible because every vote records the model digest.

### T-001: Model size vs. a 16 GB dev laptop
- The dev machine is Apple Silicon with 16 GB RAM. An 8B judge (~5 GB at Q4) plus an 8B guardian won't fit comfortably alongside Docker.
- **Tradeoff:** default to the **2B Granite Guardian** and keep the 8B judge. We accept a somewhat weaker guardian vote, in exchange for being able to run the full stack on a laptop. Because the guardian is only one vote in a quorum, the risk is limited.

### D-003: Colima instead of Docker Desktop
- **Context:** No container runtime was installed.
- **Choice:** Colima plus the Docker CLI, installed with Homebrew.
- **Why:** Free, headless, lightweight.
- **Consequence:** Docker on macOS can't reach the Metal GPU, so **Ollama runs natively on the host**. Containers reach it at `host.docker.internal:11434`. On Linux with a GPU, a compose profile runs Ollama in a container instead.

### D-004: uv workspace monorepo
- **Choice:** One repo with a `uv` workspace whose members are `gateway`, `sdk` and `agent_demo`.
- **Why:** The SDK must be installable on its own (agents shouldn't pull in FastAPI or SQLAlchemy), but a single lockfile keeps versions consistent, and uv is much faster than pip or poetry in CI.

### S-001: Blank toolchain at project start
- **Problem:** The machine had Python 3.13 but no `uv`, Docker, Ollama, `gitleaks` or `pre-commit`, and no global git identity.
- **Fix:**
  - Linked `docker-compose` into `~/.docker/cli-plugins`; without that, Homebrew's docker CLI doesn't recognize `docker compose`.
  - Installed the tools with Homebrew.
  - Set git identity *repo-locally*, so the global config stays untouched.
  - Pinned the project to Python ≥3.12, and uv manages the interpreter.

### S-002: The pre-commit Ruff hook kept rejecting correct commits
- **Symptom:** A commit containing `tests/unit/test_health.py` failed twice with "files were modified by this hook". Ruff merged the `fastapi` and `gateway` import blocks.
- **Diagnosis:** Two issues combined:
  1. Ruff running in pre-commit's isolated environment can't tell that `gateway` (a `src/` layout package) is first-party code, so it sorts it as third-party.
  2. Pre-commit **stashes unstaged changes** before running hooks. The `known-first-party` fix in `pyproject.toml` was unstaged, so it was invisible to the hook.
  - Side effect: the failed commit left its files staged, and the *next* commit silently swept them in.
- **Fix:**
  - Committed the lint config *before* the code that depends on it.
  - Split the accidental combined commit with `git reset --soft`.
  - Now run `ruff check --fix` and `ruff format` before staging.

### D-005: Tamper evidence through a hash chain plus a DB trigger, not only DB permissions
- **Context:** The audit log must show that nobody edited or deleted a decision.
- **Options:**
  1. Revoke UPDATE/DELETE from the application role.
  2. Hash-chain the rows.
  3. Use an external append-only store (WORM bucket, ledger DB).
- **Choice:** Options 1 and 2, done as a **trigger** that blocks UPDATE, DELETE and TRUNCATE on the audit tables, plus a `sha256(prev_hash ‖ canonical_json(row))` chain with a `verify` walker.
- **Why:**
  - Roles are easy to misconfigure in dev, while a trigger protects every connection.
  - A superuser can still disable triggers, and the hash chain *detects* that; there's an integration test that bypasses the trigger with `session_replication_role = replica` to prove it.
  - An external ledger is out of scope for a local stack.

### T-002: Serialized audit appends
- A chain needs exactly one "previous row". Concurrent requests would fork it, so appends take a transaction-scoped `pg_advisory_xact_lock`.
- **Gave up:** parallel audit writes; audit inserts are effectively single-file.
- **Got:** a linear, verifiable chain. At expected volumes (tens to hundreds of screens per second) one indexed insert under a lock is not the bottleneck; the LLM calls are. If it ever becomes one, the fix is to chain per session or per shard.

### S-003: Timestamps and JSONB must round-trip to the same bytes
- **Risk:** A hash computed in Python before the insert has to match the row after Postgres returns it, but JSONB reorders keys and `server_default=now()` isn't known client-side.
- **Fix:**
  - Canonical JSON uses sorted keys.
  - `created_at` is set in the application in UTC, instead of by the database default, before hashing.
  - The integration test calls `expire_all()` to force a real reload from the DB before verifying.

---

## 2026-09-12: Phase 2 (Gateway API + Policy Engine)

### D-006: Allowlists come in two modes, `strict` and `or_trusted`
- **Context:** A hard domain allowlist on `send_email.to` would block "email this to my personal gmail", a legitimate request. With no allowlist at all, "email it to attacker@evil.io" becomes easy.
- **Choice:** Each argument declares an `allowlist_mode`.
  - `strict` (for `http_post.url`): a non-allowlisted host is a hard policy DENY.
  - `or_trusted` (for `send_email.to`): the policy stage *defers* the check (`deferred_allowlist_args`). The adjudicator then passes the value only if it is allowlisted **or** its provenance traces to trusted user input.
- **Why:** This keeps the deterministic guarantee (an attacker-sourced recipient can never pass) without breaking legitimate one-off recipients.

### D-007: With no adjudicator wired in, an ESCALATE becomes DENY
- In Phase 2 the adjudicator doesn't exist yet. `PipelineConfig.unresolved_escalation` defaults to `DENY`, with the reason code `escalation_unresolved`.
- **Tradeoff:** Until Phase 5 every T3 call is denied, which is useless for real work but safe. The same switch drives benchmark configuration C ("policy + detection, escalations denied").

### D-008: The audit policy key is `version + sha256[:12]`
- **Problem:** Someone can edit `policies/default.yaml` without bumping `version:`, and two different rule sets would then share one audit label.
- **Choice:** Audit rows reference `"<version>+<first 12 hex of file sha256>"`, and the full YAML text is stored in `policies` on startup. Any past decision can be traced to the exact rules that produced it.

### D-009: Lookalike-domain matching
- `host == d or host.endswith("." + d)`. A naive `endswith(d)` would accept `evilcompany.com`, and substring matching would accept `api.company.com.evil.io`. Both are parametrized in the unit tests, along with the query-string trick `evil.io/?next=api.company.com`.

### S-004: Cached async engine plus multiple TestClients meant "attached to a different loop"
- **Symptom (anticipated during design, then guarded against):** Each `TestClient` runs the app on its own event loop, but `get_engine()` and `get_redis()` are `lru_cache` singletons. A pooled asyncpg connection created on one loop breaks when the next client reuses it.
- **Fix:**
  - The app lifespan disposes the engine, closes Redis and calls `cache_clear()` on shutdown, so every app lifetime starts clean.
  - Integration tests share one module-scoped client instead of creating nested clients.

### S-005: Leftover staged files poisoned the next commit (again)
- **Symptom:** A whole batch of commits failed on an ASYNC240 lint error in `main.py`, even though the working-tree `main.py` had already been fixed with `asyncio.to_thread`.
- **Diagnosis:** The same trap as S-002. The earlier failed commit left the *old* `main.py` staged. The next `git add <other files> && git commit` included it, and pre-commit linted the staged blob, not the working-tree file.
- **Fix:** A commit helper that runs `git reset` (clearing the index) before `git add <exact paths>`, so every commit contains only the files it names. Lesson: in a chained script, a failed commit is not a no-op; it leaves state behind.

### D-010: The SDK duplicates wire types instead of importing the gateway's
- **Options:**
  1. A shared `guardrail-contracts` package.
  2. The SDK imports `gateway.schemas`.
  3. Duplicate the small set of types.
- **Choice:** Option 3, for now.
- **Why:**
  - Option 2 drags FastAPI and SQLAlchemy into every agent process.
  - Option 1 is the "right" answer at scale, but it's a third package to version for about 60 lines of enums and dataclasses.
- **Mitigation:** A contract test compares the SDK and gateway `Decision` enums.

### D-011: The SDK's failure semantics depend on what is being screened
- Gateway unreachable:
  - **Tool calls:** follow the tool's *cached* policy tier. Tiers 0–1 fail open (configurable) and tiers 2–3 are denied. **Unknown tools count as tier 3.**
  - **Untrusted content:** quarantined.
  - **User input:** allowed, because the user is the principal and their later tool calls are still screened.
- **Why the SDK caches tiers (`GET /v1/policy`):** Without them, an outage forces a choice between "deny everything", which breaks read-only agents, and "allow everything", which is an easy bypass (knock the gateway over, then act). Caching tiers gives graded behavior without trusting the model.
- **Tradeoff:** A policy change during an outage isn't seen until the next refresh.
