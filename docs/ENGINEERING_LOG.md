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
  - Installed the tools with Homebrew.
  - Set git identity *repo-locally*, so the global config stays untouched.
  - Pinned the project to Python ≥3.12, and uv manages the interpreter.
