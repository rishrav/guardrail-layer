# Policy Reference

The gateway's deterministic rules live in [`policies/default.yaml`](../policies/default.yaml). Here's what each field does and how it affects decisions.

The policy is the **trusted** source of truth:
- Tool descriptions shown to the LLM judges come from this file, never from runtime docstrings.
- Every audit row records the exact policy version as `version + sha256[:12]`, so any decision can be traced to the rules that produced it.

## Top level

```yaml
version: "2026-09-12.1"
defaults:
  unknown_tool: deny        # tools not listed are always denied (treated as tier 3)
  allow_extra_args: false   # arguments not declared below are a policy violation
allowlists:
  email_domains: [company.com]
budgets:
  transfer_amount_per_session: 1000
tools:
  send_email: { ... }
```

## Tools

| Field | Type | Meaning |
|---|---|---|
| `tier` | 0–3 | Risk tier. **0:** read-only. **1:** internal, reversible writes. **2:** external side effects or data egress. **3:** irreversible, financial or privileged. |
| `description` | string | What the tool does. The alignment judges see this text. |
| `args` | map | Argument specs (see below). |
| `fallback` | string | Safe mode used for `ALLOW_DEGRADED` decisions, e.g. `create_draft` or `simulate`. |
| `budget` | string | The name of a session budget this tool consumes. |
| `output` | `external` \| `system` | `system` means the tool returns its own confirmation text, so the output isn't screened for injection. Anything relaying outside data must stay `external`. |

### How tier and session state combine

|  | Clean session | Tainted session | Call itself flagged |
|---|---|---|---|
| T0 | ALLOW | ALLOW | ALLOW |
| T1 | ALLOW | ALLOW | ESCALATE |
| T2 | ALLOW* | ESCALATE | ESCALATE |
| T3 | ESCALATE | ESCALATE | DENY |

\* Tier-2+ calls that would be allowed still pass deterministic pre-checks (credential invariants, and provenance when a sensitive argument is present). Any failure escalates the call.

## Arguments

| Field | Applies to | Meaning |
|---|---|---|
| `type` | all | `string`, `email`, `url`, `number`, `integer`, `account`, `object` or `array`. |
| `required` | all | A missing value is a violation. |
| `max_length` / `pattern` / `deny_patterns` | strings | Length limit, required full-match regex, and forbidden regexes (e.g. SQL writes). |
| `min` / `max` | numbers | Inclusive bounds; non-finite values are rejected. |
| `max_items` | arrays | Size limit. |
| `sensitive` | all | Checked by **provenance**: where in the session did this value come from? |
| `allowlist` | email, url | The name of an entry in `allowlists`. Subdomains match; lookalikes like `company.com.evil.io` don't. |
| `allowlist_mode` | email, url | `strict`: a non-allowlisted host is a hard DENY. `or_trusted`: the host must be allowlisted **or** the value must have been typed by the user. |
| `novel` | sensitive args | What happens if the value appears nowhere in the session. `fail` is a hard deny, `allow` passes, and `allow_within_budget` passes but the budget still applies. |

## Provenance outcomes for sensitive arguments

| Origin | Effect |
|---|---|
| `TRUSTED_ORIGIN`: the user typed it | pass |
| `UNTRUSTED_CLEAN`: seen only in clean documents or tool outputs | soft fail (blocks ALLOW, permits the safe fallback). Allowlisted emails and numbers are exempt; URLs never are. |
| `UNTRUSTED_FLAGGED`: seen only in content flagged as an injection | **hard deny** |
| `NOVEL`: seen nowhere | governed by `novel` |

## Adding a tool

1. Add it under `tools:` with the lowest tier that is honest about its blast radius.
2. Mark every recipient, destination, account or amount as `sensitive: true`.
3. Give tier ≥ 2 tools a `fallback` if a safe partial action exists; otherwise uncertain calls are denied.
4. Add a matching canary tool to `agent_demo/tools.py` and cases to `benchmarks/generate_cases.py`, then run `make bench-all` to see how the tool affects safety and utility.
