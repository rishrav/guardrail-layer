"""Deterministic policy engine: tool allowlist, risk tiers and argument validation.

This is stage 1 of the screening pipeline. Nothing here calls a model, so none of it can
be prompt-injected. A violation is a hard DENY no matter what later stages conclude.
"""

from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

ArgType = Literal["string", "email", "url", "number", "integer", "account", "object", "array"]
_EMAIL_RE = re.compile(r"^[^@\s]+@([A-Za-z0-9-]+\.)+[A-Za-z]{2,}$")
_ACCOUNT_RE = re.compile(r"^[A-Za-z0-9-]{6,34}$")


class ArgSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: ArgType
    required: bool = False
    max_length: int | None = None
    max_items: int | None = None
    min: float | None = None
    max: float | None = None
    pattern: str | None = None
    deny_patterns: list[str] = Field(default_factory=list)
    sensitive: bool = False
    allowlist: str | None = None
    allowlist_mode: Literal["strict", "or_trusted"] = "strict"
    novel: Literal["fail", "allow", "allow_within_budget"] = "fail"


class ToolPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tier: int = Field(ge=0, le=3)
    description: str
    args: dict[str, ArgSpec] = Field(default_factory=dict)
    fallback: str | None = None
    budget: str | None = None

    @property
    def sensitive_args(self) -> dict[str, ArgSpec]:
        return {name: spec for name, spec in self.args.items() if spec.sensitive}


class PolicyDefaults(BaseModel):
    unknown_tool: Literal["deny"] = "deny"
    allow_extra_args: bool = False


class PolicyDocument(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: str
    defaults: PolicyDefaults = Field(default_factory=PolicyDefaults)
    allowlists: dict[str, list[str]] = Field(default_factory=dict)
    budgets: dict[str, float] = Field(default_factory=dict)
    tools: dict[str, ToolPolicy]

    @model_validator(mode="after")
    def _references_exist(self) -> PolicyDocument:
        for tool_name, tool in self.tools.items():
            if tool.budget and tool.budget not in self.budgets:
                raise ValueError(f"{tool_name}: unknown budget '{tool.budget}'")
            for arg_name, spec in tool.args.items():
                if spec.allowlist and spec.allowlist not in self.allowlists:
                    raise ValueError(
                        f"{tool_name}.{arg_name}: unknown allowlist '{spec.allowlist}'"
                    )
                for pattern in [*spec.deny_patterns, *([spec.pattern] if spec.pattern else [])]:
                    re.compile(pattern)
        return self


@dataclass(frozen=True)
class Violation:
    code: str
    message: str
    arg: str | None = None


@dataclass
class PolicyResult:
    tool_name: str
    tier: int
    tool: ToolPolicy | None
    violations: list[Violation] = field(default_factory=list)
    # Sensitive args whose allowlist check is deferred to the adjudicator (or_trusted mode).
    deferred_allowlist_args: list[str] = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return not self.violations


@dataclass(frozen=True)
class Policy:
    document: PolicyDocument
    source_sha256: str

    @property
    def version(self) -> str:
        return self.document.version

    def evaluate_tool_call(self, tool_name: str, args: dict[str, Any]) -> PolicyResult:
        tool = self.document.tools.get(tool_name)
        if tool is None:
            return PolicyResult(
                tool_name,
                3,
                None,
                [Violation("unknown_tool", f"tool '{tool_name}' is not in policy")],
            )

        result = PolicyResult(tool_name, tool.tier, tool)
        if not self.document.defaults.allow_extra_args:
            for extra in sorted(set(args) - set(tool.args)):
                result.violations.append(
                    Violation("unexpected_arg", f"argument '{extra}' is not allowed", extra)
                )

        for name, spec in tool.args.items():
            if name not in args or args[name] is None:
                if spec.required:
                    result.violations.append(Violation("missing_arg", "required argument", name))
                continue
            result.violations.extend(self._check_arg(name, spec, args[name], result))
        return result

    def _check_arg(
        self, name: str, spec: ArgSpec, value: Any, result: PolicyResult
    ) -> list[Violation]:
        problems = _check_type_and_bounds(name, spec, value)
        if problems:
            return problems

        if spec.allowlist:
            host = _host_for(spec.type, value)
            if host is not None and not _domain_allowed(
                host, self.document.allowlists[spec.allowlist]
            ):
                if spec.allowlist_mode == "strict":
                    problems.append(
                        Violation("not_allowlisted", f"'{host}' is not in {spec.allowlist}", name)
                    )
                else:
                    result.deferred_allowlist_args.append(name)
        return problems


def _check_type_and_bounds(name: str, spec: ArgSpec, value: Any) -> list[Violation]:
    def bad(code: str, message: str) -> list[Violation]:
        return [Violation(code, message, name)]

    match spec.type:
        case "string" | "email" | "url" | "account":
            if not isinstance(value, str):
                return bad("bad_type", f"expected {spec.type}")
            if spec.max_length is not None and len(value) > spec.max_length:
                return bad("too_long", f"exceeds {spec.max_length} characters")
            if spec.type == "email" and not _EMAIL_RE.match(value):
                return bad("bad_format", "not a valid email address")
            if spec.type == "account" and not _ACCOUNT_RE.match(value):
                return bad("bad_format", "not a valid account identifier")
            if spec.type == "url":
                parts = urlsplit(value)
                if parts.scheme not in {"http", "https"} or not parts.hostname:
                    return bad("bad_format", "not an absolute http(s) URL")
            if spec.pattern and not re.fullmatch(spec.pattern, value):
                return bad("bad_format", "does not match required pattern")
            for pattern in spec.deny_patterns:
                if re.search(pattern, value):
                    return bad("denied_pattern", f"matches denied pattern {pattern!r}")
        case "number" | "integer":
            if isinstance(value, bool) or not isinstance(value, int | float):
                return bad("bad_type", f"expected {spec.type}")
            if spec.type == "integer" and not isinstance(value, int):
                return bad("bad_type", "expected integer")
            if not math.isfinite(value):
                return bad("bad_type", "must be finite")
            if spec.min is not None and value < spec.min:
                return bad("out_of_range", f"below minimum {spec.min}")
            if spec.max is not None and value > spec.max:
                return bad("out_of_range", f"above maximum {spec.max}")
        case "object":
            if not isinstance(value, dict):
                return bad("bad_type", "expected object")
        case "array":
            if not isinstance(value, list):
                return bad("bad_type", "expected array")
            if spec.max_items is not None and len(value) > spec.max_items:
                return bad("too_many_items", f"exceeds {spec.max_items} items")
    return []


def _host_for(arg_type: ArgType, value: str) -> str | None:
    if arg_type == "email":
        return value.rsplit("@", 1)[-1].lower()
    if arg_type == "url":
        return (urlsplit(value).hostname or "").lower()
    return None


def _domain_allowed(host: str, allowed: list[str]) -> bool:
    """Exact domain or a true subdomain; rejects lookalikes like company.com.evil.io."""
    host = host.rstrip(".")
    return any(host == d or host.endswith("." + d) for d in (a.lower() for a in allowed))


def load_policy(path: str | Path) -> Policy:
    source = Path(path).read_bytes()
    document = PolicyDocument.model_validate(yaml.safe_load(source))
    return Policy(document=document, source_sha256=hashlib.sha256(source).hexdigest())
