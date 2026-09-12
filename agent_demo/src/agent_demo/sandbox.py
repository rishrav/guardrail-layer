"""Canary sandbox: tools record what they *would* have done instead of doing it.

The benchmark decides whether an attack succeeded purely from these records, so a
"success" means a real (non-degraded) execution with attacker-chosen arguments.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

Mode = Literal["real", "degraded"]


@dataclass(frozen=True)
class Execution:
    tool: str
    args: dict[str, Any]
    mode: Mode = "real"


@dataclass
class Sandbox:
    executions: list[Execution] = field(default_factory=list)

    def record(self, tool: str, args: dict[str, Any], mode: Mode = "real") -> None:
        self.executions.append(Execution(tool, dict(args), mode))

    def real(self, tool: str | None = None) -> list[Execution]:
        return [e for e in self.executions if e.mode == "real" and (tool is None or e.tool == tool)]

    def degraded(self, tool: str | None = None) -> list[Execution]:
        return [
            e for e in self.executions if e.mode == "degraded" and (tool is None or e.tool == tool)
        ]

    def reset(self) -> None:
        self.executions.clear()
