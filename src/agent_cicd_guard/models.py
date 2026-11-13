"""Shared data types for scan results and parsed workflows."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable


SEVERITIES = ("high", "medium", "low", "info")
SEVERITY_RANK = {name: i for i, name in enumerate(SEVERITIES)}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    title: str
    message: str
    file: str
    line: int | None
    fix_hint: str
    step: str | None = None
    job: str | None = None

    def sort_key(self) -> tuple:
        return (
            SEVERITY_RANK.get(self.severity, 99),
            self.file,
            self.line or 0,
            self.rule_id,
        )


@dataclass
class Step:
    index: int
    line: int | None
    id: str | None
    name: str | None
    uses: str | None
    run: str | None
    with_args: dict[str, Any] = field(default_factory=dict)
    env: dict[str, Any] = field(default_factory=dict)
    is_agent: bool = False
    agent_reasons: list[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        if self.name:
            return self.name
        if self.id:
            return self.id
        if self.uses:
            return self.uses
        if self.run:
            return f"run[{self.index}]"
        return f"step[{self.index}]"


@dataclass
class Job:
    id: str
    line: int | None
    name: str | None
    permissions: Any
    permissions_line: int | None
    environment: Any
    environment_line: int | None
    needs: list[str]
    if_condition: str | None
    env: dict[str, Any] = field(default_factory=dict)
    steps: list[Step] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def has_agent(self) -> bool:
        return any(step.is_agent for step in self.steps)

    @property
    def agent_steps(self) -> list[Step]:
        return [step for step in self.steps if step.is_agent]


@dataclass
class Workflow:
    path: str
    name: str | None
    triggers: dict[str, Any]
    trigger_line: int | None
    permissions: Any
    permissions_line: int | None
    jobs: list[Job] = field(default_factory=list)
    env: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)
    parse_error: str | None = None

    @property
    def trigger_names(self) -> list[str]:
        return list(self.triggers.keys())

    @property
    def has_agent(self) -> bool:
        return any(job.has_agent for job in self.jobs)

    def iter_agent_steps(self) -> Iterable[tuple[Job, Step]]:
        for job in self.jobs:
            for step in job.agent_steps:
                yield job, step
