"""Discover workflows, run rules, and collect findings."""

from __future__ import annotations

from pathlib import Path

from agent_cicd_guard.models import Finding, SEVERITY_RANK, Workflow
from agent_cicd_guard.parser import discover_workflow_files, parse_workflow_file
from agent_cicd_guard.rules import run_rules


class ScanError(Exception):
    pass


def scan_path(path: str | Path) -> tuple[list[Workflow], list[Finding]]:
    root = Path(path)
    if not root.exists():
        raise ScanError(f"Path does not exist: {root}")
    files = discover_workflow_files(root)
    if not files:
        raise ScanError(
            f"No GitHub Actions workflow files found under {root}. "
            "Pass a workflow file, a .github/workflows directory, or a repository root."
        )
    workflows: list[Workflow] = []
    findings: list[Finding] = []
    for file in files:
        # Keep paths relative to the scan root when possible, for readable reports.
        display = _display_path(root, file)
        workflow = parse_workflow_file(file)
        workflow.path = display
        workflows.append(workflow)
        findings.extend(run_rules(workflow))
    findings.sort(key=lambda f: f.sort_key())
    return workflows, findings


def _display_path(root: Path, file: Path) -> str:
    root = root.resolve()
    file = file.resolve()
    scan_base = root if root.is_dir() else root.parent
    try:
        return str(file.relative_to(scan_base))
    except ValueError:
        return str(file)


def highest_severity(findings: list[Finding]) -> str | None:
    if not findings:
        return None
    return min(findings, key=lambda f: SEVERITY_RANK.get(f.severity, 99)).severity


def should_fail(findings: list[Finding], fail_on: str) -> bool:
    threshold = SEVERITY_RANK.get(fail_on, SEVERITY_RANK["high"])
    return any(SEVERITY_RANK.get(f.severity, 99) <= threshold for f in findings)
