"""Human-readable text report."""

from __future__ import annotations

from collections import Counter

from agent_cicd_guard.models import Finding, Workflow

SEVERITY_MARK = {
    "high": "HIGH",
    "medium": "MED ",
    "low": "LOW ",
    "info": "INFO",
}


def render_text(workflows: list[Workflow], findings: list[Finding]) -> str:
    lines: list[str] = []
    file_count = len(workflows)
    parse_errors = sum(1 for wf in workflows if wf.parse_error)
    lines.append(
        f"agent-cicd-guard scanned {file_count} workflow file(s)"
        + (f" ({parse_errors} unreadable)" if parse_errors else "")
        + "."
    )
    if not findings:
        lines.append("No findings.")
        return "\n".join(lines) + "\n"

    counts = Counter(f.severity for f in findings)
    summary = ", ".join(
        f"{counts[level]} {level}"
        for level in ("high", "medium", "low", "info")
        if counts.get(level)
    )
    lines.append(f"Found {len(findings)} finding(s): {summary}.")
    lines.append("")

    for finding in findings:
        loc = finding.file
        if finding.line:
            loc = f"{finding.file}:{finding.line}"
        mark = SEVERITY_MARK.get(finding.severity, finding.severity.upper())
        scope = ""
        if finding.job:
            scope = f" [job {finding.job}]"
        if finding.step:
            scope += f" [step {finding.step}]"
        lines.append(f"[{mark}] {finding.rule_id} {finding.title}")
        lines.append(f"  at {loc}{scope}")
        lines.append(f"  {finding.message}")
        lines.append(f"  Fix: {finding.fix_hint}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
