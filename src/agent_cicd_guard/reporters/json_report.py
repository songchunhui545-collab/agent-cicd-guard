"""JSON report."""

from __future__ import annotations

import json
from collections import Counter

from agent_cicd_guard import __version__
from agent_cicd_guard.models import Finding, Workflow


def render_json(workflows: list[Workflow], findings: list[Finding]) -> str:
    counts = Counter(f.severity for f in findings)
    payload = {
        "tool": "agent-cicd-guard",
        "version": __version__,
        "summary": {
            "workflow_count": len(workflows),
            "finding_count": len(findings),
            "high": counts.get("high", 0),
            "medium": counts.get("medium", 0),
            "low": counts.get("low", 0),
            "info": counts.get("info", 0),
        },
        "workflows": [
            {
                "path": wf.path,
                "name": wf.name,
                "triggers": wf.trigger_names,
                "parse_error": wf.parse_error,
            }
            for wf in workflows
        ],
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity,
                "title": f.title,
                "message": f.message,
                "file": f.file,
                "line": f.line,
                "job": f.job,
                "step": f.step,
                "fix_hint": f.fix_hint,
            }
            for f in findings
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
