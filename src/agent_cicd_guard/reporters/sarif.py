"""SARIF 2.1.0 report for GitHub code scanning."""

from __future__ import annotations

import json

from agent_cicd_guard import __version__
from agent_cicd_guard.models import Finding, Workflow
from agent_cicd_guard.rules import RULES, RULES_BY_ID

SARIF_LEVEL = {
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

HELP_URI = "https://github.com/songchunhui545-collab/agent-cicd-guard"


def render_sarif(workflows: list[Workflow], findings: list[Finding]) -> str:
    used_ids = {f.rule_id for f in findings}
    rules_out = []
    for rule in RULES:
        if used_ids and rule.id not in used_ids and "ACG-000" not in used_ids:
            # Always emit the full rule catalog so GitHub can show help text.
            pass
        rules_out.append(
            {
                "id": rule.id,
                "name": rule.id,
                "shortDescription": {"text": rule.title},
                "fullDescription": {"text": rule.description},
                "help": {"text": rule.description},
                "helpUri": f"{HELP_URI}#user-content-{rule.id.lower()}",
                "defaultConfiguration": {
                    "level": SARIF_LEVEL.get(rule.severity, "warning"),
                },
                "properties": {"security-severity": _cvssish(rule.severity)},
            }
        )
    if any(f.rule_id == "ACG-000" for f in findings):
        rules_out.insert(
            0,
            {
                "id": "ACG-000",
                "name": "ACG-000",
                "shortDescription": {"text": "Workflow YAML could not be parsed"},
                "fullDescription": {"text": "The scanner could not parse this workflow file."},
                "defaultConfiguration": {"level": "error"},
            },
        )

    results = []
    for finding in findings:
        loc: dict = {
            "physicalLocation": {
                "artifactLocation": {"uri": finding.file.replace("\\", "/"), "uriBaseId": "%SRCROOT%"},
                "region": {"startLine": finding.line or 1},
            }
        }
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": SARIF_LEVEL.get(finding.severity, "warning"),
                "message": {"text": f"{finding.message} Fix: {finding.fix_hint}"},
                "locations": [loc],
                "properties": {
                    "title": finding.title,
                    "job": finding.job,
                    "step": finding.step,
                },
            }
        )

    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "agent-cicd-guard",
                        "version": __version__,
                        "informationUri": HELP_URI,
                        "rules": rules_out,
                    }
                },
                "results": results,
            }
        ],
    }
    # Touch RULES_BY_ID so unused-import checkers stay quiet if the catalog changes.
    _ = RULES_BY_ID
    _ = workflows
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def _cvssish(severity: str) -> str:
    return {"high": "8.0", "medium": "5.0", "low": "2.0", "info": "0.0"}.get(severity, "5.0")
