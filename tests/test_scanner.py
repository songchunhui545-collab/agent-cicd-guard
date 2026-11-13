"""Tests for agent-cicd-guard against vulnerable and safer workflow fixtures."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from agent_cicd_guard.cli import main
from agent_cicd_guard.detect import known_agent_action
from agent_cicd_guard.models import Finding
from agent_cicd_guard.parser import parse_workflow_file, parse_yaml
from agent_cicd_guard.reporters import render_json, render_sarif, render_text
from agent_cicd_guard.scanner import ScanError, scan_path, should_fail

FIXTURES = Path(__file__).parent / "fixtures"
VULN_LABELER = FIXTURES / "vulnerable-issue-labeler.yml"
VULN_PR = FIXTURES / "vulnerable-pr-target.yml"
SAFE_LABELER = FIXTURES / "safe-manual-labeler.yml"
SAFE_CI = FIXTURES / "safe-ci.yml"
INVALID = FIXTURES / "invalid.yml"


def _ids(findings: list[Finding]) -> set[str]:
    return {f.rule_id for f in findings}


def _by_id(findings: list[Finding], rule_id: str) -> list[Finding]:
    return [f for f in findings if f.rule_id == rule_id]


def test_yaml_preserves_on_key():
    doc = parse_yaml("on:\n  issues:\n    types: [opened]\n")
    assert "on" in doc
    assert True not in doc
    assert "issues" in doc["on"]


def test_parser_records_line_numbers():
    workflow = parse_workflow_file(VULN_LABELER)
    assert workflow.parse_error is None
    assert workflow.name == "Issue labeler (vulnerable example)"
    assert "issues" in workflow.trigger_names
    job = workflow.jobs[0]
    assert job.id == "gather-labels"
    assert job.line is not None and job.line > 1
    agent = job.agent_steps[0]
    assert agent.is_agent
    assert agent.line is not None and agent.line >= 20
    assert "openai/codex-action" in (agent.uses or "")


def test_known_agent_actions():
    assert known_agent_action("openai/codex-action@v1")
    assert known_agent_action("anthropics/claude-code-action@main")
    assert known_agent_action("google-github-actions/run-gemini-cli@v0")
    assert known_agent_action("github/copilot-swe-agent@v1")
    assert not known_agent_action("actions/checkout@v4")


def test_vulnerable_issue_labeler_flags_core_risks():
    _, findings = scan_path(VULN_LABELER)
    ids = _ids(findings)
    # Core Codex-style chain
    for rule_id in (
        "ACG-001",
        "ACG-002",
        "ACG-004",
        "ACG-005",
        "ACG-006",
        "ACG-007",
        "ACG-008",
        "ACG-009",
        "ACG-010",
        "ACG-011",
        "ACG-012",
        "ACG-014",
    ):
        assert rule_id in ids, f"{rule_id} should fire on the vulnerable labeler, got {sorted(ids)}"

    prompt = _by_id(findings, "ACG-001")[0]
    assert prompt.line is not None
    assert "github.event.issue" in prompt.message
    assert prompt.severity == "high"

    injection = _by_id(findings, "ACG-008")[0]
    assert injection.line is not None
    assert "run:" in injection.message

    allow = _by_id(findings, "ACG-009")[0]
    assert "allow-users" in allow.message

    secrets = _by_id(findings, "ACG-005")[0]
    assert "NPM_TOKEN" in secrets.message or "NODE_AUTH_TOKEN" in secrets.message

    # ACG-003 may or may not fire because the job sets permissions; either is acceptable
    # but a top-level block is still recommended. We only require it not to crash.
    assert should_fail(findings, "high")
    assert any(f.severity == "high" and f.line for f in findings)


def test_vulnerable_pr_target_flags_injection_and_triggers():
    _, findings = scan_path(VULN_PR)
    ids = _ids(findings)
    for rule_id in ("ACG-001", "ACG-002", "ACG-007", "ACG-008", "ACG-009", "ACG-014"):
        assert rule_id in ids, f"{rule_id} should fire, got {sorted(ids)}"
    assert any("SSH_PRIVATE_KEY" in f.message for f in _by_id(findings, "ACG-005"))
    assert any("pull_request_target" in f.message or "issue_comment" in f.message for f in findings)


def test_safe_manual_labeler_has_no_high_findings():
    workflows, findings = scan_path(SAFE_LABELER)
    assert workflows[0].parse_error is None
    highs = [f for f in findings if f.severity == "high"]
    assert highs == [], f"safer example should have no high findings, got {highs}"
    # These should be resolved by the safer pattern
    assert not _ids(findings) & {
        "ACG-001",
        "ACG-002",
        "ACG-005",
        "ACG-006",
        "ACG-007",
        "ACG-008",
        "ACG-009",
        "ACG-012",
        "ACG-013",
        "ACG-014",
    }


def test_safe_ci_is_clean():
    _, findings = scan_path(SAFE_CI)
    assert findings == []


def test_invalid_yaml_is_reported_not_crashed():
    _, findings = scan_path(INVALID)
    assert len(findings) == 1
    assert findings[0].rule_id == "ACG-000"
    assert findings[0].severity == "high"


def test_scan_directory_of_fixtures():
    workflows, findings = scan_path(FIXTURES)
    paths = {wf.path for wf in workflows}
    assert any("vulnerable-issue-labeler.yml" in p for p in paths)
    assert any("safe-ci.yml" in p for p in paths)
    assert any(f.rule_id == "ACG-001" for f in findings)
    assert any(f.rule_id == "ACG-000" for f in findings)


def test_scan_missing_path():
    with pytest.raises(ScanError):
        scan_path(FIXTURES / "does-not-exist.yml")


def test_text_and_json_and_sarif_reports():
    workflows, findings = scan_path(VULN_LABELER)
    text = render_text(workflows, findings)
    assert "ACG-001" in text
    assert "Fix:" in text
    assert "vulnerable-issue-labeler.yml" in text

    payload = json.loads(render_json(workflows, findings))
    assert payload["tool"] == "agent-cicd-guard"
    assert payload["summary"]["high"] >= 1
    assert any(item["rule_id"] == "ACG-001" for item in payload["findings"])

    sarif = json.loads(render_sarif(workflows, findings))
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "agent-cicd-guard"
    assert any(r["ruleId"] == "ACG-001" for r in run["results"])
    assert any(r["level"] == "error" for r in run["results"])


def test_cli_text_nonzero_on_high(capsys, tmp_path):
    code = main(["scan", str(VULN_LABELER)])
    captured = capsys.readouterr()
    assert code == 1
    assert "ACG-001" in captured.out
    assert "HIGH" in captured.out

    out = tmp_path / "report.json"
    code = main(["scan", str(VULN_LABELER), "--format", "json", "-o", str(out), "--fail-on", "never"])
    assert code == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["summary"]["finding_count"] >= 1


def test_cli_clean_exit_zero(capsys):
    code = main(["scan", str(SAFE_CI)])
    captured = capsys.readouterr()
    assert code == 0
    assert "No findings" in captured.out


def test_cli_help_without_subcommand(capsys):
    code = main([])
    assert code == 2
    assert "scan" in capsys.readouterr().out


def test_cli_missing_path_exits_2(capsys):
    code = main(["scan", os.path.join("no", "such", "path")])
    assert code == 2
    assert "error:" in capsys.readouterr().err
