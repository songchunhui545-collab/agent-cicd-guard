# agent-cicd-guard

A practical security checklist and a small static scanner for **AI agents wired into CI/CD**, with a focus on GitHub Actions.

In November 2026, researchers at Depi showed that a prompt injection in the OpenAI Codex issue-labeler workflow could be chained far enough to threaten publishing of the official `@openai/codex` npm package. OpenAI fixed the issue; Depi reported that no malicious release went out. The starting point was ordinary and easy to copy: untrusted issue text was fed straight into an agent prompt, on a workflow anyone could trigger by opening an issue.

This project turns that class of mistake into:

- a checklist you can apply in review
- a Python CLI that flags the risky patterns in `.github/workflows/*.yml`

It is a defensive tool. It does not exploit workflows, and it does not ship proof-of-concept payloads.

Repository (placeholder): <https://github.com/songchunhui545-collab/agent-cicd-guard>

中文说明见 [README.zh-CN.md](README.zh-CN.md)。完整清单见 [CHECKLIST.md](CHECKLIST.md) / [CHECKLIST.zh-CN.md](CHECKLIST.zh-CN.md)。

## Quick start

Requires Python 3.9+ and [PyYAML](https://pyyaml.org/).

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e ".[dev]"

# Scan a repo root, a workflows directory, or a single file
agent-cicd-guard scan .
agent-cicd-guard scan tests/fixtures/vulnerable-issue-labeler.yml

# Machine-readable output
agent-cicd-guard scan . --format json
agent-cicd-guard scan . --format sarif -o reports/agent-cicd-guard.sarif
```

The command exits `1` when at least one **high** finding is present (override with `--fail-on medium|low|info|never`). Exit `2` means a usage or path error.

```bash
pytest   # the bundled unit tests
```

A sample GitHub Actions workflow lives at [`.github/workflows/agent-cicd-guard.yml`](.github/workflows/agent-cicd-guard.yml).

## Usage

```
agent-cicd-guard scan [path] [--format text|json|sarif] [-o FILE] [--fail-on high]
```

| Argument | Meaning |
| --- | --- |
| `path` | Repository root (looks in `.github/workflows/`), a workflows directory, or one YAML file. Defaults to `.`. |
| `--format` | `text` (default), `json`, or SARIF 2.1.0 for code scanning. |
| `-o, --output` | Write the report to a file. |
| `--fail-on` | Minimum severity that fails CI. Default: `high`. |

The scanner looks for known agent actions (`openai/codex-action`, `anthropics/claude-code-action`, `google-github-actions/run-gemini-cli`, GitHub Copilot-related actions, and similar) and for LLM API keys in `env` / `with`. It then applies the rules below.

## Rules

| ID | Default severity | What it flags |
| --- | --- | --- |
| ACG-001 | high | Untrusted issue / PR / comment fields interpolated into an agent prompt |
| ACG-002 | high | Privileged triggers outsiders can fire (`issues`, `issue_comment`, `pull_request_target`, `workflow_run`, …) combined with an agent or write access |
| ACG-003 | medium | No default `permissions:` block |
| ACG-004 | high / medium | Broad write permissions (`contents`, `id-token`, `packages`, `actions`, or `write-all`) |
| ACG-005 | high | High-value secrets (`NPM_TOKEN`, cloud keys, write-capable `GITHUB_TOKEN`, …) visible to an agent step, including job/workflow `env` |
| ACG-006 | high | Agent work and publish/release in the same job (or an untrusted agent job holding publish permissions) |
| ACG-007 | medium (high for agent actions) | `uses:` not pinned to a 40-character commit SHA |
| ACG-008 | high | `${{ github.event.* }}` expanded inside a `run:` script |
| ACG-009 | high | `allow-users: "*"`, skipped permission checks, or shell/write tools on untrusted triggers |
| ACG-010 | medium | Publish job uses a long-lived registry token instead of OIDC trusted publishing |
| ACG-011 | medium | Publish or privileged agent job has no GitHub Environment |
| ACG-012 | medium | Agent job on an untrusted trigger with no apparent egress policy |
| ACG-013 | low | Agent run does not obviously persist logs / artifacts for audit |
| ACG-014 | high | Agent starts automatically on an untrusted event with no human gate |

ACG-000 is reserved for unreadable YAML (treated as high so CI fails closed).

## Examples

- [`examples/vulnerable-issue-labeler.yml`](examples/vulnerable-issue-labeler.yml) — a compact illustration of the issue-labeler anti-pattern (not a copy of any proprietary workflow, and not an exploit).
- [`examples/vulnerable-pr-target.yml`](examples/vulnerable-pr-target.yml) — `pull_request_target` plus script injection.
- [`examples/safe-manual-labeler.yml`](examples/safe-manual-labeler.yml) — maintainer `workflow_dispatch`, pinned actions, least privilege, tool allowlist, protected environment, egress control, audit artifact.
- [`examples/safe-ci.yml`](examples/safe-ci.yml) — ordinary CI with no agent.

Background articles (incident, attack chain at a high level, how to use the tool):

- [articles/article-en.md](articles/article-en.md)
- [articles/article-zh.md](articles/article-zh.md)

## Limitations

- This is static analysis of workflow YAML. It cannot prove a workflow is safe, and it will miss agents invoked in ways it does not recognize.
- It cannot see organization default GITHUB_TOKEN permissions, Environment required-reviewer settings, or branch protection. ACG-011 only checks that an `environment:` name is declared.
- Pinning an action to a SHA is necessary and still not enough. The Codex issue-labeler already pinned `openai/codex-action` to a commit; the failure was untrusted input plus overly broad agent authority.
- GitLab CI, CircleCI, Jenkins, and cloud-provider pipelines are out of scope for v0.1.
- Findings are hints for a human review, not a compliance certification.

## Source for the incident

Facts about the Codex case in the docs and articles are taken from Depi's public write-up (11 November 2026), *[Backdooring the next release of Codex through GitHub Action pipeline exploit chaining](https://depi.security/blog/20261111-backdooring-codex/)*. We do not invent download counts, bounty amounts, or timelines beyond what that source (or other cited public sources) states.

## License

[MIT](LICENSE). Copyright (c) 2026 agent-cicd-guard contributors.

This project is not affiliated with OpenAI, GitHub, or Depi.
