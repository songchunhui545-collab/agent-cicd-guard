# Checklist: AI agents in CI/CD (GitHub Actions)

Use this when you add, review, or audit a workflow that calls a coding agent, an issue-triage bot, or any LLM with tools. Items map to scanner rule IDs where a static check exists.

The motivating case is the November 2026 Codex issue-labeler chain documented by [Depi](https://depi.security/blog/20261111-backdooring-codex/): untrusted issue text reached an agent prompt, and that foothold was chained toward npm publish rights. OpenAI shipped a fix; Depi reported no malicious package was published. Treat the list below as hardening, not as a reconstruction of that exploit.

## 1. Untrusted input must not become instructions

**Scanner: ACG-001, ACG-008**

- [ ] Issue titles, issue bodies, comment bodies, PR titles/bodies, review text, and discussion text are **untrusted**. Anyone who can open an issue or comment can usually set them.
- [ ] Do not interpolate `${{ github.event.issue.title }}`, `${{ github.event.issue.body }}`, `${{ github.event.comment.body }}`, `${{ github.event.pull_request.title }}`, `${{ github.event.pull_request.body }}`, or similar fields into an agent `prompt:` / `instructions:` input as if they were data you control.
- [ ] If the agent must see the text, fetch it inside a tightly sandboxed, tool-restricted run, and tell the model explicitly that the text is untrusted data, not instructions. This is a mitigation, not a guarantee — prompt injection remains a residual risk.
- [ ] Never expand those expressions inside a `run:` script. `${{ }}` is expanded by Actions *before* the shell starts, so a title like `$(malicious)` or a body with extra backticks can become shell commands.
- [ ] Safe pattern for scripts: pass the value through `env:` and read it quoted.

```yaml
# Unsafe
- run: echo "${{ github.event.issue.title }}"

# Safer (still do not send this string to an agent with shell tools)
- env:
    ISSUE_TITLE: ${{ github.event.issue.title }}
  run: echo "$ISSUE_TITLE"
```

## 2. Triggers: who can start the workflow?

**Scanner: ACG-002, ACG-014**

These events run in the *base repository* context and can often be fired by people outside the maintainer set:

- `issues` (especially `opened`)
- `issue_comment`
- `pull_request_target`
- `pull_request_review` / `pull_request_review_comment`
- `discussion` / `discussion_comment`
- `workflow_run` (a low-privilege workflow can sometimes start a more privileged one)

Checklist:

- [ ] Do not attach an agent to `issues: opened` or `issue_comment` unless there is a hard gate (below).
- [ ] Prefer `workflow_dispatch` (maintainer starts it) or a labeled-issue flow that only runs when a **maintainer** applies a label, with `author_association` checked in the job `if:`.
- [ ] Avoid `pull_request_target` for agents. If you must use it, never check out or execute code from the pull request head, and keep permissions at read-only.
- [ ] `pull_request` (not `_target`) is safer because fork PRs usually do not receive repo secrets, but PR titles and bodies are still untrusted — ACG-008 still applies.

## 3. Permissions: default deny, then grant

**Scanner: ACG-003, ACG-004**

- [ ] Every workflow has a top-level `permissions:` block. Prefer `permissions: {}` or `contents: read` at the top, then grant extra scopes on the job that needs them.
- [ ] Do not use `permissions: write-all`.
- [ ] Agent jobs should almost never have `contents: write`, `id-token: write`, `packages: write`, or `actions: write`.
- [ ] If the agent only suggests labels, `issues: write` plus `contents: read` is usually enough — and even `issues: write` is worth questioning on an untrusted trigger.
- [ ] Remember: a missing `permissions:` block inherits the repository or organization default, which may still be broad.

## 4. Secrets the agent can see

**Scanner: ACG-005**

- [ ] The agent step receives only the LLM API key it needs (for example `CODEX_OPENAI_API_KEY` / `ANTHROPIC_API_KEY`).
- [ ] `NPM_TOKEN`, `NODE_AUTH_TOKEN`, `PYPI_TOKEN`, `CARGO_REGISTRY_TOKEN`, cloud access keys, SSH / signing keys, and write-capable `GITHUB_TOKEN` / `GH_TOKEN` are **not** in the agent job — including job-level and workflow-level `env:`, which every step inherits.
- [ ] Assume anything in the runner environment can leak if the agent is prompt-injected or leaves its sandbox. The Codex write-up is a reminder that sandbox boundaries are part of the threat model.

## 5. Separate agent jobs from publish jobs

**Scanner: ACG-006, ACG-010, ACG-011**

- [ ] Labeling, reviewing, or code-editing agents never run `npm publish`, `twine upload`, `cargo publish`, `docker push`, or `gh release` in the same job.
- [ ] Publish happens in a different job (better: a different workflow) that `needs:` only trusted build artifacts, runs on trusted refs, and does not invoke the agent.
- [ ] Prefer [OIDC trusted publishing](https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect) for npm, PyPI, and similar registries: `permissions: { id-token: write }` on the *publish* job only, and no long-lived `NPM_TOKEN` in the repo.
- [ ] The publish job sets `environment: release` (or similar). In repository settings, that environment has **required reviewers** and, if appropriate, a wait timer and a deployment-branch allowlist.
- [ ] YAML can only show that an environment name exists; confirm the reviewer policy in the GitHub UI.

## 6. Pin actions to commit SHAs

**Scanner: ACG-007**

- [ ] Every `uses:` is pinned to a 40-character commit SHA, with the tag in a comment: `uses: actions/checkout@<sha> # v4.3.0`.
- [ ] Do not use `@v1`, `@main`, or `@master` for actions that see secrets or run an agent.
- [ ] Pinning stops a *moved tag* from silently changing the action. It does **not** stop prompt injection into a pinned agent action.

## 7. Tool allowlists and sandbox

**Scanner: ACG-009**

- [ ] `allow-users` is not `"*"`. Restrict invocation to maintainers when the action supports it.
- [ ] Do not set `dangerously-skip-permissions` or equivalent bypass flags.
- [ ] On any untrusted trigger, the agent has an explicit tool allowlist and **does not** get shell, unrestricted file write, or open network tools.
- [ ] Prefer read-only sandbox modes. `workspace-write` (or equivalent) on untrusted content is a red flag.
- [ ] If the task is “suggest a label”, the allowlist should be that narrow: maybe `github.issues.update`, and nothing else.

## 8. Network egress

**Scanner: ACG-012**

- [ ] Agent jobs that can be influenced by untrusted text have an egress policy (for example [step-security/harden-runner](https://github.com/step-security/harden-runner) with `egress-policy: block` and an allowlist of the API endpoints you actually need).
- [ ] Disable or tightly limit the agent's own network tools on those runs.
- [ ] Logs, artifacts, and issue comments are also exfil channels — do not let the agent print secrets, and be careful what it is allowed to post back.

## 9. Logging, audit, and human-in-the-loop

**Scanner: ACG-013, ACG-014**

- [ ] Persist the prompt (redacted), tool-call trace, and model output as a build artifact or a redacted job summary so you can investigate later.
- [ ] Do not start the agent automatically on `issues: opened` with no review.
- [ ] Require at least one of: a protected environment with reviewers, a maintainer label, an `author_association == 'OWNER' | 'MEMBER' | 'COLLABORATOR'` check, or `workflow_dispatch`.
- [ ] A human should still approve anything that writes to the default branch, creates a release, or publishes a package.

## 10. Review questions to ask on every PR that touches `.github/workflows`

1. What untrusted string can reach the model or the shell?
2. Who can fire this trigger, including from a fork or a new issue?
3. What can this job write (git, packages, id-token, cache, issues)?
4. Which secrets are in this job's environment, not just this step?
5. If the agent does the wrong thing, is there still a human between that and a release?

If you cannot answer those five clearly, do not merge the workflow.

## Related documents

- [README.md](README.md) — install and CLI
- [articles/article-en.md](articles/article-en.md) — background on the Codex incident
