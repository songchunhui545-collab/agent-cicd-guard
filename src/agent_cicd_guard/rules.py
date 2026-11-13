"""Static checks for AI-agent CI/CD risks in GitHub Actions workflows."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any

from agent_cicd_guard.detect import (
    CRITICAL_WRITE_SCOPES,
    action_ref,
    action_slug,
    combined_text,
    effective_write_scopes,
    environment_name,
    find_script_injection_exprs,
    find_untrusted_exprs,
    has_permissions_block,
    has_write_all,
    if_has_actor_gate,
    is_docker_action,
    is_local_action,
    is_publish_step,
    is_sha_ref,
    job_has_egress_control,
    job_has_publish,
    looks_like_publish_secret,
    looks_like_sensitive_secret,
    privileged_untrusted_triggers,
    secret_names_in,
    with_arg,
    write_scopes,
)
from agent_cicd_guard.models import Finding, Job, Step, Workflow
from agent_cicd_guard.parser import source_line


Check = Callable[[Workflow], Iterator[Finding]]


@dataclass(frozen=True)
class Rule:
    id: str
    severity: str
    title: str
    description: str
    check: Check


def _finding(
    rule: Rule,
    workflow: Workflow,
    message: str,
    fix_hint: str,
    line: int | None = None,
    job: Job | None = None,
    step: Step | None = None,
    severity: str | None = None,
) -> Finding:
    return Finding(
        rule_id=rule.id,
        severity=severity or rule.severity,
        title=rule.title,
        message=message,
        file=workflow.path,
        line=line if line is not None else (step.line if step else (job.line if job else workflow.trigger_line)),
        fix_hint=fix_hint,
        step=step.label if step else None,
        job=job.id if job else None,
    )


def _check_untrusted_prompt(workflow: Workflow) -> Iterator[Finding]:
    rule = RULES_BY_ID["ACG-001"]
    for job, step in workflow.iter_agent_steps():
        # Prompt-like inputs plus env values that are later sent to the model.
        prompt_bits = combined_text(
            with_arg(step, "prompt", "instructions", "query", "message", "input", "prompt-file"),
            step.with_args,
            step.env,
            step.run,
        )
        hits = find_untrusted_exprs(prompt_bits)
        if not hits:
            continue
        triggers = privileged_untrusted_triggers(workflow) or workflow.trigger_names
        yield _finding(
            rule,
            workflow,
            message=(
                f"Agent step {step.label!r} interpolates untrusted event data into its prompt "
                f"({', '.join(hits[:4])}). Trigger(s): {', '.join(triggers) or 'unknown'}. "
                "A crafted issue, comment, or PR body can hijack the agent."
            ),
            fix_hint=(
                "Do not feed issue/PR titles, bodies, or comments straight into an agent prompt "
                "from an untrusted trigger. Gate the job on maintainer labels or "
                "author_association, treat event text as untrusted data (not instructions), "
                "and disable shell/write tools for that run."
            ),
            line=source_line(step.with_args, step.line),
            job=job,
            step=step,
        )


def _check_untrusted_triggers(workflow: Workflow) -> Iterator[Finding]:
    rule = RULES_BY_ID["ACG-002"]
    triggers = privileged_untrusted_triggers(workflow)
    if not triggers:
        return
    has_write = False
    for job in workflow.jobs:
        scopes = effective_write_scopes(workflow, job)
        if has_write_all(job.permissions if job.permissions is not None else workflow.permissions) or any(
            s in CRITICAL_WRITE_SCOPES or s == "write-all" or s == "<default-or-inherited>"
            for s in scopes
        ):
            has_write = True
            break
    if not (workflow.has_agent or has_write):
        return
    why = []
    if workflow.has_agent:
        why.append("runs an AI agent")
    if has_write:
        why.append("has write or unknown default permissions")
    yield _finding(
        rule,
        workflow,
        message=(
            f"Workflow is triggered by untrusted events ({', '.join(triggers)}) and "
            f"{' and '.join(why)}. Outsiders can usually fire these by opening an issue, "
            "commenting, or submitting a pull request."
        ),
        fix_hint=(
            "Avoid issues / issue_comment / pull_request_target for agent jobs. Prefer "
            "workflow_dispatch or a maintainer-only label gate with an author_association "
            "check. If you must use pull_request_target, do not check out or execute PR code, "
            "and keep permissions at least privilege."
        ),
        line=workflow.trigger_line,
    )


def _check_missing_permissions(workflow: Workflow) -> Iterator[Finding]:
    rule = RULES_BY_ID["ACG-003"]
    if has_permissions_block(workflow):
        return
    yield _finding(
        rule,
        workflow,
        message=(
            "Workflow has no top-level `permissions:` block, and at least one job also "
            "omits `permissions:`. The default GITHUB_TOKEN scope is organization-dependent "
            "and may be broader than this workflow needs."
        ),
        fix_hint=(
            "Add a top-level `permissions: {}` (or `contents: read`) and grant extra scopes "
            "only on the jobs that need them."
        ),
        line=workflow.trigger_line,
        severity="medium",
    )


def _check_write_permissions(workflow: Workflow) -> Iterator[Finding]:
    rule = RULES_BY_ID["ACG-004"]
    untrusted = privileged_untrusted_triggers(workflow)
    for job in workflow.jobs:
        source = job.permissions if job.permissions is not None else workflow.permissions
        line = job.permissions_line or workflow.permissions_line or job.line
        if source is None:
            if untrusted and job.has_agent:
                yield _finding(
                    rule,
                    workflow,
                    message=(
                        f"Job {job.id!r} runs an agent on untrusted trigger(s) "
                        f"({', '.join(untrusted)}) without an explicit permissions block."
                    ),
                    fix_hint="Set job-level permissions to the minimum required (often contents: read only).",
                    line=line,
                    job=job,
                    severity="high",
                )
            continue
        if has_write_all(source):
            yield _finding(
                rule,
                workflow,
                message=f"Job {job.id!r} (or the workflow) sets `permissions: write-all`.",
                fix_hint="Replace write-all with an explicit least-privilege map.",
                line=line,
                job=job,
                severity="high",
            )
            continue
        scopes = write_scopes(source)
        critical = [s for s in scopes if s in CRITICAL_WRITE_SCOPES]
        if not critical:
            continue
        severity = "high" if (untrusted and (job.has_agent or job_has_publish(job) or critical)) else "medium"
        if untrusted or job.has_agent or job_has_publish(job) or critical:
            yield _finding(
                rule,
                workflow,
                message=(
                    f"Job {job.id!r} grants write access to {', '.join(critical)}. "
                    + (
                        f"This is especially risky with untrusted trigger(s): {', '.join(untrusted)}."
                        if untrusted
                        else "Drop any scope this job does not need."
                    )
                ),
                fix_hint=(
                    "Keep agent jobs at contents: read (plus issues: write only if labeling). "
                    "Grant contents / id-token / packages write only to a separate, protected "
                    "publish job that does not run the agent."
                ),
                line=line,
                job=job,
                severity=severity,
            )


def _unique(names: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for name in names:
        if name not in seen:
            seen.add(name)
            out.append(name)
    return out


def _secrets_from_mapping(*parts: object) -> list[str]:
    names: list[str] = []
    blob = combined_text(*parts)
    names.extend(secret_names_in(blob))
    for part in parts:
        if isinstance(part, dict):
            names.extend(str(key) for key in part.keys())
    return _unique(names)


def _secrets_visible_to_agent(workflow: Workflow, job: Job, step: Step) -> list[str]:
    """Secrets on the step, plus job- and workflow-level env inherited by every step."""
    return _secrets_from_mapping(workflow.env, job.env, step.env, step.with_args, step.run)


def _check_secrets_on_agent(workflow: Workflow) -> Iterator[Finding]:
    rule = RULES_BY_ID["ACG-005"]
    for job, step in workflow.iter_agent_steps():
        flagged: list[str] = []
        writes = effective_write_scopes(workflow, job)
        has_write = has_write_all(job.permissions if job.permissions is not None else workflow.permissions) or any(
            s in CRITICAL_WRITE_SCOPES or s in {"write-all", "<default-or-inherited>"} for s in writes
        )
        for name in _secrets_visible_to_agent(workflow, job, step):
            upper = name.upper()
            if looks_like_publish_secret(name):
                flagged.append(name)
            elif upper in {"GITHUB_TOKEN", "GH_TOKEN", "ACTIONS_RUNTIME_TOKEN"} and has_write:
                flagged.append(name)
            elif looks_like_sensitive_secret(name) and upper not in {
                "OPENAI_API_KEY",
                "CODEX_OPENAI_API_KEY",
                "ANTHROPIC_API_KEY",
                "CLAUDE_API_KEY",
                "GEMINI_API_KEY",
            }:
                # SSH / signing keys etc. — skip pure LLM keys
                if not upper.endswith("_API_KEY") or looks_like_publish_secret(name):
                    if "SSH" in upper or "PRIVATE" in upper or "SIGNING" in upper or "PASSWORD" in upper or "TOKEN" in upper or "CREDENTIAL" in upper:
                        flagged.append(name)
        # unique
        flagged = list(dict.fromkeys(flagged))
        if not flagged:
            continue
        yield _finding(
            rule,
            workflow,
            message=(
                f"Agent step {step.label!r} can see high-value secret(s): {', '.join(flagged)}. "
                "If the agent is prompt-injected or escapes its sandbox, these credentials leak."
            ),
            fix_hint=(
                "Give the agent only the LLM API key it needs. Keep NPM_TOKEN, cloud keys, "
                "and write-capable GITHUB_TOKEN out of the agent job; pass them only to a "
                "later, isolated publish job."
            ),
            line=source_line(step.env, step.line),
            job=job,
            step=step,
        )


def _check_agent_publish_same_job(workflow: Workflow) -> Iterator[Finding]:
    rule = RULES_BY_ID["ACG-006"]
    for job in workflow.jobs:
        if not job.has_agent:
            continue
        publish_steps = [step for step in job.steps if is_publish_step(step)]
        if not publish_steps:
            # Also: agent job has packages/id-token write even without an obvious publish command
            scopes = effective_write_scopes(workflow, job)
            critical = [s for s in scopes if s in {"packages", "id-token", "contents"} or s == "write-all"]
            if critical and privileged_untrusted_triggers(workflow):
                yield _finding(
                    rule,
                    workflow,
                    message=(
                        f"Job {job.id!r} runs an AI agent and also holds publish-related write "
                        f"permissions ({', '.join(critical)}) on an untrusted trigger. "
                        "A compromised agent step can reach the release path."
                    ),
                    fix_hint=(
                        "Split agent work and publishing into separate jobs (and preferably "
                        "separate workflows). The publish job should need: the agent job, run "
                        "only on trusted refs, and use a protected environment."
                    ),
                    line=job.line,
                    job=job,
                )
            continue
        names = ", ".join(step.label for step in publish_steps)
        yield _finding(
            rule,
            workflow,
            message=(
                f"Job {job.id!r} runs an AI agent and also publishes or releases "
                f"({names}) in the same job."
            ),
            fix_hint=(
                "Move npm/pypi/docker/gh-release steps into a separate job that does not "
                "run the agent, is gated by a protected environment, and uses OIDC trusted publishing."
            ),
            line=publish_steps[0].line or job.line,
            job=job,
            step=publish_steps[0],
        )


def _check_unpinned_actions(workflow: Workflow) -> Iterator[Finding]:
    rule = RULES_BY_ID["ACG-007"]
    for job in workflow.jobs:
        for step in job.steps:
            uses = step.uses
            if not uses or is_local_action(uses):
                continue
            if is_docker_action(uses):
                ref = uses.split(":", 2)[-1] if ":" in uses[len("docker://"):] else ""
                # docker://image@sha256:... is pinned; tags are not
                if "@sha256:" in uses:
                    continue
                yield _finding(
                    rule,
                    workflow,
                    message=f"Step {step.label!r} uses a Docker image tag rather than a digest: {uses}",
                    fix_hint="Pin container actions to a sha256 digest.",
                    line=step.line,
                    job=job,
                    step=step,
                    severity="medium",
                )
                continue
            ref = action_ref(uses)
            if is_sha_ref(ref):
                continue
            slug = action_slug(uses)
            severity = "high" if step.is_agent else "medium"
            displayed = ref or "(no ref)"
            yield _finding(
                rule,
                workflow,
                message=(
                    f"Action {slug} is not pinned to a 40-character commit SHA (ref: {displayed}). "
                    "Floating tags like v1 or @main can be moved to a malicious commit."
                ),
                fix_hint=(
                    f"Pin with uses: {slug}@<full-sha>  # {displayed}. Pinning is necessary "
                    "but not sufficient — a pinned agent action can still be prompt-injected."
                ),
                line=step.line,
                job=job,
                step=step,
                severity=severity,
            )


def _check_script_injection(workflow: Workflow) -> Iterator[Finding]:
    rule = RULES_BY_ID["ACG-008"]
    for job in workflow.jobs:
        for step in job.steps:
            if not step.run:
                continue
            hits = find_script_injection_exprs(step.run)
            if not hits:
                continue
            yield _finding(
                rule,
                workflow,
                message=(
                    f"Step {step.label!r} interpolates untrusted context into a `run:` script: "
                    f"{', '.join(hits[:4])}. An issue title or PR body can break out of the shell "
                    "string and run arbitrary commands on the runner."
                ),
                fix_hint=(
                    "Never expand `${{ github.event.* }}` inside `run:`. Assign the value to an "
                    "environment variable and read it quoted from the shell, e.g. "
                    "`env: TITLE: ${{ github.event.issue.title }}` then `echo \"$TITLE\"`."
                ),
                line=step.line,
                job=job,
                step=step,
            )


def _looks_like_wildcard_allow(value: Any) -> bool:
    if value is None:
        return False
    text = str(value).strip().strip("\"'")
    return text in {"*", "all", "true"} or text.lower() in {"*", "everyone"}


def _allowed_tools_include_shell(value: Any) -> bool:
    if value is None:
        return False
    text = str(value).lower()
    return any(token in text for token in ("bash", "shell", "sh", "python", "write", "*", "all"))


def _check_agent_allowlist(workflow: Workflow) -> Iterator[Finding]:
    rule = RULES_BY_ID["ACG-009"]
    untrusted = privileged_untrusted_triggers(workflow)
    for job, step in workflow.iter_agent_steps():
        problems: list[str] = []
        allow_users = with_arg(step, "allow-users", "allow_users", "allowed-users", "allowed_users")
        if _looks_like_wildcard_allow(allow_users):
            problems.append(f"allow-users is {allow_users!r} (anyone can invoke the action)")

        skip = with_arg(
            step,
            "dangerously-skip-permissions",
            "dangerously_skip_permissions",
            "skip-permissions",
            "bypass-permissions",
        )
        if skip is not None and str(skip).lower() in {"true", "yes", "1"}:
            problems.append("permissions/tool checks are skipped")

        allowed_tools = with_arg(step, "allowed-tools", "allowed_tools", "allow-tools", "tools")
        disallowed = with_arg(step, "disallowed-tools", "disallowed_tools", "deny-tools")
        if untrusted:
            if allowed_tools is None and disallowed is None:
                problems.append(
                    "no tool allowlist/denylist is set while the workflow runs on an untrusted trigger"
                )
            elif _allowed_tools_include_shell(allowed_tools):
                problems.append(f"allowed tools include shell or write capabilities ({allowed_tools!r})")

        # Codex-style sandbox write mode on untrusted input
        sandbox = with_arg(step, "sandbox", "sandbox-mode", "sandbox_mode")
        if sandbox and "write" in str(sandbox).lower() and untrusted:
            problems.append(f"sandbox mode {sandbox!r} allows writes on an untrusted trigger")

        if not problems:
            continue
        severity = "high" if untrusted else "medium"
        yield _finding(
            rule,
            workflow,
            message=f"Agent step {step.label!r}: " + "; ".join(problems) + ".",
            fix_hint=(
                "Restrict allow-users to maintainers. On untrusted events, set an explicit "
                "tool allowlist that excludes shell, file-write, and network tools, or do not "
                "run the agent at all."
            ),
            line=step.line,
            job=job,
            step=step,
            severity=severity,
        )


def _job_uses_long_lived_publish_token(job: Job) -> list[str]:
    names: list[str] = []
    for step in job.steps:
        blob = combined_text(step.env, step.with_args, step.run)
        for name in secret_names_in(blob):
            if looks_like_publish_secret(name):
                names.append(name)
        for key in step.env.keys():
            if looks_like_publish_secret(str(key)):
                names.append(str(key))
    return list(dict.fromkeys(names))


def _job_has_id_token_write(workflow: Workflow, job: Job) -> bool:
    source = job.permissions if job.permissions is not None else workflow.permissions
    if has_write_all(source):
        return True
    return "id-token" in write_scopes(source)


def _check_oidc_trusted_publishing(workflow: Workflow) -> Iterator[Finding]:
    rule = RULES_BY_ID["ACG-010"]
    for job in workflow.jobs:
        if not job_has_publish(job):
            continue
        tokens = _job_uses_long_lived_publish_token(job)
        if not tokens:
            continue
        if _job_has_id_token_write(workflow, job) and not tokens:
            continue
        yield _finding(
            rule,
            workflow,
            message=(
                f"Publish job {job.id!r} uses a long-lived registry token "
                f"({', '.join(tokens)}) instead of (or in addition to) OIDC trusted publishing."
            ),
            fix_hint=(
                "Prefer npm / PyPI / RubyGems trusted publishing with `permissions: { id-token: write }` "
                "and no long-lived NPM_TOKEN in the repository secrets. If a token is unavoidable, "
                "scope it tightly and keep it out of any agent job."
            ),
            line=job.line,
            job=job,
        )


def _check_protected_environment(workflow: Workflow) -> Iterator[Finding]:
    rule = RULES_BY_ID["ACG-011"]
    for job in workflow.jobs:
        publishes = job_has_publish(job)
        dangerous = publishes or (
            job.has_agent
            and privileged_untrusted_triggers(workflow)
            and any(
                s in CRITICAL_WRITE_SCOPES or s in {"write-all", "<default-or-inherited>"}
                for s in effective_write_scopes(workflow, job)
            )
        )
        if not dangerous:
            continue
        if environment_name(job.environment):
            # YAML cannot prove required reviewers; mention as a reminder at info? skip.
            continue
        kind = "publish/release" if publishes else "agent job with write access on an untrusted trigger"
        yield _finding(
            rule,
            workflow,
            message=(
                f"Job {job.id!r} is a {kind} but does not declare a GitHub Environment. "
                "Required reviewers cannot be enforced from the workflow file alone without one."
            ),
            fix_hint=(
                "Set `environment: release` (or similar) on the publish job and configure "
                "required reviewers / wait timer on that environment in the repository settings."
            ),
            line=job.line,
            job=job,
        )


def _check_network_egress(workflow: Workflow) -> Iterator[Finding]:
    rule = RULES_BY_ID["ACG-012"]
    untrusted = privileged_untrusted_triggers(workflow)
    if not untrusted:
        return
    for job in workflow.jobs:
        if not job.has_agent:
            continue
        if job_has_egress_control(job):
            continue
        yield _finding(
            rule,
            workflow,
            message=(
                f"Agent job {job.id!r} runs on untrusted trigger(s) ({', '.join(untrusted)}) "
                "without an obvious egress policy (for example step-security/harden-runner). "
                "A compromised agent can exfiltrate secrets or prompts over the network."
            ),
            fix_hint=(
                "Add step-security/harden-runner (or equivalent) with egress-policy: block "
                "and an allowlist of required endpoints. Disable agent network tools on "
                "untrusted events."
            ),
            line=job.line,
            job=job,
        )


def _check_audit_logging(workflow: Workflow) -> Iterator[Finding]:
    rule = RULES_BY_ID["ACG-013"]
    if not workflow.has_agent:
        return
    text = combined_text(workflow.raw)
    lowered = text.lower()
    has_audit = any(
        token in lowered
        for token in (
            "upload-artifact",
            "actions/upload-artifact",
            "agent-log",
            "audit",
            "step summary",
            "github.step_summary",
            "GITHUB_STEP_SUMMARY".lower(),
        )
    )
    if has_audit:
        return
    yield _finding(
        rule,
        workflow,
        message=(
            "Workflow runs an AI agent but does not obviously persist prompts, tool calls, "
            "or outputs as an artifact or job summary. After an incident it is hard to tell "
            "what the agent did."
        ),
        fix_hint=(
            "Write the agent's prompt, tool-call trace, and output to a log file, upload it "
            "with actions/upload-artifact, and consider echoing a redacted summary to "
            "$GITHUB_STEP_SUMMARY. Redact secrets before upload."
        ),
        line=workflow.trigger_line,
    )


def _check_human_in_the_loop(workflow: Workflow) -> Iterator[Finding]:
    rule = RULES_BY_ID["ACG-014"]
    untrusted = privileged_untrusted_triggers(workflow)
    if not untrusted or not workflow.has_agent:
        return
    # workflow_dispatch-only is fine; mixed with issues still risky
    only_manual = set(name.lower() for name in workflow.trigger_names) <= {"workflow_dispatch", "workflow_call"}
    if only_manual:
        return
    for job in workflow.jobs:
        if not job.has_agent:
            continue
        if environment_name(job.environment):
            continue
        if if_has_actor_gate(job.if_condition):
            continue
        # A label-only trigger without `opened` is a weak gate; still flag if `opened` is present
        # or if issue_comment / pull_request_target is used.
        yield _finding(
            rule,
            workflow,
            message=(
                f"Agent job {job.id!r} starts automatically on {', '.join(untrusted)} "
                "without a human gate (no environment reviewers, and no author_association / "
                "actor check). Anyone who can open an issue or comment can start the agent."
            ),
            fix_hint=(
                "Require a maintainer to label the issue, check "
                "github.event.comment.author_association == 'MEMBER' (or OWNER / COLLABORATOR), "
                "or put the job in a GitHub Environment with required reviewers. Do not run "
                "the agent on issues: opened alone."
            ),
            line=job.line or workflow.trigger_line,
            job=job,
        )


def _all_rules() -> list[Rule]:
    return [
        Rule(
            id="ACG-001",
            severity="high",
            title="Untrusted input reaches an LLM prompt",
            description=(
                "Issue, PR, or comment fields are interpolated into an agent prompt, "
                "which enables prompt injection."
            ),
            check=_check_untrusted_prompt,
        ),
        Rule(
            id="ACG-002",
            severity="high",
            title="Privileged workflow trigger accepts untrusted actors",
            description=(
                "The workflow runs on issues, issue_comment, pull_request_target, "
                "workflow_run, or similar events that outsiders can fire."
            ),
            check=_check_untrusted_triggers,
        ),
        Rule(
            id="ACG-003",
            severity="medium",
            title="Missing default permissions block",
            description="No top-level or complete job-level permissions: mapping is set.",
            check=_check_missing_permissions,
        ),
        Rule(
            id="ACG-004",
            severity="high",
            title="Overly broad write permissions",
            description=(
                "contents, id-token, packages, or actions write (or write-all) is granted "
                "more widely than needed, especially on untrusted triggers."
            ),
            check=_check_write_permissions,
        ),
        Rule(
            id="ACG-005",
            severity="high",
            title="High-value secrets exposed to an agent step",
            description="Publish or infrastructure credentials are available in an agent step.",
            check=_check_secrets_on_agent,
        ),
        Rule(
            id="ACG-006",
            severity="high",
            title="Agent work is not isolated from publishing",
            description="The same job (or an untrusted agent job with publish permissions) can release.",
            check=_check_agent_publish_same_job,
        ),
        Rule(
            id="ACG-007",
            severity="medium",
            title="GitHub Action is not pinned to a commit SHA",
            description="uses: references a tag or branch instead of a 40-character SHA.",
            check=_check_unpinned_actions,
        ),
        Rule(
            id="ACG-008",
            severity="high",
            title="Untrusted expression interpolated into a run script",
            description="${{ github.event.* }} is expanded inside run:, which enables shell injection.",
            check=_check_script_injection,
        ),
        Rule(
            id="ACG-009",
            severity="high",
            title="Agent tool or user allowlist is too broad",
            description="allow-users: '*', skipped permission checks, or shell/write tools on untrusted events.",
            check=_check_agent_allowlist,
        ),
        Rule(
            id="ACG-010",
            severity="medium",
            title="Publish job uses a long-lived registry token",
            description="Prefer OIDC trusted publishing over NPM_TOKEN-style secrets.",
            check=_check_oidc_trusted_publishing,
        ),
        Rule(
            id="ACG-011",
            severity="medium",
            title="Publish or privileged agent job lacks a protected environment",
            description="No environment: is set, so required reviewers cannot be enforced.",
            check=_check_protected_environment,
        ),
        Rule(
            id="ACG-012",
            severity="medium",
            title="Agent job has no apparent network egress control",
            description="Untrusted-trigger agent jobs should restrict outbound network access.",
            check=_check_network_egress,
        ),
        Rule(
            id="ACG-013",
            severity="low",
            title="Agent run is not clearly audited",
            description="Prompt/tool/output traces are not obviously persisted.",
            check=_check_audit_logging,
        ),
        Rule(
            id="ACG-014",
            severity="high",
            title="No human-in-the-loop gate for an untrusted agent job",
            description="The agent starts automatically without environment or actor checks.",
            check=_check_human_in_the_loop,
        ),
    ]


RULES: list[Rule] = _all_rules()
RULES_BY_ID: dict[str, Rule] = {rule.id: rule for rule in RULES}


def run_rules(workflow: Workflow) -> list[Finding]:
    findings: list[Finding] = []
    if workflow.parse_error:
        findings.append(
            Finding(
                rule_id="ACG-000",
                severity="high",
                title="Workflow YAML could not be parsed",
                message=workflow.parse_error,
                file=workflow.path,
                line=1,
                fix_hint="Fix the YAML syntax, then re-run the scan.",
            )
        )
        return findings
    for rule in RULES:
        findings.extend(rule.check(workflow))
    return findings
