"""Heuristics for spotting AI-agent steps and high-value secrets."""

from __future__ import annotations

import re
from typing import Any, Iterable

from agent_cicd_guard.models import Step, Workflow


# Known GitHub Actions that run coding / issue-triage agents.
# Matched against the owner/repo portion of `uses:` (before @ or slash path).
KNOWN_AGENT_ACTIONS = (
    "openai/codex-action",
    "anthropics/claude-code-action",
    "anthropic/claude-code-action",
    "google-github-actions/run-gemini-cli",
    "google-github-actions/run-gemini",
    "github/copilot-swe-agent",
    "github/copilot-coding-agent-action",
    "github/copilot-action",
    "actions/ai-inference",
    "actions/github-copilot",
)

# Action name fragments that strongly suggest an agent / LLM CLI.
AGENT_ACTION_KEYWORDS = (
    "codex-action",
    "claude-code-action",
    "run-gemini-cli",
    "gemini-cli",
    "copilot-swe",
    "copilot-coding-agent",
    "ai-inference",
    "llm-action",
    "aider-action",
)

# Environment / secret names that typically unlock an LLM provider.
LLM_KEY_PATTERN = re.compile(
    r"""
    (
        OPENAI_API_KEY
        | CODEX_OPENAI_API_KEY
        | ANTHROPIC_API_KEY
        | CLAUDE_API_KEY
        | GEMINI_API_KEY
        | GOOGLE_GENAI_API_KEY
        | GOOGLE_GENERATIVE_AI_API_KEY
        | AZURE_OPENAI_API_KEY
        | MISTRAL_API_KEY
        | GROQ_API_KEY
        | XAI_API_KEY
        | TOGETHER_API_KEY
        | DEEPSEEK_API_KEY
        | COHERE_API_KEY
        | LLM_API_KEY
        | AGENT_API_KEY
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)

# High-value publish / infrastructure secrets that should never reach an agent.
SENSITIVE_SECRET_PATTERN = re.compile(
    r"""
    (
        NPM_TOKEN
        | NODE_AUTH_TOKEN
        | PYPI_TOKEN
        | PYPI_API_TOKEN
        | TWINE_PASSWORD
        | CARGO_REGISTRY_TOKEN
        | RUBYGEMS_API_KEY
        | NUGET_API_KEY
        | DOCKER_PASSWORD
        | DOCKERHUB_TOKEN
        | GHCR_TOKEN
        | AWS_SECRET_ACCESS_KEY
        | AWS_ACCESS_KEY_ID
        | AZURE_CREDENTIALS
        | GCP_SA_KEY
        | GOOGLE_APPLICATION_CREDENTIALS
        | SSH_PRIVATE_KEY
        | SSH_KEY
        | PRIVATE_KEY
        | PGP_PRIVATE_KEY
        | SIGNING_KEY
        | PACKAGIST_TOKEN
        | GITLAB_TOKEN
        | GH_TOKEN
        | GITHUB_TOKEN
        | ACTIONS_RUNTIME_TOKEN
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)

# Secrets still used for publishing, but GITHUB_TOKEN is special-cased in rules.
PUBLISH_SECRET_PATTERN = re.compile(
    r"""
    (
        NPM_TOKEN
        | NODE_AUTH_TOKEN
        | PYPI_TOKEN
        | PYPI_API_TOKEN
        | TWINE_PASSWORD
        | CARGO_REGISTRY_TOKEN
        | RUBYGEMS_API_KEY
        | NUGET_API_KEY
        | DOCKER_PASSWORD
        | DOCKERHUB_TOKEN
        | GHCR_TOKEN
        | PACKAGIST_TOKEN
        | AWS_SECRET_ACCESS_KEY
        | AWS_ACCESS_KEY_ID
        | AZURE_CREDENTIALS
        | GCP_SA_KEY
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)

SECRET_EXPR = re.compile(r"\$\{\{\s*secrets\.([A-Za-z0-9_]+)\s*\}\}", re.IGNORECASE)

PUBLISH_RUN_PATTERN = re.compile(
    r"""
    (
        npm\s+publish
        | pnpm\s+publish
        | yarn\s+npm\s+publish
        | yarn\s+publish
        | twine\s+upload
        | cargo\s+publish
        | gem\s+push
        | nuget\s+push
        | mvn\s+deploy
        | gradle\s+publish
        | docker\s+push
        | gh\s+release\s+create
        | softprops/action-gh-release
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)

PUBLISH_ACTIONS = (
    "pypa/gh-action-pypi-publish",
    "softprops/action-gh-release",
    "js-devtools/npm-publish",
    "npm/action-publish",
    "docker/build-push-action",
    "goreleaser/goreleaser-action",
    "actions/publish-action",
)

# Untrusted GitHub event fields that attackers can often set themselves.
UNTRUSTED_EXPR = re.compile(
    r"""
    \$\{\{\s*
    github
    \.
    (
        event
        \.
        (
            issue\.(title|body|label\.name)
            | comment\.body
            | review\.body
            | review_comment\.body
            | discussion\.(title|body)
            | discussion_comment\.body
            | pull_request\.(title|body|head\.ref|head\.label|head\.sha|user\.login)
            | head_commit\.(message|author\.name|author\.email)
            | commits\[.+\].message
        )
        | head_ref
        | event\.pull_request\.head\.repo\.full_name
    )
    \s*\}\}
    """,
    re.IGNORECASE | re.VERBOSE,
)

# Expressions interpolated directly into `run:` scripts.
SCRIPT_INJECTION_EXPR = re.compile(
    r"""
    \$\{\{\s*
    (
        github\.event\.(issue|comment|review|review_comment|discussion|discussion_comment|pull_request|head_commit)
        \.
        [A-Za-z0-9_.\[\]]+
        | github\.head_ref
        | github\.event\.commits\[[^\]]+\](?:\.message)?
        | github\.event\.pull_request\.head\.(ref|label|sha)
        | github\.event\.issue\.(title|body)
        | github\.event\.comment\.body
    )
    \s*\}\}
    """,
    re.IGNORECASE | re.VERBOSE,
)

# Triggers that run in the base repository context and can be fired by outsiders.
PRIVILEGED_UNTRUSTED_TRIGGERS = frozenset(
    {
        "pull_request_target",
        "issues",
        "issue_comment",
        "workflow_run",
        "discussion",
        "discussion_comment",
        "pull_request_review",
        "pull_request_review_comment",
    }
)

WRITE_PERMISSION_SCOPES = frozenset(
    {
        "contents",
        "id-token",
        "packages",
        "actions",
        "attestations",
        "deployments",
        "security-events",
        "statuses",
        "checks",
        "pull-requests",
        "issues",
        "discussions",
        "pages",
        "models",
    }
)

# Scopes that are especially dangerous if granted on an untrusted trigger.
CRITICAL_WRITE_SCOPES = frozenset(
    {"contents", "id-token", "packages", "actions", "attestations"}
)

Harden_RUNNER_ACTIONS = (
    "step-security/harden-runner",
    "step-security/secure-workflows",
)

AUTHOR_ASSOCIATION_RE = re.compile(
    r"author_association\s*==\s*['\"](OWNER|MEMBER|COLLABORATOR)['\"]",
    re.IGNORECASE,
)

ALLOW_USERS_WILDCARD = re.compile(r'^\s*["\']?\*["\']?\s*$')


def action_slug(uses: str | None) -> str:
    """Return owner/repo (or owner/repo/path) without the ref."""
    if not uses:
        return ""
    uses = uses.strip()
    if uses.startswith("./") or uses.startswith("docker://"):
        return uses
    if "@" in uses:
        uses = uses.split("@", 1)[0]
    return uses.strip()


def action_ref(uses: str | None) -> str | None:
    if not uses or "@" not in uses:
        return None
    return uses.split("@", 1)[1].strip()


def is_sha_ref(ref: str | None) -> bool:
    if not ref:
        return False
    # Allow "# comment" after the SHA, though `uses:` usually cannot hold comments
    # on the same token; callers may pass the raw suffix.
    ref = ref.split("#", 1)[0].strip()
    return bool(re.fullmatch(r"[0-9a-fA-F]{40}", ref))


def is_local_action(uses: str | None) -> bool:
    return bool(uses) and uses.startswith("./")


def is_docker_action(uses: str | None) -> bool:
    return bool(uses) and uses.startswith("docker://")


def known_agent_action(uses: str | None) -> bool:
    slug = action_slug(uses).lower()
    if not slug or is_local_action(uses) or is_docker_action(uses):
        return False
    for known in KNOWN_AGENT_ACTIONS:
        if slug == known or slug.startswith(known + "/"):
            return True
    return any(keyword in slug for keyword in AGENT_ACTION_KEYWORDS)


def iter_strings(value: Any) -> Iterable[str]:
    if value is None:
        return
    if isinstance(value, dict):
        for key, inner in value.items():
            yield str(key)
            yield from iter_strings(inner)
        return
    if isinstance(value, list):
        for inner in value:
            yield from iter_strings(inner)
        return
    yield str(value)


def combined_text(*parts: Any) -> str:
    chunks: list[str] = []
    for part in parts:
        chunks.extend(iter_strings(part))
    return "\n".join(chunks)


def _normalize_expr(expr: str) -> str:
    return re.sub(r"\s+", " ", expr).strip()


def find_untrusted_exprs(text: str | None) -> list[str]:
    if not text:
        return []
    return sorted({_normalize_expr(match.group(0)) for match in UNTRUSTED_EXPR.finditer(text)})


def find_script_injection_exprs(text: str | None) -> list[str]:
    if not text:
        return []
    return sorted({_normalize_expr(match.group(0)) for match in SCRIPT_INJECTION_EXPR.finditer(text)})


def secret_names_in(text: str | None) -> list[str]:
    if not text:
        return []
    names = [match.group(1) for match in SECRET_EXPR.finditer(text)]
    # Also catch bare KEY: ${{ secrets.X }} already covered; plus env key names.
    return names


def looks_like_llm_key(name: str) -> bool:
    return bool(LLM_KEY_PATTERN.search(name))


def looks_like_sensitive_secret(name: str) -> bool:
    return bool(SENSITIVE_SECRET_PATTERN.search(name))


def looks_like_publish_secret(name: str) -> bool:
    return bool(PUBLISH_SECRET_PATTERN.search(name))


def step_text(step: Step) -> str:
    return combined_text(step.uses, step.run, step.with_args, step.env, step.name, step.id)


def detect_agent_reasons(step: Step) -> list[str]:
    reasons: list[str] = []
    if known_agent_action(step.uses):
        reasons.append(f"known agent action {action_slug(step.uses)}")

    env_keys = [str(key) for key in step.env.keys()]
    with_keys = [str(key) for key in step.with_args.keys()]
    blob = combined_text(step.env, step.with_args, step.run)
    key_hits = []
    for name in env_keys + with_keys + secret_names_in(blob):
        if looks_like_llm_key(name) and name not in key_hits:
            key_hits.append(name)
    # Also scan env values and secret references
    for name in secret_names_in(blob):
        if looks_like_llm_key(name) and name not in key_hits:
            key_hits.append(name)
    # Match keys inside values like ${{ secrets.OPENAI_API_KEY }}
    for match in LLM_KEY_PATTERN.finditer(blob):
        hit = match.group(0)
        if hit not in key_hits:
            key_hits.append(hit)
    if key_hits:
        reasons.append("LLM API key in env/with: " + ", ".join(key_hits[:4]))

    # Keyword fallback: step name / run mentioning an agent CLI plus a prompt.
    lowered = step_text(step).lower()
    name_hit = any(
        word in lowered
        for word in (
            "codex",
            "claude-code",
            "claude code",
            "gemini cli",
            "github copilot",
            "openai api",
            "anthropic",
        )
    )
    has_prompt_input = any(
        str(key).lower() in {"prompt", "instructions", "query", "message", "input"}
        for key in with_keys
    )
    if name_hit and has_prompt_input and not reasons:
        reasons.append("step looks like an LLM prompt invocation")
    return reasons


def annotate_agent_steps(workflow: Workflow) -> None:
    for job in workflow.jobs:
        for step in job.steps:
            reasons = detect_agent_reasons(step)
            step.is_agent = bool(reasons)
            step.agent_reasons = reasons


def is_publish_step(step: Step) -> bool:
    slug = action_slug(step.uses).lower()
    if slug and any(slug == name or slug.startswith(name + "/") for name in PUBLISH_ACTIONS):
        return True
    text = combined_text(step.run, step.uses, step.name)
    return bool(PUBLISH_RUN_PATTERN.search(text))


def job_has_publish(job) -> bool:
    return any(is_publish_step(step) for step in job.steps)


def workflow_has_trigger(workflow: Workflow, names: Iterable[str]) -> list[str]:
    wanted = {name.lower() for name in names}
    return [name for name in workflow.trigger_names if name.lower() in wanted]


def privileged_untrusted_triggers(workflow: Workflow) -> list[str]:
    return workflow_has_trigger(workflow, PRIVILEGED_UNTRUSTED_TRIGGERS)


def flatten_permissions(value: Any) -> dict[str, str] | str | None:
    """Return a scope->level map, or 'read-all' / 'write-all', or None if missing."""
    if value is None:
        return None
    if isinstance(value, str):
        return value.strip().lower()
    if isinstance(value, dict):
        return {str(k).lower(): str(v).lower() for k, v in value.items()}
    return None


def write_scopes(value: Any) -> list[str]:
    flat = flatten_permissions(value)
    if flat is None:
        return []
    if isinstance(flat, str):
        if flat == "write-all":
            return ["write-all"]
        return []
    return sorted(scope for scope, level in flat.items() if level == "write")


def has_write_all(value: Any) -> bool:
    flat = flatten_permissions(value)
    return flat == "write-all"


def effective_write_scopes(workflow: Workflow, job) -> list[str]:
    """Job permissions replace (not merge with) workflow permissions when set."""
    if job.permissions is not None:
        return write_scopes(job.permissions)
    if workflow.permissions is not None:
        return write_scopes(workflow.permissions)
    # Missing permissions: treat as unknown / potentially permissive.
    return ["<default-or-inherited>"]


def has_permissions_block(workflow: Workflow) -> bool:
    if workflow.permissions is not None:
        return True
    return all(job.permissions is not None for job in workflow.jobs) and bool(workflow.jobs)


def step_has_harden_runner(step: Step) -> bool:
    slug = action_slug(step.uses).lower()
    return any(slug == name or slug.startswith(name + "/") for name in Harden_RUNNER_ACTIONS)


def job_has_egress_control(job) -> bool:
    for step in job.steps:
        if step_has_harden_runner(step):
            return True
        text = step_text(step).lower()
        if "egress-policy" in text or "block-network" in text or "allowed-endpoints" in text:
            return True
    return False


def if_has_actor_gate(if_condition: str | None) -> bool:
    if not if_condition:
        return False
    if AUTHOR_ASSOCIATION_RE.search(if_condition):
        return True
    lowered = if_condition.lower()
    return "github.actor" in lowered and (
        "contains(" in lowered or "==" in lowered
    )


def environment_name(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str) and value.strip():
        return value.strip()
    if isinstance(value, dict):
        name = value.get("name")
        if name:
            return str(name)
    return None


def with_arg(step: Step, *names: str) -> Any:
    lowered = {str(k).lower(): v for k, v in step.with_args.items()}
    for name in names:
        if name.lower() in lowered:
            return lowered[name.lower()]
    return None
