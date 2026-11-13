# A GitHub issue almost reached Codex's npm publish path

On 11 November 2026, Depi published [*Backdooring the next release of Codex through GitHub Action pipeline exploit chaining*](https://depi.security/blog/20261111-backdooring-codex/), by Pierre Martin (Worty) and Garance de la Brosse (Madder).

The starting point was ordinary. The OpenAI Codex repository had a GitHub Actions workflow that labeled issues with `openai/codex-action`. Anyone could open an issue — or apply a special label — and the workflow would run, feeding the **issue title and body** straight into the Codex agent's prompt.

Depi then showed that a prompt injection against that agent could be chained far enough to threaten publishing of the official npm package `@openai/codex`. Their write-up describes the package as being downloaded millions of times every month.

A few facts should stay attached to that sentence, so it is not over-read:

- OpenAI shipped a fix quickly.
- Depi reported that no malicious version was published.
- The report went through Bugcrowd. The public article says an initial bounty of $1,000 was awarded and the report was still under further review; OpenAI's policy lists rewards of up to $100,000 for critical findings. Those figures are Depi's, not independently re-counted here.

This article is about why the chain could exist, and how to harden your own workflows. It does not include exploits, payloads, or reproduction steps.

## A workflow that looked harmless

According to Depi's public description, the issue-labeler was shaped roughly like this:

- It triggered on `issues` (`opened`, or labeled `codex-label`).
- A job-level `if:` limited it to the `openai/codex` repository, but **not** to who opened the issue.
- The prompt interpolated `${{ github.event.issue.title }}` and `${{ github.event.issue.body }}`.
- `openai/codex-action` was configured with `allow-users: "*"`, so invocation was not limited to maintainers.
- The agent ran with a writable sandbox (`workspace-write`).

One detail is easy to miss: the action **was already pinned to a commit SHA**. Depi's article cites `openai/codex-action@5c3f4ccdb2b8790f73d6b21751ac00e602aa0c02` (commented as v1.7). Pinning stops a moved tag from swapping in a malicious action. It does not stop untrusted text from being handed to a model. SHA pins alone can create a false sense of safety.

## The chain, at the level of design flaws

It helps to picture five steps. Each one, on its own, looks contained. Together, they are not.

**1. Untrusted input reached the prompt.**  
The title and body of an issue are fully attacker-controlled. The workflow treated them as data to classify. The model saw them in the same natural-language context as its system instructions. That seam is what prompt injection needs.

**2. The agent in CI had tools, not just a chat box.**  
A labeling bot that is allowed to run commands or write to the workspace is no longer a text classifier. Depi reported that, once the injection landed, they could execute commands inside the Codex sandbox.

**3. The sandbox is not the end of the trust boundary.**  
A GitHub runner still holds workflow processes, caches, and tokens. Depi described escaping the sandbox and recovering credentials from runner process memory. For someone writing workflows, the mechanism matters less than the conclusion: “the agent is sandboxed” is not the same as “it cannot touch `GITHUB_TOKEN` or publishing rights.”

**4. A low-privilege entry reached a higher-privilege workflow.**  
The same repository had other workflows with broader permissions that trusted the Actions cache. Depi wrote that the recovered tokens could be used to poison a more privileged CI job (they name `rust-ci.yml`, which restored a cache and ran with wide permissions). Cache extraction is not verified like a signed package; stacked on an agent entry point, it becomes a jump between jobs.

**5. Publishing rights.**  
Further along, the path pointed at GitHub OIDC identity and npm trusted publishing — the release path for official `@openai/codex`. Depi stresses that Codex CLI runs on developer machines and is designed to execute code. For an agent, running is the product. Combined with auto-update, a bad release might not even get a human glance.

That is why a “just label the issue” automation should not be risk-assessed as a small feature. The question is which credentials and release actions untrusted text can eventually touch.

## How this differs from classic Actions injection

Putting `${{ github.event.issue.title }}` directly inside a `run:` script is an old bug class. Actions expands `${{ }}` before the shell starts, so a few special characters in a title can become commands. The fix is well known: assign the value to `env:` and read it quoted in the script.

The new part is a **model that follows instructions and can call tools**. Even if you pass the issue body into a prompt rather than into bash, the model may still treat that body as instructions. A default assumption has to be retired:

> “This is data, not code.” For an LLM agent, data and instructions share a channel.

Defense therefore has to be twofold: keep the old shell-injection hygiene, and additionally restrict the agent's triggers, tools, secrets, and path to a release.

## A checklist you can actually review against

The longer list lives in [CHECKLIST.md](../CHECKLIST.md). The items people skip most often:

1. **Do not** let `issues`, `issue_comment`, or `pull_request_target` automatically start a tool-using agent. Prefer maintainer `workflow_dispatch`, or a maintainer-applied label plus an `author_association` check.
2. Always set a top-level `permissions:` block. Agent jobs should not get `contents: write`, `id-token: write`, or `packages: write`.
3. Keep `NPM_TOKEN`, cloud keys, and a write-capable `GITHUB_TOKEN` out of the agent job — including job-level `env`, which every step inherits.
4. Split labeling or review from `npm publish` / GitHub Releases. Publish with OIDC trusted publishing, behind a GitHub Environment that requires reviewers.
5. Do not set `allow-users: "*"`. On untrusted events, do not give the agent shell, unrestricted file write, or open network tools.
6. Pin actions to SHAs. That is a starting point, not the finish.
7. Allowlist egress. Keep redacted logs of the prompt, tool calls, and output so you can investigate later.
8. Leave a human in the loop before anything is published.

## A small scanner

Reading YAML by hand works until it does not. **agent-cicd-guard** is a Python CLI with a single heavy-ish dependency, PyYAML, that scans `.github/workflows/`:

- It detects known agent actions (Codex, Claude Code, Gemini CLI, Copilot-related actions, and similar) and LLM API keys in the environment.
- It flags the risks above with rule IDs ACG-001–ACG-014, file:line locations when it can, and a fix hint.
- It prints text, JSON, or SARIF, and exits non-zero on high findings so you can hang it in CI.

The placeholder repository URL is:

https://github.com/<your-username>/agent-cicd-guard

Locally:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
agent-cicd-guard scan .
# or a single file
agent-cicd-guard scan .github/workflows/issue-labeler.yml --format text
```

The `examples/` directory has a deliberately broken issue-labeler and a safer maintainer-dispatch variant. The former is only there so you can see what the scanner reports. Do not copy it into production.

This is static analysis, not a proof. It will miss agents it does not recognize, organization-level default permissions, and whether an Environment actually has required reviewers in the GitHub UI. Findings are for a human review, not a certification.

## Closing

Depi's write-up ends on a point that is more useful than the length of the chain: this did not start as a memory-corruption bug someone fuzzed for months. It started as a string of text, in a repository, in a workflow that trusted it.

If your Actions also say “when an issue or PR arrives, let an agent handle it” — Codex, Claude, Gemini, Copilot, it does not matter — this is a good week to open the workflow and walk the checklist. Taking untrusted text out of the prompt and `run:` block, and taking publish credentials out of the agent job, usually buys more than adding another model-side guardrail.
