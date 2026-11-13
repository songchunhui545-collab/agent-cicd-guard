# 检查清单：把 AI Agent 接入 CI/CD（GitHub Actions）

在新增、评审或审计会调用编程 Agent、issue 分诊机器人，或任何带工具的 LLM 的 workflow 时使用这份清单。能做静态检查的条目，对应扫描器的规则 ID。

直接动机是 2026 年 11 月 Depi 披露的 [Codex issue 打标签链路](https://depi.security/blog/20261111-backdooring-codex/)：不受信任的 issue 文本进入了 Agent prompt，并被一路串到可能影响 npm 发布权限的程度。OpenAI 已修复；Depi 写明没有恶意包被发布。下面是加固清单，不是对那次利用的复现。

## 1. 不受信任的输入不能变成指令

**扫描规则：ACG-001、ACG-008**

- [ ] Issue 标题和正文、评论正文、PR 标题和正文、Review 文本、Discussion 文本都是**不受信任的**。通常只要能开 issue 或发评论，就能控制这些字段。
- [ ] 不要把 `${{ github.event.issue.title }}`、`${{ github.event.issue.body }}`、`${{ github.event.comment.body }}`、`${{ github.event.pull_request.title }}`、`${{ github.event.pull_request.body }}` 这类字段，直接插进 Agent 的 `prompt:` / `instructions:`，当作你能控制的数据。
- [ ] 如果 Agent 必须看到这段文字，应在工具权限收得很紧、沙箱很窄的运行里去拉取，并明确告诉模型：这是不受信任的数据，不是指令。这只是缓解，不是保证——提示注入的残余风险还在。
- [ ] 永远不要在 `run:` 脚本里直接展开这些表达式。`${{ }}` 会在 shell 启动之前就被 Actions 替换掉，标题里的 `$(…)` 或正文里多出来的反引号，都可能变成要执行的命令。
- [ ] 脚本的安全写法：先放进 `env:`，再在 shell 里加引号读取。

```yaml
# 不安全
- run: echo "${{ github.event.issue.title }}"

# 更稳妥（即使如此，也不要把这串文字交给带 shell 工具的 Agent）
- env:
    ISSUE_TITLE: ${{ github.event.issue.title }}
  run: echo "$ISSUE_TITLE"
```

## 2. 触发器：谁能启动这条 workflow？

**扫描规则：ACG-002、ACG-014**

下面这些事件跑在*本仓库*的上下文里，仓库外部的人往往也能触发：

- `issues`（尤其是 `opened`）
- `issue_comment`
- `pull_request_target`
- `pull_request_review` / `pull_request_review_comment`
- `discussion` / `discussion_comment`
- `workflow_run`（权限较低的 workflow 有时能拉起权限更高的那条）

检查：

- [ ] 除非有下面说的硬门禁，否则不要把 Agent 挂在 `issues: opened` 或 `issue_comment` 上。
- [ ] 优先用 `workflow_dispatch`（由维护者手动启动），或者「只有**维护者**打了某个标签才运行」，并在 job 的 `if:` 里检查 `author_association`。
- [ ] Agent 场景尽量避开 `pull_request_target`。非用不可时，不要检出或执行 PR 头提交里的代码，权限保持只读。
- [ ] `pull_request`（不是 `_target`）相对更安全，因为来自 fork 的 PR 通常拿不到仓库密钥；但 PR 标题和正文仍然不受信任，ACG-008 照样适用。

## 3. 权限：默认拒绝，再按需授予

**扫描规则：ACG-003、ACG-004**

- [ ] 每条 workflow 都有顶层 `permissions:`。顶层优先写 `permissions: {}` 或 `contents: read`，真正需要的权限只加在对应 job 上。
- [ ] 不要使用 `permissions: write-all`。
- [ ] Agent job 几乎不应该拥有 `contents: write`、`id-token: write`、`packages: write` 或 `actions: write`。
- [ ] 如果 Agent 只是建议标签，通常 `issues: write` 加 `contents: read` 就够了——即便是 `issues: write`，在不受信任的触发器上也值得再问一句。
- [ ] 记住：缺少 `permissions:` 时，会继承仓库或组织的默认值，这个默认值可能仍然很宽。

## 4. Agent 能看到哪些密钥

**扫描规则：ACG-005**

- [ ] Agent 步骤只拿到它需要的 LLM API 密钥（例如 `CODEX_OPENAI_API_KEY` / `ANTHROPIC_API_KEY`）。
- [ ] `NPM_TOKEN`、`NODE_AUTH_TOKEN`、`PYPI_TOKEN`、`CARGO_REGISTRY_TOKEN`、云厂商访问密钥、SSH / 签名密钥，以及可写的 `GITHUB_TOKEN` / `GH_TOKEN`，都**不要**出现在 Agent 所在的 job 里——包括 job 级和 workflow 级的 `env:`，因为每个 step 都会继承。
- [ ] 假定：一旦 Agent 被提示注入，或离开沙箱，运行环境里的东西都可能泄露。Codex 那篇文章提醒我们，沙箱边界本身就是威胁模型的一部分。

## 5. 把 Agent 任务和发布任务拆开

**扫描规则：ACG-006、ACG-010、ACG-011**

- [ ] 负责打标签、做 review 或改代码的 Agent，不要在同一个 job 里运行 `npm publish`、`twine upload`、`cargo publish`、`docker push` 或 `gh release`。
- [ ] 发布放在另一个 job（更好是另一条 workflow）里：只 `needs:` 受信任的构建产物，只在受信任的引用上跑，并且不再调用 Agent。
- [ ] 发布 npm、PyPI 等仓库时，优先使用 [OIDC 受信发布](https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect)：只在*发布* job 上授予 `permissions: { id-token: write }`，仓库里不要长期存放 `NPM_TOKEN`。
- [ ] 发布 job 设置 `environment: release`（或类似名称）。在仓库设置里，给这个环境配置**必需的审批人**，必要时再加等待时间和可部署分支名单。
- [ ] YAML 只能看出声明了环境名称；审批策略要到 GitHub 界面里确认。

## 6. 把 action 钉到 commit SHA

**扫描规则：ACG-007**

- [ ] 每个 `uses:` 都钉在 40 位 commit SHA 上，用注释标出版本：`uses: actions/checkout@<sha> # v4.3.0`。
- [ ] 会接触密钥或运行 Agent 的 action，不要用 `@v1`、`@main` 或 `@master`。
- [ ] 钉 SHA 能防止*被挪动的 tag* 悄悄换成恶意提交。它**不能**阻止针对已钉死 Agent action 的提示注入。

## 7. 工具白名单和沙箱

**扫描规则：ACG-009**

- [ ] `allow-users` 不是 `"*"`。如果 action 支持，只允许维护者调用。
- [ ] 不要打开 `dangerously-skip-permissions` 或同类绕过开关。
- [ ] 在任何不受信任的触发器上，给 Agent 设置明确的工具白名单，**不要**给它 shell、不受限制的写文件，或开放的网络工具。
- [ ] 优先使用只读沙箱。在不受信任的内容上开启 `workspace-write`（或同等模式）是危险信号。
- [ ] 如果任务只是「建议一个标签」，白名单就应该这么窄：也许只有 `github.issues.update`，别的都不要。

## 8. 出站网络

**扫描规则：ACG-012**

- [ ] 可能被不受信任文本影响的 Agent job，要有出站策略（例如用 [step-security/harden-runner](https://github.com/step-security/harden-runner)，设置 `egress-policy: block`，只放行真正需要的 API 地址）。
- [ ] 在这类运行里关闭或严格限制 Agent 自己的网络工具。
- [ ] 日志、产物和 issue 评论也是外带通道——不要让 Agent 打印密钥，并小心它被允许回帖的内容。

## 9. 日志、审计和人工确认

**扫描规则：ACG-013、ACG-014**

- [ ] 把 prompt（脱敏后）、工具调用记录和模型输出保存为构建产物，或写进脱敏后的 job summary，方便事后追查。
- [ ] 不要在没有人看一眼的情况下，仅靠 `issues: opened` 就自动启动 Agent。
- [ ] 至少具备下面之一：带审批人的受保护环境、维护者打标签、`author_association == 'OWNER' | 'MEMBER' | 'COLLABORATOR'` 检查，或 `workflow_dispatch`。
- [ ] 凡是会写入默认分支、创建 Release，或发布软件包的操作，仍然应该有人审批。

## 10. 每次改 `.github/workflows` 时要问的五个问题

1. 有哪些不受信任的字符串会到达模型或 shell？
2. 谁能触发这条 workflow，包括来自 fork 或一条新 issue？
3. 这个 job 能写什么（git、包仓库、id-token、cache、issues）？
4. 这个 job 的环境里有哪些密钥，而不只是这一个 step？
5. 就算 Agent 做错了，发布之前是不是还有一道人工关卡？

这五个问题答不清楚，就不要合并这条 workflow。

## 相关文档

- [README.zh-CN.md](README.zh-CN.md) —— 安装和命令行
- [articles/article-zh.md](articles/article-zh.md) —— Codex 事件背景
