# 给 issue 自动打个标签，差点碰到 Codex 的 npm 发布权限

2026 年 11 月 11 日，安全公司 Depi 公开了一篇排查笔记：[《Backdooring the next release of Codex through GitHub Action pipeline exploit chaining》](https://depi.security/blog/20261111-backdooring-codex/)。作者是 Pierre Martin（Worty）和 Garance de la Brosse（Madder）。

事情的起点并不炫技。OpenAI Codex 仓库里有一个 issue 自动打标签的 GitHub Actions，用的是 `openai/codex-action`。任何人新开一个 issue，或者给 issue 打上特定标签，这条 workflow 就会跑起来，并把 **issue 的标题和正文**直接写进 Codex Agent 的 prompt。

Depi 后来证明，一次针对这个 Agent 的提示注入，可以在沙箱里执行命令，再被串到更后面的发布链路上，最终威胁到官方 npm 包 `@openai/codex` 的发布权限。Depi 的原文用的说法是：这个包「每个月被下载数百万次」。

好消息先说清楚，免得误读：

- OpenAI 很快修复了问题；
- Depi 写明，没有恶意版本被发布出去；
- 他们通过 Bugcrowd 提交了完整报告。公开文章里写的是，初步奖金 1,000 美元，报告还在继续评估；OpenAI 的安全奖励政策里，严重问题最高可到 10 万美元。这些数字都以 Depi 原文为准，我没有另外核实或改写。

下面要讲的不是「怎么打」，而是这条链路为什么能成立，以及我们自己的仓库该怎么防。利用细节、payload、复现步骤这里都不会写。

## 一条看起来无害的 workflow

按 Depi 的公开描述，问题 workflow 大致是这样设计的：

- 触发器是 `issues`：`opened` 或被打上 `codex-label`；
- 条件里限制了仓库名是 `openai/codex`，但**没有**限制「谁开的 issue」；
- prompt 里直接插入 `${{ github.event.issue.title }}` 和 `${{ github.event.issue.body }}`；
- `openai/codex-action` 设置了 `allow-users: "*"`，等于不限制调用者；
- Agent 跑在 `workspace-write` 这类可写沙箱里。

有一个细节值得单独记一笔：这条 workflow **已经把 action 钉在了具体的 commit SHA 上**（Depi 原文里写的是 `5c3f4ccdb2b8790f73d6b21751ac00e602aa0c02`，注释为 v1.7）。钉 SHA 能防止 tag 被挪到恶意提交，但挡不住「把不受信任的文本塞进模型」。只做依赖钉选，会有一种虚假的安全感。

## 攻击链（只讲层级，不讲做法）

可以把整件事看成五级台阶。每一级单独看，都像「还好，影响有限」；串起来就不一样了。

**第一级：不受信任的输入进了 prompt。**  
Issue 标题和正文是开 issue 的人完全可控的。Workflow 把它们当成「待分类的数据」，模型却是在同一种自然语言上下文里同时看到系统说明和这段正文。提示注入要的就是这个缝。

**第二级：Agent 在 CI 里有工具，不只是在聊天。**  
打标签机器人如果被允许执行命令、写工作区，那它就不再是纯文本分类器。Depi 写到，注入成功后，他们能在 Codex 沙箱里执行命令。

**第三级：沙箱不是信任边界的终点。**  
Runner 上还有工作流进程、缓存、令牌。Depi 描述了从沙箱里逃逸、并读出 runner 进程内存中凭证的路径。对写 workflow 的人来说，结论比机制更重要：不要假设「Agent 在沙箱里」就等于「它碰不到 `GITHUB_TOKEN` 或发布相关权限」。

**第四级：低权限入口，打到高权限 workflow。**  
同一个仓库里往往还有别的 workflow，权限更宽，并且信任 GitHub Actions 的 cache。Depi 指出，拿到的令牌可以被用来污染一条权限更大的 CI（文中点名了使用 cache、且权限较宽的 `rust-ci.yml`）。cache 解开时不会当软件包那样验签，这是老问题；和 Agent 入口叠在一起，就成了跨 job 的跳板。

**第五级：发布权。**  
再往后，链路指向 GitHub 的 OIDC 身份和 npm 的受信发布，也就是官方 `@openai/codex` 包的发布路径。Codex CLI 会在开发者机器上跑、会执行代码，这一点 Depi 特别强调：对 Agent 来说，「运行」本身就是产品功能。如果再叠上自动更新，用户甚至不一定会看到那次发布。

这就是为什么「打标签」这种小自动化，不能按小功能来评估风险。真正要评估的是：不受信任的文本，最终能接触到哪一类凭证和发布动作。

## 这和普通 CI 注入有什么不同

`${{ github.event.issue.title }}` 直接写进 `run:` 脚本，是老问题了。Actions 会在 shell 启动之前做字符串替换，标题里随便带一点特殊字符，就可能变成要执行的命令。正确做法是先放进 `env:`，再在脚本里加引号读。

这次不一样的地方在于多了一个**会听指令、会调工具的模型**。就算你把 issue 正文规规矩矩传进 prompt，而不是插进 bash，模型仍可能被这段正文改写行为。于是出现了一种新的默认假设，必须被推翻：

> 「这只是数据，不是代码。」对 LLM Agent 来说，数据和指令共用一个通道。

所以防的时候要两手一起做：shell 注入按老规矩防；Agent 还要额外限制触发器、工具、密钥和发布路径。

## 一份能直接拿去评审的清单

我把实践要点收进了仓库里的 [CHECKLIST.zh-CN.md](../CHECKLIST.zh-CN.md)，这里只列最容易漏的几条：

1. **不要**让 `issues` / `issue_comment` / `pull_request_target` 自动拉起带工具的 Agent。更稳妥的是维护者手动 `workflow_dispatch`，或维护者打标签后再跑，并且检查 `author_association`。
2. 顶层必须有 `permissions:`。Agent job 不要给 `contents: write`、`id-token: write`、`packages: write`。
3. `NPM_TOKEN`、云厂商密钥、可写的 `GITHUB_TOKEN`，不要出现在 Agent 那个 job 的环境里——包括 job 级 `env`，每个 step 都会继承。
4. 打标签、做 review 的 job，和 `npm publish` / 出 Release 的 job 拆开。发布走 OIDC 受信发布，并加上带审批人的 GitHub Environment。
5. `allow-users: "*"` 不要开。不受信任的事件上，不要给 Agent shell、随便写文件、随便出网的工具。
6. Action 要钉 SHA，但这只是起步，不是结束。
7. 出站网络做白名单；prompt、工具调用和输出要留日志（记得脱敏），方便出事之后追查。
8. 发布之前保留人工确认。

## 我写了一个小扫描器

对照清单人工翻 YAML 可以，但容易看漏。我做了一个只依赖 PyYAML 的命令行工具，叫 **agent-cicd-guard**，专门扫 `.github/workflows/`：

- 识别常见 Agent action（Codex、Claude Code、Gemini CLI、Copilot 相关等）以及环境里的 LLM 密钥；
- 对上面那些风险打上规则 ID（ACG-001 到 ACG-014），尽量给出文件和行号，以及修改建议；
- 支持文本、JSON、SARIF；遇到 high 级别发现问题就返回非 0，方便挂到 CI 里。

仓库在这里（占位地址，发布前换成你的账号）：

https://github.com/<your-username>/agent-cicd-guard

本地用法：

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
agent-cicd-guard scan .
# 或只扫一个文件
agent-cicd-guard scan .github/workflows/issue-labeler.yml --format text
```

仓库的 `examples/` 里放了一个刻意写坏的 issue 打标签 workflow，以及一条更稳妥的「维护者手动触发」示例。前者用来看扫描器会报什么，**不要**抄到生产环境。

它是静态检查，不是证明。认不出的 Action、组织级默认权限、Environment 在界面里到底有没有配审批人，它都看不到。扫描结果给人做 review 用，不能当成「扫过了就安全」。

## 结尾

Depi 文末有一句话，我觉得比利用链本身更值得记住：整件事不是从某个抠了几个月的内存破坏开始的，而是从仓库里一段被工作流当作可信输入的文字开始的。

如果你的 Actions 里也有「来了 issue 或 PR，就交给 Agent 处理一下」——不一定是 Codex，Claude、Gemini、Copilot 都一样——现在就是把 workflow 翻出来对照清单的时候。先把不受信任的文本从 prompt 和 `run:` 里拿掉，先把发布密钥从 Agent job 里拿走，通常比再加一个模型防护层更管用。
