# dsh-command-guard

> DeepSeek Harness（DSH）插件：命令守卫——**只在 `careful-full-access` 模式下生效**，
> 在派发前判定每一条 `pwsh`/`bash` 调用：静态分级 + WhatIf 范围解析 + model-check 三问复核 +
> 灾难级红色人工确认 + 轮转文件审计。目标：把"解析错误的删除命令误删整个盘/工作区"
> 这一类事故挡在执行之前。
>
> `careful-full-access` 是 DSH 核心的沙箱枚举，第三方插件无法自行添加，因此本仓库附带
> `patches/careful-full-access.patch`（对 DSH 源码树的核心补丁，与插件代码版本配套）——
> 应用补丁后守卫才有可触发的模式，两者共同构成完整功能。

[English](README.en.md) | 中文

## 两个部分

| 部分 | 内容 | 关系 |
| --- | --- | --- |
| 守卫插件（本仓库 src/） | careful 模式下的分级、复核、确认与审计 | 需要 careful 模式存在才有行为 |
| harness 核心补丁（patches/） | `SandboxMode` 第四档、权限预设、UI 档位与图标、审批红色标注链路、ACL 根防删 | `git apply` 后注册 careful 模式 |

## 解决什么问题

AI 编码代理最大的无防护风险之一是**误删**：一条解析错误的
`Remove-Item -Recurse -Force C:\` 在 `danger-full-access`（沙箱关、审批关）下会原样执行；
即使在默认的 `workspace-write` 模式下，整个工作区（含根目录）也可被一条递归删除命令清空。
本插件给 DSH 增加**第四档沙箱模式 `careful-full-access`**：文件权限等同全权限（用户要的
"全权限体验"），但每一条删除命令先"预演给你看、模型复核、确认了才真删"。守卫只在
该模式下介入——`workspace-write` 由沙箱自身约束，`danger-full-access` 是用户明确的放手选择，
两者都不被二次猜疑。

## 功能

- **静态四档分级**（对每条 `pwsh`/`bash` 调用，派发前执行）：
  - **normal → 放行**：非破坏性命令，以及 `git rm --cached`/`-n`（只操作索引，不删工作区文件）。
  - **elevated → model-check**：所有删除/格式化/镜像动词——单个显式删除、`git clean`、
    `git reset --hard`、清空回收站、动态目标的递归删除、批量删除。
  - **disaster → model-check 且永不自动放行**：盘符根、根通配（`X:\*`）、UNC/`\\?\` 根、
    用户主目录、系统目录、工作区根、`Format-*`/`Clear-Disk`/`Initialize-Disk`/`Remove-Partition`、
    `diskpart clean`、向受保护根 `robocopy /MIR`、受保护根的递归 `.NET` 删除。
  - **unparseable → 按 disaster 对待**：AST/词法失败与动态执行；`iex` 绝不漏过闸门。
- **WhatIf 真实范围**：pwsh 删除命令先以 `$WhatIfPreference = $true` 干跑——通配、变量、
  `$env:` 由 PowerShell 自己展开，守卫的解析不可能成为误读的那一环；递归目录目标再补一次
  只读子树枚举。干跑解析到受保护根时升级为 disaster 档。
- **model-check 三问**：一次对会话当前路由模型的有界调用（温度 0、约 300 token 上限、超时
  fail-closed），展示命令全文、档位、标记原因与预演范围，要求严格 JSON 回答三个问题——
  ①这是不是本意要执行的命令？②是且安全？③是但确实危险？结果映射：模型否认 → 直接拒绝
  （附模型自己的解释）；"本意且安全" → elevated 放行、disaster 仍人工；"危险" → 一律人工。
- **红色人工兜底**：灾难级（或模型自称危险）的命令走常规审批通道，携带命令全文、档位标注
  与模型复核结论，`severity: 'danger'` 在审批面板以红色条带/边框突出；审批策略 `never`
  时自动拒绝（该会话中被标记的命令不可执行）。
- **审计**：每个判定（放行/拒绝/确认）双重审计——完整流水写入轮转文件日志
  `$DSH_HOME/logs/command-guard.log`（默认 5 MB × 3 份），会话日志只留有界窗口
  `command-guard/decision`（默认每会话 20 条），相同命令在 TTL（默认 10 分钟）内合并计数。

## 实现思路

1. **零成本词法预筛**：进程内纯 JS 扫描（危险动词/别名表、cmd 风格开关、.NET 删除调用、
   动态标记、顶层 `git` 子命令分派）。大多数命令无破坏信号直接放行，正常使用不付任何开销。
2. **PowerShell AST 精析**：仅对可疑命令拉起辅助 `pwsh` 进程（`Parser::ParseInput`，经
   `-EncodedCommand` 传递脚本、命令走环境变量，无引号注入面），由解析器而不是模型告诉我们
   命令是什么。
3. **model-check 旁路调用**：结构化一次性 JSON 问答，不进入会话历史（KV 前缀不受扰动），
   答案解析确定；失败一律按 disaster 兜底。
4. **防御纵深**：命令守卫是主防线；补丁同时把工作区授权拆成两条 ACE（子孙完整 Modify、
   根对象无 DELETE/FILE_DELETE_CHILD），守卫被绕过或模型误判时工作区根本身也删不掉。

## 安装与挂载

1. 把补丁打到 DSH 源码树（注册 `careful-full-access` 模式、预设、UI 与红色确认链路）：
   `git apply patches/careful-full-access.patch` 并重建。
2. 安装插件：`pnpm add dsh-command-guard`（或 npm install）。
3. 在宿主组合（host composition，例如 `packages/bundle/base/cordis.patch.yml`）加入一行
   （补丁已包含此行，手动挂载时自行添加）：

```yaml
- id: command-guard
  name: 'dsh-command-guard'
```

重启后把会话权限切到 `careful-full-access`，守卫即生效。

> 源码开发方式：把本仓库放入 DSH 源码树的 `packages/guard/command-guard/` 再应用补丁，
> 即可享受 monorepo 的类型引用与全量测试；npm 安装方式则只需挂载行，无需 tsconfig 改动。

## 配置项

`extraProtectedPaths`（追加受保护根）、`dedupeTtlMs`（审计去重窗口）、`analyzeTimeoutMs`、
`previewTimeoutMs`、`previewSampleLimit`、`modelCheckTimeoutMs`、`modelCheckMaxTokens`、
`auditLogPath`（默认 `$DSH_HOME/logs/command-guard.log`）、`auditLogMaxBytes`（默认 5 MB）、
`auditLogRotations`（默认 3）、`sessionDecisionCap`（默认 20）、`pwshPath`、`enablePrompt`。

## 测试与验证

- 单元 + 管线集成测试 228 例、100% 行/分支/函数覆盖率（`pnpm test` 于 harness 树内运行；
  独立仓库中测试依赖 DSH 公开发布包）。
- 零风险冒烟：`Remove-Item -Recurse -Force Z:\`（不存在的盘符）→ 守卫在 careful 模式下
  走灾难级复核，未执行。
- runner e2e：受限令牌下子项删除/改名可用、工作区根不可删除/改名、旧授权形态原地迁移。

## 已知局限

- `iex`/脚本块动态构造无法静态分析 → fail-closed（按 disaster：人工确认，`never` 下拒绝）。
- bash 无 WhatIf 等价物：POSIX 上复核不带解析出的范围摘要。
- 只有**顶层** `git` 调用获得子命令分派；管道或嵌套的 `git` 退回通用扫描，可能误读其子命令语义。
- model-check 每条被标记命令消耗一次模型调用（延迟与 token），其判断质量取决于复核模型——
  这正是 disaster 档与模型自称危险的命令永远以人工收尾的原因。
- manual/auto 确认策略、持久化规则表（"始终允许此模式"）与软删除恢复层为后续项。

## License

[MIT](LICENSE)
