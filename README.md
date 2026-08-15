# dsh-command-guard

> DeepSeek Harness（DSH）插件：命令守卫——在派发前判定每一条 `pwsh`/`bash` 调用。
> 它分两个层次：插件本体做**全模式灾难删除拦截**（挂载即生效）；`patches/` 里附带的
> harness 核心补丁（可选）注册 **`careful-full-access`** 审慎删除模式。
> 两者目标一致：把"解析错误的删除命令误删整个盘/工作区"这一类事故挡在执行之前。

[English](README.en.md) | 中文

## 两个层次

| 层次 | 内容 | 是否必须 |
| --- | --- | --- |
| 第一层：命令守卫（本插件） | 灾难级删除在**任何沙箱模式**下拒绝、高风险走审批、审计与提示 | 挂载即生效，无需改核心 |
| 第二层：careful-full-access（harness 侧补丁） | 第四档沙箱模式：全权限体验 + 删除预演/二次确认 + 根对象防删 | 可选，`git apply` 核心补丁 |

`SandboxMode` 是 DSH 核心的枚举类型，第三方插件无法自行添加，因此第二层以补丁形式
随仓库发布，与插件代码版本配套。只想要灾难拦截的用户可以只用第一层。

## 第一层：命令守卫（插件本体，所有模式生效）

### 解决什么问题

AI 编码代理最大的无防护风险之一是**误删**：一条解析错误的
`Remove-Item -Recurse -Force C:\` 在 `danger-full-access`（沙箱关、审批关）下会原样执行；
即使在默认的 `workspace-write` 模式下，整个工作区（含根目录）也可被一条递归删除命令清空。
本插件在工具派发前加一道**命令语义守卫**——它在任何模式下都生效，包括全权限。

### 功能

- **四级分级判定**（对每条 `pwsh`/`bash` 调用，派发前执行）：
  - **灾难级 → 任何模式下都拒绝**（含 `danger-full-access`）：盘符根、根级通配
    （`X:\*`）、UNC/`\\?\` 扩展根、用户主目录、系统目录、工作区根、
    `Format-*`/`Clear-Disk`/`Initialize-Disk`/`Remove-Partition`、`diskpart clean`、
    向受保护根 `robocopy /MIR`、受保护根的递归 `.NET` 删除。
  - **高风险 → 审批**（审批策略为 `never` 时自动拒绝）：工作区外递归强制删除、
    动态目标（`$var`/`$env:`/`iex`）的递归删除、清空回收站、批量删除。
  - **普通 → 放行**：单个显式路径的非递归删除等。
  - **无法解析 → fail-closed 审批**：AST/词法失败与动态执行；`iex` 绝不漏过闸门。
- **审计与提示**：每次非放行判定写入 log-only 的 `command-guard/decision` 会话事件；
  注册"删除纪律"系统提示段。
- **配置项**：`extraProtectedPaths`（追加受保护根）、`analyzeTimeoutMs`（辅助进程超时）、
  `pwshPath`、`enablePrompt`。

### 实现思路

1. **零成本词法预筛**：进程内纯 JS 扫描（危险动词/别名表、cmd 风格开关、.NET 删除
   调用、动态标记）。绝大多数命令无破坏信号，直接放行，**不为正常使用付任何开销**。
2. **PowerShell AST 精析**：仅对可疑命令拉起辅助 `pwsh` 进程
   （`Parser::ParseInput`，经 `-EncodedCommand` 传递脚本、命令走环境变量，无引号
   注入面），精确提取动词、字面路径、变量、参数——**由解析器而不是模型告诉我们
   命令是什么**。
3. **分级 + fail-closed**：保护根分层（系统/用户/工作区/可配置），解析失败一律
   不静默放行。

## 第二层：careful-full-access 模式（harness 核心补丁，可选）

### 解决什么问题

用户想要"全权限体验"，但删除仍然危险：`danger-full-access` 下连普通误删都不设防。
第二层给 DSH 注册**第四档沙箱模式 `careful-full-access`**：文件权限等同全权限，
但每一条删除命令先"预演给你看、确认了才真删"。

### 功能（补丁应用后）

- **第四档模式注册**：`SandboxMode` 枚举 + 权限预设表第三档（默认 `ask`）+ UI 档位
  与盾牌眼睛图标。
- **WhatIf 预演 + 两步确认（model-check）**：每条非灾难删除先干跑 + 子树枚举得到
  真实范围，首次提交被拒绝并附有界预览摘要，模型复核后**原样重发同一命令**才执行；
  无法预演的删除直接拒绝。
- **Windows 根对象防删（防御纵深）**：工作区授权拆成两条 ACE——子孙完整 Modify、
  根对象无 DELETE/FILE_DELETE_CHILD；旧授权形态自动原地迁移。
- **相关配置项**：`confirmTtlMs`（确认窗口 TTL）、`previewTimeoutMs`、
  `previewSampleLimit`（摘要采样上限）。

### 实现思路

1. **WhatIf 干跑解析真实范围**：`$WhatIfPreference = $true` 让 PowerShell 引擎自行
   展开通配/变量/`$env:`，干跑输出的 `What if:` 行就是真实目标清单；递归目录目标
   再补一次只读子树枚举（干跑只打印顶层目录）。
2. **两步确认协议**：命令规范化指纹（会话隔离、TTL、一次性消费）——首次提交
   deny+预览摘要，同指纹重发 = 确认执行，改动过的命令必然重新预演。
3. **双 ACE 根保护**：命令守卫是主防线；ACL 拆分让"守卫被绕过/模型误判"时，
   工作区根本身也删不掉。

## 安装与挂载（第一层）

```sh
pnpm add dsh-command-guard        # 或 npm install dsh-command-guard
```

在宿主组合（host composition，例如 `packages/bundle/base/cordis.patch.yml`）加入一行：

```yaml
- id: command-guard
  name: 'dsh-command-guard'
```

重启后每条 `pwsh`/`bash` 调用即被守卫。灾难级拒绝在**任何沙箱模式**下生效，
无需其它配置。

## 启用第二层（careful-full-access）

`careful-full-access` 是**沙箱模式值**，需要 harness 侧配合注册（`SandboxMode` 枚举、
权限预设表、UI 档位）。把 `patches/careful-full-access.patch` 打到 DSH 源码树
（`git apply patches/careful-full-access.patch`）并重建即可；补丁内容即本插件作者
向上游提交的对应改动，与插件代码版本配套。

> 源码开发方式：把本仓库放入 DSH 源码树的 `packages/guard/command-guard/` 再应用补丁，
> 即可享受 monorepo 的类型引用与全量测试；npm 安装方式则只需挂载行，无需 tsconfig 改动。

## 测试与验证

- 单元 + 管线集成测试 157 例、100% 行/分支/函数覆盖率（`pnpm test` 于 harness 树内
  运行；独立仓库中测试依赖 DSH 公开发布包）。
- 零风险冒烟：`Remove-Item -Recurse -Force Z:\`（不存在的盘符）→ 守卫拒绝、未执行。
- runner e2e：受限令牌下子项删除/改名可用、工作区根不可删除/改名、旧授权形态原地迁移。

## 已知局限

- `iex`/脚本块动态构造无法静态分析 → fail-closed（普通模式审批、careful 模式拒绝）。
- bash 无 WhatIf 等价物：POSIX 上 careful 模式退化为分级规则。
- 跟随 junction 的递归删除（[PowerShell#26913](https://github.com/PowerShell/PowerShell/issues/26913)）被通配/递归规则归为高风险，静态上无法识别其具体形态。
- manual/auto 确认策略、持久化规则表（"始终允许此模式"）与软删除恢复层为后续项。

## License

[MIT](LICENSE)
