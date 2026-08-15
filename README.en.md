# dsh-command-guard

> A DeepSeek Harness (DSH) plugin: a command guard that is **active only in the
> `careful-full-access` sandbox mode** — static tiering, WhatIf scope
> resolution, a model-check review (intent / safety / scope), danger-marked
> human confirmation for disaster tiers, and a rotated file audit. One goal:
> stop a misparsed delete command from wiping a whole drive or workspace.
>
> `careful-full-access` is a core DSH sandbox enum that third-party plugins
> cannot add themselves, so this repository ships
> `patches/careful-full-access.patch` (the core source-tree patch, kept in
> lockstep with the plugin version). Applying the patch registers the mode the
> guard needs; the two together are the complete feature.

[中文](README.md) | English

## Two parts

| Part | What it provides | Relationship |
| --- | --- | --- |
| The guard plugin (this repo's src/) | Tiering, review, confirmation, and audit inside careful mode | Needs the careful mode to exist |
| The harness core patch (patches/) | The fourth `SandboxMode`, the permission preset, the UI option + glyph, the red approval-severity chain, the ACL root protection | `git apply` registers careful mode |

## What it solves

Accidental deletion is the top unguarded failure mode for coding agents: a
misparsed `Remove-Item -Recurse -Force C:\` runs verbatim under
`danger-full-access`, and even under `workspace-write` a single recursive
delete can empty the whole workspace. This plugin adds a **fourth sandbox
mode, `careful-full-access`**: file permissions equal full access (the
"full-access experience" users want), but every delete command shows a
preview, passes a model review, and only then executes. The guard engages in
THAT mode only — workspace-write is already confined by the sandbox itself and
danger-full-access is the user's explicit opt-out; neither is second-guessed.

## Features

- **Four static tiers** for every `pwsh`/`bash` call, before dispatch:
  - **normal → allow**: non-destructive commands, and `git rm --cached`/`-n`
    (index-only — no working-tree files touched).
  - **elevated → model-check**: every delete/format/mirror verb — single
    explicit deletes, `git clean`, `git reset --hard`, recycle-bin clearing,
    recursive deletes with dynamic targets, batch deletes.
  - **disaster → model-check, never auto-allowed**: drive roots, root
    wildcards (`X:\*`), UNC and `\\?\` roots, the user profile, system
    directories, the workspace root,
    `Format-*`/`Clear-Disk`/`Initialize-Disk`/`Remove-Partition`,
    `diskpart clean`, `robocopy /MIR` into a protected root, recursive `.NET`
    deletion of a protected root.
  - **unparseable → treated as disaster**: AST/lex failures and dynamic
    execution; `iex` never slips through the gate.
- **WhatIf real scope**: pwsh deletions first dry-run with
  `$WhatIfPreference = $true` — PowerShell itself expands wildcards,
  variables, and `$env:`, so the guard's parsing cannot be the thing that
  misreads them; recursive directory targets get one extra read-only subtree
  enumeration. A dry run that resolves a protected root upgrades the tier to
  disaster.
- **Model-check three questions**: one bounded call to the session's routed
  model (temperature 0, ~300-token cap, fail-closed timeout) showing the
  command text, its tier, why it was flagged, and the previewed scope, with a
  strict JSON answer to three questions — ① is this the command you meant?
  ② is it safe and in scope? ③ is it genuinely dangerous? Outcome mapping:
  "not intended" → deny outright with the model's own explanation; "intended
  and safe" → elevated runs, disaster still needs a human; "dangerous" →
  human confirmation for every tier.
- **Red human backstop**: disaster-tier (or model-declared-dangerous) commands
  route through the ordinary approval seam carrying the command text, the tier
  heading, and the model-check conclusion; `severity: 'danger'` renders the
  approval panel with a red band/border/dot. Under approval policy `never`
  they are auto-rejected (flagged commands simply cannot run in that session).
- **Audit**: every decision — allow, deny, human-confirm — is audited twice.
  The complete trail goes to the rotated file log
  `$DSH_HOME/logs/command-guard.log` (5 MB × 3 copies by default), while the
  session log keeps a bounded window of `command-guard/decision` events (20
  per session by default) with identical commands merged into one counted
  entry inside the dedupe TTL (10 minutes by default).

## Implementation

1. **Zero-cost lexical pre-scan**: in-process pure-JS scanning (dangerous
   verb/alias tables, cmd-style switches, `.NET` deletion calls, dynamic
   markers, top-level `git` subcommand dispatch). Most commands carry no
   destructive signal and pass immediately — normal use pays nothing.
2. **PowerShell AST analysis**: only suspicious commands spawn a helper `pwsh`
   process (`Parser::ParseInput` via `-EncodedCommand`; the command travels in
   an environment variable, leaving no quoting-injection surface) — the
   parser, not the model, tells us what the command is.
3. **Model-check as a side call**: one structured JSON Q&A that never enters
   the conversation history (the transcript's KV prefix stays untouched) and
   parses deterministically; every failure fails closed as disaster.
4. **Defense in depth**: the guard is the primary line; the patch also splits
   the workspace grant into two ACEs (full Modify on descendants, no
   DELETE/FILE_DELETE_CHILD on the root object), so the workspace root itself
   stays undeletable even if the guard is bypassed or the model errs.

## Install and mount

1. Apply the patch to a DSH source tree (registers the careful mode, the
   preset, the UI, and the red confirmation chain):
   `git apply patches/careful-full-access.patch`, then rebuild.
2. Install the plugin: `pnpm add dsh-command-guard` (or npm install).
3. Mount in the host composition (e.g.
   `packages/bundle/base/cordis.patch.yml` — the patch already contains this
   row; add it yourself for manual mounting):

```yaml
- id: command-guard
  name: 'dsh-command-guard'
```

Restart, switch the session permission to `careful-full-access`, and the
guard is live.

> Source-development mode: place this repo at
> `packages/guard/command-guard/` inside a DSH source tree and apply the patch
> to get monorepo type references and the full test suite; the npm install
> path needs only the mount row, no tsconfig changes.

## Config

`extraProtectedPaths` (extra protected roots), `dedupeTtlMs` (audit merge
window), `analyzeTimeoutMs`, `previewTimeoutMs`, `previewSampleLimit`,
`modelCheckTimeoutMs`, `modelCheckMaxTokens`, `auditLogPath` (defaults to
`$DSH_HOME/logs/command-guard.log`), `auditLogMaxBytes` (default 5 MB),
`auditLogRotations` (default 3), `sessionDecisionCap` (default 20),
`pwshPath`, `enablePrompt`.

## Testing and verification

- 228 unit + pipeline integration tests, 100% line/branch/function coverage
  (`pnpm test` inside the harness tree; the standalone repo's tests depend on
  published DSH packages).
- Zero-risk smoke: `Remove-Item -Recurse -Force Z:\` (nonexistent drive) →
  disaster-tier review under careful mode, never executed.
- Runner e2e: under a restricted token, child delete/rename work, the
  workspace root cannot be deleted/renamed, and legacy grant shapes migrate
  in place.

## Known limitations

- `iex`/script-block dynamic construction cannot be analyzed statically →
  fail-closed (treated as disaster: human confirmation, auto-reject under
  `never`).
- bash has no WhatIf equivalent: on POSIX the review runs without a resolved
  scope summary.
- Only a TOP-LEVEL `git` invocation gets subcommand dispatch; a piped or
  nested `git` falls back to the generic scan, which may misread its
  subcommand semantics.
- The model-check costs one model call per flagged command (latency and
  tokens), and its judgment inherits the reviewing model's quality — exactly
  why disaster tiers and model-declared-dangerous commands always end at a
  human.
- manual/auto confirmation policies, a persistent rule table ("always allow
  this"), and a soft-delete recovery layer are future items.

## License

[MIT](LICENSE)
