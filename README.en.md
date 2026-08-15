# dsh-command-guard

> A DeepSeek Harness (DSH) plugin: a command guard that judges every
> `pwsh`/`bash` call before dispatch. It has two layers: the plugin itself
> blocks disaster-tier deletions in EVERY sandbox mode (works as soon as it is
> mounted), and the optional harness-side patch in `patches/` registers the
> `careful-full-access` cautious-deletion mode. One goal: stop a misparsed
> delete command from wiping a whole drive or workspace.

[中文](README.md) | English

## Two layers

| Layer | What it provides | Required? |
| --- | --- | --- |
| 1: the command guard (this plugin) | Disaster-tier deletions refused in every sandbox mode, high-risk escalated to approval, audit + prompt | No core changes needed |
| 2: careful-full-access (harness-side patch) | A fourth sandbox mode: full-access experience + delete preview/confirmation + root-object protection | Optional; `git apply` the core patch |

`SandboxMode` is a core DSH enum that third-party plugins cannot extend, so layer
2 ships as a patch kept in lockstep with the plugin. Users who only want the
disaster blocking can use layer 1 alone.

## Layer 1: the command guard (works in every mode)

### What it solves

Accidental deletion is the top unguarded failure mode for coding agents: a
misparsed `Remove-Item -Recurse -Force C:\` runs verbatim under
`danger-full-access`, and even under `workspace-write` a single recursive
delete can empty the whole workspace. This plugin adds a command-semantics
guard in front of tool dispatch — active in every mode, including full access.

### Features

- **Four-tier classification** for every `pwsh`/`bash` call, before dispatch:
  - **Disaster → denied in EVERY mode** (including `danger-full-access`): drive
    roots, root wildcards (`X:\*`), UNC/`\\?\` roots, the user profile, system
    directories, the workspace root, `Format-*`/`Clear-Disk`/`Initialize-Disk`/
    `Remove-Partition`, `diskpart clean`, `robocopy /MIR` into protected roots,
    recursive `.NET` deletion of a protected root.
  - **High-risk → approval** (auto-denied when the approval policy is `never`):
    recursive forced deletes outside the workspace, dynamic targets
    (`$var`/`$env:`/`iex`), recycle-bin clearing, batch deletes.
  - **Normal → allow**: single explicit-path non-recursive deletes, etc.
  - **Unparseable → fail-closed approval**: AST/lexer failures and dynamic
    execution; `iex` never slips through the gate.
- **Audit and prompt**: every non-allow decision appends a log-only
  `command-guard/decision` session event; a deletion-discipline system-prompt
  section is registered.
- **Config**: `extraProtectedPaths` (extra protected roots),
  `analyzeTimeoutMs` (helper-process timeout), `pwshPath`, `enablePrompt`.

### Implementation

1. **Zero-cost lexical pre-scan**: in-process pure-JS scanning (dangerous
   verb/alias tables, cmd-style switches, .NET deletion calls, dynamic
   markers). Most commands carry no destructive signal and pass through
   immediately — normal use pays nothing.
2. **PowerShell AST analysis**: only suspicious commands spawn a helper `pwsh`
   process (`Parser::ParseInput` via `-EncodedCommand`; the command travels in
   an environment variable, leaving no quoting-injection surface) to extract
   verbs, literal paths, variables, and parameters — **the parser, not the
   model, tells us what the command is**.
3. **Tiers + fail-closed**: protected roots are layered (system / user /
   workspace / configurable), and parse failures are never silently allowed.

## Layer 2: the careful-full-access mode (optional core patch)

### What it solves

Users who want the full-access experience still face risky deletions:
`danger-full-access` does not even guard ordinary mistakes. Layer 2 registers a
**fourth sandbox mode, `careful-full-access`**: file permissions equal full
access, but every delete command first shows a preview and executes only after
confirmation.

### Features (after applying the patch)

- **Fourth-mode registration**: the `SandboxMode` enum, a third permission
  preset (default `ask`), and the UI option with its shield-and-eye glyph.
- **WhatIf preview + two-step model-check**: every non-disaster delete first
  resolves its real scope (dry run + subtree enumeration); the first
  submission is denied with a bounded preview summary, and an identical
  resubmission — a session-scoped, TTL'd, one-shot command fingerprint —
  executes; deletes that cannot be previewed are refused outright.
- **Windows root-object protection (defense in depth)**: the workspace grant is
  split into two ACEs — full Modify on descendants, no DELETE/FILE_DELETE_CHILD
  on the root object itself; legacy grant shapes are migrated in place.
- **Related config**: `confirmTtlMs` (confirmation window TTL),
  `previewTimeoutMs`, `previewSampleLimit` (summary sampling cap).

### Implementation

1. **WhatIf dry run resolves the real scope**: `$WhatIfPreference = $true`
   makes the PowerShell engine expand wildcards, variables, and `$env:`
   references itself; the `What if:` output lines are the true target list,
   and recursive directory targets get one extra read-only subtree
   enumeration (the dry run prints only top-level directories).
2. **Two-step confirm protocol**: normalized command fingerprints
   (session-scoped, TTL'd, consumed once) — first submission returns
   deny + preview summary; resending the same fingerprint confirms execution;
   any modified command is re-previewed by construction.
3. **Dual-ACE root protection**: the command guard is the primary line of
   defense; the ACL split keeps the workspace root itself undeletable even if
   the guard is bypassed or the model errs.

## Install (layer 1)

```sh
pnpm add dsh-command-guard
```

Mount in the host composition (e.g. `packages/bundle/base/cordis.patch.yml`):

```yaml
- id: command-guard
  name: 'dsh-command-guard'
```

After a restart every `pwsh`/`bash` call is guarded. The disaster tier works in
every sandbox mode with no further configuration.

## Enabling layer 2 (careful-full-access)

`careful-full-access` is a **sandbox mode value** and needs harness-side
registration (`SandboxMode` enum, permission-preset table, UI option). Apply
`patches/careful-full-access.patch` to a DSH source tree
(`git apply patches/careful-full-access.patch`) and rebuild; the patch contains
the corresponding changes this plugin's author submitted upstream, kept in
lockstep with the plugin version.

> Source-development mode: place this repo at `packages/guard/command-guard/`
> inside a DSH source tree and apply the patch to get monorepo type references
> and the full test suite; the npm install path needs only the mount row, no
> tsconfig changes.

## Testing and verification

- 157 unit + pipeline integration tests, 100% line/branch/function coverage
  (`pnpm test` inside the harness tree; the standalone repo's tests depend on
  published DSH packages).
- Zero-risk smoke: `Remove-Item -Recurse -Force Z:\` (nonexistent drive) →
  refused by the guard, never executed.
- Runner e2e: under a restricted token, child delete/rename work, the workspace
  root cannot be deleted/renamed, and legacy grant shapes migrate in place.

## Known limitations

- `iex`/script-block dynamic construction cannot be analyzed statically →
  fail-closed (approval in normal modes, refusal in careful mode).
- bash has no WhatIf equivalent: on POSIX the careful mode degrades to the
  tier rules.
- Junction-following recursive deletes
  ([PowerShell#26913](https://github.com/PowerShell/PowerShell/issues/26913))
  fall under the wildcard/recursive rules as high-risk; their specific shape is
  not statically recognizable.
- manual/auto confirmation policies, a persistent rule table ("always allow
  this pattern"), and a soft-delete recovery layer are future items.

## License

[MIT](LICENSE)
