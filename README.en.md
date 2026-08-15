# dsh-command-guard

> A DeepSeek Harness (DSH) plugin: a command guard that judges every `pwsh`/`bash`
> call before dispatch — disaster-tier deletions are refused in every mode,
> high-risk ones escalate to approval, and the optional `careful-full-access`
> mode adds a preview + model-check pipeline to every deletion.

[中文](README.md) | English

## What it solves

Accidental deletion is the top unguarded failure mode for coding agents: a
misparsed `Remove-Item -Recurse -Force C:\` runs verbatim under
`danger-full-access`, and even under `workspace-write` a single recursive
delete can empty the whole workspace. This plugin adds a command-semantics
guard in front of tool dispatch and, together with the harness-side patch in
`patches/`, a "full-access experience with deletion caution" mode.

## Features

- Four-tier classification for every `pwsh`/`bash` call: **disaster** (denied
  in EVERY mode — drive roots, root wildcards, UNC/`\\?\` roots, user profile,
  system dirs, workspace root, `Format-*`/`Clear-Disk`/`diskpart clean`,
  `robocopy /MIR` into protected roots, recursive `.NET` deletion),
  **high-risk** (approval ask; fail-closed under `never`), **normal** (allow),
  **unparseable** (fail-closed; `iex` never slips through).
- `careful-full-access` pipeline: WhatIf dry run + subtree enumeration resolve
  the REAL scope, then a two-step model-check — the first submission is denied
  with a bounded preview summary, and an identical resubmission (session-scoped,
  TTL'd command fingerprint) executes without re-previewing.
- Log-only `command-guard/decision` audit events and a deletion-discipline
  prompt section.

## Implementation

A zero-cost in-process lexical pre-scan gates a PowerShell AST pass
(`Parser::ParseInput` through a helper `pwsh -EncodedCommand` invocation); the
WhatIf dry run (`$WhatIfPreference = $true`) lets PowerShell itself resolve
wildcards, variables, and `$env:` expansions; the confirm protocol consumes
one-shot command fingerprints.

## Install

```sh
pnpm add dsh-command-guard
```

Mount in the host composition:

```yaml
- id: command-guard
  name: 'dsh-command-guard'
```

The disaster tier works in every sandbox mode with no further configuration.
The optional `careful-full-access` sandbox mode needs the harness-side patch:
`git apply patches/careful-full-access.patch` and rebuild.

## License

[MIT](LICENSE)
