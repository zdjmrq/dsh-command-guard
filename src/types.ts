/**
 * Shared types for the command-guard package: the analyzer reports, the tier
 * verdicts, the preview outcome, and the spawner seam that keeps every
 * process-backed path injectable in tests.
 *
 * @module @deepseek-ai/dsh-command-guard/types
 */

/** One PowerShell command's AST-extracted facts. */
export interface PwshCommandReport {
  /** The raw verb token (aliases stay as written). */
  verb: string
  /** Literal string arguments (StringConstantExpressionAst values). */
  strings: string[]
  /** Expandable string arguments (`"$env:…"`) — dynamic, unexpanded text. */
  expandables: string[]
  /** Variable references (`$target`). */
  variables: string[]
  /** Parameter names (`Recurse`, `Force`, `Path`, …). */
  parameters: string[]
}

/** The complete AST pass over one PowerShell command. */
export interface PwshReport {
  /** The parse succeeded with zero parser errors. */
  ok: boolean
  /** The caller aborted before or during the analysis spawn. */
  aborted: boolean
  /** Parser error count (zero on `ok`). */
  parseErrors: number
  /** Every CommandAst found, in source order. */
  commands: PwshCommandReport[]
  /** `.NET` deletion primitives found (`Directory`, `File`, …). */
  memberCalls: string[]
}

/** The settled outcome of one preview (careful-full-access pipeline) run. */
export type PreviewOutcome =
  /** The dry run resolved a concrete scope and produced a bounded summary. */
  | { kind: 'previewed'; objectCount: number; fileCount: number; directoryCount: number; samples: string[]; truncated: boolean }
  /** The dry run proved the command deletes nothing. */
  | { kind: 'zero-targets' }
  /** The dry run resolved a target that is a protected root — refuse outright. */
  | { kind: 'protected-hit'; target: string }
  /** No reliable dry run was possible (timeout, no WhatIf support, parse failure). */
  | { kind: 'unpreviewable'; detail: string }

/** The tier a destructive command classifies into. */
export type GuardTier = 'disaster' | 'high-risk' | 'normal' | 'unparseable'

/** The classifier's verdict with its model-facing reason. */
export interface GuardVerdict {
  tier: GuardTier
  reason: string
}

/** One spawned helper process's settled output. */
export interface SpawnResult {
  stdout: string
  stderr: string
  exitCode: number | null
  timedOut: boolean
  /** Set when the spawn itself failed (executable missing, EPERM, …). */
  spawnError?: string
}

/** Options for one helper spawn. */
export interface SpawnOptions {
  /** Extra environment entries layered over the process environment. */
  env?: Record<string, string>
  /** Kill deadline for the whole helper run. */
  timeoutMs: number
  /** Per-stream character cap; overlong streams are cut with a marker. */
  maxChars?: number
}

/** The injectable spawner seam every process-backed guard path goes through. */
export type Spawner = (argv: string[], options: SpawnOptions) => Promise<SpawnResult>
