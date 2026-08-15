/**
 * The command-guard plugin: a host-plane `tools/pre-execute` listener that
 * judges every `pwsh`/`bash` call before dispatch. Disaster-tier deletions are
 * denied in every sandbox mode; high-risk ones ask through the ordinary
 * approval pipeline (fail-closed under `never`); and in `careful-full-access`
 * every non-disaster deletion runs the WhatIf preview plus the model-check
 * two-step confirmation. Every non-allow judgment is audited as a
 * `command-guard/decision` session event, and a system-prompt section teaches
 * the deletion discipline the model cooperates with.
 *
 * @module @deepseek-ai/dsh-command-guard
 */

import { Context } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'
import type { CallId } from '@deepseek-ai/dsh-llm'
import type { Session } from '@deepseek-ai/dsh-session'
import type {} from '@deepseek-ai/dsh-system-prompt'
import type { SandboxPolicyService } from '@deepseek-ai/dsh-sandbox-policy'
import type { PreToolDecision } from '@deepseek-ai/dsh-tools'
import { GuardEngine } from './engine.ts'
import { PwshAnalyzer, nodeSpawner } from './analyzer.ts'
import { PreviewRunner } from './preview.ts'
import { buildProtectedRoots } from './protected.ts'

declare module '@deepseek-ai/dsh-session/types' {
  interface SessionEventMap {
    /**
     * One command-guard judgment for a shell tool call — log-only audit. Only
     * non-allow judgments are appended (an allow leaves no trail by design:
     * the call ran normally). `tier` names the classifier tier, `reason` the
     * model-facing denial or ask text, `mode` the per-call sandbox mode.
     */
    'command-guard/decision': {
      toolName: string
      decision: 'allow' | 'deny' | 'ask'
      tier?: string
      reason?: string
      mode?: string
      callId?: CallId
    }
  }
}

/** The model-facing deletion-discipline section. */
const PROMPT = 'Deletion discipline (enforced by the command guard): prefer a -WhatIf dry run or an explicit listing before deleting; never recurse into drive roots, the user profile, or system directories; treat undefined $env: variables as errors, not empty strings; in careful-full-access mode a deletion first returns a preview of its resolved scope — verify it matches your intent, then re-send the identical command to confirm execution.'

/** Cordis plugin name used by loader diagnostics. */
export const name = 'command-guard'

/** The tool registry whose pre-execute waterfall this plugin listens on. */
export const inject = ['tools']

/** Plugin config. All optional — the schema supplies every default. */
export interface Config {
  /** Extra protected roots beyond the platform-derived ones (absolute paths). */
  extraProtectedPaths?: string[]
  /** How long an unconfirmed preview stays confirmable. */
  confirmTtlMs?: number
  /** Kill deadline for the AST analysis spawn. */
  analyzeTimeoutMs?: number
  /** Kill deadline for each preview/enumeration spawn. */
  previewTimeoutMs?: number
  /** Sample-path cap in preview summaries. */
  previewSampleLimit?: number
  /** The PowerShell helper executable. */
  pwshPath?: string
  /** Register the deletion-discipline prompt section. */
  enablePrompt?: boolean
}

/** Default kill deadline for the AST analysis spawn. */
export const DEFAULT_ANALYZE_TIMEOUT_MS = 15_000
/** Default kill deadline for each preview/enumeration spawn. */
export const DEFAULT_PREVIEW_TIMEOUT_MS = 15_000
/** Default sample-path cap in preview summaries. */
export const DEFAULT_PREVIEW_SAMPLE_LIMIT = 10
/** Default confirmation window for an unconfirmed preview. */
export const DEFAULT_CONFIRM_TTL_MS = 120_000

export const Config: z<Config> = z.object({
  extraProtectedPaths: z.array(z.string()).default([]),
  confirmTtlMs: z.number().default(DEFAULT_CONFIRM_TTL_MS),
  analyzeTimeoutMs: z.number().default(DEFAULT_ANALYZE_TIMEOUT_MS),
  previewTimeoutMs: z.number().default(DEFAULT_PREVIEW_TIMEOUT_MS),
  previewSampleLimit: z.number().default(DEFAULT_PREVIEW_SAMPLE_LIMIT),
  pwshPath: z.string().default('pwsh'),
  enablePrompt: z.boolean().default(true),
})

/** Extract the command string from parsed shell-tool arguments. */
function extractCommand(arguments_: unknown): string | undefined {
  /* v8 ignore next -- the tool registry validates arguments as an object; this guard only covers hostile typed-boundary input */
  if (typeof arguments_ !== 'object' || arguments_ === null) return undefined
  const command = (arguments_ as Record<string, unknown>)['command']
  return typeof command === 'string' && command.trim().length > 0 ? command : undefined
}

/**
 * Register the pre-execute listener, the audit append, and the prompt section.
 * @param ctx - the host context the row mounts under.
 * @param config - the validated plugin config.
 */
export function apply(ctx: Context, config: Config): void {
  const protectedRoots = buildProtectedRoots(config.extraProtectedPaths ?? [], process.env)
  const analyzer = new PwshAnalyzer(nodeSpawner, {
    timeoutMs: config.analyzeTimeoutMs ?? DEFAULT_ANALYZE_TIMEOUT_MS,
    pwshPath: config.pwshPath ?? 'pwsh',
  })
  const preview = new PreviewRunner(
    nodeSpawner,
    {
      timeoutMs: config.previewTimeoutMs ?? DEFAULT_PREVIEW_TIMEOUT_MS,
      sampleLimit: config.previewSampleLimit ?? DEFAULT_PREVIEW_SAMPLE_LIMIT,
      pwshPath: config.pwshPath ?? 'pwsh',
    },
    protectedRoots,
  )
  const engine = new GuardEngine({ analyzer, preview, protectedRoots, confirmTtlMs: config.confirmTtlMs ?? DEFAULT_CONFIRM_TTL_MS })
  const sandboxPolicy = ctx.get('sandboxPolicy') as SandboxPolicyService | undefined

  ctx.on('tools/pre-execute', async (exec, next): Promise<PreToolDecision> => {
    if (exec.name !== 'pwsh' && exec.name !== 'bash') return next()
    const command = extractCommand(exec.arguments)
    if (command === undefined) return next()
    const session: Session | undefined = exec.agent?.session
    const policy = sandboxPolicy === undefined || session === undefined
      ? undefined
      : sandboxPolicy.resolve({ session })
    const decision = await engine.judge({
      dialect: exec.name === 'pwsh' ? 'pwsh' : 'bash',
      command,
      mode: policy?.mode,
      workspaceRoot: policy?.workspaceRoot,
      signal: exec.signal,
      sessionKey: session === undefined ? '' : String(session.id),
    })
    if (session !== undefined && decision.kind !== 'allow') {
      try {
        session.append('command-guard/decision', {
          toolName: exec.name,
          decision: decision.kind,
          ...policy?.mode !== undefined ? { mode: policy.mode } : {},
          /* v8 ignore next -- audit appends only for non-allow decisions, so the false side is unreachable */
          ...decision.kind === 'deny' || decision.kind === 'ask' ? { reason: decision.reason } : {},
          /* v8 ignore next -- the registry always stamps callId on executions */
          ...exec.callId !== undefined ? { callId: exec.callId } : {},
        })
      } catch (error) {
        // The decision already stands and the pipeline enforces it; a failed
        // audit append only loses the trail, so it must not flip the outcome.
        ctx.logger.warn(`command-guard: audit append failed: ${error instanceof Error ? error.message : String(error)}`)
      }
    }
    switch (decision.kind) {
      case 'allow': return next()
      case 'deny': return { kind: 'deny', reason: decision.reason }
      case 'ask': return { kind: 'ask', reason: decision.reason }
    }
  })

  if (config.enablePrompt) {
    ctx.inject(['systemPrompt'], (scope) => {
      scope.systemPrompt.context({
        name: 'command-guard:deletion-discipline',
        order: 112,
        text: () => PROMPT,
      })
    })
  }
}

export { GuardEngine } from './engine.ts'
export type { EngineDecision, EngineOptions, JudgeInput } from './engine.ts'
export { PendingConfirmations, fingerprintCommand } from './fingerprint.ts'
export { PwshAnalyzer, encodeCommand, nodeSpawner, parsePwshReport } from './analyzer.ts'
export { PreviewRunner, parseEnumeration, parseWhatIfLines, previewDenyReason, renderPreviewSummary } from './preview.ts'
export { classifyBash, classifyPwsh } from './tiers.ts'
export type { GuardTier, TierContext } from './tiers.ts'
export type { GuardVerdict } from './types.ts'
export { hasDestructiveSignal, lexBash, lexPwsh } from './lexer.ts'
export type { LexFacts } from './lexer.ts'
export {
  buildProtectedRoots,
  isBareDriveForm,
  isDriveRootPath,
  isDriveRootWildcard,
  isExtendedRoot,
  isInside,
  isPosixRoot,
  isProtectedTarget,
  isUncRoot,
  normalizeTarget,
} from './protected.ts'
export type { ProtectedRoots } from './protected.ts'
export { bashVerbFamily, isPwshDynamicVerb, pwshVerbFamily } from './verbs.ts'
export type { VerbFamily } from './verbs.ts'
export type { PreviewOutcome, PwshCommandReport, PwshReport, SpawnOptions, SpawnResult, Spawner } from './types.ts'
