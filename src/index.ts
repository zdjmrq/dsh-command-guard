/**
 * The command-guard plugin: a host-plane `tools/pre-execute` listener that is
 * ACTIVE ONLY in `careful-full-access`. Every other sandbox mode passes
 * through untouched — workspace-write is already confined by the sandbox
 * itself and danger-full-access is the user's explicit opt-out. Inside
 * careful mode every flagged command runs the model-check three-question
 * review (intent, safety, scope), disaster-tier or model-declared-dangerous
 * commands additionally require human confirmation (red-marked in the
 * approval panel, fail-closed under the `never` policy), and every non-allow
 * decision is audited twice: the complete trail goes to the rotated file log
 * `$DSH_HOME/logs/command-guard.log`, while the session log keeps only a
 * bounded, deduplicated window of decision events.
 *
 * @module @deepseek-ai/dsh-command-guard
 */

import { Context } from '@deepseek-ai/cordis'
import { join } from 'node:path'
import z from '@deepseek-ai/schemastery'
import type { Agent } from '@deepseek-ai/dsh-agent'
import { resolveDshHome } from '@deepseek-ai/dsh-home-paths'
import type { CallId } from '@deepseek-ai/dsh-llm'
import type { Session } from '@deepseek-ai/dsh-session'
import type {} from '@deepseek-ai/dsh-system-prompt'
import type { SandboxPolicyService } from '@deepseek-ai/dsh-sandbox-policy'
import type { PreToolDecision } from '@deepseek-ai/dsh-tools'
import { AuditLogger, SessionAuditGate } from './audit.ts'
import { GuardEngine } from './engine.ts'
import { DedupeWindow, fingerprintCommand } from './fingerprint.ts'
import { PwshAnalyzer, nodeSpawner } from './analyzer.ts'
import { ModelCheckRunner, type ModelCheckRoute, type ModelCompleter } from './model-check.ts'
import { PreviewRunner } from './preview.ts'
import { buildProtectedRoots } from './protected.ts'

declare module '@deepseek-ai/dsh-session/types' {
  interface SessionEventMap {
    /**
     * One command-guard judgment for a shell tool call in careful-full-access
     * mode — the session-log side of the audit. Only non-allow judgments are
     * appended, capped per session and deduplicated by command fingerprint;
     * the complete trail lives in the rotated file log. `tier` names the
     * classifier tier, `reason` the model-facing denial or ask text, `mode`
     * the per-call sandbox mode, `modelCheck` the review outcome.
     */
    'command-guard/decision': {
      toolName: string
      decision: 'allow' | 'deny' | 'ask'
      tier?: string
      reason?: string
      mode?: string
      callId?: CallId
      modelCheck?: 'not-intended' | 'safe' | 'dangerous' | 'unavailable'
    }
  }
}

/** The model-facing deletion-discipline section. */
const PROMPT = 'Deletion discipline (enforced by the command guard, active only in careful-full-access mode): prefer a -WhatIf dry run or an explicit listing before deleting; never recurse into drive roots, the user profile, or system directories; treat undefined $env: variables as errors, not empty strings. In careful-full-access mode every flagged deletion is reviewed by a model-check (intent, safety, and scope questions) before it runs; disaster-tier targets additionally require human confirmation.'

/** Cordis plugin name used by loader diagnostics. */
export const name = 'command-guard'

/** The tool registry whose pre-execute waterfall this plugin listens on. */
export const inject = ['tools']

/** Plugin config. All optional — the schema supplies every default. */
export interface Config {
  /** Extra protected roots beyond the platform-derived ones (absolute paths). */
  extraProtectedPaths?: string[]
  /** How long identical commands merge into one audited entry. */
  dedupeTtlMs?: number
  /** Kill deadline for the AST analysis spawn. */
  analyzeTimeoutMs?: number
  /** Kill deadline for each preview/enumeration spawn. */
  previewTimeoutMs?: number
  /** Sample-path cap in preview summaries. */
  previewSampleLimit?: number
  /** Kill deadline for the whole model-check call. */
  modelCheckTimeoutMs?: number
  /** Output budget for the model-check call. */
  modelCheckMaxTokens?: number
  /** Explicit audit file path; defaults to `$DSH_HOME/logs/command-guard.log`. */
  auditLogPath?: string
  /** Rotate the audit file once it reaches this many bytes. */
  auditLogMaxBytes?: number
  /** How many rotated audit copies (`.1` … `.N`) are kept. */
  auditLogRotations?: number
  /** How many decision events one session log keeps. */
  sessionDecisionCap?: number
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
/** Default dedupe window for identical commands. */
export const DEFAULT_DEDUPE_TTL_MS = 600_000
/** Default kill deadline for the model-check call. */
export const DEFAULT_MODEL_CHECK_TIMEOUT_MS = 20_000
/** Default output budget for the model-check call. */
export const DEFAULT_MODEL_CHECK_MAX_TOKENS = 300
/** Default audit rotation size (5 MB). */
export const DEFAULT_AUDIT_LOG_MAX_BYTES = 5 * 1024 * 1024
/** Default rotated audit copies. */
export const DEFAULT_AUDIT_LOG_ROTATIONS = 3
/** Default per-session decision-event cap. */
export const DEFAULT_SESSION_DECISION_CAP = 20

export const Config: z<Config> = z.object({
  extraProtectedPaths: z.array(z.string()).default([]),
  dedupeTtlMs: z.number().default(DEFAULT_DEDUPE_TTL_MS),
  analyzeTimeoutMs: z.number().default(DEFAULT_ANALYZE_TIMEOUT_MS),
  previewTimeoutMs: z.number().default(DEFAULT_PREVIEW_TIMEOUT_MS),
  previewSampleLimit: z.number().default(DEFAULT_PREVIEW_SAMPLE_LIMIT),
  modelCheckTimeoutMs: z.number().default(DEFAULT_MODEL_CHECK_TIMEOUT_MS),
  modelCheckMaxTokens: z.number().default(DEFAULT_MODEL_CHECK_MAX_TOKENS),
  auditLogPath: z.string().default(''),
  auditLogMaxBytes: z.number().default(DEFAULT_AUDIT_LOG_MAX_BYTES),
  auditLogRotations: z.number().default(DEFAULT_AUDIT_LOG_ROTATIONS),
  sessionDecisionCap: z.number().default(DEFAULT_SESSION_DECISION_CAP),
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

/** Resolve the session's current provider/model route for the model-check call. */
function resolveRoute(agent: Agent | undefined): ModelCheckRoute | undefined {
  /* v8 ignore next -- agentless executions return at the policy gate before any route resolution */
  if (agent === undefined) return undefined
  const header = agent.session.requestHeader?.()
  const provider = header?.config.provider ?? agent.options?.provider
  const model = header?.config.model ?? agent.options?.model
  if (provider === undefined || model === undefined) return undefined
  return { provider, model }
}

/**
 * Register the pre-execute listener, the audit sinks, and the prompt section.
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
  const modelCheck = new ModelCheckRunner({
    completer: ctx.get('llm') as ModelCompleter | undefined,
    timeoutMs: config.modelCheckTimeoutMs ?? DEFAULT_MODEL_CHECK_TIMEOUT_MS,
    maxTokens: config.modelCheckMaxTokens ?? DEFAULT_MODEL_CHECK_MAX_TOKENS,
  })
  const engine = new GuardEngine({ analyzer, preview, protectedRoots, modelCheck })
  const sandboxPolicy = ctx.get('sandboxPolicy') as SandboxPolicyService | undefined
  /* v8 ignore next -- the audit onError fires only on filesystem failures no test can force; the chain still routes real errors to it */
  const auditWarn = (error: unknown): void => {
    ctx.logger.warn(`command-guard: audit file write failed: ${error instanceof Error ? error.message : String(error)}`)
  }
  const auditLogger = new AuditLogger({
    path: config.auditLogPath === '' || config.auditLogPath === undefined
      ? join(resolveDshHome(), 'logs', 'command-guard.log')
      : config.auditLogPath,
    maxBytes: config.auditLogMaxBytes ?? DEFAULT_AUDIT_LOG_MAX_BYTES,
    rotations: config.auditLogRotations ?? DEFAULT_AUDIT_LOG_ROTATIONS,
    onError: auditWarn,
  })
  const gate = new SessionAuditGate({
    maxEvents: config.sessionDecisionCap ?? DEFAULT_SESSION_DECISION_CAP,
    dedupe: new DedupeWindow(config.dedupeTtlMs ?? DEFAULT_DEDUPE_TTL_MS),
  })

  ctx.on('tools/pre-execute', async (exec, next): Promise<PreToolDecision> => {
    if (exec.name !== 'pwsh' && exec.name !== 'bash') return next()
    const command = extractCommand(exec.arguments)
    if (command === undefined) return next()
    const session: Session | undefined = exec.agent?.session
    const policy = sandboxPolicy === undefined || session === undefined
      ? undefined
      : sandboxPolicy.resolve({ session })
    // The guard is careful-full-access ONLY: every other mode passes through
    // without any guard work or audit trail.
    if (policy?.mode !== 'careful-full-access') return next()
    const decision = await engine.judge({
      dialect: exec.name === 'pwsh' ? 'pwsh' : 'bash',
      command,
      mode: policy.mode,
      workspaceRoot: policy.workspaceRoot,
      signal: exec.signal,
      /* v8 ignore next -- the careful-mode gate above guarantees a session is present here */
      sessionKey: session === undefined ? '' : String(session.id),
      route: resolveRoute(exec.agent),
    })
    /* v8 ignore next -- the careful-mode gate above guarantees a session is present here */
    const sessionKey = session === undefined ? '' : String(session.id)
    const fingerprint = fingerprintCommand(command)
    const gated = gate.shouldAppend(sessionKey, fingerprint)
    if (gated.note.repeat) {
      // Merged repeat: one compact marker line instead of a duplicate decision.
      auditLogger.write({ event: 'repeat', fingerprint, count: gated.note.count })
    } else {
      auditLogger.write({
        ts: new Date().toISOString(),
        /* v8 ignore next -- the careful-mode gate above guarantees a session is present here */
        ...session === undefined ? {} : { sessionId: sessionKey },
        toolName: exec.name,
        decision: decision.kind,
        ...decision.tier === undefined ? {} : { tier: decision.tier },
        /* v8 ignore next -- the careful-mode gate above guarantees the resolved policy carries a mode */
        ...policy.mode !== undefined ? { mode: policy.mode } : {},
        ...decision.modelCheck === undefined ? {} : { modelCheck: decision.modelCheck },
        fingerprint,
        count: gated.note.count,
      })
    }
    if (session !== undefined && gated.append) {
      try {
        session.append('command-guard/decision', {
          toolName: exec.name,
          decision: decision.kind,
          ...decision.tier === undefined ? {} : { tier: decision.tier },
          /* v8 ignore next -- the careful-mode gate above guarantees the resolved policy carries a mode */
          ...policy.mode !== undefined ? { mode: policy.mode } : {},
          ...decision.kind === 'deny' || decision.kind === 'ask' ? { reason: decision.reason } : {},
          ...decision.modelCheck === undefined ? {} : { modelCheck: decision.modelCheck },
          /* v8 ignore next -- the registry always stamps callId on executions */
          ...exec.callId !== undefined ? { callId: exec.callId } : {},
        })
      } catch (error) {
        // The decision already stands and the pipeline enforces it; a failed
        // audit append only loses the session-side trail, so it must not flip
        // the outcome.
        ctx.logger.warn(`command-guard: session audit append failed: ${error instanceof Error ? error.message : String(error)}`)
      }
    }
    switch (decision.kind) {
      case 'allow': return next()
      case 'deny': return { kind: 'deny', reason: decision.reason }
      case 'ask': return { kind: 'ask', reason: decision.reason, ...decision.severity === undefined ? {} : { severity: decision.severity } }
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
export { AuditLogger, SessionAuditGate } from './audit.ts'
export type { AuditDecision, AuditLine } from './audit.ts'
export { DedupeWindow, fingerprintCommand } from './fingerprint.ts'
export type { FingerprintNote } from './fingerprint.ts'
export { analyzeGit, isGitInvocation } from './git.ts'
export type { GitFacts } from './git.ts'
export { ModelCheckRunner, parseModelAnswer } from './model-check.ts'
export type { ModelCheckInput, ModelCheckOutcome, ModelCheckRoute, ModelCompleter } from './model-check.ts'
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
