/**
 * The guard engine: one judge pass per shell tool call. It runs the cheap
 * lexical scan first (the fast allow/deny gate for the overwhelming majority
 * of commands), spawns the AST analyzer only for destructive signals, maps the
 * tier verdict onto the per-mode decision, and in `careful-full-access` routes
 * every non-disaster deletion through the preview pipeline and the model-check
 * two-step confirmation.
 *
 * @module @deepseek-ai/dsh-command-guard/engine
 */

import type { SandboxMode } from '@deepseek-ai/dsh-sandbox'
import type { PwshAnalyzer } from './analyzer.ts'
import { PendingConfirmations, fingerprintCommand } from './fingerprint.ts'
import { hasDestructiveSignal, lexBash, lexPwsh } from './lexer.ts'
import type { ProtectedRoots } from './protected.ts'
import { PreviewRunner, previewDenyReason } from './preview.ts'
import { classifyBash, classifyPwsh, type TierContext } from './tiers.ts'

/** The engine's settled decision for one call. */
export type EngineDecision =
  | { kind: 'allow' }
  | { kind: 'deny'; reason: string }
  | { kind: 'ask'; reason: string }

/** Engine construction facts resolved once per plugin apply. */
export interface EngineOptions {
  analyzer: PwshAnalyzer
  preview: PreviewRunner
  protectedRoots: ProtectedRoots
  /** How long an unconfirmed preview stays confirmable. */
  confirmTtlMs: number
}

/** One judgment request: the shell call facts the engine needs. */
export interface JudgeInput {
  dialect: 'pwsh' | 'bash'
  command: string
  /** The per-call resolved sandbox mode; undefined when no policy is mounted. */
  mode: SandboxMode | undefined
  /** The per-call workspace root; undefined when no policy is mounted. */
  workspaceRoot: string | undefined
  /** The tool-call abort signal, observed around every spawn. */
  signal?: AbortSignal
  /** Scopes the pending-confirmation memory to one session. */
  sessionKey: string
}

/**
 * The stateless-per-call orchestrator. Instance state is only the pending
 * confirmation memory, keyed per session by the caller.
 */
export class GuardEngine {
  private readonly pending: PendingConfirmations

  constructor(private readonly options: EngineOptions) {
    this.pending = new PendingConfirmations(options.confirmTtlMs)
  }

  /**
   * Judge one shell call.
   * @param input - the call facts.
   * @returns the mode-aware decision.
   */
  async judge(input: JudgeInput): Promise<EngineDecision> {
    const context: TierContext = {
      ...input.workspaceRoot === undefined ? {} : { workspaceRoot: input.workspaceRoot },
      protectedRoots: this.options.protectedRoots,
    }
    if (input.dialect === 'bash') return this.judgeBash(input, context)
    return this.judgePwsh(input, context)
  }

  private async judgePwsh(input: JudgeInput, context: TierContext): Promise<EngineDecision> {
    const facts = lexPwsh(input.command)
    if (!hasDestructiveSignal(facts)) return { kind: 'allow' }
    // The lex-only fast path proves disaster without a spawn.
    const fastVerdict = classifyPwsh(input.command, undefined, facts, context)
    if (fastVerdict.tier === 'disaster') return { kind: 'deny', reason: fastVerdict.reason }
    const report = await this.options.analyzer.analyze(input.command, input.signal)
    const verdict = classifyPwsh(input.command, report, facts, context)
    return await this.route(input, verdict, 'pwsh')
  }

  private async judgeBash(input: JudgeInput, context: TierContext): Promise<EngineDecision> {
    const facts = lexBash(input.command)
    if (!hasDestructiveSignal(facts)) return { kind: 'allow' }
    const verdict = classifyBash(facts, context)
    return await this.route(input, verdict, 'bash')
  }

  private async route(input: JudgeInput, verdict: ReturnType<typeof classifyPwsh>, dialect: 'pwsh' | 'bash'): Promise<EngineDecision> {
    if (verdict.tier === 'disaster') return { kind: 'deny', reason: verdict.reason }
    if (input.mode === 'careful-full-access' && dialect === 'pwsh') {
      return await this.carefulRoute(input, verdict)
    }
    if (verdict.tier === 'normal') return { kind: 'allow' }
    return { kind: 'ask', reason: verdict.reason }
  }

  /** The careful-full-access route: preview + model-check two-step confirmation. */
  private async carefulRoute(input: JudgeInput, verdict: ReturnType<typeof classifyPwsh>): Promise<EngineDecision> {
    void verdict
    // The confirmation leg: an identical resubmission consumes its pending
    // preview and executes WITHOUT re-previewing.
    const fingerprint = this.pendingKey(input.sessionKey, fingerprintCommand(input.command))
    if (this.pending.consume(fingerprint)) return { kind: 'allow' }
    const outcome = await this.options.preview.preview(input.command, input.signal)
    switch (outcome.kind) {
      case 'protected-hit':
        return { kind: 'deny', reason: `command guard: the preview resolved the protected root "${outcome.target}" — recursive deletion there is refused in every mode` }
      case 'zero-targets':
        return { kind: 'allow' }
      case 'unpreviewable':
        return { kind: 'deny', reason: `command guard: this deletion cannot be dry-run safely (${outcome.detail}); rewrite it as an explicit Remove-Item with literal paths` }
      case 'previewed':
        this.pending.add(fingerprint)
        return { kind: 'deny', reason: previewDenyReason(outcome) }
      /* v8 ignore next 3 -- PreviewOutcome is a typed same-process closed union; this branch is only the static exhaustiveness guard. */
      default: {
        const never: never = outcome
        throw new Error(`unreachable preview outcome: ${String(never)}`)
      }
    }
  }

  /** Session-scoped pending key: the same command in another session previews again. */
  private pendingKey(sessionKey: string, fingerprint: string): string {
    return sessionKey + '\n' + fingerprint
  }
}
