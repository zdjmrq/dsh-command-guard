/**
 * The guard engine: one judge pass per shell tool call. The guard is active
 * ONLY in `careful-full-access` — every other sandbox mode passes through
 * untouched (workspace-write is already confined by the sandbox itself, and
 * danger-full-access is the user's explicit opt-out). Inside careful mode the
 * engine runs the cheap lexical scan first (the fast allow gate for the
 * overwhelming majority of commands), spawns the AST analyzer only for
 * destructive signals, maps the tier verdict onto the review route, and
 * resolves every flagged command through the WhatIf preview (deletions) and
 * the model-check three-question review — with human confirmation as the last
 * layer for disaster-tier or model-declared-dangerous commands.
 *
 * @module dsh-careful-full-access/engine
 */

import type { SandboxMode } from '@deepseek-ai/dsh-sandbox'
import type { PwshAnalyzer } from './analyzer.ts'
import { hasDestructiveSignal, lexBash, lexPwsh, type LexFacts } from './lexer.ts'
import type { ModelCheckOutcome, ModelCheckRoute, ModelCheckRunner } from './model-check.ts'
import { PreviewRunner, renderPreviewSummary } from './preview.ts'
import type { ProtectedRoots } from './protected.ts'
import { classifyBash, classifyPwsh, type TierContext } from './tiers.ts'
import type { GuardTier, GuardVerdict } from './types.ts'

/** The engine's settled decision for one call. */
export type EngineDecision =
  | { kind: 'allow'; tier?: GuardTier; modelCheck?: ModelCheckOutcome['kind'] }
  | { kind: 'deny'; tier?: GuardTier; reason: string; modelCheck?: ModelCheckOutcome['kind'] }
  | { kind: 'ask'; tier?: GuardTier; reason: string; severity?: 'danger'; modelCheck?: ModelCheckOutcome['kind'] }

/** Engine construction facts resolved once per plugin apply. */
export interface EngineOptions {
  analyzer: PwshAnalyzer
  preview: PreviewRunner
  protectedRoots: ProtectedRoots
  modelCheck: ModelCheckRunner
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
  /** Scopes the session audit gate to one session. */
  sessionKey: string
  /** The session's model route for the model-check call. */
  route: ModelCheckRoute | undefined
}

/**
 * The stateless-per-call orchestrator. All instance state lives in the
 * injected runners (model-check, preview, analyzer), so one engine instance
 * serves every session.
 */
export class GuardEngine {
  constructor(private readonly options: EngineOptions) {}

  /**
   * Judge one shell call.
   * @param input - the call facts.
   * @returns the careful-mode decision; every other mode allows outright.
   */
  async judge(input: JudgeInput): Promise<EngineDecision> {
    if (input.mode !== 'careful-full-access') return { kind: 'allow' }
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
    // The lex-only pass already proves disaster and git subcommand semantics;
    // everything else is refined through the AST analyzer.
    const fast = classifyPwsh(input.command, undefined, facts, context)
    const verdict = fast.tier === 'disaster' || facts.git !== undefined
      ? fast
      : classifyPwsh(input.command, await this.options.analyzer.analyze(input.command, input.signal), facts, context)
    return this.route(input, verdict, 'pwsh', facts)
  }

  private async judgeBash(input: JudgeInput, context: TierContext): Promise<EngineDecision> {
    const facts = lexBash(input.command)
    if (!hasDestructiveSignal(facts)) return { kind: 'allow' }
    const verdict = classifyBash(facts, context)
    return this.route(input, verdict, 'bash', facts)
  }

  /** Every flagged command runs the review route; only `normal` allows straight through. */
  private async route(
    input: JudgeInput,
    verdict: GuardVerdict,
    dialect: 'pwsh' | 'bash',
    facts: LexFacts,
  ): Promise<EngineDecision> {
    if (verdict.tier === 'normal') return { kind: 'allow' }
    return this.review(input, verdict, dialect, facts)
  }

  /** The review route: optional WhatIf scope, then the model-check three questions. */
  private async review(
    input: JudgeInput,
    verdict: GuardVerdict,
    dialect: 'pwsh' | 'bash',
    facts: LexFacts,
  ): Promise<EngineDecision> {
    // route() only reaches the review for non-normal verdicts; the cast is the
    // one place the classifier's closed union narrows to the review tiers.
    const reviewTier = verdict.tier as Exclude<GuardTier, 'normal'>
    let effectiveTier: Exclude<GuardTier, 'normal'> = reviewTier
    let scopeSummary: string | undefined
    let previewDetail: string | undefined
    if (dialect === 'pwsh' && facts.families.includes('delete')) {
      const outcome = await this.options.preview.preview(input.command, input.signal)
      switch (outcome.kind) {
        case 'zero-targets':
          // The dry run proved the command deletes nothing — nothing to review.
          return { kind: 'allow', tier: effectiveTier }
        case 'previewed':
          scopeSummary = renderPreviewSummary(outcome.fileCount, outcome.directoryCount, outcome.samples, outcome.truncated)
          break
        case 'protected-hit':
          // The resolved scope IS a protected root: upgrade to the disaster tier
          // so the human confirmation carries the red disaster marking.
          effectiveTier = 'disaster'
          scopeSummary = `resolved to the protected root "${outcome.target}"`
          break
        case 'unpreviewable':
          previewDetail = outcome.detail
          break
        /* v8 ignore next 3 -- PreviewOutcome is a typed same-process closed union; this branch is only the static exhaustiveness guard. */
        default: {
          const never: never = outcome
          throw new Error(`unreachable preview outcome: ${String(never)}`)
        }
      }
    }
    const outcome = await this.options.modelCheck.check({
      command: input.command,
      tier: reviewTier,
      reason: verdict.reason,
      ...scopeSummary === undefined ? {} : { scopeSummary },
      route: input.route,
      ...input.signal === undefined ? {} : { signal: input.signal },
    })
    switch (outcome.kind) {
      case 'not-intended':
        // The model disowns the command — this is the misparse case the guard
        // exists for. No human confirmation: the model said no itself.
        return {
          kind: 'deny',
          tier: verdict.tier,
          modelCheck: 'not-intended',
          reason: `command guard: model-check concluded this command was not the intended one: ${outcome.explanation}`,
        }
      case 'safe':
        if (effectiveTier === 'elevated') return { kind: 'allow', tier: 'elevated', modelCheck: 'safe' }
        return {
          kind: 'ask',
          tier: effectiveTier,
          severity: 'danger',
          modelCheck: 'safe',
          reason: this.confirmReason(effectiveTier, verdict, 'the model confirms this is the intended, expected operation', previewDetail),
        }
      case 'dangerous':
        return {
          kind: 'ask',
          tier: effectiveTier,
          ...effectiveTier === 'disaster' || effectiveTier === 'unparseable' ? { severity: 'danger' as const } : {},
          modelCheck: 'dangerous',
          reason: this.confirmReason(effectiveTier, verdict, `the model itself declared it dangerous: ${outcome.explanation}`, previewDetail),
        }
      case 'unavailable':
        // Fail closed: a review that could not run is treated as disaster.
        return {
          kind: 'ask',
          tier: effectiveTier,
          severity: 'danger',
          modelCheck: 'unavailable',
          reason: this.confirmReason(effectiveTier === 'elevated' ? 'unparseable' : effectiveTier, verdict, `model-check unavailable: ${outcome.detail}`, previewDetail),
        }
      /* v8 ignore next 3 -- ModelCheckOutcome is a typed same-process closed union; this branch is only the static exhaustiveness guard. */
      default: {
        const never: never = outcome
        throw new Error(`unreachable model-check outcome: ${String(never)}`)
      }
    }
  }

  /** Assemble the human-confirmation request body: tier heading, finding, conclusion, preview note. */
  private confirmReason(
    tier: Exclude<GuardTier, 'normal'>,
    verdict: GuardVerdict,
    conclusion: string,
    previewDetail: string | undefined,
  ): string {
    let heading: string
    switch (tier) {
      case 'disaster': heading = 'DISASTER tier'; break
      case 'unparseable': heading = 'unparseable (treated as disaster)'; break
      case 'elevated': heading = 'elevated tier'; break
      /* v8 ignore next 3 -- the review tiers are a closed union; this branch is only the static exhaustiveness guard. */
      default: {
        const never: never = tier
        throw new Error(`unreachable review tier: ${String(never)}`)
      }
    }
    const base = `command guard: ${heading} — ${verdict.reason} — ${conclusion}`
    return previewDetail === undefined ? base : `${base}; the command could not be dry-run previewed (${previewDetail})`
  }
}
