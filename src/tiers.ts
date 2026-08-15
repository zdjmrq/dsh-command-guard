/**
 * The tier classifier: maps an analyzer report (plus the lexical fallback
 * facts) onto the four guard tiers. Pure — no processes, no sessions — so the
 * same rules run identically for the fast lex-only path and the full AST path.
 *
 * The tiers are mode-independent by design: which tier becomes allow,
 * model-check, or model-check plus human confirmation is the engine's
 * decision, not the classifier's.
 *
 * @module dsh-careful-full-access/tiers
 */

import type { GuardTier, GuardVerdict, PwshReport } from './types.ts'
import type { LexFacts } from './lexer.ts'
import {
  isBareDriveForm,
  isInside,
  isProtectedTarget,
  targetEquals,
  type ProtectedRoots,
} from './protected.ts'
import { pwshVerbFamily, type VerbFamily } from './verbs.ts'

/** The classifier context: per-call policy facts plus the engine's protected registry. */
export interface TierContext {
  /** The session workspace root (absolute), when the policy service supplied one. */
  workspaceRoot?: string
  /** The normalized protected-root registry. */
  protectedRoots: ProtectedRoots
}

/** Collect every candidate target path from both analysis layers, deduplicated. */
function collectTargets(report: PwshReport | undefined, facts: LexFacts): string[] {
  const seen = new Set<string>()
  const targets: string[] = []
  for (const target of [...facts.literalPaths, ...(report === undefined ? [] : report.commands.flatMap(command => command.strings))]) {
    const folded = target.toLowerCase()
    if (seen.has(folded)) continue
    seen.add(folded)
    targets.push(target)
  }
  return targets
}

/** Whether any AST command (or the lex pass) carries the recursive marker. */
function hasRecursive(report: PwshReport | undefined, facts: LexFacts): boolean {
  if (facts.recursive) return true
  if (report === undefined) return false
  return report.commands.some(command => command.parameters.some(parameter => parameter.toLowerCase() === 'recurse'))
}

/** Whether any AST command (or the lex pass) carries the force marker. */
function hasForce(report: PwshReport, facts: LexFacts): boolean {
  if (facts.force) return true
  return report.commands.some(command => command.parameters.some(parameter => parameter.toLowerCase() === 'force'))
}

/** Whether the command references dynamic, statically unresolvable targets. */
function hasDynamicTarget(report: PwshReport, facts: LexFacts): boolean {
  if (facts.dynamic) return true
  return report.commands.some(command => command.variables.length > 0 || command.expandables.length > 0)
}

/** Whether any candidate target hits the protected registry or the workspace root. */
function hitsProtected(targets: readonly string[], context: TierContext): string | undefined {
  for (const target of targets) {
    if (isProtectedTarget(target, context.protectedRoots)) return target
    // A globbed workspace path (`C:\ws\*`) names the CONTENTS, not the root;
    // only the literal root itself is disaster-tier.
    if (target.includes('*') || target.includes('?')) continue
    if (context.workspaceRoot !== undefined && targetEquals(context.workspaceRoot, target)) return target
  }
  return undefined
}

/** Whether any candidate target sits INSIDE a registered protected root (but is not the root itself). */
function hitsInsideProtected(targets: readonly string[], context: TierContext): string | undefined {
  for (const target of targets) {
    for (const root of context.protectedRoots.roots) {
      if (!targetEquals(root, target) && isInside(root, target)) return target
    }
  }
  return undefined
}

/** Whether any candidate target is a bare drive form (`C:`) or sits outside the workspace. */
function findsUnbounded(targets: readonly string[], context: TierContext): string | undefined {
  for (const target of targets) {
    if (isBareDriveForm(target)) return target
    if (context.workspaceRoot !== undefined && !isInside(context.workspaceRoot, target)) return target
  }
  return undefined
}

/** Whether a `.NET` delete call names a recursive erase (`true` second argument). */
function netDeleteRecursive(rawCommand: string): boolean {
  return /Delete\s*\([^)]*,\s*\$?true\s*\)/i.test(rawCommand)
}

/**
 * Classify one PowerShell command.
 * @param rawCommand - the full command text (for `.NET` call argument checks).
 * @param report - the AST report, or `undefined` when the analysis failed.
 * @param facts - the lexical facts (always present).
 * @param context - per-call policy facts and protected roots.
 * @returns the tier verdict with its model-facing reason.
 */
export function classifyPwsh(rawCommand: string, report: PwshReport | undefined, facts: LexFacts, context: TierContext): GuardVerdict {
  // Top-level git dispatch: subcommand semantics decide, not inner words.
  if (facts.git !== undefined) {
    if (!facts.git.destructive) return { tier: 'normal', reason: '' }
    return { tier: 'elevated', reason: facts.git.reason ?? 'command guard: a destructive git subcommand needs review' }
  }

  const families = new Set<VerbFamily>(facts.families)
  if (report !== undefined) {
    for (const command of report.commands) {
      const family = pwshVerbFamily(command.verb)
      if (family !== undefined) families.add(family)
    }
  }
  const destructive = families.size > 0 || facts.netDeleteCall || facts.diskpartClean || facts.robocopyMir || facts.dynamicVerb
  if (!destructive) return { tier: 'normal', reason: '' }

  if (facts.dynamicVerb) {
    return { tier: 'unparseable', reason: 'command guard: dynamic execution (iex/Invoke-Expression) cannot be statically analyzed' }
  }

  if (families.has('format') || facts.diskpartClean) {
    return { tier: 'disaster', reason: 'command guard: disk-level operations (format/clear/partition)' }
  }

  const targets = collectTargets(report, facts)
  const protectedHit = hitsProtected(targets, context)
  const recursive = hasRecursive(report, facts)

  if (facts.robocopyMir && protectedHit !== undefined) {
    return { tier: 'disaster', reason: `command guard: robocopy /MIR against the protected root "${protectedHit}"` }
  }
  if (facts.netDeleteCall && protectedHit !== undefined && netDeleteRecursive(rawCommand)) {
    return { tier: 'disaster', reason: `command guard: recursive .NET deletion of the protected root "${protectedHit}"` }
  }
  if (facts.netDeleteCall && protectedHit !== undefined) {
    return { tier: 'elevated', reason: `command guard: .NET deletion targeting the protected root "${protectedHit}"` }
  }
  const insideProtected = facts.netDeleteCall ? hitsInsideProtected(targets, context) : undefined
  if (insideProtected !== undefined) {
    return { tier: 'elevated', reason: `command guard: .NET deletion inside the protected root (${insideProtected})` }
  }
  if (families.has('delete') && recursive && protectedHit !== undefined) {
    return { tier: 'disaster', reason: `command guard: recursive deletion of the protected root "${protectedHit}"` }
  }

  if (families.has('recycle')) {
    return { tier: 'elevated', reason: 'command guard: emptying the recycle bin' }
  }

  // Without a readable AST report the remaining refinements cannot be trusted;
  // every non-disaster destructive command then fails closed as unparseable.
  if (report === undefined || !report.ok) {
    return { tier: 'unparseable', reason: 'command guard: the deletion command could not be parsed safely' }
  }

  const force = hasForce(report, facts)
  const dynamic = hasDynamicTarget(report, facts)
  if (families.has('delete')) {
    if (recursive && dynamic) {
      return { tier: 'elevated', reason: 'command guard: recursive deletion with dynamically resolved targets' }
    }
    if (recursive && force && (facts.wildcard || findsUnbounded(targets, context) !== undefined)) {
      return { tier: 'elevated', reason: 'command guard: recursive forced deletion outside the workspace' }
    }
    if (recursive && targets.length === 0) {
      return { tier: 'elevated', reason: 'command guard: recursive deletion with no statically visible target' }
    }
    if (targets.length > 1) {
      return { tier: 'elevated', reason: `command guard: batch deletion of ${targets.length} targets` }
    }
    return { tier: 'elevated', reason: '' }
  }

  return { tier: 'normal', reason: '' }
}

/**
 * Classify one bash command from its lexical facts (POSIX has no AST pass).
 * @param facts - the lexical facts.
 * @param context - per-call policy facts and protected roots.
 * @returns the tier verdict with its model-facing reason.
 */
export function classifyBash(facts: LexFacts, context: TierContext): GuardVerdict {
  if (facts.git !== undefined) {
    if (!facts.git.destructive) return { tier: 'normal', reason: '' }
    return { tier: 'elevated', reason: facts.git.reason ?? 'command guard: a destructive git subcommand needs review' }
  }
  const families = new Set<VerbFamily>(facts.families)
  if (families.size === 0) return { tier: 'normal', reason: '' }
  if (families.has('format')) {
    return { tier: 'disaster', reason: 'command guard: disk-level operations (mkfs/fdisk/wipefs)' }
  }
  const protectedHit = hitsProtected(facts.literalPaths, context)
  if (facts.recursive && protectedHit !== undefined) {
    return { tier: 'disaster', reason: `command guard: recursive deletion of the protected root "${protectedHit}"` }
  }
  if (facts.recursive && facts.dynamic) {
    return { tier: 'elevated', reason: 'command guard: recursive deletion with dynamically resolved targets' }
  }
  if (facts.recursive && facts.force && (facts.wildcard || findsUnbounded(facts.literalPaths, context) !== undefined)) {
    return { tier: 'elevated', reason: 'command guard: recursive forced deletion outside the workspace' }
  }
  if (facts.findDelete) {
    return { tier: 'elevated', reason: 'command guard: find -delete' }
  }
  if (families.has('delete')) {
    return { tier: 'elevated', reason: '' }
  }
  return { tier: 'normal', reason: '' }
}

export type { GuardTier }
