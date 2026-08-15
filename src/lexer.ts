/**
 * The in-process lexical pre-scan: a conservative, dependency-free first pass
 * over a PowerShell or bash command string. It never spawns anything, runs for
 * every pwsh/bash call, and answers two questions: does this command carry any
 * destructive signal at all (fast allow when not), and which crude facts are
 * visible without an AST (used by the fast disaster path and as fallback when
 * the AST analyzer is unavailable).
 *
 * False positives are acceptable here — the AST pass refines; false negatives
 * are not, so the tokenizer errs toward flagging.
 *
 * @module @deepseek-ai/dsh-command-guard/lexer
 */

import { analyzeGit, isGitInvocation, type GitFacts } from './git.ts'
import {
  CMD_FORCE_SWITCHES,
  CMD_MIRROR_SWITCHES,
  CMD_RECURSIVE_SWITCHES,
  DISKPART_CLEAN_WORD,
  NET_DELETE_CALL,
  bashVerbFamily,
  isPwshDynamicVerb,
  pwshVerbFamily,
  type VerbFamily,
} from './verbs.ts'

/** The crude facts one lexical pass extracts from a command string. */
export interface LexFacts {
  /** Canonical risk families of the verbs found (aliases resolved). */
  families: VerbFamily[]
  /** Raw verbs found, lowercase, in order. */
  verbs: string[]
  /** Literal path-like tokens (quoted strings and drive-letter tokens). */
  literalPaths: string[]
  /** A `.NET` `[IO.Directory]::Delete` style call is present. */
  netDeleteCall: boolean
  /** `diskpart` appears together with the `clean` word. */
  diskpartClean: boolean
  /** `robocopy` appears with a mirror switch. */
  robocopyMir: boolean
  /** A recursive marker is present (`-Recurse`, cmd `/s`, bash `-r`/`-R`). */
  recursive: boolean
  /** A force marker is present (`-Force`, cmd `/q`/`/f`, bash `-f`). */
  force: boolean
  /** A glob wildcard (`*` or `?`) appears in a path-like token. */
  wildcard: boolean
  /** Dynamic markers: `$` variables, `iex`, parenthesized sub-expressions, backticks. */
  dynamic: boolean
  /** A dynamic-execution verb (`iex`/`Invoke-Expression`) heads a command. */
  dynamicVerb: boolean
  /** Bash `find` appears with `-delete`. */
  findDelete: boolean
  /** Top-level `git` dispatch facts; set only when `git` heads the command. */
  git?: GitFacts
}

const EMPTY_FACTS: LexFacts = {
  families: [], verbs: [], literalPaths: [], netDeleteCall: false, diskpartClean: false,
  robocopyMir: false, recursive: false, force: false, wildcard: false, dynamic: false, dynamicVerb: false, findDelete: false,
}

/** Split a command into whitespace-separated tokens while keeping quoted spans intact. */
function tokenize(command: string): string[] {
  const tokens: string[] = []
  let current = ''
  let quote: string | undefined
  for (const char of command) {
    if (quote !== undefined) {
      current += char
      if (char === quote) quote = undefined
      continue
    }
    if (char === '"' || char === "'") {
      quote = char
      current += char
      continue
    }
    if (char === ' ' || char === '\t' || char === '\r' || char === '\n') {
      if (current.length > 0) tokens.push(current)
      current = ''
      continue
    }
    current += char
  }
  if (current.length > 0) tokens.push(current)
  return tokens
}

/** Strip one pair of matching surrounding quotes from a token. */
function unquote(token: string): string {
  if (token.length >= 2) {
    const first = token[0]
    const last = token[token.length - 1]
    if ((first === '"' || first === "'") && last === first) return token.slice(1, -1)
  }
  return token
}

/** A Windows drive-letter path form: `C:`, `C:\`, `C:\foo` (with or without quotes already removed). */
const DRIVE_FORM = /^[A-Za-z]:[\\/]?/
/** An extended-length root: `\\?\C:\` and `\\?\C:\path`. */
const EXTENDED_ROOT_FORM = /^\\\\\?\\[A-Za-z]:\\?/
/** A UNC root: `\\server\share\` (exactly two components). */
const UNC_ROOT_FORM = /^\\\\[^\\]+\\([^\\]+)\\(?:[^\\]*)$/

/** Whether a token looks like an absolute or drive-anchored path worth extracting. */
function isPathToken(token: string): boolean {
  const bare = unquote(token)
  return DRIVE_FORM.test(bare) || bare.startsWith('\\\\') || bare.startsWith('/')
}

/** Whether a token carries a glob wildcard. */
function hasWildcardChar(token: string): boolean {
  return token.includes('*') || token.includes('?')
}

/**
 * Whether the raw command contains a `.NET` deletion-primitive call.
 * @param command - the full command text.
 */
export function hasNetDeleteCall(command: string): boolean {
  return NET_DELETE_CALL.test(command)
}

/**
 * Lex one PowerShell-family command string into crude facts. Verbs are
 * canonicalized through {@link pwshVerbFamily}; switches and path tokens fill
 * the rest. The `verb` filter accepts every token that could be a command
 * position, so aliases and cmd-style binaries both surface.
 * @param command - the model-supplied command text.
 * @returns the crude facts; never throws.
 */
export function lexPwsh(command: string): LexFacts {
  const facts: LexFacts = { ...EMPTY_FACTS, families: [], verbs: [], literalPaths: [] }
  if (command.includes('$') || command.includes('${') || command.includes('`')) facts.dynamic = true
  if (NET_DELETE_CALL.test(command)) facts.netDeleteCall = true
  const tokens = tokenize(command)
  // Top-level-verb dispatch: a leading `git` routes into subcommand semantics
  // (`git rm --cached` must not read as a delete verb). Non-leading git words
  // fall through to the generic scan, which errs toward flagging.
  const firstVerbIndex = tokens.findIndex(token => !token.startsWith('-') && !token.startsWith('/'))
  const firstVerb = firstVerbIndex >= 0 ? tokens[firstVerbIndex] : undefined
  if (firstVerb !== undefined && isGitInvocation([unquote(firstVerb).toLowerCase()])) {
    facts.git = analyzeGit(tokens.slice(firstVerbIndex + 1))
    return facts
  }
  const verbs: string[] = []
  const switches = new Set<string>()
  for (const token of tokens) {
    const bare = unquote(token)
    if (bare.length === 0) continue
    const lowerBare = bare.toLowerCase()
    if (token.startsWith('-') || token.startsWith('/')) {
      if (bare.startsWith('--')) {
        // Long-form parameter names (PowerShell) still carry recurse/force info.
        if (lowerBare === '--recurse') facts.recursive = true
        if (lowerBare === '--force') facts.force = true
        continue
      }
      const lowerSwitch = token.toLowerCase()
      switches.add(lowerSwitch)
      if (CMD_RECURSIVE_SWITCHES.has(lowerSwitch)) facts.recursive = true
      if (CMD_FORCE_SWITCHES.has(lowerSwitch)) facts.force = true
      if (CMD_MIRROR_SWITCHES.has(lowerSwitch)) facts.robocopyMir = true
      if (lowerSwitch === '-recurse') facts.recursive = true
      if (lowerSwitch === '-force') facts.force = true
      continue
    }
    const family = pwshVerbFamily(bare)
    if (family !== undefined) {
      facts.families.push(family)
      verbs.push(lowerBare)
      continue
    }
    if (isPwshDynamicVerb(bare)) {
      facts.dynamicVerb = true
      verbs.push(lowerBare)
      continue
    }
    if (isPathToken(bare)) {
      facts.literalPaths.push(bare)
      if (hasWildcardChar(bare)) facts.wildcard = true
      continue
    }
    // Non-verb, non-switch, non-path tokens that still carry destructive meaning.
    verbs.push(lowerBare)
  }
  facts.verbs = verbs
  if (facts.verbs.includes('diskpart') && tokens.some(token => token.toLowerCase() === DISKPART_CLEAN_WORD)) {
    facts.diskpartClean = true
  }
  // `-delete` arrives as a bare token without a leading dash only in unusual
  // quoting; the standard form is covered by the switch branch above.
  return facts
}

/**
 * Lex one bash command string into the same crude-facts vocabulary.
 * @param command - the model-supplied command text.
 * @returns the crude facts; never throws.
 */
export function lexBash(command: string): LexFacts {
  const facts: LexFacts = { ...EMPTY_FACTS, families: [], verbs: [], literalPaths: [] }
  if (command.includes('$') || command.includes('`') || command.includes('$((')) facts.dynamic = true
  const tokens = tokenize(command)
  const firstVerbIndex = tokens.findIndex(token => !token.startsWith('-') && !token.startsWith('/'))
  const firstVerb = firstVerbIndex >= 0 ? tokens[firstVerbIndex] : undefined
  if (firstVerb !== undefined && isGitInvocation([unquote(firstVerb).toLowerCase()])) {
    facts.git = analyzeGit(tokens.slice(firstVerbIndex + 1))
    return facts
  }
  for (const token of tokens) {
    const bare = unquote(token)
    if (bare.length === 0) continue
    const family = bashVerbFamily(bare)
    if (family !== undefined) {
      facts.families.push(family)
      facts.verbs.push(bare.toLowerCase())
      continue
    }
    if (bare.startsWith('-')) {
      if (bare.includes('r') && !bare.startsWith('--')) facts.recursive = true
      if (bare.includes('f') && !bare.startsWith('--')) facts.force = true
      if (bare === '-delete') facts.findDelete = true
      if (bare === '-r' || bare === '-R' || bare === '--recursive') facts.recursive = true
      if (bare === '-f' || bare === '--force') facts.force = true
      continue
    }
    if (isPathToken(bare)) {
      facts.literalPaths.push(bare)
      if (hasWildcardChar(bare)) facts.wildcard = true
      continue
    }
    facts.verbs.push(bare.toLowerCase())
  }
  if (facts.verbs.includes('find') && facts.findDelete) {
    facts.families.push('delete')
  }
  return facts
}

/**
 * Whether the crude facts contain any destructive signal at all — the cheap
 * allow gate before any analyzer spawn. Dynamic-execution verbs count: their
 * payload is opaque, so they must never slip through the gate.
 * @param facts - the lex result.
 */
export function hasDestructiveSignal(facts: LexFacts): boolean {
  return facts.families.length > 0 || facts.netDeleteCall || facts.diskpartClean || facts.robocopyMir || facts.dynamicVerb || facts.git?.destructive === true
}

export { EXTENDED_ROOT_FORM, UNC_ROOT_FORM, DRIVE_FORM }
