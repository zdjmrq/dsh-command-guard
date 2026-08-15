/**
 * The git subcommand analyzer: top-level-verb dispatch for `git` invocations.
 * When the first verb of a command is `git`, the generic destructive-verb scan
 * must not see inside it — `git rm --cached` only rewrites the index and must
 * classify as normal, while `git clean -fd` and `git reset --hard` destroy
 * working-tree files and must classify as elevated.
 *
 * Pure — no processes, no state. The same rules run for both PowerShell and
 * bash dialects.
 *
 * @module dsh-careful-full-access/git
 */

/** The analysis of one `git …` invocation; `undefined` when the command is not one. */
export interface GitFacts {
  /** The git subcommand (e.g. `rm`, `clean`, `reset`); undefined when unreadable. */
  subcommand?: string
  /**
   * Whether the invocation destroys working-tree or index content:
   * `git rm` without `--cached`/`-n`, `git clean`, `git reset --hard`.
   */
  destructive: boolean
  /** Model-facing explanation of why the invocation was flagged. */
  reason?: string
}

/** Top-level verbs that select git dispatch (with or without an `.exe` suffix). */
const GIT_VERBS: ReadonlySet<string> = new Set(['git', 'git.exe'])

/** git global options that consume a following value (skipped before the subcommand). */
const GIT_VALUE_OPTIONS: ReadonlySet<string> = new Set(['-c', '-C', '--git-dir', '--work-tree', '--exec-path'])

/**
 * Whether the first verb of the token list is a git invocation.
 * @param verbs - the leading verb tokens in order (case-insensitive).
 */
export function isGitInvocation(verbs: readonly string[]): boolean {
  const head = verbs[0]
  return head !== undefined && GIT_VERBS.has(head.toLowerCase())
}

/**
 * Analyze one git invocation's subcommand semantics.
 * @param tokens - the raw command tokens AFTER the leading `git` verb.
 * @returns the git facts; never throws.
 */
export function analyzeGit(tokens: readonly string[]): GitFacts {
  // Options may precede the subcommand (`git -C repo status`); value-taking
  // global options consume their argument, and the first remaining
  // non-option token names the subcommand.
  let first: string | undefined
  let skipNext = false
  for (const token of tokens) {
    if (skipNext) { skipNext = false; continue }
    if (GIT_VALUE_OPTIONS.has(token)) { skipNext = true; continue }
    if (token.length > 0 && !token.startsWith('-')) { first = token; break }
  }
  if (first === undefined) return { destructive: false }
  const subcommand = first.toLowerCase().replace(/^['"]|['"]$/g, '')
  if (subcommand === 'rm') {
    const flags = new Set(tokens.filter(token => token.startsWith('-')).map(token => token.toLowerCase()))
    // `--cached`/`--staged` only rewrites the index; `-n`/`--dry-run` changes nothing.
    if (flags.has('--cached') || flags.has('--staged') || flags.has('-n') || flags.has('--dry-run')) {
      return { subcommand: 'rm', destructive: false }
    }
    return {
      subcommand: 'rm',
      destructive: true,
      reason: 'command guard: git rm without --cached removes working-tree files',
    }
  }
  if (subcommand === 'clean') {
    return {
      subcommand: 'clean',
      destructive: true,
      reason: 'command guard: git clean deletes untracked working-tree files',
    }
  }
  if (subcommand === 'reset') {
    const flags = new Set(tokens.filter(token => token.startsWith('-')).map(token => token.toLowerCase()))
    if (flags.has('--hard')) {
      return {
        subcommand: 'reset',
        destructive: true,
        reason: 'command guard: git reset --hard overwrites working-tree files with the repository version',
      }
    }
    return { subcommand: 'reset', destructive: false }
  }
  return { subcommand, destructive: false }
}
