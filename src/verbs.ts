/**
 * The destructive-command vocabulary the guard classifies: PowerShell and
 * cmd-style verbs with their alias maps, the format/disk family, the recycle
 * verb, and the POSIX (bash-dialect) set. Pure data plus canonicalization
 * helpers — the analyzer and tier classifier both consume it.
 *
 * @module dsh-careful-full-access/verbs
 */

/** The risk families the guard tiers route on. */
export type VerbFamily = 'delete' | 'format' | 'recycle'

/** PowerShell delete verbs and their cmd aliases, canonicalized to `delete`. */
const PWSH_DELETE_VERBS: ReadonlySet<string> = new Set([
  'remove-item', 'rm', 'del', 'erase', 'rd', 'rmdir', 'ri',
])

/** The disk/format family — always disaster-tier in every mode. */
const PWSH_FORMAT_VERBS: ReadonlySet<string> = new Set([
  'format', 'format-volume', 'clear-disk', 'initialize-disk', 'remove-partition',
])

/** The recycle verb — elevated tier. */
const PWSH_RECYCLE_VERBS: ReadonlySet<string> = new Set(['clear-recyclebin'])

/** Bash-dialect delete verbs. */
const BASH_DELETE_VERBS: ReadonlySet<string> = new Set(['rm', 'rmdir', 'unlink', 'shred'])

/** Bash-dialect format/disk verbs — always disaster-tier. */
const BASH_FORMAT_VERBS: ReadonlySet<string> = new Set(['mkfs', 'mkfs.ext4', 'mkfs.xfs', 'mkfs.btrfs', 'mkswap', 'fdisk', 'wipefs'])

/** cmd-style switches that mark a recursive delete (`rd /s`, `del /s`). */
export const CMD_RECURSIVE_SWITCHES: ReadonlySet<string> = new Set(['/s', '-s'])

/** cmd-style switches that mark a forced delete (`rd /q`, `del /q`, `del /f`). */
export const CMD_FORCE_SWITCHES: ReadonlySet<string> = new Set(['/q', '-q', '/f', '-f'])

/** The robocopy mirror switch — mirroring INTO a protected root destroys its content. */
export const CMD_MIRROR_SWITCHES: ReadonlySet<string> = new Set(['/mir', '-mir'])

/**
 * The `.NET` deletion-primitive call pattern: `[IO.Directory]::Delete(path, $true)`
 * and friends. Member expressions are not `CommandAst`s, so both the lexer and
 * the AST analyzer match this signature textually.
 */
export const NET_DELETE_CALL = /\[(?:System\.IO\.|IO\.)(Directory|File|FileInfo|DirectoryInfo)\]\s*::\s*Delete\s*\(/i

/** The PowerShell dynamic-execution verbs the static analyzer cannot see through. */
export const PWSH_DYNAMIC_VERBS: ReadonlySet<string> = new Set(['iex', 'invoke-expression'])

/** The cmd `diskpart` verb plus the `clean` subcommand word that makes it destructive. */
export const DISKPART_VERB = 'diskpart'
export const DISKPART_CLEAN_WORD = 'clean'

/** The robocopy verb whose `/MIR` against a protected root is disaster-tier. */
export const ROBOCOPY_VERB = 'robocopy'

/** Bash `find` plus the `-delete` action word. */
export const FIND_VERB = 'find'
export const FIND_DELETE_WORD = '-delete'

/** Lowercase a verb for the canonical set lookups. */
function lower(verb: string): string {
  return verb.toLowerCase()
}

/**
 * Canonicalize a PowerShell verb into its risk family.
 * @param verb - the raw command verb (aliases stay as written in the AST).
 * @returns the family, or `undefined` for a non-destructive verb.
 */
export function pwshVerbFamily(verb: string): VerbFamily | undefined {
  const canonical = lower(verb)
  if (PWSH_DELETE_VERBS.has(canonical)) return 'delete'
  if (PWSH_FORMAT_VERBS.has(canonical)) return 'format'
  if (PWSH_RECYCLE_VERBS.has(canonical)) return 'recycle'
  return undefined
}

/**
 * Whether a PowerShell verb is a dynamic-execution verb (`iex`).
 * @param verb - the raw command verb.
 */
export function isPwshDynamicVerb(verb: string): boolean {
  return PWSH_DYNAMIC_VERBS.has(lower(verb))
}

/**
 * Canonicalize a bash verb into its risk family.
 * @param verb - the raw command verb.
 * @returns the family, or `undefined` for a non-destructive verb.
 */
export function bashVerbFamily(verb: string): VerbFamily | undefined {
  const canonical = lower(verb)
  if (BASH_DELETE_VERBS.has(canonical)) return 'delete'
  if (BASH_FORMAT_VERBS.has(canonical)) return 'format'
  return undefined
}
