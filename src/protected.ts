/**
 * Protected-path predicates: the registry of absolute roots whose recursive
 * deletion (or mirror-overwrite) is disaster-tier in every sandbox mode, plus
 * the containment helper the high-risk tier uses to decide "inside the
 * workspace". All comparisons are case-insensitive on Windows path forms and
 * byte-exact otherwise, decided from the path text itself so the same code
 * classifies both PowerShell and bash targets on any host.
 *
 * @module @deepseek-ai/dsh-command-guard/protected
 */

/** A PowerShell-style drive-letter root WITH its separator: `C:\`. */
const DRIVE_ROOT = /^[A-Za-z]:\\$/
/** A drive-root glob: `C:\*`, `C:\*.*`, `C:*`. */
const DRIVE_ROOT_WILDCARD = /^[A-Za-z]:\\?\*+(?:\.\*+)?$/
/** An extended-length root: `\\?\C:\` (trailing separator optional). */
const EXTENDED_ROOT = /^\\\\\?\\[A-Za-z]:\\?$/
/** A bare drive form without a separator: `C:` (relative to that drive's cwd). */
const BARE_DRIVE = /^[A-Za-z]:$/
/** A UNC share root: exactly `\\server\share` with an optional trailing separator. */
const UNC_ROOT = /^\\\\[^\\]+\\([^\\]+)\\?$/
/** The POSIX filesystem root. */
const POSIX_ROOT = '/'

/** Whether a path form uses Windows drive-letter semantics. */
function isWindowsForm(path: string): boolean {
  return /^[A-Za-z]:/.test(path) || path.startsWith('\\\\')
}

/** Lowercase a path only when it uses Windows path forms. */
function fold(path: string): string {
  return isWindowsForm(path) ? path.toLowerCase() : path
}

/** Strip trailing separators and a trailing glob star from a target path. */
export function normalizeTarget(raw: string): string {
  let target = raw.trim()
  if ((target.startsWith('"') && target.endsWith('"')) || (target.startsWith("'") && target.endsWith("'"))) {
    target = target.slice(1, -1)
  }
  target = target.replace(/[*]+$/, '')
  target = target.replace(/[\\/]+$/, '')
  return target
}

/**
 * Whether a raw target string is a drive root (`C:\` or `C:`-with-separator forms).
 * @param raw - the raw path token.
 */
export function isDriveRootPath(raw: string): boolean {
  return DRIVE_ROOT.test(raw.trim())
}

/**
 * Whether a raw target string is a drive-root glob (`C:\*`, `C:\*.*`).
 * @param raw - the raw path token.
 */
export function isDriveRootWildcard(raw: string): boolean {
  return DRIVE_ROOT_WILDCARD.test(raw.trim())
}

/**
 * Whether a raw target string is an extended-length root (`\\?\C:\`).
 * @param raw - the raw path token.
 */
export function isExtendedRoot(raw: string): boolean {
  return EXTENDED_ROOT.test(raw.trim())
}

/**
 * Whether a raw target string is a bare drive form (`C:`) whose meaning depends
 * on that drive's current directory.
 * @param raw - the raw path token.
 */
export function isBareDriveForm(raw: string): boolean {
  return BARE_DRIVE.test(raw.trim())
}

/**
 * Whether a raw target string is a UNC share root (`\\server\share\`).
 * @param raw - the raw path token.
 */
export function isUncRoot(raw: string): boolean {
  return UNC_ROOT.test(raw.trim())
}

/**
 * Whether a raw target string is the POSIX filesystem root.
 * @param raw - the raw path token.
 */
export function isPosixRoot(raw: string): boolean {
  return raw.trim() === POSIX_ROOT
}

/** The protected roots resolved for one engine lifetime (config + platform environment). */
export interface ProtectedRoots {
  /** Absolute roots whose recursive deletion is disaster-tier (already normalized). */
  readonly roots: readonly string[]
  /** The user profile root (normalized). */
  readonly home: string
  /** The system roots (SystemRoot, ProgramFiles, …) (normalized). */
  readonly system: readonly string[]
}

/**
 * Build the protected-root set from platform environment facts plus
 * user-configured extra roots. Every entry is normalized and folded.
 * @param extra - user-configured extra protected roots (absolute paths).
 * @param env - the environment facts to read roots from.
 * @returns the normalized registry.
 */
export function buildProtectedRoots(extra: readonly string[], env: NodeJS.ProcessEnv): ProtectedRoots {
  const roots = new Set<string>()
  const system: string[] = []
  for (const key of ['SystemRoot', 'ProgramFiles', 'ProgramFiles(x86)', 'ProgramW6432'] as const) {
    const value = env[key]
    if (value === undefined) continue
    const normalized = fold(normalizeTarget(value))
    roots.add(normalized)
    system.push(normalized)
  }
  const home = fold(normalizeTarget(env.USERPROFILE ?? env.HOME ?? process.cwd()))
  roots.add(home)
  for (const extraPath of extra) {
    const normalized = fold(normalizeTarget(extraPath))
    if (normalized.length > 0) roots.add(normalized)
  }
  // Drive roots are matched structurally (isDriveRootPath), not from this set.
  return { roots: [...roots], home, system }
}

/**
 * Whether a raw target equals one of the registered protected roots, or is a
 * drive/UNC/extended root, or a drive-root glob — the disaster-tier targets.
 * @param raw - the raw target token.
 * @param protectedRoots - the normalized registry.
 */
export function isProtectedTarget(raw: string, protectedRoots: ProtectedRoots): boolean {
  if (isDriveRootPath(raw) || isDriveRootWildcard(raw) || isExtendedRoot(raw) || isUncRoot(raw) || isPosixRoot(raw)) {
    return true
  }
  const normalized = fold(normalizeTarget(raw))
  return normalized.length > 0 && protectedRoots.roots.includes(normalized)
}

/**
 * Whether two target paths name the same object after normalization and
 * case folding.
 * @param left - one normalized-or-raw target.
 * @param right - the other normalized-or-raw target.
 */
export function targetEquals(left: string, right: string): boolean {
  return fold(normalizeTarget(left)) === fold(normalizeTarget(right))
}

/**
 * Whether `child` is `parent` itself or a strict descendant of it.
 * @param parent - the normalized root.
 * @param child - the normalized candidate.
 */
export function isInside(parent: string, child: string): boolean {
  const foldedParent = fold(normalizeTarget(parent))
  const foldedChild = fold(normalizeTarget(child))
  if (foldedChild === foldedParent) return true
  if (foldedParent.length === 0) return false
  const separator = foldedChild.includes('\\') && !foldedChild.includes('/') ? '\\' : '/'
  return foldedChild.startsWith(foldedParent + separator)
}
