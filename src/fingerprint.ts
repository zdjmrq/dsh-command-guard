/**
 * The model-check two-step protocol's memory: command fingerprints that were
 * previewed but not yet confirmed. A matching resubmission consumes the entry
 * (one-shot) and executes; a changed command gets a new fingerprint and a new
 * preview. Unconsumed entries expire after the configured TTL so a preview
 * never stays confirmable forever.
 *
 * @module @deepseek-ai/dsh-command-guard/fingerprint
 */

/**
 * Normalize a command into its confirmation fingerprint: trimmed, with every
 * whitespace run collapsed, so cosmetic re-formatting still confirms while any
 * real change re-previews.
 * @param command - the raw command text.
 * @returns the normalized fingerprint string.
 */
export function fingerprintCommand(command: string): string {
  return command.trim().replace(/\s+/g, ' ')
}

/**
 * Scoped pending-confirmation memory: fingerprint → expiry. Entries are pruned
 * lazily on every read and write, and consumed exactly once.
 */
export class PendingConfirmations {
  private readonly entries = new Map<string, number>()

  /** @param ttlMs - how long an unconfirmed preview stays confirmable. */
  constructor(private readonly ttlMs: number) {}

  /**
   * Whether a fingerprint was previewed and its confirmation window is open.
   * @param fingerprint - the normalized command fingerprint.
   */
  has(fingerprint: string): boolean {
    this.prune()
    const expiresAt = this.entries.get(fingerprint)
    return expiresAt !== undefined && expiresAt > Date.now()
  }

  /**
   * Record one previewed fingerprint.
   * @param fingerprint - the normalized command fingerprint.
   */
  add(fingerprint: string): void {
    this.prune()
    this.entries.set(fingerprint, Date.now() + this.ttlMs)
  }

  /**
   * Consume one confirmation: returns true exactly once per recorded entry.
   * @param fingerprint - the normalized command fingerprint.
   */
  consume(fingerprint: string): boolean {
    this.prune()
    const expiresAt = this.entries.get(fingerprint)
    if (expiresAt === undefined || expiresAt <= Date.now()) return false
    this.entries.delete(fingerprint)
    return true
  }

  /** Drop every expired entry. */
  private prune(): void {
    const now = Date.now()
    for (const [fingerprint, expiresAt] of this.entries) {
      if (expiresAt <= now) this.entries.delete(fingerprint)
    }
  }
}
