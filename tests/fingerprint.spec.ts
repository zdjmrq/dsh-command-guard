import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { PendingConfirmations, fingerprintCommand } from '../src/fingerprint.ts'

describe('fingerprintCommand', () => {
  it('trims and collapses whitespace so cosmetic reformatting still confirms', () => {
    expect(fingerprintCommand('  Remove-Item   C:\\ws\\x \n')).toBe('Remove-Item C:\\ws\\x')
    expect(fingerprintCommand('Remove-Item C:\\ws\\x')).toBe(fingerprintCommand('  Remove-Item  C:\\ws\\x  '))
  })

  it('keeps real changes distinct', () => {
    expect(fingerprintCommand('Remove-Item a')).not.toBe(fingerprintCommand('Remove-Item b'))
  })
})

describe('PendingConfirmations', () => {
  beforeEach(() => {
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('adds, reports, and one-shot consumes a confirmation', () => {
    const pending = new PendingConfirmations(60_000)
    pending.add('fp')
    expect(pending.has('fp')).toBe(true)
    expect(pending.consume('fp')).toBe(true)
    expect(pending.consume('fp')).toBe(false)
    expect(pending.has('fp')).toBe(false)
  })

  it('returns false for unknown fingerprints', () => {
    const pending = new PendingConfirmations(60_000)
    expect(pending.consume('nope')).toBe(false)
    expect(pending.has('nope')).toBe(false)
  })

  it('expires entries after the TTL', () => {
    const pending = new PendingConfirmations(1000)
    pending.add('fp')
    vi.advanceTimersByTime(1001)
    expect(pending.has('fp')).toBe(false)
    expect(pending.consume('fp')).toBe(false)
  })

  it('prunes expired entries while keeping live ones', () => {
    const pending = new PendingConfirmations(1000)
    pending.add('old')
    vi.advanceTimersByTime(500)
    pending.add('fresh')
    vi.advanceTimersByTime(501)
    expect(pending.has('old')).toBe(false)
    expect(pending.has('fresh')).toBe(true)
  })
})
