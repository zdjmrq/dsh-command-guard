import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { DedupeWindow, fingerprintCommand } from '../src/fingerprint.ts'

describe('fingerprintCommand', () => {
  it('trims and collapses whitespace so cosmetic reformatting still merges', () => {
    expect(fingerprintCommand('  Remove-Item   C:\\ws\\x \n')).toBe('Remove-Item C:\\ws\\x')
    expect(fingerprintCommand('Remove-Item C:\\ws\\x')).toBe(fingerprintCommand('  Remove-Item  C:\\ws\\x  '))
  })

  it('keeps real changes distinct', () => {
    expect(fingerprintCommand('Remove-Item a')).not.toBe(fingerprintCommand('Remove-Item b'))
  })
})

describe('DedupeWindow', () => {
  beforeEach(() => {
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('notes a first fingerprint as a fresh entry', () => {
    const window = new DedupeWindow(60_000)
    expect(window.note('fp')).toEqual({ count: 1, repeat: false })
  })

  it('merges repeats inside the TTL into a growing count', () => {
    const window = new DedupeWindow(60_000)
    window.note('fp')
    vi.advanceTimersByTime(1000)
    expect(window.note('fp')).toEqual({ count: 2, repeat: true })
    expect(window.note('fp')).toEqual({ count: 3, repeat: true })
    expect(window.note('other')).toEqual({ count: 1, repeat: false })
  })

  it('starts a fresh window after the TTL expires', () => {
    const window = new DedupeWindow(1000)
    window.note('fp')
    vi.advanceTimersByTime(1001)
    expect(window.note('fp')).toEqual({ count: 1, repeat: false })
  })

  it('extends the window on every repeat', () => {
    const window = new DedupeWindow(1000)
    window.note('fp')
    vi.advanceTimersByTime(900)
    window.note('fp')
    vi.advanceTimersByTime(900)
    expect(window.note('fp')).toEqual({ count: 3, repeat: true })
  })

  it('prunes expired entries while keeping live ones', () => {
    const window = new DedupeWindow(1000)
    window.note('old')
    vi.advanceTimersByTime(500)
    window.note('fresh')
    vi.advanceTimersByTime(501)
    expect(window.note('old')).toEqual({ count: 1, repeat: false })
    expect(window.note('fresh')).toEqual({ count: 2, repeat: true })
  })
})
