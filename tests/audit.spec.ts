import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { AuditLogger, SessionAuditGate } from '../src/audit.ts'
import type { AuditLine } from '../src/audit.ts'
import { DedupeWindow } from '../src/fingerprint.ts'

let dir: string

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'command-guard-audit-'))
})

afterEach(async () => {
  await rm(dir, { recursive: true, force: true })
})

function line(overrides: Partial<AuditLine> = {}): AuditLine {
  return {
    ts: '2026-08-15T00:00:00.000Z',
    toolName: 'pwsh',
    decision: 'deny',
    reason: 'command guard: recursive deletion of the protected root "C:\\"',
    mode: 'careful-full-access',
    fingerprint: 'Remove-Item -Recurse -Force C:\\',
    count: 1,
    ...overrides,
  }
}

describe('AuditLogger', () => {
  it('appends one JSON line per decision and creates missing directories', async () => {
    const errors: unknown[] = []
    const path = join(dir, 'logs', 'command-guard.log')
    const logger = new AuditLogger({ path, maxBytes: 1024 * 1024, rotations: 3, onError: e => errors.push(e) })
    logger.write(line())
    await logger.flush()
    const lines = (await readFile(path, 'utf8')).trim().split('\n')
    expect(lines).toHaveLength(1)
    expect(JSON.parse(lines[0] ?? '') as AuditLine).toMatchObject({ toolName: 'pwsh', decision: 'deny', count: 1 })
    expect(errors).toEqual([])
  })

  it('serializes concurrent writes so lines never interleave', async () => {
    const path = join(dir, 'command-guard.log')
    const logger = new AuditLogger({ path, maxBytes: 1024 * 1024, rotations: 3, onError: () => {} })
    for (let index = 0; index < 20; index += 1) logger.write(line({ fingerprint: `fp-${index}` }))
    await logger.flush()
    const lines = (await readFile(path, 'utf8')).trim().split('\n')
    expect(lines).toHaveLength(20)
    for (const entry of lines) {
      const parsed = JSON.parse(entry) as AuditLine
      expect(typeof parsed.fingerprint).toBe('string')
    }
  })

  it('rotates at the size cap and shifts older copies up', async () => {
    const path = join(dir, 'command-guard.log')
    const logger = new AuditLogger({ path, maxBytes: 100, rotations: 2, onError: () => {} })
    logger.write(line({ fingerprint: 'first' }))
    logger.write(line({ fingerprint: 'second' }))
    logger.write(line({ fingerprint: 'third' }))
    await logger.flush()
    const live = (await readFile(path, 'utf8')).trim()
    expect(JSON.parse(live) as AuditLine).toMatchObject({ fingerprint: 'third' })
    const one = JSON.parse((await readFile(`${path}.1`, 'utf8')).trim()) as AuditLine
    expect(one).toMatchObject({ fingerprint: 'second' })
    const two = JSON.parse((await readFile(`${path}.2`, 'utf8')).trim()) as AuditLine
    expect(two).toMatchObject({ fingerprint: 'first' })
  })

  it('contains append failures into onError without rejecting the queue', async () => {
    const errors: unknown[] = []
    // The path is an existing DIRECTORY: appendFile must fail with EISDIR/EPERM.
    const logger = new AuditLogger({ path: dir, maxBytes: 100, rotations: 2, onError: e => errors.push(e) })
    logger.write(line())
    await logger.flush()
    expect(errors.length).toBeGreaterThan(0)
    // The queue stays usable: a later write still settles without throwing.
    const healthy = new AuditLogger({ path: join(dir, 'later.log'), maxBytes: 100, rotations: 2, onError: () => {} })
    healthy.write(line())
    await healthy.flush()
  })

  it('tolerates a missing pre-existing file on rotation shift', async () => {
    const path = join(dir, 'command-guard.log')
    const logger = new AuditLogger({ path, maxBytes: 100, rotations: 5, onError: () => {} })
    for (let index = 0; index < 4; index += 1) logger.write(line({ fingerprint: `fp-${index}` }))
    await logger.flush()
    const live = JSON.parse((await readFile(path, 'utf8')).trim()) as AuditLine
    expect(live).toMatchObject({ fingerprint: 'fp-3' })
  })
})

describe('SessionAuditGate', () => {
  it('appends up to the cap and then stops', () => {
    const gate = new SessionAuditGate({ maxEvents: 3, dedupe: new DedupeWindow(60_000) })
    const results = ['a', 'b', 'c', 'd'].map(fp => gate.shouldAppend('s1', fp))
    expect(results.map(r => r.append)).toEqual([true, true, true, false])
  })

  it('never lets a repeat within the TTL consume the cap', () => {
    const gate = new SessionAuditGate({ maxEvents: 2, dedupe: new DedupeWindow(60_000) })
    expect(gate.shouldAppend('s1', 'fp').append).toBe(true)
    expect(gate.shouldAppend('s1', 'fp')).toMatchObject({ append: false, note: { count: 2, repeat: true } })
    expect(gate.shouldAppend('s1', 'other').append).toBe(true)
  })

  it('counts each session independently', () => {
    const gate = new SessionAuditGate({ maxEvents: 1, dedupe: new DedupeWindow(60_000) })
    expect(gate.shouldAppend('s1', 'fp').append).toBe(true)
    expect(gate.shouldAppend('s1', 'other').append).toBe(false)
    expect(gate.shouldAppend('s2', 'fp').append).toBe(true)
  })

  it('scopes dedupe per session', () => {
    const gate = new SessionAuditGate({ maxEvents: 5, dedupe: new DedupeWindow(60_000) })
    gate.shouldAppend('s1', 'fp')
    const other = gate.shouldAppend('s2', 'fp')
    expect(other).toMatchObject({ append: true, note: { count: 1, repeat: false } })
  })
})
