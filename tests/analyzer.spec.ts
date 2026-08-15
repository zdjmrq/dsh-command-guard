import { describe, expect, it } from 'vitest'
import { PwshAnalyzer, encodeCommand, nodeSpawner, parsePwshReport } from '../src/analyzer.ts'
import type { SpawnResult } from '../src/types.ts'

const GOOD_REPORT = JSON.stringify({
  ok: true,
  parseErrors: 0,
  commands: [{ verb: 'Remove-Item', strings: ['C:\\temp'], expandables: [], variables: [], parameters: ['Recurse'] }],
  memberCalls: ['Directory'],
})

describe('encodeCommand', () => {
  it('round-trips UTF-16LE base64', () => {
    const script = 'Write-Output "你好"'
    const decoded = Buffer.from(encodeCommand(script), 'base64').toString('utf16le')
    expect(decoded).toBe(script)
  })
})

describe('parsePwshReport', () => {
  it('parses a valid report line', () => {
    const report = parsePwshReport(GOOD_REPORT)
    expect(report.ok).toBe(true)
    expect(report.parseErrors).toBe(0)
    expect(report.commands).toHaveLength(1)
    expect(report.commands[0]?.verb).toBe('Remove-Item')
    expect(report.memberCalls).toEqual(['Directory'])
  })

  it('takes the last non-empty output line', () => {
    const report = parsePwshReport('noise\n\n' + GOOD_REPORT + '\n')
    expect(report.ok).toBe(true)
  })

  it('fails closed on unreadable output', () => {
    for (const stdout of ['', 'not json', '{"ok":true}', '[1,2]', '5', 'null', 'true']) {
      const report = parsePwshReport(stdout)
      expect(report.ok).toBe(false)
    }
  })

  it('fails closed on a non-zero parseErrors count', () => {
    const report = parsePwshReport('{"ok":false,"parseErrors":2,"commands":[],"memberCalls":[]}')
    expect(report.ok).toBe(false)
    expect(report.parseErrors).toBe(2)
  })

  it('drops malformed command entries and clamps arrays', () => {
    const many = JSON.stringify({ ok: true, parseErrors: 0, commands: [{ verb: 'rm' }, { nope: true }, null], memberCalls: ['File'] })
    const report = parsePwshReport(many)
    expect(report.ok).toBe(true)
    expect(report.commands).toHaveLength(1)
    expect(report.commands[0]?.strings).toEqual([])
  })

  it('filters non-string members out of every command array', () => {
    const dirty = JSON.stringify({
      ok: true,
      parseErrors: 0,
      commands: [{
        verb: 'rm',
        strings: ['a', 1, null],
        expandables: ['b', 2],
        variables: ['$x', false],
        parameters: ['Recurse', 3],
      }],
      memberCalls: ['Directory', 4],
    })
    const report = parsePwshReport(dirty)
    expect(report.ok).toBe(true)
    expect(report.commands[0]).toEqual({
      verb: 'rm', strings: ['a'], expandables: ['b'], variables: ['$x'], parameters: ['Recurse'],
    })
    expect(report.memberCalls).toEqual(['Directory'])
  })
})

describe('nodeSpawner', () => {
  it('captures stdout and exit code on success', async () => {
    const result = await nodeSpawner([process.execPath, '-e', 'process.stdout.write("hello")'], { timeoutMs: 5000 })
    expect(result.exitCode).toBe(0)
    expect(result.stdout).toBe('hello')
    expect(result.timedOut).toBe(false)
  })

  it('captures non-zero exits', async () => {
    const result = await nodeSpawner([process.execPath, '-e', 'process.exit(3)'], { timeoutMs: 5000 })
    expect(result.exitCode).toBe(3)
  })

  it('reports a spawn failure instead of throwing', async () => {
    const result = await nodeSpawner(['definitely-not-a-real-binary-xyz', '--help'], { timeoutMs: 5000 })
    expect(result.spawnError).toBeDefined()
    expect(result.exitCode).toBeNull()
  })

  it('kills a hung child and reports the timeout', async () => {
    const result = await nodeSpawner([process.execPath, '-e', 'setTimeout(() => {}, 60_000)'], { timeoutMs: 200 })
    expect(result.timedOut).toBe(true)
  })

  it('caps oversized streams with a marker', async () => {
    const result = await nodeSpawner([process.execPath, '-e', 'process.stdout.write("a".repeat(1000))'], { timeoutMs: 5000, maxChars: 100 })
    expect(result.stdout).toContain('[output truncated]')
    expect(result.stdout.length).toBeLessThan(300)
  })

  it('captures stderr and exit code on success', async () => {
    const result = await nodeSpawner([process.execPath, '-e', 'process.stderr.write("warn")'], { timeoutMs: 5000 })
    expect(result.exitCode).toBe(0)
    expect(result.stderr).toBe('warn')
  })

  it('caps oversized stderr streams too', async () => {
    const result = await nodeSpawner([process.execPath, '-e', 'process.stderr.write("b".repeat(1000))'], { timeoutMs: 5000, maxChars: 100 })
    expect(result.stderr).toContain('[output truncated]')
  })

  it('reports a synchronous spawn throw instead of throwing', async () => {
    const result = await nodeSpawner(['', 'x'], { timeoutMs: 5000 })
    expect(result.spawnError).toBeDefined()
    expect(result.exitCode).toBeNull()
  })

  it('reports an empty argv as a spawn error', async () => {
    const result = await nodeSpawner([], { timeoutMs: 5000 })
    expect(result).toMatchObject({ stdout: '', stderr: '', exitCode: null, timedOut: false, spawnError: 'argv is empty' })
  })
})

describe('PwshAnalyzer', () => {
  async function analyzerWith(spawn: (argv: string[], env: Record<string, string> | undefined) => Promise<SpawnResult>) {
    const calls: Array<{ argv: string[]; env: Record<string, string> | undefined }> = []
    const analyzer = new PwshAnalyzer(async (argv, options) => {
      calls.push({ argv, env: options.env })
      return await spawn(argv, options.env)
    }, { timeoutMs: 1000, pwshPath: 'pwsh' })
    return { analyzer, calls }
  }

  it('passes the command through the environment and uses EncodedCommand', async () => {
    const { analyzer, calls } = await analyzerWith(async () => ({ stdout: GOOD_REPORT, stderr: '', exitCode: 0, timedOut: false }))
    const report = await analyzer.analyze('Remove-Item C:\\temp')
    expect(report.ok).toBe(true)
    expect(calls).toHaveLength(1)
    expect(calls[0]?.argv).toContain('-EncodedCommand')
    expect(calls[0]?.env?.['DGUARD_CMD']).toBe('Remove-Item C:\\temp')
  })

  it('fails closed on non-zero exits, spawn errors, and timeouts', async () => {
    const cases: SpawnResult[] = [
      { stdout: '', stderr: '', exitCode: 1, timedOut: false },
      { stdout: '', stderr: '', exitCode: null, timedOut: false, spawnError: 'missing' },
      { stdout: '', stderr: '', exitCode: null, timedOut: true },
      { stdout: '', stderr: '', exitCode: 0, timedOut: false },
    ]
    for (const result of cases) {
      const { analyzer } = await analyzerWith(async () => result)
      expect((await analyzer.analyze('rm x')).ok).toBe(false)
    }
  })

  it('exposes the .NET deletion cross-check', () => {
    expect(PwshAnalyzer.hasNetDelete('[IO.Directory]::Delete("x")')).toBe(true)
    expect(PwshAnalyzer.hasNetDelete('Remove-Item x')).toBe(false)
  })

  it('reports an aborted caller without spawning', async () => {
    const { analyzer, calls } = await analyzerWith(async () => ({ stdout: GOOD_REPORT, stderr: '', exitCode: 0, timedOut: false }))
    const aborted = new AbortController()
    aborted.abort()
    const report = await analyzer.analyze('rm x', aborted.signal)
    expect(report.aborted).toBe(true)
    expect(calls).toHaveLength(0)
  })

  it('marks a late abort when the caller aborts while the spawn is in flight', async () => {
    const controller = new AbortController()
    const { analyzer } = await analyzerWith(async () => {
      controller.abort()
      return { stdout: GOOD_REPORT, stderr: '', exitCode: 0, timedOut: false }
    })
    const report = await analyzer.analyze('rm x', controller.signal)
    expect(report.aborted).toBe(true)
    expect(report.ok).toBe(false)
  })
})
