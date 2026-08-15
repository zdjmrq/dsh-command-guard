import { describe, expect, it, vi } from 'vitest'
import type { PwshAnalyzer } from '../src/analyzer.ts'
import { GuardEngine } from '../src/engine.ts'
import type { PreviewRunner } from '../src/preview.ts'
import { buildProtectedRoots } from '../src/protected.ts'
import type { PreviewOutcome, PwshReport } from '../src/types.ts'

const ROOTS = buildProtectedRoots([], { USERPROFILE: 'C:\\Users\\me', SystemRoot: 'C:\\Windows' })

function okReport(): PwshReport {
  return { ok: true, aborted: false, parseErrors: 0, commands: [], memberCalls: [] }
}

function engineWith(overrides: { analyze?: (command: string) => Promise<PwshReport>; preview?: (command: string) => Promise<PreviewOutcome> } = {}) {
  const analyzer = { analyze: vi.fn(async (command: string) => overrides.analyze?.(command) ?? okReport()) } as unknown as PwshAnalyzer
  const preview = {
    preview: vi.fn(async (command: string) => overrides.preview?.(command) ?? { kind: 'unpreviewable', detail: 'no fake' } as PreviewOutcome),
  } as unknown as PreviewRunner
  const engine = new GuardEngine({ analyzer, preview, protectedRoots: ROOTS, confirmTtlMs: 60_000 })
  return { engine, analyzer, preview }
}

function pwsh(command: string, mode: Parameters<GuardEngine['judge']>[0]['mode'], workspaceRoot = 'C:\\ws') {
  return { dialect: 'pwsh' as const, command, mode, workspaceRoot, sessionKey: 's1' }
}

describe('GuardEngine pwsh', () => {
  it('allows non-destructive commands without spawning the analyzer', async () => {
    const { engine, analyzer } = engineWith()
    expect(await engine.judge(pwsh('Get-ChildItem C:\\ws', 'workspace-write'))).toEqual({ kind: 'allow' })
    expect(analyzer.analyze).not.toHaveBeenCalled()
  })

  it('denies lex-proven disaster commands without spawning the analyzer', async () => {
    const { engine, analyzer } = engineWith()
    const decision = await engine.judge(pwsh('Remove-Item -Recurse -Force C:\\', 'danger-full-access'))
    expect(decision.kind).toBe('deny')
    expect(analyzer.analyze).not.toHaveBeenCalled()
  })

  it('asks on high-risk tiers', async () => {
    const { engine } = engineWith({
      analyze: async () => ({
        ...okReport(),
        commands: [{ verb: 'Remove-Item', strings: ['D:\\data'], expandables: [], variables: [], parameters: ['Recurse', 'Force'] }],
      }),
    })
    const decision = await engine.judge(pwsh('Remove-Item D:\\data -Recurse -Force', 'workspace-write'))
    expect(decision.kind).toBe('ask')
  })

  it('asks when the analysis fails closed (unparseable)', async () => {
    const { engine } = engineWith({ analyze: async () => ({ ok: false, aborted: false, parseErrors: -1, commands: [], memberCalls: [] }) })
    const decision = await engine.judge(pwsh('Remove-Item C:\\ws\\x', 'workspace-write'))
    expect(decision.kind).toBe('ask')
  })

  it('allows normal-tier deletions outside careful mode', async () => {
    const { engine } = engineWith({
      analyze: async () => ({
        ...okReport(),
        commands: [{ verb: 'Remove-Item', strings: ['C:\\ws\\old.txt'], expandables: [], variables: [], parameters: [] }],
      }),
    })
    expect(await engine.judge(pwsh('Remove-Item C:\\ws\\old.txt', 'workspace-write'))).toEqual({ kind: 'allow' })
  })

  it('runs the careful two-step: preview deny, then identical resubmission executes without re-previewing', async () => {
    const { engine, preview, analyzer } = engineWith({
      preview: async () => ({ kind: 'previewed', objectCount: 2, fileCount: 2, directoryCount: 0, samples: ['C:\\ws\\a.txt'], truncated: false }),
    })
    const first = await engine.judge(pwsh('Remove-Item C:\\ws\\a.txt', 'careful-full-access'))
    expect(first.kind).toBe('deny')
    expect(first.kind === 'deny' && first.reason).toContain('re-send the identical command to confirm execution')
    const second = await engine.judge(pwsh('Remove-Item C:\\ws\\a.txt', 'careful-full-access'))
    expect(second).toEqual({ kind: 'allow' })
    expect(preview.preview).toHaveBeenCalledTimes(1)
    expect(analyzer.analyze).toHaveBeenCalledTimes(2)
  })

  it('refuses when the careful preview resolves a protected root', async () => {
    const { engine } = engineWith({ preview: async () => ({ kind: 'protected-hit', target: 'D:\\' }) })
    const decision = await engine.judge(pwsh('Remove-Item (Get-PSDrive D).Root -Recurse', 'careful-full-access'))
    expect(decision.kind).toBe('deny')
    expect(decision.kind === 'deny' && decision.reason).toContain('protected root "D:\\"')
  })

  it('denies unpreviewable deletions in careful mode', async () => {
    const { engine } = engineWith({ preview: async () => ({ kind: 'unpreviewable', detail: 'timeout' }) })
    const decision = await engine.judge(pwsh('iex (Get-Content script.ps1)', 'careful-full-access'))
    expect(decision.kind).toBe('deny')
    expect(decision.kind === 'deny' && decision.reason).toContain('cannot be dry-run safely')
  })

  it('allows zero-target previews in careful mode without a confirmation leg', async () => {
    const { engine } = engineWith({ preview: async () => ({ kind: 'zero-targets' }) })
    expect(await engine.judge(pwsh('Remove-Item C:\\ws\\gone.txt', 'careful-full-access'))).toEqual({ kind: 'allow' })
  })

  it('scopes pending confirmations per session', async () => {
    const { engine, preview } = engineWith({
      preview: async () => ({ kind: 'previewed', objectCount: 1, fileCount: 1, directoryCount: 0, samples: ['x'], truncated: false }),
    })
    await engine.judge(pwsh('Remove-Item C:\\ws\\a.txt', 'careful-full-access'))
    const otherSession = await engine.judge({ ...pwsh('Remove-Item C:\\ws\\a.txt', 'careful-full-access'), sessionKey: 's2' })
    expect(otherSession.kind).toBe('deny')
    expect(preview.preview).toHaveBeenCalledTimes(2)
  })

  it('keeps disaster denial ahead of the careful pipeline', async () => {
    const { engine, preview } = engineWith()
    const decision = await engine.judge(pwsh('Format-Volume D', 'careful-full-access'))
    expect(decision.kind).toBe('deny')
    expect(preview.preview).not.toHaveBeenCalled()
  })
})

describe('GuardEngine bash', () => {
  function bash(command: string, mode: Parameters<GuardEngine['judge']>[0]['mode']) {
    return { dialect: 'bash' as const, command, mode, workspaceRoot: '/ws', sessionKey: 's1' }
  }

  it('allows non-destructive bash commands without any analysis', async () => {
    const { engine } = engineWith()
    expect(await engine.judge(bash('ls -la /tmp', 'workspace-write'))).toEqual({ kind: 'allow' })
  })

  it('denies recursive deletion of the POSIX root', async () => {
    const { engine } = engineWith()
    expect(await engine.judge(bash('rm -rf /', 'danger-full-access'))).toMatchObject({ kind: 'deny' })
  })

  it('asks on high-risk bash deletions', async () => {
    const { engine } = engineWith()
    const decision = await engine.judge(bash('rm -rf "$HOME/docs"', 'workspace-write'))
    expect(decision.kind).toBe('ask')
  })

  it('allows ordinary bash deletions', async () => {
    const { engine } = engineWith()
    expect(await engine.judge(bash('rm /ws/old.txt', 'workspace-write'))).toEqual({ kind: 'allow' })
  })

  it('has no preview pipeline on bash even in careful mode (documented degradation)', async () => {
    const { engine, preview } = engineWith()
    const decision = await engine.judge(bash('rm -rf /outside -f', 'careful-full-access'))
    expect(decision.kind).toBe('ask')
    expect(preview.preview).not.toHaveBeenCalled()
  })
})
