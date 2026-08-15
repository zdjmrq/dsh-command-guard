import { describe, expect, it } from 'vitest'
import { Context } from '@deepseek-ai/cordis'
import type { Agent } from '@deepseek-ai/dsh-agent'
import { CallId } from '@deepseek-ai/dsh-llm'
import SystemPrompt from '@deepseek-ai/dsh-system-prompt'
import ToolRuntime, { defineTool } from '@deepseek-ai/dsh-tools'
import { apply, inject, name, Config, type Config as ConfigType } from '../src/index.ts'

const FULL_CONFIG: ConfigType = {
  extraProtectedPaths: [],
  confirmTtlMs: 60_000,
  analyzeTimeoutMs: 2000,
  previewTimeoutMs: 2000,
  previewSampleLimit: 10,
  pwshPath: 'pwsh',
  enablePrompt: true,
}

interface RecordedEvent {
  type: string
  data: unknown
}

function fakeAgent(records: RecordedEvent[]): Agent {
  return {
    session: {
      id: 'fake-session',
      events: [{ type: 'turn/start' }],
      append: (type: string, data: unknown) => {
        records.push({ type, data })
        return {} as never
      },
    },
  } as unknown as Agent
}

const pwshTool = defineTool({
  name: 'pwsh',
  description: 'run one PowerShell command',
  parameters: { command: { type: 'string', required: true } },
  output: {
    schema: { type: 'string' },
    render: (_args, value) => [{ type: 'text', text: value }],
  },
  async execute(args) {
    return args.command ?? ''
  },
})

async function setup(_records: RecordedEvent[]) {
  const ctx = new Context()
  await ctx.plugin(SystemPrompt)
  await ctx.plugin(ToolRuntime)
  await ctx.plugin({ name, inject, apply }, FULL_CONFIG)
  ctx.tools.register(pwshTool)
  return ctx
}

/** The model-facing text of a settled result's first content block, if any. */
function resultText(result: { content: readonly unknown[] }): string {
  const block = result.content[0] as { text?: unknown } | undefined
  return typeof block?.text === 'string' ? block.text : ''
}

describe('command-guard plugin', () => {
  it('exposes the loader contract and schema defaults', () => {
    expect(name).toBe('command-guard')
    expect(inject).toEqual(['tools'])
    expect(Config({}).confirmTtlMs).toBe(120_000)
    expect(Config({}).analyzeTimeoutMs).toBe(15_000)
    expect(Config({}).extraProtectedPaths).toEqual([])
  })

  it('lets non-destructive commands through without audit trail', async () => {
    const records: RecordedEvent[] = []
    const ctx = await setup(records)
    const result = await ctx.tools.execute({
      callId: CallId('c1'), name: 'pwsh', arguments: { command: 'Get-ChildItem C:\\ws' }, agent: fakeAgent(records), signal: new AbortController().signal,
    })
    expect(result.isError).toBe(false)
    expect(records).toHaveLength(0)
  })

  it('denies the disaster tier in every mode and audits the decision', async () => {
    const records: RecordedEvent[] = []
    const ctx = await setup(records)
    const result = await ctx.tools.execute({
      callId: CallId('c2'), name: 'pwsh', arguments: { command: 'Remove-Item -Recurse -Force C:\\' }, agent: fakeAgent(records), signal: new AbortController().signal,
    })
    expect(result.isError).toBe(true)
    expect(result.content[0]).toMatchObject({
      text: 'Error: command guard: recursive deletion of the protected root "C:\\" is refused in every mode',
    })
    expect(records).toHaveLength(1)
    expect(records[0]?.type).toBe('command-guard/decision')
    expect(records[0]?.data).toMatchObject({ toolName: 'pwsh', decision: 'deny' })
  })

  it('denies bash root deletions through the bash dialect', async () => {
    const records: RecordedEvent[] = []
    const ctx = await setup(records)
    const result = await ctx.tools.execute({
      callId: CallId('c3'), name: 'bash', arguments: { command: 'rm -rf /' }, agent: fakeAgent(records), signal: new AbortController().signal,
    })
    expect(result.isError).toBe(true)
    expect(resultText(result)).toContain('command guard: recursive deletion of the protected root "/"')
  })

  it('routes high-risk commands through the ask decision (denied without an approval seam)', async () => {
    const records: RecordedEvent[] = []
    const ctx = await setup(records)
    const result = await ctx.tools.execute({
      callId: CallId('c4'), name: 'pwsh', arguments: { command: 'Remove-Item $target -Recurse -Force' }, agent: fakeAgent(records), signal: new AbortController().signal,
    })
    expect(result.isError).toBe(true)
    // Without an approval service the ask degrades to a deny carrying the
    // guard's own reason.
    expect(resultText(result)).toContain('command guard: recursive deletion with dynamically resolved targets')
    expect(records.at(-1)?.type).toBe('command-guard/decision')
  })

  it('ignores non-shell tool calls', async () => {
    const records: RecordedEvent[] = []
    const ctx = await setup(records)
    const other = defineTool({
      name: 'web_search',
      description: 'search',
      parameters: { query: { type: 'string', required: true } },
      output: { schema: { type: 'string' }, render: (_a, v) => [{ type: 'text', text: v }] },
      async execute(args) { return args.query ?? '' },
    })
    ctx.tools.register(other)
    const result = await ctx.tools.execute({
      callId: CallId('c5'), name: 'web_search', arguments: { query: 'rm -rf /' }, agent: fakeAgent(records), signal: new AbortController().signal,
    })
    expect(result.isError).toBe(false)
  })

  it('registers the deletion-discipline prompt section', async () => {
    const ctx = await setup([])
    const assembly = await ctx.systemPrompt.assemble()
    expect(JSON.stringify(assembly)).toContain('Deletion discipline (enforced by the command guard)')
  })

  it('lets shell calls without a command argument through', async () => {
    const records: RecordedEvent[] = []
    const ctx = await setup(records)
    const result = await ctx.tools.execute({
      callId: CallId('c6'), name: 'pwsh', arguments: {}, agent: fakeAgent(records), signal: new AbortController().signal,
    })
    expect(result.isError).toBe(true)
    expect(records).toHaveLength(0)
  })

  it('judges agentless executions without audit trail', async () => {
    const ctx = await setup([])
    const result = await ctx.tools.execute({
      callId: CallId('c7'), name: 'pwsh', arguments: { command: 'Remove-Item -Recurse -Force C:\\' }, signal: new AbortController().signal,
    })
    expect(result.isError).toBe(true)
    expect(resultText(result)).toContain('command guard: recursive deletion of the protected root')
  })

  it('keeps the decision when the audit append fails', async () => {
    const records: RecordedEvent[] = []
    const ctx = await setup(records)
    const throwingAgent = {
      session: {
        id: 'throwing-session',
        events: [{ type: 'turn/start' }],
        append: () => { throw new Error('audit store down') },
      },
    } as unknown as Agent
    const result = await ctx.tools.execute({
      callId: CallId('c8'), name: 'pwsh', arguments: { command: 'Remove-Item -Recurse -Force C:\\' }, agent: throwingAgent, signal: new AbortController().signal,
    })
    expect(result.isError).toBe(true)
    expect(resultText(result)).toContain('command guard: recursive deletion of the protected root')
  })

  it('stamps the resolved mode onto the audit event', async () => {
    const records: RecordedEvent[] = []
    const ctx = new Context()
    await ctx.plugin(SystemPrompt)
    await ctx.plugin(ToolRuntime)
    ctx.provide('sandboxPolicy', {
      resolve: () => ({ mode: 'danger-full-access', workspaceRoot: 'C:\\ws' }),
    })
    await ctx.plugin({ name, inject, apply }, FULL_CONFIG)
    ctx.tools.register(pwshTool)
    await ctx.tools.execute({
      callId: CallId('c9'), name: 'pwsh', arguments: { command: 'Remove-Item -Recurse -Force C:\\' }, agent: fakeAgent(records), signal: new AbortController().signal,
    })
    expect(records.at(-1)?.data).toMatchObject({ mode: 'danger-full-access' })
  })

  it('omits the prompt section when enablePrompt is false', async () => {
    const ctx = new Context()
    await ctx.plugin(SystemPrompt)
    await ctx.plugin(ToolRuntime)
    await ctx.plugin({ name, inject, apply }, { ...FULL_CONFIG, enablePrompt: false })
    const assembly = await ctx.systemPrompt.assemble()
    expect(JSON.stringify(assembly)).not.toContain('Deletion discipline')
  })

  it('applies config defaults when mounted without config', async () => {
    const records: RecordedEvent[] = []
    const ctx = new Context()
    await ctx.plugin(SystemPrompt)
    await ctx.plugin(ToolRuntime)
    await ctx.plugin({ name, inject, apply }, {})
    ctx.tools.register(pwshTool)
    const result = await ctx.tools.execute({
      callId: CallId('c10'), name: 'pwsh', arguments: { command: 'Get-ChildItem C:\\ws' }, agent: fakeAgent(records), signal: new AbortController().signal,
    })
    expect(result.isError).toBe(false)
  })

  it('formats a non-Error audit failure into the warning', async () => {
    const ctx = await setup([])
    const throwingAgent = {
      session: {
        id: 'throwing-session-2',
        events: [{ type: 'turn/start' }],
        append: () => { throw 'plain string failure' },
      },
    } as unknown as Agent
    const result = await ctx.tools.execute({
      callId: CallId('c11'), name: 'pwsh', arguments: { command: 'Remove-Item -Recurse -Force C:\\' }, agent: throwingAgent, signal: new AbortController().signal,
    })
    expect(result.isError).toBe(true)
  })
})
