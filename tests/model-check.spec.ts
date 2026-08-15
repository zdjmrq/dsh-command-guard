import { describe, expect, it, vi } from 'vitest'
import type { GenerateOptions, StreamChunk } from '@deepseek-ai/dsh-llm'
import { ModelCheckRunner, parseModelAnswer, type ModelCompleter } from '../src/model-check.ts'

const ROUTE = { provider: 'deepseek-official', model: 'deepseek-chat' } as const

function completerWith(chunks: AsyncIterable<StreamChunk> | ((options: GenerateOptions) => AsyncIterable<StreamChunk>)): ModelCompleter & { calls: GenerateOptions[] } {
  const calls: GenerateOptions[] = []
  return {
    calls,
    stream(options: GenerateOptions): AsyncIterable<StreamChunk> {
      calls.push(options)
      return typeof chunks === 'function' ? chunks(options) : chunks
    },
  }
}

/** A stream that stalls until its request signal aborts (signal-honoring like a real adapter). */
function hangingStream(options: GenerateOptions): AsyncIterable<StreamChunk> {
  return (async function* () {
    await new Promise<never>((_resolve, reject) => {
      options.signal?.addEventListener('abort', () => { reject(new Error('aborted')) }, { once: true })
    })
    yield { type: 'text-delta', index: 0, text: '' }
  })()
}

/** A stream that completes (with the given finish reason) only after its signal aborts. */
function completesAfterAbort(options: GenerateOptions, reason: StreamChunk & { type: 'finish' }): AsyncIterable<StreamChunk> {
  return (async function* () {
    await new Promise<void>(resolve => {
      options.signal?.addEventListener('abort', () => { resolve() }, { once: true })
    })
    yield reason
  })()
}

async function* textChunks(reply: string): AsyncIterable<StreamChunk> {
  yield { type: 'text-delta', index: 0, text: reply }
  yield { type: 'finish', reason: { kind: 'stop' } }
}

describe('parseModelAnswer', () => {
  it('parses a strict JSON answer', () => {
    expect(parseModelAnswer('{"intent":"yes","assessment":"safe","explanation":"exactly the requested cleanup"}'))
      .toEqual({ intent: 'yes', assessment: 'safe', explanation: 'exactly the requested cleanup' })
  })

  it('parses a fenced JSON answer', () => {
    expect(parseModelAnswer('```json\n{"intent":"no","assessment":"dangerous","explanation":"misparsed path"}\n```'))
      .toEqual({ intent: 'no', assessment: 'dangerous', explanation: 'misparsed path' })
  })

  it('extracts the JSON object from surrounding prose', () => {
    expect(parseModelAnswer('Here is my answer: {"intent":"yes","assessment":"dangerous","explanation":"wildcard escapes"} thanks'))
      .toEqual({ intent: 'yes', assessment: 'dangerous', explanation: 'wildcard escapes' })
  })

  it('rejects malformed or off-vocabulary answers', () => {
    expect(parseModelAnswer('not json at all')).toBeUndefined()
    expect(parseModelAnswer('{"intent":"maybe","assessment":"safe","explanation":"x"}')).toBeUndefined()
    expect(parseModelAnswer('{"intent":"yes","assessment":"safe"}')).toBeUndefined()
    expect(parseModelAnswer('{"intent":"yes","assessment":"safe","explanation":""}')).toBeUndefined()
    expect(parseModelAnswer('')).toBeUndefined()
  })
})

describe('ModelCheckRunner', () => {
  const input = {
    command: 'Remove-Item C:\\ws\\old.txt -Recurse -Force',
    tier: 'elevated' as const,
    reason: 'command guard: recursive forced deletion outside the workspace',
    scopeSummary: '1 file (C:\\ws\\old.txt)',
    route: ROUTE,
  }

  it('fails closed when no completer or route is available', async () => {
    const noCompleter = new ModelCheckRunner({ completer: undefined, timeoutMs: 1000, maxTokens: 300 })
    expect(await noCompleter.check(input)).toEqual({ kind: 'unavailable', detail: 'no model route available for the model-check call' })
    const withCompleter = new ModelCheckRunner({ completer: completerWith(textChunks('{}')), timeoutMs: 1000, maxTokens: 300 })
    expect(await withCompleter.check({ ...input, route: undefined })).toEqual({ kind: 'unavailable', detail: 'no model route available for the model-check call' })
  })

  it('returns safe for an intended, in-scope answer and sends the full brief', async () => {
    const completer = completerWith(textChunks('{"intent":"yes","assessment":"safe","explanation":"fine"}'))
    const runner = new ModelCheckRunner({ completer, timeoutMs: 1000, maxTokens: 300 })
    expect(await runner.check(input)).toEqual({ kind: 'safe' })
    const options = completer.calls[0] as GenerateOptions
    expect(options.provider).toBe('deepseek-official')
    expect(options.model).toBe('deepseek-chat')
    expect(options.maxTokens).toBe(300)
    expect(options.temperature).toBe(0)
    const serialized = JSON.stringify(options)
    // JSON escapes the command's backslashes, so assert against the escaped form.
    expect(serialized).toContain('Remove-Item C:\\\\ws\\\\old.txt -Recurse -Force')
    expect(serialized).toContain('Resolved scope (WhatIf dry run)')
    expect(serialized).toContain('Static tier: elevated (dangerous verb)')
  })

  it('returns not-intended for a model that disowns the command', async () => {
    const runner = new ModelCheckRunner({ completer: completerWith(textChunks('{"intent":"no","assessment":"dangerous","explanation":"misparsed variable"}')), timeoutMs: 1000, maxTokens: 300 })
    expect(await runner.check(input)).toEqual({ kind: 'not-intended', explanation: 'misparsed variable' })
  })

  it('returns dangerous for a model-declared-dangerous answer', async () => {
    const runner = new ModelCheckRunner({ completer: completerWith(textChunks('{"intent":"yes","assessment":"dangerous","explanation":"wildcard escapes"}')), timeoutMs: 1000, maxTokens: 300 })
    expect(await runner.check(input)).toEqual({ kind: 'dangerous', explanation: 'wildcard escapes' })
  })

  it('fails closed on an unparseable answer', async () => {
    const runner = new ModelCheckRunner({ completer: completerWith(textChunks('sure, go ahead!')), timeoutMs: 1000, maxTokens: 300 })
    expect(await runner.check(input)).toEqual({ kind: 'unavailable', detail: 'the model-check answer could not be parsed' })
  })

  it('fails closed on an error finish', async () => {
    async function* errorChunks(): AsyncIterable<StreamChunk> {
      yield { type: 'finish', reason: { kind: 'error', failure: { message: 'provider 500', code: 'HTTP' } } }
    }
    const runner = new ModelCheckRunner({ completer: completerWith(errorChunks()), timeoutMs: 1000, maxTokens: 300 })
    expect(await runner.check(input)).toEqual({ kind: 'unavailable', detail: 'the model-check call failed: provider 500' })
  })

  it('fails closed on a max-tokens finish', async () => {
    async function* truncated(): AsyncIterable<StreamChunk> {
      yield { type: 'finish', reason: { kind: 'max-tokens' } }
    }
    const runner = new ModelCheckRunner({ completer: completerWith(truncated()), timeoutMs: 1000, maxTokens: 300 })
    const outcome = await runner.check(input)
    expect(outcome.kind).toBe('unavailable')
  })

  it('ignores non-text non-finish chunks', async () => {
    async function* noisy(): AsyncIterable<StreamChunk> {
      yield { type: 'block-start', index: 0, blockType: 'text' }
      yield { type: 'text-delta', index: 0, text: '{"intent":"yes","assessment":"safe","explanation":"ok"}' }
      yield { type: 'finish', reason: { kind: 'stop' } }
    }
    const runner = new ModelCheckRunner({ completer: completerWith(noisy()), timeoutMs: 1000, maxTokens: 300 })
    expect(await runner.check(input)).toEqual({ kind: 'safe' })
  })

  it('classifies an aborted finish caused by the timeout as timed-out', async () => {
    vi.useFakeTimers()
    try {
      const aborted = { type: 'finish', reason: { kind: 'aborted', failure: { message: 'aborted', code: 'ABORTED' } } } as const
      const runner = new ModelCheckRunner({ completer: completerWith(options => completesAfterAbort(options, aborted)), timeoutMs: 1000, maxTokens: 300 })
      const promise = runner.check(input)
      await vi.advanceTimersByTimeAsync(1001)
      expect(await promise).toEqual({ kind: 'unavailable', detail: 'the model-check call timed out' })
    } finally {
      vi.useRealTimers()
    }
  })

  it('classifies a stop-finish stream that outlived the timeout as timed-out', async () => {
    vi.useFakeTimers()
    try {
      const stop = { type: 'finish', reason: { kind: 'stop' } } as const
      const runner = new ModelCheckRunner({ completer: completerWith(options => completesAfterAbort(options, stop)), timeoutMs: 1000, maxTokens: 300 })
      const promise = runner.check(input)
      await vi.advanceTimersByTimeAsync(1001)
      expect(await promise).toEqual({ kind: 'unavailable', detail: 'the model-check call timed out' })
    } finally {
      vi.useRealTimers()
    }
  })

  it('classifies a stop-finish stream that outlived an outer abort as aborted', async () => {
    const controller = new AbortController()
    const stop = { type: 'finish', reason: { kind: 'stop' } } as const
    const runner = new ModelCheckRunner({ completer: completerWith(options => completesAfterAbort(options, stop)), timeoutMs: 1000, maxTokens: 300 })
    const promise = runner.check({ ...input, signal: controller.signal })
    controller.abort()
    expect(await promise).toEqual({ kind: 'unavailable', detail: 'the model-check call was aborted' })
  })

  it('contains a throwing completer', async () => {
    const throwing: ModelCompleter = {
      stream() {
        throw new Error('boom')
      },
    }
    const runner = new ModelCheckRunner({ completer: throwing, timeoutMs: 1000, maxTokens: 300 })
    expect(await runner.check(input)).toEqual({ kind: 'unavailable', detail: 'the model-check call threw: boom' })
  })

  it('formats a non-Error throw from the completer', async () => {
    const throwing: ModelCompleter = {
      stream() {
        throw 'plain string failure'
      },
    }
    const runner = new ModelCheckRunner({ completer: throwing, timeoutMs: 1000, maxTokens: 300 })
    expect(await runner.check(input)).toEqual({ kind: 'unavailable', detail: 'the model-check call threw: plain string failure' })
  })

  it('times out through the abort signal', async () => {
    vi.useFakeTimers()
    try {
      const runner = new ModelCheckRunner({ completer: completerWith(hangingStream), timeoutMs: 1000, maxTokens: 300 })
      const promise = runner.check(input)
      await vi.advanceTimersByTimeAsync(1001)
      expect(await promise).toEqual({ kind: 'unavailable', detail: 'the model-check call timed out' })
    } finally {
      vi.useRealTimers()
    }
  })

  it('propagates an outer abort as an aborted-unavailable outcome', async () => {
    const controller = new AbortController()
    const runner = new ModelCheckRunner({ completer: completerWith(hangingStream), timeoutMs: 1000, maxTokens: 300 })
    const promise = runner.check({ ...input, signal: controller.signal })
    controller.abort()
    expect(await promise).toEqual({ kind: 'unavailable', detail: 'the model-check call was aborted' })
  })

  it('reports an aborted finish when the signal aborts mid-stream', async () => {
    async function* aborted(): AsyncIterable<StreamChunk> {
      yield { type: 'finish', reason: { kind: 'aborted', failure: { message: 'aborted', code: 'ABORTED' } } }
    }
    const controller = new AbortController()
    const runner = new ModelCheckRunner({ completer: completerWith(aborted()), timeoutMs: 1000, maxTokens: 300 })
    const promise = runner.check({ ...input, signal: controller.signal })
    controller.abort()
    const outcome = await promise
    expect(outcome.kind).toBe('unavailable')
  })

  it('contains a throwing completer', async () => {
    const throwing: ModelCompleter = {
      stream() {
        throw new Error('boom')
      },
    }
    const runner = new ModelCheckRunner({ completer: throwing, timeoutMs: 1000, maxTokens: 300 })
    expect(await runner.check(input)).toEqual({ kind: 'unavailable', detail: 'the model-check call threw: boom' })
  })

  it('labels unparseable tiers in the presented brief', async () => {
    const completer = completerWith(textChunks('{"intent":"yes","assessment":"safe","explanation":"ok"}'))
    const runner = new ModelCheckRunner({ completer, timeoutMs: 1000, maxTokens: 300 })
    await runner.check({ ...input, tier: 'unparseable' })
    expect(JSON.stringify(completer.calls[0])).toContain('unparseable (cannot be statically analyzed; treated as disaster)')
  })

  it('labels disaster tiers in the presented brief', async () => {
    const completer = completerWith(textChunks('{"intent":"yes","assessment":"safe","explanation":"ok"}'))
    const runner = new ModelCheckRunner({ completer, timeoutMs: 1000, maxTokens: 300 })
    await runner.check({ ...input, tier: 'disaster' })
    expect(JSON.stringify(completer.calls[0])).toContain('DISASTER (protected root or disk-level operation)')
  })
})
