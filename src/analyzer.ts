/**
 * The process-backed analyzer: a PowerShell AST pass over one command string,
 * run as a helper `pwsh` invocation through an injectable {@link Spawner}. The
 * analyzer script travels as a UTF-16LE `-EncodedCommand`, so the command text
 * itself never crosses a command line — it rides the environment — and no
 * quoting layer can corrupt it. The script parses WITHOUT executing: it walks
 * every `CommandAst` and reports verbs, literal/expandable strings, variables,
 * parameters, and `.NET` deletion member calls as one compact JSON line.
 *
 * @module @deepseek-ai/dsh-command-guard/analyzer
 */

import { spawn } from 'node:child_process'
import type { PwshCommandReport, PwshReport, Spawner, SpawnOptions, SpawnResult } from './types.ts'
import { NET_DELETE_CALL } from './verbs.ts'

/** The embedded analyzer script: parse `$env:DGUARD_CMD`, report, never execute. */
const ANALYZER_SCRIPT = String.raw`
$ErrorActionPreference = 'Stop'
$cmd = $env:DGUARD_CMD
if ([string]::IsNullOrEmpty($cmd)) { Write-Output '{"ok":false,"parseErrors":1,"commands":[],"memberCalls":[]}'; exit 0 }
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseInput($cmd, [ref]$tokens, [ref]$errors)
$commands = @()
$ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object {
  $strings = @()
  $expandables = @()
  $variables = @()
  $parameters = @()
  foreach ($el in $_.CommandElements) {
    if ($el -is [System.Management.Automation.Language.StringConstantExpressionAst]) { $strings += $el.Value }
    elseif ($el -is [System.Management.Automation.Language.ExpandableStringExpressionAst]) { $expandables += $el.Extent.Text }
    elseif ($el -is [System.Management.Automation.Language.VariableExpressionAst]) { $variables += ('$' + $el.VariablePath.UserPath) }
    elseif ($el -is [System.Management.Automation.Language.CommandParameterAst]) { $parameters += $el.ParameterName }
  }
  $commands += [ordered]@{ verb = $_.CommandElements[0].Extent.Text; strings = $strings; expandables = $expandables; variables = $variables; parameters = $parameters }
}
$memberCalls = @()
$match = [regex]::Match($cmd, '\[(?:System\.IO\.|IO\.)(Directory|File|FileInfo|DirectoryInfo)\]\s*::\s*Delete\s*\(')
while ($match.Success) { $memberCalls += $match.Groups[1].Value; $match = $match.NextMatch() }
[ordered]@{ ok = ($errors.Count -eq 0); parseErrors = $errors.Count; commands = $commands; memberCalls = $memberCalls } | ConvertTo-Json -Depth 6 -Compress
`

/** UTF-16LE base64, the encoding `pwsh -EncodedCommand` requires. */
export function encodeCommand(script: string): string {
  return Buffer.from(script, 'utf16le').toString('base64')
}

/**
 * The default spawner: ordinary `node:child_process` spawn with a kill
 * deadline and bounded stream collection. The host process is never confined
 * when the guard runs, so pipe capture is safe here.
 * @param argv - program plus arguments.
 * @param options - environment overlay, timeout, and per-stream cap.
 * @returns the settled output; never throws.
 */
export async function nodeSpawner(argv: string[], options: SpawnOptions): Promise<SpawnResult> {
  const maxChars = options.maxChars ?? 262_144
  return await new Promise<SpawnResult>((resolve) => {
    let stdout = ''
    let stderr = ''
    let stdoutTruncated = false
    let stderrTruncated = false
    let timedOut = false
    let settled = false
    const settle = (result: SpawnResult): void => {
      if (settled) return
      settled = true
      resolve(result)
    }
    let child: ReturnType<typeof spawn>
    const executable = argv[0]
    if (executable === undefined) {
      settle({ stdout: '', stderr: '', exitCode: null, timedOut: false, spawnError: 'argv is empty' })
      return
    }
    try {
      child = spawn(executable, argv.slice(1), {
        env: { ...process.env, ...options.env },
        stdio: ['ignore', 'pipe', 'pipe'],
      })
    } catch (error) {
      // ENOENT and EINVAL surface synchronously on Windows before any event.
      /* v8 ignore next -- spawn throws Error instances only; String(error) is a hostile-value guard */
      settle({ stdout: '', stderr: '', exitCode: null, timedOut: false, spawnError: error instanceof Error ? error.message : String(error) })
      return
    }
    const timer = setTimeout(() => {
      timedOut = true
      child.kill()
    }, options.timeoutMs)
    const outStream = child.stdout
    /* v8 ignore next -- stdio: 'pipe' always yields streams; the null side only covers a hostile spawn result */
    if (outStream !== null) {
      outStream.on('data', (chunk: Buffer | string) => {
        const text = String(chunk)
        if (stdout.length + text.length > maxChars) {
          /* v8 ignore next -- one stream cannot cross the cap twice per run; the second cut is a defensive no-op */
          if (!stdoutTruncated) {
            stdout += '\n[output truncated]'
            stdoutTruncated = true
          }
        } else {
          stdout += text
        }
      })
    }
    const errStream = child.stderr
    /* v8 ignore next -- stdio: 'pipe' always yields streams; the null side only covers a hostile spawn result */
    if (errStream !== null) {
      errStream.on('data', (chunk: Buffer | string) => {
        const text = String(chunk)
        if (stderr.length + text.length > maxChars) {
          /* v8 ignore next -- one stream cannot cross the cap twice per run; the second cut is a defensive no-op */
          if (!stderrTruncated) {
            stderr += '\n[output truncated]'
            stderrTruncated = true
          }
        } else {
          stderr += text
        }
      })
    }
    child.on('error', (error) => {
      clearTimeout(timer)
      settle({ stdout, stderr, exitCode: null, timedOut, spawnError: error.message })
    })
    child.on('close', (code) => {
      clearTimeout(timer)
      settle({ stdout, stderr, exitCode: code, timedOut })
    })
  })
}

/** Whether the caller aborted before a pending spawn could start. */
function aborted(signal: AbortSignal | undefined): boolean {
  return signal !== undefined && signal.aborted
}

/** Validate and normalize one command entry from the untrusted script output. */
function parseCommandReport(value: unknown): PwshCommandReport | undefined {
  if (typeof value !== 'object' || value === null) return undefined
  const record = value as Record<string, unknown>
  if (typeof record['verb'] !== 'string') return undefined
  const strings = Array.isArray(record['strings'])
    ? (record['strings'] as unknown[]).filter((item): item is string => typeof item === 'string').slice(0, 64)
    : []
  const expandables = Array.isArray(record['expandables'])
    ? (record['expandables'] as unknown[]).filter((item): item is string => typeof item === 'string').slice(0, 64)
    : []
  const variables = Array.isArray(record['variables'])
    ? (record['variables'] as unknown[]).filter((item): item is string => typeof item === 'string').slice(0, 64)
    : []
  const parameters = Array.isArray(record['parameters'])
    ? (record['parameters'] as unknown[]).filter((item): item is string => typeof item === 'string').slice(0, 64)
    : []
  return { verb: record['verb'], strings, expandables, variables, parameters }
}

/**
 * Parse and validate the analyzer script's single JSON output line. Rogue or
 * truncated output fails closed into a non-ok report.
 * @param stdout - the helper's captured stdout.
 * @returns the validated report.
 */
export function parsePwshReport(stdout: string): PwshReport {
  const line = stdout.trim().split(/\r?\n/).filter(part => part.length > 0).at(-1)
  if (line === undefined) return { ok: false, aborted: false, parseErrors: -1, commands: [], memberCalls: [] }
  try {
    const parsed: unknown = JSON.parse(line)
    if (typeof parsed !== 'object' || parsed === null) {
      return { ok: false, aborted: false, parseErrors: -1, commands: [], memberCalls: [] }
    }
    const record = parsed as Record<string, unknown>
    const commands = Array.isArray(record['commands'])
      ? (record['commands'] as unknown[]).map(parseCommandReport).filter((item): item is PwshCommandReport => item !== undefined)
      : []
    const memberCalls = Array.isArray(record['memberCalls'])
      ? (record['memberCalls'] as unknown[]).filter((item): item is string => typeof item === 'string').slice(0, 16)
      : []
    return {
      ok: record['ok'] === true && typeof record['parseErrors'] === 'number' && record['parseErrors'] === 0,
      aborted: false,
      parseErrors: typeof record['parseErrors'] === 'number' ? record['parseErrors'] : -1,
      commands,
      memberCalls,
    }
  } catch {
    return { ok: false, aborted: false, parseErrors: -1, commands: [], memberCalls: [] }
  }
}

/** The analyzer configuration the engine resolves per call. */
export interface AnalyzerOptions {
  /** Kill deadline for the analysis spawn. */
  timeoutMs: number
  /** The helper executable, already resolved from config defaults. */
  pwshPath: string
}

/**
 * The PowerShell AST analyzer. One instance per guard engine; every analysis
 * is a fresh helper process, so no state accumulates.
 */
export class PwshAnalyzer {
  constructor(
    private readonly spawner: Spawner,
    private readonly options: AnalyzerOptions,
  ) {}

  /**
   * Run the read-only AST pass over one command.
   * @param command - the model-supplied PowerShell command text.
   * @param signal - the tool-call abort signal; an aborted caller yields an aborted report.
   * @returns the validated report; spawn failures and timeouts fail closed.
   */
  async analyze(command: string, signal?: AbortSignal): Promise<PwshReport> {
    if (aborted(signal)) return { ok: false, aborted: true, parseErrors: -1, commands: [], memberCalls: [] }
    const result = await this.spawner(
      [this.options.pwshPath, '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', encodeCommand(ANALYZER_SCRIPT)],
      { env: { DGUARD_CMD: command }, timeoutMs: this.options.timeoutMs },
    )
    if (result.spawnError !== undefined || result.exitCode === null || result.timedOut) {
      return { ok: false, aborted: aborted(signal), parseErrors: -1, commands: [], memberCalls: [] }
    }
    if (result.exitCode !== 0) return { ok: false, aborted: aborted(signal), parseErrors: -1, commands: [], memberCalls: [] }
    const report = parsePwshReport(result.stdout)
    return aborted(signal) ? { ...report, ok: false, aborted: true } : report
  }

  /** The `.NET` deletion member calls the caller-visible regex already found, for cross-checks. */
  static hasNetDelete(command: string): boolean {
    return NET_DELETE_CALL.test(command)
  }
}
