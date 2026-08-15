import { describe, expect, it } from 'vitest'
import type { LexFacts } from '../src/lexer.ts'
import { buildProtectedRoots, type ProtectedRoots } from '../src/protected.ts'
import { classifyBash, classifyPwsh, type TierContext } from '../src/tiers.ts'
import type { PwshReport } from '../src/types.ts'

const ROOTS: ProtectedRoots = buildProtectedRoots([], {
  SystemRoot: 'C:\\Windows',
  ProgramFiles: 'C:\\Program Files',
  USERPROFILE: 'C:\\Users\\me',
})

const CONTEXT: TierContext = { workspaceRoot: 'C:\\ws', protectedRoots: ROOTS }

function facts(partial: Partial<LexFacts> = {}): LexFacts {
  return {
    families: [], verbs: [], literalPaths: [], netDeleteCall: false, diskpartClean: false,
    robocopyMir: false, recursive: false, force: false, wildcard: false, dynamic: false, dynamicVerb: false, findDelete: false,
    ...partial,
  }
}

function report(partial: Partial<PwshReport> = {}): PwshReport {
  return {
    ok: true, aborted: false, parseErrors: 0, commands: [], memberCalls: [],
    ...partial,
  }
}

function deleteCommand(strings: string[], parameters: string[] = [], variables: string[] = []): PwshReport {
  return report({ commands: [{ verb: 'Remove-Item', strings, expandables: [], variables, parameters }] })
}

describe('classifyPwsh', () => {
  it('classifies non-destructive commands as normal', () => {
    const verdict = classifyPwsh('Get-ChildItem C:\\ws', report(), facts(), CONTEXT)
    expect(verdict.tier).toBe('normal')
  })

  it('refuses the format family in every case', () => {
    const verdict = classifyPwsh('Format-Volume D', report(), facts({ families: ['format'], verbs: ['format-volume'] }), CONTEXT)
    expect(verdict.tier).toBe('disaster')
  })

  it('refuses diskpart clean', () => {
    const verdict = classifyPwsh('diskpart clean', report(), facts({ diskpartClean: true }), CONTEXT)
    expect(verdict.tier).toBe('disaster')
  })

  it('refuses robocopy mirroring into a protected root', () => {
    const verdict = classifyPwsh('robocopy C:\\empty C:\\Users\\me /MIR', report(), facts({ robocopyMir: true, literalPaths: ['C:\\Users\\me'] }), CONTEXT)
    expect(verdict.tier).toBe('disaster')
  })

  it('refuses recursive .NET deletion of a protected root', () => {
    const verdict = classifyPwsh(
      '[System.IO.Directory]::Delete("C:\\Users\\me", $true)',
      report({ memberCalls: ['Directory'] }),
      facts({ netDeleteCall: true, literalPaths: ['C:\\Users\\me'] }),
      CONTEXT,
    )
    expect(verdict.tier).toBe('disaster')
  })

  it('refuses recursive deletion of any protected root', () => {
    for (const target of ['C:\\', 'E:\\', 'C:\\*', '\\\\server\\share\\', 'C:\\Windows', 'C:\\Users\\me', 'C:\\ws']) {
      const verdict = classifyPwsh('Remove-Item -Recurse ' + target, deleteCommand([target], ['Recurse']), facts({ families: ['delete'], literalPaths: [target], recursive: true }), CONTEXT)
      expect(verdict.tier, target).toBe('disaster')
    }
  })

  it('flags non-recursive .NET deletion of a protected root as high-risk', () => {
    const verdict = classifyPwsh(
      '[System.IO.Directory]::Delete("C:\\Users\\me")',
      report({ memberCalls: ['Directory'] }),
      facts({ netDeleteCall: true, literalPaths: ['C:\\Users\\me'] }),
      CONTEXT,
    )
    expect(verdict.tier).toBe('high-risk')
  })

  it('flags .NET deletion inside a protected root as high-risk', () => {
    const verdict = classifyPwsh(
      '[System.IO.File]::Delete("C:\\Windows\\x.dll")',
      report({ memberCalls: ['File'] }),
      facts({ netDeleteCall: true, literalPaths: ['C:\\Windows\\x.dll'] }),
      CONTEXT,
    )
    expect(verdict.tier).toBe('high-risk')
  })

  it('passes .NET deletion of an ordinary file as normal', () => {
    const verdict = classifyPwsh(
      '[System.IO.File]::Delete("C:\\ws\\x.txt")',
      report({ memberCalls: ['File'] }),
      facts({ netDeleteCall: true, literalPaths: ['C:\\ws\\x.txt'] }),
      CONTEXT,
    )
    expect(verdict.tier).toBe('normal')
  })

  it('passes robocopy mirroring into an ordinary directory as normal', () => {
    const verdict = classifyPwsh(
      'robocopy C:\\a C:\\ws\\b /MIR',
      report(),
      facts({ robocopyMir: true, literalPaths: ['C:\\a', 'C:\\ws\\b'] }),
      CONTEXT,
    )
    expect(verdict.tier).toBe('normal')
  })

  it('passes recursive forced deletion fully inside the workspace as normal', () => {
    const verdict = classifyPwsh(
      'Remove-Item C:\\ws\\sub -Recurse -Force',
      deleteCommand(['C:\\ws\\sub'], ['Recurse', 'Force']),
      facts({ families: ['delete'], recursive: true, force: true, literalPaths: ['C:\\ws\\sub'] }),
      CONTEXT,
    )
    expect(verdict.tier).toBe('normal')
  })

  it('flags recycle-bin emptying as high-risk', () => {
    const verdict = classifyPwsh('Clear-RecycleBin', report(), facts({ families: ['recycle'], verbs: ['clear-recyclebin'] }), CONTEXT)
    expect(verdict.tier).toBe('high-risk')
  })

  it('flags recursive deletion with dynamic targets as high-risk', () => {
    const verdict = classifyPwsh('Remove-Item $target -Recurse -Force', deleteCommand([], ['Recurse', 'Force'], ['$target']), facts({ families: ['delete'], recursive: true, force: true, dynamic: true }), CONTEXT)
    expect(verdict.tier).toBe('high-risk')
  })

  it('flags recursive forced deletion outside the workspace as high-risk', () => {
    const verdict = classifyPwsh('Remove-Item D:\\data -Recurse -Force', deleteCommand(['D:\\data'], ['Recurse', 'Force']), facts({ families: ['delete'], recursive: true, force: true, literalPaths: ['D:\\data'] }), CONTEXT)
    expect(verdict.tier).toBe('high-risk')
  })

  it('flags recursive forced deletion with wildcards as high-risk', () => {
    const verdict = classifyPwsh('Remove-Item C:\\ws\\* -Recurse -Force', deleteCommand(['C:\\ws\\*'], ['Recurse', 'Force']), facts({ families: ['delete'], recursive: true, force: true, wildcard: true }), CONTEXT)
    expect(verdict.tier).toBe('high-risk')
  })

  it('flags recursive deletion with no statically visible target as high-risk', () => {
    const verdict = classifyPwsh('Remove-Item -Recurse', deleteCommand([], ['Recurse']), facts({ families: ['delete'], recursive: true }), CONTEXT)
    expect(verdict.tier).toBe('high-risk')
  })

  it('flags recursive forced deletion with a bare drive form as high-risk', () => {
    const verdict = classifyPwsh('Remove-Item D: -Recurse -Force', deleteCommand(['D:'], ['Recurse', 'Force']), facts({ families: ['delete'], recursive: true, force: true, literalPaths: ['D:'] }), CONTEXT)
    expect(verdict.tier).toBe('high-risk')
  })

  it('merges report verbs with lex families even when a report verb is non-destructive', () => {
    const mixed = report({
      commands: [
        { verb: 'Get-ChildItem', strings: [], expandables: [], variables: [], parameters: [] },
        { verb: 'Remove-Item', strings: ['C:\\ws\\x.txt'], expandables: [], variables: [], parameters: [] },
      ],
    })
    const verdict = classifyPwsh('Remove-Item C:\\ws\\x.txt', mixed, facts({ families: ['delete'], literalPaths: ['C:\\ws\\x.txt'] }), CONTEXT)
    expect(verdict.tier).toBe('normal')
  })

  it('flags batch deletion as high-risk', () => {
    const verdict = classifyPwsh('Remove-Item a.txt, b.txt', deleteCommand(['a.txt', 'b.txt']), facts({ families: ['delete'], literalPaths: ['a.txt', 'b.txt'] }), CONTEXT)
    expect(verdict.tier).toBe('high-risk')
  })

  it('passes a single non-recursive deletion as normal', () => {
    const verdict = classifyPwsh('Remove-Item C:\\ws\\old.txt', deleteCommand(['C:\\ws\\old.txt']), facts({ families: ['delete'], literalPaths: ['C:\\ws\\old.txt'] }), CONTEXT)
    expect(verdict.tier).toBe('normal')
  })

  it('detects recursion from the AST report alone', () => {
    const verdict = classifyPwsh(
      'Remove-Item C:\\ws\\dir -Recurse',
      deleteCommand(['C:\\ws\\dir'], ['Recurse']),
      facts({ families: ['delete'], literalPaths: ['C:\\ws\\dir'] }),
      CONTEXT,
    )
    expect(verdict.tier).toBe('normal')
  })

  it('fails closed as unparseable without a readable report', () => {
    const verdict = classifyPwsh('Remove-Item C:\\ws\\x -Recurse', undefined, facts({ families: ['delete'], recursive: true, literalPaths: ['C:\\ws\\x'] }), CONTEXT)
    expect(verdict.tier).toBe('unparseable')
    const parsedWithErrors = classifyPwsh('Remove-Item C:\\ws\\x', report({ ok: false, parseErrors: 1 }), facts({ families: ['delete'], literalPaths: ['C:\\ws\\x'] }), CONTEXT)
    expect(parsedWithErrors.tier).toBe('unparseable')
  })

  it('fails closed as unparseable without a readable report and no lex recursion', () => {
    const verdict = classifyPwsh('Remove-Item C:\\ws\\x', undefined, facts({ families: ['delete'], literalPaths: ['C:\\ws\\x'] }), CONTEXT)
    expect(verdict.tier).toBe('unparseable')
  })
})

describe('classifyBash', () => {
  it('classifies non-destructive commands as normal', () => {
    expect(classifyBash(facts({ verbs: ['ls'] }), CONTEXT).tier).toBe('normal')
  })

  it('refuses the format family', () => {
    expect(classifyBash(facts({ families: ['format'], verbs: ['mkfs.ext4'] }), CONTEXT).tier).toBe('disaster')
  })

  it('refuses recursive deletion of protected roots', () => {
    const verdict = classifyBash(facts({ families: ['delete'], verbs: ['rm'], recursive: true, force: true, literalPaths: ['/'] }), CONTEXT)
    expect(verdict.tier).toBe('disaster')
  })

  it('flags recursive dynamic deletion as high-risk', () => {
    const verdict = classifyBash(facts({ families: ['delete'], verbs: ['rm'], recursive: true, dynamic: true }), CONTEXT)
    expect(verdict.tier).toBe('high-risk')
  })

  it('flags recursive forced deletion outside the workspace as high-risk', () => {
    const verdict = classifyBash(facts({ families: ['delete'], verbs: ['rm'], recursive: true, force: true, literalPaths: ['/home/other'] }), CONTEXT)
    expect(verdict.tier).toBe('high-risk')
  })

  it('flags find -delete as high-risk', () => {
    const verdict = classifyBash(facts({ families: ['delete'], verbs: ['find'], findDelete: true }), CONTEXT)
    expect(verdict.tier).toBe('high-risk')
  })

  it('passes a single non-recursive deletion as normal', () => {
    const verdict = classifyBash(facts({ families: ['delete'], verbs: ['rm'], literalPaths: ['/ws/old.txt'] }), CONTEXT)
    expect(verdict.tier).toBe('normal')
  })
})
