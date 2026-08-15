import { describe, expect, it } from 'vitest'
import { hasDestructiveSignal, hasNetDeleteCall, lexBash, lexPwsh } from '../src/lexer.ts'

describe('hasNetDeleteCall', () => {
  it('matches .NET deletion calls and rejects look-alikes', () => {
    expect(hasNetDeleteCall('[System.IO.Directory]::Delete("D:\\", $true)')).toBe(true)
    expect(hasNetDeleteCall('[IO.File]::Delete("x.txt")')).toBe(true)
    expect(hasNetDeleteCall('[System.IO.Directory]::Exists("x")')).toBe(false)
  })
})

describe('lexPwsh', () => {
  it('collects delete verbs, literal paths, and switch markers', () => {
    const facts = lexPwsh('Remove-Item -Path C:\\temp -Recurse -Force')
    expect(facts.families).toContain('delete')
    expect(facts.verbs).toContain('remove-item')
    expect(facts.literalPaths).toContain('C:\\temp')
    expect(facts.recursive).toBe(true)
    expect(facts.force).toBe(true)
  })

  it('keeps quoted paths with spaces as one token', () => {
    const facts = lexPwsh('Remove-Item "C:\\my dir\\file.txt"')
    expect(facts.literalPaths).toContain('C:\\my dir\\file.txt')
  })

  it('recognizes cmd-style switches on rd and del', () => {
    expect(lexPwsh('rd /s /q D:\\data').recursive).toBe(true)
    expect(lexPwsh('rd /s /q D:\\data').force).toBe(true)
    expect(lexPwsh('del /s D:\\*').wildcard).toBe(true)
  })

  it('flags robocopy mirror switches', () => {
    expect(lexPwsh('robocopy C:\\empty D:\\ /MIR').robocopyMir).toBe(true)
    expect(lexPwsh('robocopy C:\\empty D:\\ /mir').robocopyMir).toBe(true)
    expect(lexPwsh('robocopy C:\\a D:\\b').robocopyMir).toBe(false)
  })

  it('flags diskpart clean', () => {
    expect(lexPwsh('diskpart clean').diskpartClean).toBe(true)
    expect(lexPwsh('diskpart list disk').diskpartClean).toBe(false)
  })

  it('flags .NET deletion calls', () => {
    expect(lexPwsh('[System.IO.Directory]::Delete("D:\\", $true)').netDeleteCall).toBe(true)
    expect(lexPwsh('Get-ChildItem D:\\').netDeleteCall).toBe(false)
  })

  it('flags dynamic markers', () => {
    expect(lexPwsh('Remove-Item $target -Recurse').dynamic).toBe(true)
    expect(lexPwsh('Remove-Item "$env:USERPROFILE\\Docs"').dynamic).toBe(true)
    expect(lexPwsh('Remove-Item C:\\x').dynamic).toBe(false)
  })

  it('detects wildcards in path tokens', () => {
    expect(lexPwsh('Remove-Item D:\\*').wildcard).toBe(true)
    expect(lexPwsh('Remove-Item D:\\file.txt').wildcard).toBe(false)
  })

  it('skips empty quoted tokens', () => {
    const facts = lexPwsh('Remove-Item "" C:\\x')
    expect(facts.literalPaths).toEqual(['C:\\x'])
  })

  it('tolerates repeated whitespace and a trailing space', () => {
    const facts = lexPwsh('  Remove-Item    C:\\x  ')
    expect(facts.families).toContain('delete')
    expect(facts.literalPaths).toEqual(['C:\\x'])
  })

  it('tokenizes single-quoted spans as one token', () => {
    const facts = lexPwsh("Remove-Item 'C:\\my dir\\file.txt'")
    expect(facts.literalPaths).toContain('C:\\my dir\\file.txt')
  })

  it('recognizes long-form PowerShell recurse/force parameters', () => {
    const facts = lexPwsh('Remove-Item C:\\temp --recurse --force')
    expect(facts.recursive).toBe(true)
    expect(facts.force).toBe(true)
  })

  it('flags dynamic-execution verbs', () => {
    expect(lexPwsh('iex (Get-Content script.ps1)').dynamicVerb).toBe(true)
    expect(lexPwsh('Invoke-Expression "x"').dynamicVerb).toBe(true)
    expect(hasDestructiveSignal(lexPwsh('iex (Get-Content script.ps1)'))).toBe(true)
  })

  it('reports no destructive signal for ordinary commands', () => {
    const facts = lexPwsh('Get-ChildItem C:\\workspace | Select-Object Name')
    expect(hasDestructiveSignal(facts)).toBe(false)
  })

  it('reports destructive signal through families, net calls, diskpart, and robocopy', () => {
    expect(hasDestructiveSignal(lexPwsh('Remove-Item x'))).toBe(true)
    expect(hasDestructiveSignal(lexPwsh('[IO.File]::Delete("x")'))).toBe(true)
    expect(hasDestructiveSignal(lexPwsh('diskpart clean'))).toBe(true)
    expect(hasDestructiveSignal(lexPwsh('robocopy a b /MIR'))).toBe(true)
  })
})

describe('lexBash', () => {
  it('collects delete verbs and flags', () => {
    const facts = lexBash('rm -rf /home/user/project')
    expect(facts.families).toContain('delete')
    expect(facts.recursive).toBe(true)
    expect(facts.force).toBe(true)
    expect(facts.literalPaths).toContain('/home/user/project')
  })

  it('recognizes long-form recursive/force switches', () => {
    const facts = lexBash('rm --recursive --force /tmp/x')
    expect(facts.recursive).toBe(true)
    expect(facts.force).toBe(true)
  })

  it('flags find -delete as a delete family', () => {
    const facts = lexBash('find . -name "*.log" -delete')
    expect(facts.findDelete).toBe(true)
    expect(facts.families).toContain('delete')
  })

  it('flags dynamic markers', () => {
    expect(lexBash('rm -rf "$HOME/docs"').dynamic).toBe(true)
    expect(lexBash('rm -rf $(echo /tmp)').dynamic).toBe(true)
    expect(lexBash('rm -rf /tmp/x').dynamic).toBe(false)
  })

  it('detects path wildcards and skips empty quoted tokens', () => {
    expect(lexBash('rm /tmp/*.log').wildcard).toBe(true)
    expect(lexBash('rm "" /tmp/x').literalPaths).toEqual(['/tmp/x'])
  })

  it('reports no destructive signal for ordinary commands', () => {
    expect(hasDestructiveSignal(lexBash('ls -la /tmp'))).toBe(false)
  })

  it('canonicalizes format verbs to the format family', () => {
    expect(lexBash('mkfs.ext4 /dev/sdb1').families).toContain('format')
  })
})
