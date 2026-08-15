import { describe, expect, it } from 'vitest'
import { analyzeGit, isGitInvocation } from '../src/git.ts'

describe('isGitInvocation', () => {
  it('recognizes git and git.exe as the top-level verb', () => {
    expect(isGitInvocation(['git'])).toBe(true)
    expect(isGitInvocation(['GIT.EXE'])).toBe(true)
    expect(isGitInvocation(['remove-item'])).toBe(false)
    expect(isGitInvocation([])).toBe(false)
  })
})

describe('analyzeGit', () => {
  it('returns a silent result for an empty invocation', () => {
    expect(analyzeGit([])).toEqual({ destructive: false })
  })

  it('treats git rm --cached as index-only (non-destructive)', () => {
    expect(analyzeGit(['rm', '-r', '--cached', 'src'])).toMatchObject({ subcommand: 'rm', destructive: false })
    expect(analyzeGit(['rm', '--staged', 'x'])).toMatchObject({ subcommand: 'rm', destructive: false })
    expect(analyzeGit(['rm', '-n', 'x'])).toMatchObject({ subcommand: 'rm', destructive: false })
    expect(analyzeGit(['rm', '--dry-run', 'x'])).toMatchObject({ subcommand: 'rm', destructive: false })
  })

  it('flags git rm without a cache/dry-run flag', () => {
    const facts = analyzeGit(['rm', '-r', 'src'])
    expect(facts.destructive).toBe(true)
    expect(facts.reason).toContain('git rm without --cached')
  })

  it('flags git clean as destructive', () => {
    const facts = analyzeGit(['clean', '-fd'])
    expect(facts.destructive).toBe(true)
    expect(facts.reason).toContain('git clean deletes untracked')
  })

  it('flags only git reset --hard as destructive', () => {
    expect(analyzeGit(['reset', '--hard', 'HEAD~1']).destructive).toBe(true)
    expect(analyzeGit(['reset', '--soft', 'HEAD~1']).destructive).toBe(false)
    expect(analyzeGit(['reset', '--mixed']).destructive).toBe(false)
    expect(analyzeGit(['reset']).destructive).toBe(false)
  })

  it('leaves other subcommands silent', () => {
    expect(analyzeGit(['status'])).toEqual({ subcommand: 'status', destructive: false })
    expect(analyzeGit(['log', '--oneline'])).toMatchObject({ subcommand: 'log', destructive: false })
  })

  it('handles empty tokens and option tails', () => {
    expect(analyzeGit([''])).toEqual({ destructive: false })
    expect(analyzeGit(['-c', 'user.name'])).toEqual({ destructive: false })
  })

  it('handles quoted subcommand spellings and unknown first tokens', () => {
    expect(analyzeGit(['"rm"', '--cached', 'x'])).toMatchObject({ subcommand: 'rm', destructive: false })
    expect(analyzeGit(['-C', 'repo', 'status'])).toMatchObject({ subcommand: 'status', destructive: false })
  })
})
