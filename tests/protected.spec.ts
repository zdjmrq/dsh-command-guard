import { describe, expect, it } from 'vitest'
import {
  buildProtectedRoots,
  isBareDriveForm,
  isDriveRootPath,
  isDriveRootWildcard,
  isExtendedRoot,
  isInside,
  isPosixRoot,
  isProtectedTarget,
  isUncRoot,
  normalizeTarget,
  type ProtectedRoots,
} from '../src/protected.ts'

const ROOTS: ProtectedRoots = buildProtectedRoots([], {
  SystemRoot: 'C:\\Windows',
  ProgramFiles: 'C:\\Program Files',
  USERPROFILE: 'C:\\Users\\me',
})

describe('root-shape predicates', () => {
  it('distinguishes drive roots from bare drive forms', () => {
    expect(isDriveRootPath('C:\\')).toBe(true)
    expect(isDriveRootPath('c:\\')).toBe(true)
    expect(isDriveRootPath('C:')).toBe(false)
    expect(isBareDriveForm('C:')).toBe(true)
    expect(isBareDriveForm('C:\\')).toBe(false)
  })

  it('matches drive-root wildcards but not deeper globs', () => {
    expect(isDriveRootWildcard('C:\\*')).toBe(true)
    expect(isDriveRootWildcard('C:\\*.*')).toBe(true)
    expect(isDriveRootWildcard('C:*')).toBe(true)
    expect(isDriveRootWildcard('C:\\foo\\*')).toBe(false)
  })

  it('matches extended-length roots', () => {
    expect(isExtendedRoot('\\\\?\\C:\\')).toBe(true)
    expect(isExtendedRoot('\\\\?\\C:\\')).toBe(true)
    expect(isExtendedRoot('\\\\?\\C:\\foo')).toBe(false)
  })

  it('matches UNC share roots but not deeper paths', () => {
    expect(isUncRoot('\\\\server\\share')).toBe(true)
    expect(isUncRoot('\\\\server\\share\\')).toBe(true)
    expect(isUncRoot('\\\\server\\share\\sub')).toBe(false)
  })

  it('matches the POSIX root', () => {
    expect(isPosixRoot('/')).toBe(true)
    expect(isPosixRoot('/tmp')).toBe(false)
  })
})

describe('normalizeTarget', () => {
  it('strips quotes, trailing globs, and trailing separators', () => {
    expect(normalizeTarget('"C:\\foo\\"')).toBe('C:\\foo')
    expect(normalizeTarget("'C:\\foo'")).toBe('C:\\foo')
    expect(normalizeTarget('C:\\foo\\*')).toBe('C:\\foo')
    expect(normalizeTarget('C:\\foo\\')).toBe('C:\\foo')
    expect(normalizeTarget('  C:\\foo  ')).toBe('C:\\foo')
  })
})

describe('buildProtectedRoots', () => {
  it('collects system roots, the home root, and configured extras', () => {
    const roots = buildProtectedRoots(['D:\\extra'], {
      SystemRoot: 'C:\\Windows',
      USERPROFILE: 'C:\\Users\\me',
    })
    expect(roots.system).toContain('c:\\windows')
    expect(roots.home).toBe('c:\\users\\me')
    expect(roots.roots).toContain('d:\\extra')
  })

  it('skips empty configured extras', () => {
    const roots = buildProtectedRoots(['  '], {})
    expect(roots.roots).not.toContain('')
  })

  it('falls back to HOME and then cwd for the home root', () => {
    const withHome = buildProtectedRoots([], { HOME: '/home/tester' })
    expect(withHome.home).toBe('/home/tester')
    const bare = buildProtectedRoots([], {})
    expect(bare.home.length).toBeGreaterThan(0)
  })

  it('folds Windows-form entries case-insensitively', () => {
    const roots = buildProtectedRoots(['D:\\Extra'], {})
    expect(roots.roots).toContain('d:\\extra')
  })
})

describe('isProtectedTarget', () => {
  it('protects every structural root form', () => {
    expect(isProtectedTarget('C:\\', ROOTS)).toBe(true)
    expect(isProtectedTarget('E:\\', ROOTS)).toBe(true)
    expect(isProtectedTarget('C:\\*', ROOTS)).toBe(true)
    expect(isProtectedTarget('\\\\server\\share\\', ROOTS)).toBe(true)
    expect(isProtectedTarget('\\\\?\\D:\\', ROOTS)).toBe(true)
    expect(isProtectedTarget('/', ROOTS)).toBe(true)
  })

  it('protects the platform roots from the registry', () => {
    expect(isProtectedTarget('C:\\Windows', ROOTS)).toBe(true)
    expect(isProtectedTarget('c:\\windows\\system32', ROOTS)).toBe(false)
    expect(isProtectedTarget('C:\\Users\\me', ROOTS)).toBe(true)
    expect(isProtectedTarget('C:\\Users\\me\\docs', ROOTS)).toBe(false)
  })

  it('rejects ordinary paths', () => {
    expect(isProtectedTarget('C:\\work\\project', ROOTS)).toBe(false)
    expect(isProtectedTarget('D:\\data', ROOTS)).toBe(false)
  })
})

describe('isInside', () => {
  it('treats equality as inside', () => {
    expect(isInside('C:\\ws', 'C:\\ws')).toBe(true)
  })

  it('treats strict descendants as inside and siblings as outside', () => {
    expect(isInside('C:\\ws', 'C:\\ws\\sub\\file.txt')).toBe(true)
    expect(isInside('C:\\ws', 'C:\\wsx\\file.txt')).toBe(false)
    expect(isInside('C:\\ws', 'C:\\other')).toBe(false)
  })

  it('folds case on Windows forms', () => {
    expect(isInside('C:\\WS', 'c:\\ws\\a.txt')).toBe(true)
  })

  it('handles the empty-parent edge', () => {
    expect(isInside('', 'x')).toBe(false)
    expect(isInside('', '')).toBe(true)
  })
})
