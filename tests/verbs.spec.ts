import { describe, expect, it } from 'vitest'
import {
  CMD_FORCE_SWITCHES,
  CMD_MIRROR_SWITCHES,
  CMD_RECURSIVE_SWITCHES,
  NET_DELETE_CALL,
  bashVerbFamily,
  isPwshDynamicVerb,
  pwshVerbFamily,
} from '../src/verbs.ts'

describe('pwshVerbFamily', () => {
  it('canonicalizes every delete verb and alias to the delete family', () => {
    for (const verb of ['Remove-Item', 'rm', 'del', 'erase', 'rd', 'rmdir', 'ri']) {
      expect(pwshVerbFamily(verb)).toBe('delete')
    }
  })

  it('canonicalizes the format/disk family', () => {
    for (const verb of ['Format', 'Format-Volume', 'Clear-Disk', 'Initialize-Disk', 'Remove-Partition']) {
      expect(pwshVerbFamily(verb)).toBe('format')
    }
  })

  it('canonicalizes the recycle verb', () => {
    expect(pwshVerbFamily('Clear-RecycleBin')).toBe('recycle')
  })

  it('is case-insensitive', () => {
    expect(pwshVerbFamily('REMOVE-ITEM')).toBe('delete')
    expect(pwshVerbFamily('rm')).toBe('delete')
  })

  it('returns undefined for non-destructive verbs', () => {
    for (const verb of ['Get-ChildItem', 'Set-Content', 'Write-Output', 'npm', 'node']) {
      expect(pwshVerbFamily(verb)).toBeUndefined()
    }
  })
})

describe('isPwshDynamicVerb', () => {
  it('recognizes iex and Invoke-Expression', () => {
    expect(isPwshDynamicVerb('iex')).toBe(true)
    expect(isPwshDynamicVerb('Invoke-Expression')).toBe(true)
    expect(isPwshDynamicVerb('IEX')).toBe(true)
  })

  it('rejects ordinary verbs', () => {
    expect(isPwshDynamicVerb('Remove-Item')).toBe(false)
  })
})

describe('bashVerbFamily', () => {
  it('canonicalizes bash delete verbs', () => {
    for (const verb of ['rm', 'rmdir', 'unlink', 'shred']) {
      expect(bashVerbFamily(verb)).toBe('delete')
    }
  })

  it('canonicalizes bash format verbs', () => {
    for (const verb of ['mkfs', 'mkfs.ext4', 'mkfs.xfs', 'mkfs.btrfs', 'mkswap', 'fdisk', 'wipefs']) {
      expect(bashVerbFamily(verb)).toBe('format')
    }
  })

  it('returns undefined for non-destructive bash verbs', () => {
    expect(bashVerbFamily('ls')).toBeUndefined()
    expect(bashVerbFamily('Remove-Item')).toBeUndefined()
  })
})

describe('switch vocabularies', () => {
  it('names the cmd recursive, force, and mirror switches', () => {
    expect(CMD_RECURSIVE_SWITCHES.has('/s')).toBe(true)
    expect(CMD_FORCE_SWITCHES.has('/q')).toBe(true)
    expect(CMD_FORCE_SWITCHES.has('/f')).toBe(true)
    expect(CMD_MIRROR_SWITCHES.has('/mir')).toBe(true)
  })

  it('matches .NET deletion member calls and rejects look-alikes', () => {
    expect(NET_DELETE_CALL.test('[System.IO.Directory]::Delete("D:\\", $true)')).toBe(true)
    expect(NET_DELETE_CALL.test('[IO.File]::Delete("x.txt")')).toBe(true)
    expect(NET_DELETE_CALL.test('[System.IO.Directory]::Exists("x")')).toBe(false)
    expect(NET_DELETE_CALL.test('Remove-Item x')).toBe(false)
  })
})
