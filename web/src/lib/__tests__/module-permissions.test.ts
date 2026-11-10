/*
Copyright (C) 2023-2026 QuantumNous

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.

For commercial licensing, please contact support@quantumnous.com
*/
import { describe, expect, it } from 'vitest'

import {
  canAccessPath,
  requiredPermissionForPath,
} from '@/lib/module-permissions'
import type { AuthUser } from '@/stores/auth-store'

function adminWith(matrix: Record<string, Record<string, boolean>>): AuthUser {
  return {
    id: 2,
    role: 10,
    permissions: { admin_permissions: matrix },
  } as unknown as AuthUser
}

const root = { id: 1, role: 100 } as unknown as AuthUser

describe('canAccessPath', () => {
  it('allows root on any module path without a matrix', () => {
    expect(canAccessPath(root, '/system-settings/site')).toBe(true)
    expect(canAccessPath(root, '/users')).toBe(true)
  })

  it('allows only the modules whose permission the admin holds', () => {
    const admin = adminWith({ channel: { read: true } })
    expect(canAccessPath(admin, '/channels')).toBe(true)
    expect(canAccessPath(admin, '/users')).toBe(false)
    expect(canAccessPath(admin, '/system-settings/site')).toBe(false)
  })

  it('allows system settings subpaths with option.read', () => {
    const admin = adminWith({ option: { read: true } })
    expect(canAccessPath(admin, '/system-settings/auth')).toBe(true)
  })

  it('allows paths without a module rule', () => {
    const admin = adminWith({})
    expect(canAccessPath(admin, '/dashboard')).toBe(true)
    expect(canAccessPath(admin, '/usage-logs/audit')).toBe(true)
    expect(canAccessPath(admin, '/roles')).toBe(true)
    expect(canAccessPath(admin, undefined)).toBe(true)
  })

  it('denies a null user on a module path', () => {
    expect(canAccessPath(null, '/users')).toBe(false)
  })
})

describe('canAccessPath without a permission matrix', () => {
  it('keeps the upstream role gate for admin, root and common users', () => {
    const admin = { id: 2, role: 10 } as unknown as AuthUser
    const common = { id: 3, role: 1 } as unknown as AuthUser
    const noMatrixRoot = { id: 1, role: 100 } as unknown as AuthUser
    expect(canAccessPath(admin, '/users')).toBe(true)
    expect(canAccessPath(admin, '/system-settings/site')).toBe(false)
    expect(canAccessPath(noMatrixRoot, '/system-settings/site')).toBe(true)
    expect(canAccessPath(common, '/users')).toBe(false)
  })
})

describe('requiredPermissionForPath', () => {
  it('uses the longest matching prefix', () => {
    expect(requiredPermissionForPath('/models/deployments')).toMatchObject({
      resource: 'deployment',
      action: 'read',
    })
    expect(requiredPermissionForPath('/models/metadata')).toMatchObject({
      resource: 'model',
      action: 'read',
    })
  })

  it('requires a slash boundary after the prefix', () => {
    expect(requiredPermissionForPath('/channelsx')).toBeNull()
  })
})
