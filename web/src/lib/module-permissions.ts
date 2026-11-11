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
import type { AuthUser } from '@/stores/auth-store'

import { hasPermission } from './admin-permissions'
import { ROLE } from './roles'

export type ModulePermission = {
  prefix: string
  resource: string
  action: string
  // Minimum role that reached this module before custom roles existed.
  upstreamMinRole: number
}

// Admin modules gated by a resource permission. Paths not listed here are not
// module-gated (they keep their own role checks).
export const MODULE_PERMISSIONS: readonly ModulePermission[] = [
  {
    prefix: '/channels',
    resource: 'channel',
    action: 'read',
    upstreamMinRole: ROLE.ADMIN,
  },
  {
    prefix: '/models/deployments',
    resource: 'deployment',
    action: 'read',
    upstreamMinRole: ROLE.ADMIN,
  },
  {
    prefix: '/models',
    resource: 'model',
    action: 'read',
    upstreamMinRole: ROLE.ADMIN,
  },
  {
    prefix: '/users',
    resource: 'user',
    action: 'read',
    upstreamMinRole: ROLE.ADMIN,
  },
  {
    prefix: '/redemption-codes',
    resource: 'redemption',
    action: 'read',
    upstreamMinRole: ROLE.ADMIN,
  },
  {
    prefix: '/subscriptions',
    resource: 'billing',
    action: 'read',
    upstreamMinRole: ROLE.ADMIN,
  },
  {
    prefix: '/system-info',
    resource: 'ops',
    action: 'read',
    upstreamMinRole: ROLE.SUPER_ADMIN,
  },
  {
    prefix: '/task-plugins',
    resource: 'plugin',
    action: 'read',
    upstreamMinRole: ROLE.SUPER_ADMIN,
  },
  {
    prefix: '/system-settings',
    resource: 'option',
    action: 'read',
    upstreamMinRole: ROLE.SUPER_ADMIN,
  },
]

export function requiredPermissionForPath(
  pathname: string | undefined
): ModulePermission | null {
  if (!pathname) return null
  let best: ModulePermission | null = null
  for (const rule of MODULE_PERMISSIONS) {
    const matches =
      pathname === rule.prefix || pathname.startsWith(`${rule.prefix}/`)
    if (matches && (!best || rule.prefix.length > best.prefix.length)) {
      best = rule
    }
  }
  return best
}

export function canAccessPath(
  user: AuthUser | null | undefined,
  pathname: string | undefined
): boolean {
  const rule = requiredPermissionForPath(pathname)
  if (!rule) return true
  if (!user) return false
  // Without a matrix (e.g. older payloads) keep the pre-RBAC role gate.
  if (!hasAdminPermissionMatrix(user)) return user.role >= rule.upstreamMinRole
  return hasPermission(user, rule.resource, rule.action)
}

export function hasAdminPermissionMatrix(
  user: AuthUser | null | undefined
): boolean {
  return user?.permissions?.admin_permissions !== undefined
}

// The backend tells the client which sidebar modules the user may configure
// (permissions.sidebar_modules). A stored `false` for a module the user cannot
// configure is a role-generated default, not their choice, so it must not
// narrow the sidebar.
export function dropNonConfigurableSidebarModules<
  T extends Record<string, Record<string, boolean>>,
>(config: T | null, allowed: Record<string, unknown> | undefined): T | null {
  if (!config || !allowed) return config
  const result: Record<string, Record<string, boolean>> = {}
  for (const [section, modules] of Object.entries(config)) {
    const allowedSection = allowed[section]
    if (allowedSection === false) continue
    const allowedModules =
      allowedSection && typeof allowedSection === 'object'
        ? (allowedSection as Record<string, unknown>)
        : {}
    result[section] = Object.fromEntries(
      Object.entries(modules).filter(([key]) => allowedModules[key] !== false)
    )
  }
  return result as T
}
