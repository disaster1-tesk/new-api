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
import type { QueryClient } from '@tanstack/react-query'

import { api } from '@/lib/api'
import { requireServerSuccess } from '@/lib/server-error-message'

import type { RoleInput, RoleMember, RoleView } from './types'

// Every endpoint is root-only. Failures come back as `success: false` with an
// English `message_key`, which requireServerSuccess turns into a translated
// error for the caller to present.

export async function listRoles(): Promise<RoleView[]> {
  const res = await api.get('/api/authz/roles')
  requireServerSuccess(res.data)
  return res.data?.data ?? []
}

export async function createRole(input: RoleInput): Promise<RoleView> {
  const res = await api.post('/api/authz/roles', input)
  requireServerSuccess(res.data)
  return res.data.data
}

export async function updateRole(
  key: string,
  input: Omit<RoleInput, 'key'>
): Promise<RoleView> {
  const res = await api.put(
    `/api/authz/roles/${encodeURIComponent(key)}`,
    input
  )
  requireServerSuccess(res.data)
  return res.data.data
}

// force removes the role's member bindings together with the role.
export async function deleteRole(key: string, force: boolean): Promise<void> {
  const query = force ? '?force=true' : ''
  const res = await api.delete(
    `/api/authz/roles/${encodeURIComponent(key)}${query}`
  )
  requireServerSuccess(res.data)
}

export async function getRoleMembers(key: string): Promise<RoleMember[]> {
  const res = await api.get(
    `/api/authz/roles/${encodeURIComponent(key)}/members`
  )
  requireServerSuccess(res.data)
  return res.data?.data ?? []
}

export async function setRoleMembers(
  key: string,
  userIds: number[]
): Promise<void> {
  const res = await api.put(
    `/api/authz/roles/${encodeURIComponent(key)}/members`,
    { user_ids: userIds }
  )
  requireServerSuccess(res.data)
}

export const rolesQueryKey = ['authz-roles'] as const

// Role writes change the role list, member counts and the catalog's role
// baselines, so every write refreshes both.
export async function invalidateRoleQueries(
  client: QueryClient
): Promise<void> {
  await Promise.all([
    client.invalidateQueries({ queryKey: rolesQueryKey }),
    client.invalidateQueries({ queryKey: ['admin-permission-catalog'] }),
  ])
}
