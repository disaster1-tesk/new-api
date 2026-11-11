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
import type { AdminPermissionMatrix } from '@/lib/admin-permissions'

// RoleView mirrors the backend authz role JSON. Built-in roles report a
// member_count of 0 by design: their membership follows each user's account
// role, not a role binding.
export interface RoleView {
  key: string
  name: string
  description: string
  built_in: boolean
  superuser: boolean
  grants: AdminPermissionMatrix
  member_count: number
}

export interface RoleInput {
  key?: string
  name: string
  description: string
  grants: AdminPermissionMatrix
}

export interface RoleMember {
  id: number
  username: string
  display_name: string
}
