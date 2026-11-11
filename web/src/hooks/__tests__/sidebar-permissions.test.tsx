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
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import {
  createMemoryHistory,
  createRootRoute,
  createRouter,
  RouterProvider,
} from '@tanstack/react-router'
import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it } from 'vitest'

import { useAuthStore } from '@/stores/auth-store'

import { useSidebarView } from '../use-sidebar-view'

afterEach(() => {
  cleanup()
  useAuthStore.getState().auth.reset()
})

function Entries() {
  const { navGroups } = useSidebarView()
  return (
    <ul aria-label='Entries'>
      {navGroups
        .flatMap((group) => group.items)
        .map((item) => (
          <li key={item.title}>{item.title}</li>
        ))}
    </ul>
  )
}

async function renderAdminSidebar() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  client.setQueryData(['status'], { SidebarModulesAdmin: '' })
  useAuthStore.getState().auth.setUser({
    id: 2,
    username: 'ops',
    role: 10,
    permissions: {
      sidebar_settings: true,
      sidebar_modules: { admin: { setting: false } },
      admin_permissions: {
        option: { read: true },
        channel: { read: true },
      },
    },
    // Role-generated default (setting) plus the user's own choice (channel).
    sidebar_modules: JSON.stringify({
      admin: { enabled: true, setting: false, channel: false },
    }),
  })
  const router = createRouter({
    routeTree: createRootRoute({ component: Entries }),
    history: createMemoryHistory({ initialEntries: ['/dashboard/overview'] }),
  })
  await router.load()
  render(
    <QueryClientProvider client={client}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  )
  return screen.findByRole('list', { name: 'Entries' })
}

describe('sidebar visibility for permitted admin modules', () => {
  it('shows System Settings when its stored false is a non-configurable role default', async () => {
    const list = await renderAdminSidebar()
    expect(list).toHaveTextContent('System Settings')
  })

  it('keeps Channels hidden when the user turned off a module they may configure', async () => {
    const list = await renderAdminSidebar()
    expect(list).not.toHaveTextContent('Channels')
  })
})
