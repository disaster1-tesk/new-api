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
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import i18next from 'i18next'
import { Toaster, toast } from 'sonner'
import { afterEach, expect, it, vi } from 'vitest'

import { api } from '@/lib/api'

import { Roles } from '../index'
import type { RoleMember, RoleView } from '../types'

const roles: RoleView[] = [
  {
    key: 'root',
    name: 'Root',
    description: 'Built-in root authorization role',
    built_in: true,
    superuser: true,
    grants: {},
    member_count: 0,
  },
  {
    key: 'admin',
    name: 'Admin',
    description: 'Built-in admin authorization role',
    built_in: true,
    superuser: false,
    grants: { channel: { read: true, write: false } },
    member_count: 0,
  },
  {
    key: 'ops',
    name: 'Operations',
    description: 'Channel operators',
    built_in: false,
    superuser: false,
    grants: { channel: { read: true } },
    member_count: 2,
  },
]

const members: RoleMember[] = [
  { id: 5, username: 'alice', display_name: 'Alice' },
  { id: 6, username: 'bob', display_name: 'Bob' },
]

const admins = [
  { id: 6, username: 'bob', display_name: 'Bob', role: 10 },
  { id: 7, username: 'carol', display_name: 'Carol', role: 10 },
]

function mockGet() {
  return vi.spyOn(api, 'get').mockImplementation(async (url: string) => {
    if (url === '/api/authz/roles') {
      return { data: { success: true, data: roles } }
    }
    if (url === '/api/authz/catalog') {
      return {
        data: {
          success: true,
          data: {
            resources: [
              {
                resource: 'channel',
                label_key: 'Channels',
                actions: [
                  {
                    action: 'read',
                    label_key: 'View',
                    description_key: 'View channels',
                  },
                  {
                    action: 'write',
                    label_key: 'Edit',
                    description_key: 'Edit channels',
                  },
                ],
              },
            ],
            roles: [],
          },
        },
      }
    }
    if (url === '/api/authz/roles/ops/members') {
      return { data: { success: true, data: members } }
    }
    if (url.startsWith('/api/user/search?')) {
      const keyword = new URLSearchParams(url.split('?')[1]).get('keyword')
      const items = admins.filter((admin) =>
        admin.username.includes(keyword ?? '')
      )
      return {
        data: {
          success: true,
          data: { items, total: items.length, page: 1, page_size: 10 },
        },
      }
    }
    throw new Error(`unexpected GET ${url}`)
  })
}

function renderRoles() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  render(
    <QueryClientProvider client={client}>
      <Roles />
      <Toaster duration={60_000} />
    </QueryClientProvider>
  )
}

async function selectRole(name: RegExp) {
  await userEvent.click(await screen.findByRole('button', { name }))
}

function permissionToggles() {
  const group = screen.getByRole('group', { name: 'Channels' })
  return within(group).getAllByRole('button', { name: /^(View|Edit)/ })
}

afterEach(() => {
  toast.dismiss()
  vi.restoreAllMocks()
})

it('lists built-in roles before custom roles and shows member counts only for custom roles', async () => {
  mockGet()
  renderRoles()
  const list = await screen.findByRole('list', { name: 'Roles' })
  await within(list).findByRole('button', { name: /^Operations/ })
  const items = within(list).getAllByRole('button')
  expect(items.map((item) => item.textContent)).toEqual([
    expect.stringMatching(/^Root/),
    expect.stringMatching(/^Admin/),
    expect.stringMatching(/^Operations/),
  ])
  expect(items[1]).not.toHaveTextContent('Members')
  expect(items[2]).toHaveTextContent('Members: 2')
})

it('selecting the built-in admin role shows its permissions read-only', async () => {
  mockGet()
  renderRoles()
  await selectRole(/^Admin/)
  await waitFor(() => expect(permissionToggles()).toHaveLength(2))
  const [view, edit] = permissionToggles()
  expect(view).toBeDisabled()
  expect(view).toHaveAttribute('aria-pressed', 'true')
  expect(edit).toBeDisabled()
  expect(edit).toHaveAttribute('aria-pressed', 'false')
  expect(
    screen.queryByRole('button', { name: 'Save permissions' })
  ).not.toBeInTheDocument()
})

it('the root role shows every permission granted and read-only', async () => {
  mockGet()
  renderRoles()
  await selectRole(/^Root/)
  await waitFor(() => expect(permissionToggles()).toHaveLength(2))
  for (const toggle of permissionToggles()) {
    expect(toggle).toBeDisabled()
    expect(toggle).toHaveAttribute('aria-pressed', 'true')
  }
})

it('saving a custom role sends the toggled grant', async () => {
  mockGet()
  const put = vi.spyOn(api, 'put').mockResolvedValue({
    data: { success: true, data: roles[2] },
  })
  renderRoles()
  await selectRole(/^Operations/)
  await waitFor(() => expect(permissionToggles()).toHaveLength(2))
  const edit = permissionToggles()[1]
  expect(edit).toBeEnabled()
  await userEvent.click(edit)
  await userEvent.click(
    screen.getByRole('button', { name: 'Save permissions' })
  )
  await waitFor(() =>
    expect(put).toHaveBeenCalledWith('/api/authz/roles/ops', {
      name: 'Operations',
      description: 'Channel operators',
      grants: { channel: { read: true, write: true } },
    })
  )
})

it('adding a searched administrator saves the full member list', async () => {
  const get = mockGet()
  const put = vi
    .spyOn(api, 'put')
    .mockResolvedValue({ data: { success: true } })
  renderRoles()
  await selectRole(/^Operations/)
  await userEvent.click(screen.getByRole('tab', { name: 'Members' }))
  // Without a keyword every administrator is listed; Bob is already a member,
  // so only Carol can be added.
  await screen.findByRole('button', { name: 'Add Carol' })
  expect(
    screen.queryByRole('button', { name: 'Add Bob' })
  ).not.toBeInTheDocument()
  await userEvent.type(
    screen.getByRole('searchbox', { name: 'Search administrators' }),
    'car'
  )
  await waitFor(() =>
    expect(get).toHaveBeenCalledWith(
      expect.stringMatching(/^\/api\/user\/search\?keyword=car&.*role=10/)
    )
  )
  await userEvent.click(
    await screen.findByRole('button', { name: 'Add Carol' })
  )
  await userEvent.click(screen.getByRole('button', { name: 'Save members' }))
  await waitFor(() =>
    expect(put).toHaveBeenCalledWith('/api/authz/roles/ops/members', {
      user_ids: [5, 6, 7],
    })
  )
})

it('removing a member saves the remaining member list', async () => {
  mockGet()
  const put = vi
    .spyOn(api, 'put')
    .mockResolvedValue({ data: { success: true } })
  renderRoles()
  await selectRole(/^Operations/)
  await userEvent.click(screen.getByRole('tab', { name: 'Members' }))
  await userEvent.click(
    await screen.findByRole('button', { name: 'Remove Alice' })
  )
  await userEvent.click(screen.getByRole('button', { name: 'Save members' }))
  await waitFor(() =>
    expect(put).toHaveBeenCalledWith('/api/authz/roles/ops/members', {
      user_ids: [6],
    })
  )
})

it('deleting a role with members states the member count and forces the delete', async () => {
  mockGet()
  const remove = vi
    .spyOn(api, 'delete')
    .mockResolvedValue({ data: { success: true } })
  renderRoles()
  await selectRole(/^Operations/)
  await userEvent.click(screen.getByRole('button', { name: 'Delete role' }))
  const dialog = await screen.findByRole('alertdialog')
  expect(dialog).toHaveTextContent('This role has 2 members.')
  await userEvent.click(within(dialog).getByRole('button', { name: 'Delete' }))
  await waitFor(() =>
    expect(remove).toHaveBeenCalledWith('/api/authz/roles/ops?force=true')
  )
})

it('a failed save shows the server message key translated', async () => {
  const key = 'Built-in roles cannot be changed'
  i18next.addResource('en', 'translation', key, 'Translated built-in error')
  try {
    mockGet()
    vi.spyOn(api, 'put').mockResolvedValue({
      data: { success: false, message: key, message_key: key },
    })
    renderRoles()
    await selectRole(/^Operations/)
    await waitFor(() => expect(permissionToggles()).toHaveLength(2))
    await userEvent.click(permissionToggles()[1])
    await userEvent.click(
      screen.getByRole('button', { name: 'Save permissions' })
    )
    expect(
      await screen.findByText('Translated built-in error')
    ).toBeInTheDocument()
  } finally {
    i18next.addResource('en', 'translation', key, key)
  }
})

it('creating a role validates the optional key before posting', async () => {
  mockGet()
  const post = vi.spyOn(api, 'post').mockResolvedValue({
    data: {
      success: true,
      data: { ...roles[2], key: 'billing', name: 'Billing', member_count: 0 },
    },
  })
  renderRoles()
  await userEvent.click(
    await screen.findByRole('button', { name: 'Create role' })
  )
  const dialog = await screen.findByRole('dialog')
  await userEvent.type(
    within(dialog).getByRole('textbox', { name: /^Name/ }),
    'Billing'
  )
  const key = within(dialog).getByRole('textbox', { name: 'Role key' })
  await userEvent.type(key, 'Bad Key')
  await userEvent.click(within(dialog).getByRole('button', { name: 'Save' }))
  expect(
    await within(dialog).findByText(/^Role key must start with a lowercase/)
  ).toBeInTheDocument()
  expect(post).not.toHaveBeenCalled()
  await userEvent.clear(key)
  await userEvent.type(key, 'billing')
  await userEvent.click(within(dialog).getByRole('button', { name: 'Save' }))
  await waitFor(() =>
    expect(post).toHaveBeenCalledWith('/api/authz/roles', {
      key: 'billing',
      name: 'Billing',
      description: '',
      grants: {},
    })
  )
})
