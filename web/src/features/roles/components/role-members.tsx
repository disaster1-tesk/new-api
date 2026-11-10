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
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Search, UserPlus, X } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'

import { EmptyState } from '@/components/empty-state'
import { ErrorState } from '@/components/error-state'
import { LoadingState } from '@/components/loading-state'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  InputGroup,
  InputGroupAddon,
  InputGroupInput,
} from '@/components/ui/input-group'
import {
  Item,
  ItemActions,
  ItemContent,
  ItemDescription,
  ItemGroup,
  ItemTitle,
} from '@/components/ui/item'
import { searchUsers } from '@/features/users/api'
import { useDebounce } from '@/hooks/use-debounce'
import { handleServerError } from '@/lib/handle-server-error'
import { ROLE } from '@/lib/roles'
import {
  getServerErrorMessage,
  requireServerSuccess,
} from '@/lib/server-error-message'

import {
  getRoleMembers,
  invalidateRoleQueries,
  rolesQueryKey,
  setRoleMembers,
} from '../api'
import type { RoleMember, RoleView } from '../types'

// RoleMembers edits the administrators bound to a custom role. Changes stay
// local until saved, then replace the whole member list.
export function RoleMembers(props: { role: RoleView }) {
  const { t } = useTranslation()
  const client = useQueryClient()
  const roleKey = props.role.key
  const [draft, setDraft] = useState<RoleMember[] | null>(null)
  const [search, setSearch] = useState('')
  const keyword = useDebounce(search.trim(), 300)
  const membersQuery = useQuery({
    queryKey: [...rolesQueryKey, roleKey, 'members'],
    queryFn: () => getRoleMembers(roleKey),
    meta: { errorToast: false },
  })
  const adminsQuery = useQuery({
    queryKey: ['authz-role-admin-search', keyword],
    queryFn: async () => {
      const res = requireServerSuccess(
        await searchUsers({ keyword, role: String(ROLE.ADMIN), page_size: 10 })
      )
      return res.data?.items ?? []
    },
    meta: { errorToast: false },
  })
  const members = draft ?? membersQuery.data ?? []
  const memberIds = new Set(members.map((member) => member.id))
  const save = useMutation({
    mutationFn: () =>
      setRoleMembers(
        roleKey,
        members.map((member) => member.id)
      ),
    onSuccess: async () => {
      await invalidateRoleQueries(client)
      setDraft(null)
      toast.success(t('Members saved'))
    },
    onError: (error) => handleServerError(error),
  })

  if (membersQuery.isPending) return <LoadingState />
  if (membersQuery.isError) {
    return (
      <ErrorState
        description={getServerErrorMessage(membersQuery.error)}
        onRetry={() => void membersQuery.refetch()}
      />
    )
  }

  return (
    <div className='flex flex-col gap-4'>
      <div className='grid gap-4 lg:grid-cols-2'>
        <section
          aria-labelledby='role-current-members'
          className='flex min-w-0 flex-col gap-2'
        >
          <h3 id='role-current-members' className='text-sm font-medium'>
            {t('Current members')}
          </h3>
          {members.length === 0 ? (
            <EmptyState
              bordered
              className='min-h-0 py-6'
              title={t('No members yet')}
              description={t('Search for administrators to add them.')}
            />
          ) : (
            <ItemGroup className='gap-1'>
              {members.map((member) => {
                const name = member.display_name || member.username
                return (
                  <Item
                    key={member.id}
                    role='listitem'
                    size='xs'
                    variant='outline'
                  >
                    <ItemContent className='min-w-0'>
                      <ItemTitle className='truncate'>{name}</ItemTitle>
                      {member.display_name && (
                        <ItemDescription className='truncate'>
                          {member.username}
                        </ItemDescription>
                      )}
                    </ItemContent>
                    <ItemActions>
                      <Button
                        variant='ghost'
                        size='icon-sm'
                        aria-label={t('Remove {{name}}', { name })}
                        onClick={() =>
                          setDraft(
                            members.filter((item) => item.id !== member.id)
                          )
                        }
                      >
                        <X aria-hidden='true' />
                      </Button>
                    </ItemActions>
                  </Item>
                )
              })}
            </ItemGroup>
          )}
        </section>
        <section
          aria-labelledby='role-add-members'
          className='flex min-w-0 flex-col gap-2'
        >
          <h3 id='role-add-members' className='text-sm font-medium'>
            {t('Add administrators')}
          </h3>
          <InputGroup>
            <InputGroupInput
              type='search'
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder={t('Search by username or display name')}
              aria-label={t('Search administrators')}
            />
            <InputGroupAddon>
              <Search aria-hidden='true' />
            </InputGroupAddon>
          </InputGroup>
          {adminsQuery.isPending && (
            <LoadingState size='sm' className='min-h-24' />
          )}
          {adminsQuery.isError && (
            <ErrorState
              className='min-h-0 py-6'
              description={getServerErrorMessage(adminsQuery.error)}
              onRetry={() => void adminsQuery.refetch()}
            />
          )}
          {adminsQuery.data?.length === 0 && (
            <EmptyState
              bordered
              className='min-h-0 py-6'
              title={t('No administrators found')}
            />
          )}
          {adminsQuery.data && adminsQuery.data.length > 0 && (
            <ItemGroup className='gap-1'>
              {adminsQuery.data.map((user) => {
                const name = user.display_name || user.username
                return (
                  <Item
                    key={user.id}
                    role='listitem'
                    size='xs'
                    variant='outline'
                  >
                    <ItemContent className='min-w-0'>
                      <ItemTitle className='truncate'>{name}</ItemTitle>
                      {user.display_name && (
                        <ItemDescription className='truncate'>
                          {user.username}
                        </ItemDescription>
                      )}
                    </ItemContent>
                    <ItemActions>
                      {memberIds.has(user.id) ? (
                        <Badge variant='secondary'>{t('Member')}</Badge>
                      ) : (
                        <Button
                          variant='outline'
                          size='sm'
                          aria-label={t('Add {{name}}', { name })}
                          onClick={() =>
                            setDraft([
                              ...members,
                              {
                                id: user.id,
                                username: user.username,
                                display_name: user.display_name ?? '',
                              },
                            ])
                          }
                        >
                          <UserPlus
                            data-icon='inline-start'
                            aria-hidden='true'
                          />
                          {t('Add')}
                        </Button>
                      )}
                    </ItemActions>
                  </Item>
                )
              })}
            </ItemGroup>
          )}
        </section>
      </div>
      <div className='flex justify-end gap-2'>
        {draft !== null && (
          <Button
            variant='outline'
            disabled={save.isPending}
            onClick={() => setDraft(null)}
          >
            {t('Discard changes')}
          </Button>
        )}
        <Button
          disabled={draft === null || save.isPending}
          onClick={() => save.mutate()}
        >
          {save.isPending ? t('Saving...') : t('Save members')}
        </Button>
      </div>
    </div>
  )
}
