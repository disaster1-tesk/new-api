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
import { useQuery } from '@tanstack/react-query'
import { Plus } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'

import { ErrorState } from '@/components/error-state'
import { SectionPageLayout } from '@/components/layout'
import { LoadingState } from '@/components/loading-state'
import { Button } from '@/components/ui/button'
import { getPermissionCatalog } from '@/features/users/api'
import { getServerErrorMessage } from '@/lib/server-error-message'

import { listRoles, rolesQueryKey } from './api'
import { RoleDetail } from './components/role-detail'
import { RoleList } from './components/role-list'
import { RoleMutateDialog } from './components/role-mutate-dialog'
import { RoleVerificationProvider } from './components/role-verification-provider'

// Roles is the root-only role management page: the role list on the left and
// the selected role's permissions and members on the right.
export function Roles() {
  const { t } = useTranslation()
  const [selectedKey, setSelectedKey] = useState<string | null>(null)
  const [createOpen, setCreateOpen] = useState(false)
  const rolesQuery = useQuery({
    queryKey: rolesQueryKey,
    queryFn: listRoles,
    meta: { errorToast: false },
  })
  const catalogQuery = useQuery({
    queryKey: ['admin-permission-catalog'],
    queryFn: getPermissionCatalog,
    meta: { errorToast: false },
  })
  const roles = rolesQuery.data ?? []
  const selected = roles.find((role) => role.key === selectedKey) ?? roles[0]
  const failed = rolesQuery.isError ? rolesQuery : catalogQuery

  let content = <LoadingState />
  if (rolesQuery.isError || catalogQuery.isError) {
    content = (
      <ErrorState
        description={getServerErrorMessage(
          failed.error,
          t('Failed to load roles')
        )}
        onRetry={() => void failed.refetch()}
      />
    )
  } else if (rolesQuery.data && catalogQuery.data) {
    content = (
      <div className='grid h-full min-h-0 gap-4 md:grid-cols-[16rem_minmax(0,1fr)]'>
        <div className='min-h-0 overflow-y-auto md:border-r md:pr-3'>
          <RoleList
            roles={roles}
            selectedKey={selected?.key ?? ''}
            onSelect={setSelectedKey}
          />
        </div>
        <div className='min-h-0 overflow-y-auto pb-2'>
          {selected && (
            <RoleDetail
              key={selected.key}
              role={selected}
              resources={catalogQuery.data.resources}
              onDeleted={() => setSelectedKey(null)}
            />
          )}
        </div>
      </div>
    )
  }

  return (
    <RoleVerificationProvider>
      <SectionPageLayout fixedContent>
        <SectionPageLayout.Title>
          {t('Roles & Permissions')}
        </SectionPageLayout.Title>
        <SectionPageLayout.Actions>
          <Button onClick={() => setCreateOpen(true)}>
            <Plus data-icon='inline-start' aria-hidden='true' />
            {t('Create role')}
          </Button>
        </SectionPageLayout.Actions>
        <SectionPageLayout.Content>{content}</SectionPageLayout.Content>
      </SectionPageLayout>
      <RoleMutateDialog
        open={createOpen}
        onOpenChange={setCreateOpen}
        onSaved={(role) => setSelectedKey(role.key)}
      />
    </RoleVerificationProvider>
  )
}
