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
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Info, Pencil, Trash2 } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'

import { ConfirmDialog } from '@/components/confirm-dialog'
import { PermissionMatrix } from '@/components/permission-matrix'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import type {
  AdminPermissionMatrix,
  PermissionResourceDef,
} from '@/lib/admin-permissions'
import { handleServerError } from '@/lib/handle-server-error'

import { deleteRole, invalidateRoleQueries, updateRole } from '../api'
import type { RoleView } from '../types'
import { RoleMembers } from './role-members'
import { RoleMutateDialog } from './role-mutate-dialog'
import { useRoleVerification } from './role-verification-provider'

type RoleDetailProps = {
  role: RoleView
  resources: PermissionResourceDef[]
  onDeleted: () => void
}

// RoleDetail is keyed by the role key, so the permission draft starts from
// the selected role's grants.
export function RoleDetail(props: RoleDetailProps) {
  const { t } = useTranslation()
  const client = useQueryClient()
  const { verifyRoleChange, verificationActive } = useRoleVerification()
  const role = props.role
  // Built-in role text is fixed English source text with locale entries;
  // custom role text is administrator input shown as written.
  const name = role.built_in ? t(role.name) : role.name
  const description = role.built_in ? t(role.description) : role.description
  const [draft, setDraft] = useState<AdminPermissionMatrix>(role.grants)
  const [editOpen, setEditOpen] = useState(false)
  const [deleteOpen, setDeleteOpen] = useState(false)

  // A superuser passes every check, whatever its stored grants say.
  const matrix: AdminPermissionMatrix = role.superuser
    ? Object.fromEntries(
        props.resources.map((resource) => [
          resource.resource,
          Object.fromEntries(
            resource.actions.map((option) => [option.action, true])
          ),
        ])
      )
    : draft
  const dirty = props.resources.some((resource) =>
    resource.actions.some(
      (option) =>
        (draft[resource.resource]?.[option.action] === true) !==
        (role.grants[resource.resource]?.[option.action] === true)
    )
  )

  // A cancelled verification resolves to null and sends nothing.
  const savePermissions = useMutation({
    mutationFn: async () => {
      const proof = await verifyRoleChange({
        action: 'update',
        role_key: role.key,
      })
      if (!proof) return null
      return updateRole(
        role.key,
        { name: role.name, description: role.description, grants: draft },
        proof
      )
    },
    onSuccess: async (saved) => {
      if (!saved) return
      await invalidateRoleQueries(client)
      toast.success(t('Permissions saved'))
    },
    onError: (error) => handleServerError(error),
  })
  const remove = useMutation({
    mutationFn: async () => {
      const proof = await verifyRoleChange({
        action: 'delete',
        role_key: role.key,
      })
      if (!proof) return false
      await deleteRole(role.key, role.member_count > 0, proof)
      return true
    },
    onSuccess: async (deleted) => {
      if (!deleted) return
      await invalidateRoleQueries(client)
      toast.success(t('Role deleted'))
      setDeleteOpen(false)
      props.onDeleted()
    },
    onError: (error) => handleServerError(error),
  })

  return (
    <div className='flex min-w-0 flex-col gap-4'>
      <div className='flex flex-wrap items-start justify-between gap-3'>
        <div className='flex min-w-0 flex-col gap-1'>
          <div className='flex items-center gap-2'>
            <h3 className='truncate text-base font-semibold'>{name}</h3>
            {role.built_in && (
              <Badge variant='secondary'>{t('Built-in')}</Badge>
            )}
          </div>
          <p className='text-muted-foreground font-mono text-xs'>{role.key}</p>
          {description && (
            <p className='text-muted-foreground text-sm break-words'>
              {description}
            </p>
          )}
        </div>
        {!role.built_in && (
          <div className='flex shrink-0 gap-2'>
            <Button
              variant='outline'
              size='sm'
              onClick={() => setEditOpen(true)}
            >
              <Pencil data-icon='inline-start' aria-hidden='true' />
              {t('Edit role')}
            </Button>
            <Button
              variant='outline'
              size='sm'
              onClick={() => setDeleteOpen(true)}
            >
              <Trash2 data-icon='inline-start' aria-hidden='true' />
              {t('Delete role')}
            </Button>
          </div>
        )}
      </div>

      <Tabs defaultValue='permissions'>
        <TabsList>
          <TabsTrigger value='permissions'>{t('Permissions')}</TabsTrigger>
          <TabsTrigger value='members'>{t('Members')}</TabsTrigger>
        </TabsList>
        <TabsContent
          value='permissions'
          keepMounted
          className='flex flex-col gap-3'
        >
          {role.built_in && (
            <Alert role='note'>
              <Info aria-hidden='true' />
              <AlertDescription>
                {role.superuser
                  ? t('The root role always has every permission.')
                  : t('Built-in roles are read-only.')}
              </AlertDescription>
            </Alert>
          )}
          <PermissionMatrix
            resources={props.resources}
            value={matrix}
            onChange={setDraft}
            disabled={role.built_in}
          />
          {!role.built_in && (
            <div className='flex justify-end gap-2'>
              {dirty && (
                <Button
                  variant='outline'
                  disabled={savePermissions.isPending}
                  onClick={() => setDraft(role.grants)}
                >
                  {t('Discard changes')}
                </Button>
              )}
              <Button
                disabled={!dirty || savePermissions.isPending}
                onClick={() => savePermissions.mutate()}
              >
                {savePermissions.isPending
                  ? t('Saving...')
                  : t('Save permissions')}
              </Button>
            </div>
          )}
        </TabsContent>
        <TabsContent value='members' keepMounted>
          {role.built_in ? (
            <Alert role='note'>
              <Info aria-hidden='true' />
              <AlertDescription>
                {t(
                  "Built-in role membership follows each user's account role."
                )}
              </AlertDescription>
            </Alert>
          ) : (
            <RoleMembers role={role} />
          )}
        </TabsContent>
      </Tabs>

      {!role.built_in && (
        <>
          <RoleMutateDialog
            open={editOpen}
            onOpenChange={setEditOpen}
            role={role}
          />
          <ConfirmDialog
            open={deleteOpen && !verificationActive}
            onOpenChange={setDeleteOpen}
            title={t('Delete role {{name}}?', { name: role.name })}
            desc={
              role.member_count > 0
                ? t(
                    'This role has {{total}} members. Deleting it also removes their role assignments.',
                    { total: role.member_count }
                  )
                : t('This action cannot be undone.')
            }
            confirmText={t('Delete')}
            destructive
            isLoading={remove.isPending}
            handleConfirm={() => remove.mutate()}
          />
        </>
      )}
    </div>
  )
}
