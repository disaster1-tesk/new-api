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
import { zodResolver } from '@hookform/resolvers/zod'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useEffect } from 'react'
import { useForm } from 'react-hook-form'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { z } from 'zod'

import { Dialog } from '@/components/dialog'
import { Button } from '@/components/ui/button'
import {
  Form,
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import { handleServerError } from '@/lib/handle-server-error'

import { createRole, invalidateRoleQueries, updateRole } from '../api'
import type { RoleView } from '../types'

// Same rule as the backend role key check; messages are locale keys that
// FormMessage translates.
const ROLE_KEY_PATTERN = /^[a-z][a-z0-9_-]{0,63}$/

const roleFormSchema = z.object({
  name: z.string().trim().min(1, 'Role name is required'),
  key: z
    .string()
    .trim()
    .refine(
      (value) => value === '' || ROLE_KEY_PATTERN.test(value),
      'Role key must start with a lowercase letter and contain only lowercase letters, digits, hyphens, or underscores'
    ),
  description: z.string().trim(),
})

type RoleFormValues = z.infer<typeof roleFormSchema>

type RoleMutateDialogProps = {
  open: boolean
  onOpenChange: (open: boolean) => void
  // Editing keeps the role's key and grants; only name and description change.
  role?: RoleView
  onSaved?: (role: RoleView) => void
}

export function RoleMutateDialog(props: RoleMutateDialogProps) {
  const { t } = useTranslation()
  const client = useQueryClient()
  const role = props.role
  const form = useForm<RoleFormValues>({
    resolver: zodResolver(roleFormSchema),
    defaultValues: { name: '', key: '', description: '' },
  })
  useEffect(() => {
    if (!props.open) return
    form.reset({
      name: role?.name ?? '',
      key: role?.key ?? '',
      description: role?.description ?? '',
    })
  }, [props.open, role, form])
  const save = useMutation({
    mutationFn: (values: RoleFormValues) => {
      if (role) {
        return updateRole(role.key, {
          name: values.name,
          description: values.description,
          grants: role.grants,
        })
      }
      return createRole({
        key: values.key || undefined,
        name: values.name,
        description: values.description,
        grants: {},
      })
    },
    onSuccess: async (saved) => {
      await invalidateRoleQueries(client)
      toast.success(role ? t('Role updated') : t('Role created'))
      props.onOpenChange(false)
      props.onSaved?.(saved)
    },
    onError: (error) => handleServerError(error),
  })
  return (
    <Dialog
      open={props.open}
      onOpenChange={(open) => {
        if (!save.isPending) props.onOpenChange(open)
      }}
      title={role ? t('Edit role') : t('Create role')}
      description={
        role
          ? t('Update the role name and description.')
          : t('Create a custom role, then grant its permissions and members.')
      }
      contentClassName='sm:max-w-lg'
      footer={
        <>
          <Button
            variant='outline'
            disabled={save.isPending}
            onClick={() => props.onOpenChange(false)}
          >
            {t('Cancel')}
          </Button>
          <Button
            type='submit'
            form='role-mutate-form'
            disabled={save.isPending}
          >
            {save.isPending ? t('Saving...') : t('Save')}
          </Button>
        </>
      }
    >
      <Form {...form}>
        <form
          id='role-mutate-form'
          className='flex flex-col gap-4'
          onSubmit={form.handleSubmit((values) => save.mutate(values))}
        >
          <FormField
            control={form.control}
            name='name'
            render={({ field }) => (
              <FormItem>
                <FormLabel required>{t('Name')}</FormLabel>
                <FormControl>
                  <Input maxLength={100} {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
          <FormField
            control={form.control}
            name='key'
            render={({ field }) => (
              <FormItem>
                <FormLabel>{t('Role key')}</FormLabel>
                <FormControl>
                  <Input
                    maxLength={64}
                    className='font-mono'
                    disabled={Boolean(role)}
                    {...field}
                  />
                </FormControl>
                <FormDescription>
                  {role
                    ? t('The role key cannot be changed.')
                    : t('Optional. Generated from the name when left empty.')}
                </FormDescription>
                <FormMessage />
              </FormItem>
            )}
          />
          <FormField
            control={form.control}
            name='description'
            render={({ field }) => (
              <FormItem>
                <FormLabel>{t('Description')}</FormLabel>
                <FormControl>
                  <Textarea rows={3} {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
        </form>
      </Form>
    </Dialog>
  )
}
