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
import { Lock, Shield } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { Badge } from '@/components/ui/badge'
import {
  Item,
  ItemActions,
  ItemContent,
  ItemDescription,
  ItemGroup,
  ItemMedia,
  ItemTitle,
} from '@/components/ui/item'
import { cn } from '@/lib/utils'

import type { RoleView } from '../types'

type RoleListProps = {
  roles: RoleView[]
  selectedKey: string
  onSelect: (key: string) => void
}

export function RoleList(props: RoleListProps) {
  const { t } = useTranslation()
  return (
    <ItemGroup aria-label={t('Roles')} className='gap-1'>
      {props.roles.map((role) => {
        const selected = role.key === props.selectedKey
        const Icon = role.built_in ? Lock : Shield
        return (
          <div role='listitem' key={role.key}>
            <Item
              size='sm'
              variant={selected ? 'muted' : 'default'}
              render={<button type='button' />}
              aria-current={selected ? 'true' : undefined}
              onClick={() => props.onSelect(role.key)}
              className={cn(
                'hover:bg-muted/50 text-left',
                selected && 'border-border'
              )}
            >
              <ItemMedia variant='icon'>
                <Icon aria-hidden='true' />
              </ItemMedia>
              <ItemContent className='min-w-0'>
                <ItemTitle className='w-full truncate'>
                  {role.built_in ? t(role.name) : role.name}
                  {role.built_in && (
                    <span className='sr-only'>{t('Built-in')}</span>
                  )}
                </ItemTitle>
                <ItemDescription className='truncate font-mono text-xs'>
                  {role.key}
                </ItemDescription>
              </ItemContent>
              {!role.built_in && (
                <ItemActions>
                  <Badge variant='secondary' className='tabular-nums'>
                    {t('Members: {{total}}', { total: role.member_count })}
                  </Badge>
                </ItemActions>
              )}
            </Item>
          </div>
        )
      })}
    </ItemGroup>
  )
}
