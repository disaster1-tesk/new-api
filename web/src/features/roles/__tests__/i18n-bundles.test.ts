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
import i18next from 'i18next'
import { describe, expect, it } from 'vitest'

import upstreamEn from '@/i18n/locales/en.json'

import en from '../i18n/en.json'
import fr from '../i18n/fr.json'
import ja from '../i18n/ja.json'
import { registerRolesI18n } from '../i18n/register'
import ru from '../i18n/ru.json'
import vi from '../i18n/vi.json'
import zhTW from '../i18n/zh-TW.json'
import zh from '../i18n/zh.json'

const translations: Record<string, Record<string, string>> = {
  zh,
  'zh-TW': zhTW,
  fr,
  ru,
  ja,
  vi,
}

// Backend web console messages and personal access token labels that reach
// the UI without a matching upstream locale entry.
const requiredKeys = [
  'Role not found',
  'Built-in roles cannot be changed',
  'Role key must start with a lowercase letter and contain only lowercase letters, digits, hyphens, or underscores',
  'Role key already exists',
  'Role name is required',
  'Role name must be at most 100 characters',
  'Role description is too long',
  'Role still has members; remove them first or delete with force',
  'Only administrators can be assigned roles',
  'Invalid user ID',
  'Roles and permissions',
  'View custom roles, their permissions, and members.',
  'Roles & Permissions',
]

function placeholders(text: string): string[] {
  return [...text.matchAll(/{{\s*(\w+)\s*}}/g)].map((match) => match[1]).sort()
}

describe('roles i18n bundles', () => {
  it('the English bundle maps every key to itself and holds the required keys', () => {
    for (const [key, value] of Object.entries(en)) expect(value).toBe(key)
    expect(Object.keys(en)).toEqual(expect.arrayContaining(requiredKeys))
  })

  it.each(Object.keys(translations))(
    'the %s bundle has the English key set with translated values',
    (language) => {
      const bundle = translations[language]
      expect(Object.keys(bundle).sort()).toEqual(Object.keys(en).sort())
      for (const [key, value] of Object.entries(bundle)) {
        expect(value.trim(), key).not.toBe('')
        expect(value, `${language}: ${key}`).not.toBe(key)
        expect(placeholders(value), key).toEqual(placeholders(key))
      }
    }
  )

  it('no key duplicates an upstream locale key, which would shadow this bundle', () => {
    const upstream = upstreamEn.translation as Record<string, string>
    // The backend contract requires this message; the upstream locale already
    // translates it, so its upstream entry wins.
    const sharedKeys = new Set(['Invalid user ID'])
    expect(
      Object.keys(en).filter((key) => key in upstream && !sharedKeys.has(key))
    ).toEqual([])
  })

  it('registering merges the bundles into every interface language', async () => {
    const instance = i18next.createInstance()
    await instance.init({
      lng: 'zhCN',
      fallbackLng: 'en',
      nsSeparator: false,
      resources: { en: { translation: {} }, zhCN: { translation: {} } },
    })
    registerRolesI18n(instance)
    // Keys with dots and colons resolve as flat keys, as in the app config.
    for (const key of [
      'Roles & Permissions',
      'Built-in roles are read-only.',
      'Members: {{total}}',
    ] as const) {
      expect(instance.t(key, { total: 3 })).toBe(
        zh[key].replace('{{total}}', '3')
      )
    }
    for (const language of ['en', 'zhTW', 'fr', 'ru', 'ja', 'vi']) {
      expect(instance.hasResourceBundle(language, 'translation')).toBe(true)
    }
  })
})
