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
import type { i18n } from 'i18next'

import en from './en.json'
import fr from './fr.json'
import ja from './ja.json'
import ru from './ru.json'
import vi from './vi.json'
import zhTW from './zh-TW.json'
import zh from './zh.json'

// The role management strings live in their own bundles so the upstream
// locale files stay untouched. Keys are merged into the default namespace
// without overwriting upstream entries.
const bundles: Record<string, Record<string, string>> = {
  en,
  zhCN: zh,
  zhTW,
  fr,
  ru,
  ja,
  vi,
}

export function registerRolesI18n(instance: i18n): void {
  for (const [language, bundle] of Object.entries(bundles)) {
    instance.addResourceBundle(language, 'translation', bundle, true, false)
  }
}
