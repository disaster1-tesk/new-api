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
import React, { useCallback, useMemo } from 'react'
import { useTranslation } from 'react-i18next'

import {
  SecureVerificationDialog,
  useSecureVerification,
  type AuthzRoleWriteContext,
} from '@/features/auth/secure-verification'

type RoleVerificationContextType = {
  /** Resolves to a single-use proof token for the change, or null when cancelled. */
  verifyRoleChange: (context: AuthzRoleWriteContext) => Promise<string | null>
  /** True while the step-up dialog is showing; other dialogs yield to it. */
  verificationActive: boolean
}

const RoleVerificationContext =
  React.createContext<RoleVerificationContextType | null>(null)

// RoleVerificationProvider mounts the step-up dialog once for the roles page;
// every role change obtains its own proof through it before it is sent.
export function RoleVerificationProvider(props: { children: React.ReactNode }) {
  const { t } = useTranslation()
  const verification = useSecureVerification()
  const requestVerification = verification.requestVerification
  const verificationActive = verification.isActive

  const verifyRoleChange = useCallback(
    async (context: AuthzRoleWriteContext) => {
      const proof = await requestVerification({
        scope: 'authz.role.write',
        context,
        title: t('Verify to change roles'),
        description: t(
          'Confirm your identity before changing roles, their permissions, or their members.'
        ),
      })
      return proof?.proof_token ?? null
    },
    [requestVerification, t]
  )

  const value = useMemo(
    () => ({ verifyRoleChange, verificationActive }),
    [verifyRoleChange, verificationActive]
  )

  return (
    <RoleVerificationContext value={value}>
      {props.children}
      <SecureVerificationDialog {...verification.dialogProps} />
    </RoleVerificationContext>
  )
}

// eslint-disable-next-line react-refresh/only-export-components
export function useRoleVerification(): RoleVerificationContextType {
  const context = React.useContext(RoleVerificationContext)
  if (!context) {
    throw new Error(
      'useRoleVerification has to be used within <RoleVerificationProvider>'
    )
  }
  return context
}
