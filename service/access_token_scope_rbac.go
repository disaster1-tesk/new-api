package service

import (
	"encoding/json"

	"github.com/QuantumNous/new-api/common"
)

// VerificationScopeAuthzRoleWrite guards every custom role change. Only the
// root user can obtain it, and access tokens never can.
const VerificationScopeAuthzRoleWrite = "authz.role.write"

// Role changes a VerificationScopeAuthzRoleWrite proof can be bound to.
const (
	AuthzRoleWriteCreate    = "create"
	AuthzRoleWriteUpdate    = "update"
	AuthzRoleWriteDelete    = "delete"
	AuthzRoleWriteMembers   = "members"
	AuthzRoleWriteUserRoles = "user_roles"
)

// AuthzRoleWriteContext binds a role-change proof to one action and its
// target: a custom role key, or the administrator whose roles are replaced.
// Creating a role names its key only when the caller chose one.
type AuthzRoleWriteContext struct {
	Action  string `json:"action"`
	RoleKey string `json:"role_key,omitempty"`
	UserID  int    `json:"user_id,omitempty"`
}

// normalizeAuthzRoleWriteContext accepts exactly the fields the action needs.
func normalizeAuthzRoleWriteContext(fields map[string]json.RawMessage, raw json.RawMessage) (AuthzRoleWriteContext, bool) {
	var context AuthzRoleWriteContext
	if len(raw) == 0 || common.Unmarshal(raw, &context) != nil {
		return AuthzRoleWriteContext{}, false
	}
	expected := 1
	if context.RoleKey != "" {
		expected++
	}
	if context.UserID != 0 {
		expected++
	}
	if len(fields) != expected || len(context.RoleKey) > 64 {
		return AuthzRoleWriteContext{}, false
	}
	var valid bool
	switch context.Action {
	case AuthzRoleWriteCreate:
		valid = context.UserID == 0
	case AuthzRoleWriteUpdate, AuthzRoleWriteDelete, AuthzRoleWriteMembers:
		valid = context.RoleKey != "" && context.UserID == 0
	case AuthzRoleWriteUserRoles:
		valid = context.UserID > 0 && context.RoleKey == ""
	}
	return context, valid
}

// AccessTokenStaticMinRole returns the minimum built-in role of a static
// access token resource.
func AccessTokenStaticMinRole(resource string) (int, bool) {
	for _, static := range accessTokenStaticResources {
		if static.Resource == resource {
			return static.minRole, true
		}
	}
	return 0, false
}
