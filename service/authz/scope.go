package authz

import "strings"

// PermissionFromScope parses a "resource:action" token scope into a registered
// permission.
func PermissionFromScope(scope string) (Permission, bool) {
	resource, action, ok := strings.Cut(scope, ":")
	if !ok {
		return Permission{}, false
	}
	permission := Permission{Resource: resource, Action: action}
	if !isKnownPermission(permission) {
		return Permission{}, false
	}
	return permission, true
}

// IsRegisteredResource reports whether resource is in the permission registry.
func IsRegisteredResource(resource string) bool {
	return isKnownResource(resource)
}

// Initialized reports whether Init has loaded the enforcer.
func Initialized() bool {
	return currentEnforcer() != nil
}

// RoleBaselineAllows reports whether the role's own policies allow the
// permission, ignoring per-user overrides.
func RoleBaselineAllows(roleKey string, permission Permission) bool {
	e := currentEnforcer()
	return e != nil && roleBaselineAllows(e, roleKey, permission)
}
