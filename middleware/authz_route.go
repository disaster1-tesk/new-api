package middleware

import (
	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/service/authz"
	"github.com/gin-gonic/gin"
)

// authzRouteRoleOverrides keeps routes on a plain role floor even when the
// route table declares a permission scope for them.
var authzRouteRoleOverrides = map[string]int{
	"GET /api/authz/catalog":    common.RoleAdminUser,
	"POST /api/channel/:id/key": common.RoleRootUser,
}

// dashboardRoleAllowed decides whether a dashboard user may use the matched
// route. Admin-level routes are decided by the route's declared permission so
// custom roles apply; routes without a declared scope fall back to minRole.
func dashboardRoleAllowed(c *gin.Context, userID, role, minRole int) bool {
	if role >= common.RoleRootUser {
		return true
	}
	if minRole < common.RoleAdminUser {
		return role >= minRole
	}
	if role < common.RoleAdminUser {
		return false
	}
	key := c.Request.Method + " " + c.FullPath()
	if floor, ok := authzRouteRoleOverrides[key]; ok {
		return role >= floor
	}
	if !authz.Initialized() {
		return role >= minRole
	}
	// Routes declared through DeclareAccessTokenPermissionRoute are guarded by
	// RequirePermission, which denies after the admin audit has started.
	if rule, ok := accessTokenRouteRules[key]; ok {
		if permission, ok := authz.PermissionFromScope(rule.Scope()); ok {
			return authz.Can(userID, role, permission)
		}
	}
	return role >= minRole
}
