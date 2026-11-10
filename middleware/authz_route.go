package middleware

import (
	"net/http"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service/authz"
	"github.com/gin-gonic/gin"
)

// authzRouteRoleOverrides keeps routes on a plain role floor even when the
// route table declares a permission scope for them. Channel key viewing stays
// root-only although channel:secret_view is not in the admin baseline, so a
// per-user or role grant of it cannot unlock the route.
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
	rule, ok := accessTokenRouteRules[key]
	if !ok {
		return role >= minRole
	}
	permission, ok := authz.PermissionFromScope(rule.Scope())
	if !ok {
		return role >= minRole
	}
	// A root-only route whose scope every admin holds by default stays
	// root-only; otherwise its permission would open it to all admins.
	allowed := authz.Can(userID, role, permission)
	if minRole >= common.RoleRootUser && authz.RoleBaselineAllows(authz.BuiltInRoleAdmin, permission) {
		allowed = false
	}
	if !allowed {
		recordAuthzRouteDenial(c, userID, role, rule.Scope())
	}
	return allowed
}

// recordAuthzRouteDenial writes a failed operation audit entry for a route the
// administrator's roles and overrides do not permit. The request is rejected
// before the admin write audit starts, so nothing else records it.
func recordAuthzRouteDenial(c *gin.Context, userID, role int, scope string) {
	method, route := c.Request.Method, c.FullPath()
	authMethod := "session"
	if _, ok := c.Get(accessTokenAuditContextKey); ok {
		authMethod = "access_token"
	}
	params := map[string]any{"method": method, "route": route, "scope": scope, "user_id": userID, "role": role}
	adminInfo := &model.AuditAdminInfo{AdminID: userID, AdminRole: role, AuthMethod: authMethod}
	auditInfo := &model.AuditRequestInfo{Method: method, Route: route, Path: route, Status: http.StatusForbidden, Success: false}
	content := "Permission denied: " + method + " " + route + " requires " + scope
	model.RecordOperationAuditLog(userID, role, content, c.ClientIP(), "authz.permission_denied", params, adminInfo, auditInfo, c)
}
