package controller

import (
	"errors"
	"maps"
	"strconv"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/service"
	"github.com/QuantumNous/new-api/service/authz"
	"github.com/gin-gonic/gin"
)

func init() {
	// English fallback text of the role management audit entries; the web
	// console renders them from the action and params.
	maps.Copy(auditContentTemplates, map[string]string{
		"authz.role_create":       "Created role ${role_key} with permissions ${permissions}",
		"authz.role_update":       "Updated role ${role_key} with permissions ${permissions}",
		"authz.role_delete":       "Deleted role ${role_key}",
		"authz.role_members":      "Set members of role ${role_key} to users ${user_ids}",
		"authz.user_roles_update": "Set roles of user ${target_user_id} to ${role_keys}",
	})
}

type authzRoleRequest struct {
	Key         string               `json:"key"`
	Name        string               `json:"name"`
	Description string               `json:"description"`
	Grants      authz.PermissionsMap `json:"grants"`
}

// authzRoleError maps a role store error to its web console message key.
func authzRoleError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, authz.ErrRoleNotFound):
		common.ApiErrorT(c, "Role not found")
	case errors.Is(err, authz.ErrRoleBuiltIn):
		common.ApiErrorT(c, "Built-in roles cannot be changed")
	case errors.Is(err, authz.ErrRoleKeyInvalid):
		common.ApiErrorT(c, "Role key must start with a lowercase letter and contain only lowercase letters, digits, hyphens, or underscores")
	case errors.Is(err, authz.ErrRoleKeyExists):
		common.ApiErrorT(c, "Role key already exists")
	case errors.Is(err, authz.ErrRoleNameRequired):
		common.ApiErrorT(c, "Role name is required")
	case errors.Is(err, authz.ErrRoleNameTooLong):
		common.ApiErrorT(c, "Role name must be at most 100 characters")
	case errors.Is(err, authz.ErrRoleDescriptionTooLong):
		common.ApiErrorT(c, "Role description is too long")
	case errors.Is(err, authz.ErrRoleHasMembers):
		common.ApiErrorT(c, "Role still has members; remove them first or delete with force")
	case errors.Is(err, authz.ErrRoleMemberInvalid):
		common.ApiErrorT(c, "Only administrators can be assigned roles")
	default:
		common.ApiError(c, err)
	}
}

// grantedPermissions lists a role's allowed permissions as "resource:action"
// keys in catalog order, for audit entries.
func grantedPermissions(grants authz.PermissionsMap) []string {
	granted := []string{}
	for _, definition := range authz.Catalog() {
		for _, action := range definition.Actions {
			if grants[definition.Resource][action.Action] {
				granted = append(granted, definition.Resource+":"+action.Action)
			}
		}
	}
	return granted
}

func ListAuthzRoles(c *gin.Context) {
	roles, err := authz.ListRoles()
	if err != nil {
		authzRoleError(c, err)
		return
	}
	common.ApiSuccess(c, roles)
}

func CreateAuthzRole(c *gin.Context) {
	var req authzRoleRequest
	if err := common.DecodeJson(c.Request.Body, &req); err != nil {
		common.ApiError(c, err)
		return
	}
	authorization := requireAdminUserProof(c, service.VerificationScopeAuthzRoleWrite, service.AuthzRoleWriteContext{Action: service.AuthzRoleWriteCreate, RoleKey: req.Key})
	if authorization == nil {
		return
	}
	role, err := authz.CreateRole(authz.RoleInput{Key: req.Key, Name: req.Name, Description: req.Description, Grants: req.Grants})
	if err != nil {
		authzRoleError(c, err)
		return
	}
	recordManageAudit(c, "authz.role_create", map[string]any{
		"role_key":            role.Key,
		"permissions":         grantedPermissions(role.Grants),
		"verification_method": authorization.Method,
	})
	common.ApiSuccess(c, role)
}

func UpdateAuthzRole(c *gin.Context) {
	var req authzRoleRequest
	if err := common.DecodeJson(c.Request.Body, &req); err != nil {
		common.ApiError(c, err)
		return
	}
	key := c.Param("key")
	authorization := requireAdminUserProof(c, service.VerificationScopeAuthzRoleWrite, service.AuthzRoleWriteContext{Action: service.AuthzRoleWriteUpdate, RoleKey: key})
	if authorization == nil {
		return
	}
	role, err := authz.UpdateRole(key, authz.RoleInput{Name: req.Name, Description: req.Description, Grants: req.Grants})
	if err != nil {
		authzRoleError(c, err)
		return
	}
	recordManageAudit(c, "authz.role_update", map[string]any{
		"role_key":            role.Key,
		"permissions":         grantedPermissions(role.Grants),
		"verification_method": authorization.Method,
	})
	common.ApiSuccess(c, role)
}

func DeleteAuthzRole(c *gin.Context) {
	key := c.Param("key")
	force := c.Query("force") == "true"
	authorization := requireAdminUserProof(c, service.VerificationScopeAuthzRoleWrite, service.AuthzRoleWriteContext{Action: service.AuthzRoleWriteDelete, RoleKey: key})
	if authorization == nil {
		return
	}
	if err := authz.DeleteRole(key, force); err != nil {
		authzRoleError(c, err)
		return
	}
	recordManageAudit(c, "authz.role_delete", map[string]any{
		"role_key":            key,
		"force":               force,
		"verification_method": authorization.Method,
	})
	common.ApiSuccess(c, nil)
}

func GetAuthzRoleMembers(c *gin.Context) {
	members, err := authz.RoleMembers(c.Param("key"))
	if err != nil {
		authzRoleError(c, err)
		return
	}
	common.ApiSuccess(c, members)
}

func SetAuthzRoleMembers(c *gin.Context) {
	var req struct {
		UserIDs []int `json:"user_ids"`
	}
	if err := common.DecodeJson(c.Request.Body, &req); err != nil {
		common.ApiError(c, err)
		return
	}
	key := c.Param("key")
	authorization := requireAdminUserProof(c, service.VerificationScopeAuthzRoleWrite, service.AuthzRoleWriteContext{Action: service.AuthzRoleWriteMembers, RoleKey: key})
	if authorization == nil {
		return
	}
	if err := authz.SetRoleMembers(key, req.UserIDs); err != nil {
		authzRoleError(c, err)
		return
	}
	userIDs := req.UserIDs
	if userIDs == nil {
		userIDs = []int{}
	}
	recordManageAudit(c, "authz.role_members", map[string]any{
		"role_key":            key,
		"user_ids":            userIDs,
		"verification_method": authorization.Method,
	})
	common.ApiSuccess(c, nil)
}

func GetAuthzUserRoles(c *gin.Context) {
	userID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		common.ApiErrorT(c, "Invalid user ID")
		return
	}
	keys := authz.UserRoleKeys(userID)
	if keys == nil {
		keys = []string{}
	}
	common.ApiSuccess(c, keys)
}

func SetAuthzUserRoles(c *gin.Context) {
	userID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		common.ApiErrorT(c, "Invalid user ID")
		return
	}
	if userID <= 0 {
		common.ApiErrorT(c, "Only administrators can be assigned roles")
		return
	}
	var req struct {
		RoleKeys []string `json:"role_keys"`
	}
	if err := common.DecodeJson(c.Request.Body, &req); err != nil {
		common.ApiError(c, err)
		return
	}
	authorization := requireAdminUserProof(c, service.VerificationScopeAuthzRoleWrite, service.AuthzRoleWriteContext{Action: service.AuthzRoleWriteUserRoles, UserID: userID})
	if authorization == nil {
		return
	}
	if err := authz.SetUserRoles(userID, req.RoleKeys); err != nil {
		authzRoleError(c, err)
		return
	}
	roleKeys := req.RoleKeys
	if roleKeys == nil {
		roleKeys = []string{}
	}
	recordManageAuditFor(c, userID, "authz.user_roles_update", map[string]any{
		"target_user_id":      userID,
		"role_keys":           roleKeys,
		"verification_method": authorization.Method,
	})
	common.ApiSuccess(c, nil)
}

// clearDeletedUserAuthorization drops a deleted user's role bindings and
// permission overrides, so a reused user ID cannot inherit them. The deletion
// has already committed, so a failure is only logged.
func clearDeletedUserAuthorization(userID int) {
	if err := authz.ClearUserAuthorization(userID); err != nil {
		common.SysError(common.LogText("failed to clear authorization of deleted user %d: %s", userID, err.Error()))
	}
}
