package controller

import (
	"errors"
	"strconv"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/service/authz"
	"github.com/gin-gonic/gin"
)

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
	role, err := authz.CreateRole(authz.RoleInput{Key: req.Key, Name: req.Name, Description: req.Description, Grants: req.Grants})
	if err != nil {
		authzRoleError(c, err)
		return
	}
	common.ApiSuccess(c, role)
}

func UpdateAuthzRole(c *gin.Context) {
	var req authzRoleRequest
	if err := common.DecodeJson(c.Request.Body, &req); err != nil {
		common.ApiError(c, err)
		return
	}
	role, err := authz.UpdateRole(c.Param("key"), authz.RoleInput{Name: req.Name, Description: req.Description, Grants: req.Grants})
	if err != nil {
		authzRoleError(c, err)
		return
	}
	common.ApiSuccess(c, role)
}

func DeleteAuthzRole(c *gin.Context) {
	if err := authz.DeleteRole(c.Param("key"), c.Query("force") == "true"); err != nil {
		authzRoleError(c, err)
		return
	}
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
	if err := authz.SetRoleMembers(c.Param("key"), req.UserIDs); err != nil {
		authzRoleError(c, err)
		return
	}
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
	var req struct {
		RoleKeys []string `json:"role_keys"`
	}
	if err := common.DecodeJson(c.Request.Body, &req); err != nil {
		common.ApiError(c, err)
		return
	}
	if err := authz.SetUserRoles(userID, req.RoleKeys); err != nil {
		authzRoleError(c, err)
		return
	}
	common.ApiSuccess(c, nil)
}
