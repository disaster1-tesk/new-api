package controller

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service/authz"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

type authzRoleResponse struct {
	Success bool            `json:"success"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

func setupAuthzRoleTest(t *testing.T) *gin.Engine {
	t.Helper()
	wasMaster := common.IsMasterNode
	common.IsMasterNode = true
	t.Cleanup(func() { common.IsMasterNode = wasMaster })

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&model.CasbinRule{}, &model.AuthzRole{}, &model.User{}))
	require.NoError(t, db.Create(&[]model.User{
		{Id: 5, Username: "admin5", AffCode: "a5", Password: "password", Role: common.RoleAdminUser},
		{Id: 8, Username: "common8", AffCode: "c8", Password: "password", Role: common.RoleCommonUser},
	}).Error)
	require.NoError(t, authz.Init(db))

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/roles", ListAuthzRoles)
	r.POST("/roles", CreateAuthzRole)
	r.PUT("/roles/:key", UpdateAuthzRole)
	r.DELETE("/roles/:key", DeleteAuthzRole)
	r.GET("/roles/:key/members", GetAuthzRoleMembers)
	r.PUT("/roles/:key/members", SetAuthzRoleMembers)
	r.GET("/users/:id/roles", GetAuthzUserRoles)
	r.PUT("/users/:id/roles", SetAuthzUserRoles)
	return r
}

func callAuthzRole(t *testing.T, r *gin.Engine, method, path, body string) authzRoleResponse {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	var resp authzRoleResponse
	require.NoError(t, common.Unmarshal(w.Body.Bytes(), &resp))
	return resp
}

func TestAuthzRoleManagement(t *testing.T) {
	r := setupAuthzRoleTest(t)

	created := callAuthzRole(t, r, http.MethodPost, "/roles",
		`{"key":"viewer","name":"Viewer","description":"d","grants":{"channel":{"read":true}}}`)
	require.True(t, created.Success, created.Message)

	listed := callAuthzRole(t, r, http.MethodGet, "/roles", "")
	require.True(t, listed.Success)
	var roles []authz.RoleView
	require.NoError(t, common.Unmarshal(listed.Data, &roles))
	var found *authz.RoleView
	for i := range roles {
		if roles[i].Key == "viewer" {
			found = &roles[i]
		}
	}
	require.NotNil(t, found)
	assert.Equal(t, int64(0), found.MemberCount)

	resp := callAuthzRole(t, r, http.MethodPut, "/roles/admin", `{"name":"x","grants":{}}`)
	assert.False(t, resp.Success)
	assert.Equal(t, "Built-in roles cannot be changed", resp.Message)

	resp = callAuthzRole(t, r, http.MethodPut, "/roles/viewer/members", `{"user_ids":[8]}`)
	assert.False(t, resp.Success)
	assert.Equal(t, "Only administrators can be assigned roles", resp.Message)

	resp = callAuthzRole(t, r, http.MethodPut, "/roles/viewer/members", `{"user_ids":[5]}`)
	require.True(t, resp.Success, resp.Message)
	resp = callAuthzRole(t, r, http.MethodGet, "/users/5/roles", "")
	assert.JSONEq(t, `["viewer"]`, string(resp.Data))
	resp = callAuthzRole(t, r, http.MethodGet, "/users/abc/roles", "")
	assert.Equal(t, "Invalid user ID", resp.Message)

	resp = callAuthzRole(t, r, http.MethodDelete, "/roles/viewer", "")
	assert.False(t, resp.Success)
	assert.Equal(t, "Role still has members; remove them first or delete with force", resp.Message)

	resp = callAuthzRole(t, r, http.MethodDelete, "/roles/viewer?force=true", "")
	assert.True(t, resp.Success, resp.Message)
}
