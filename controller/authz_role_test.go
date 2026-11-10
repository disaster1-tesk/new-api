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

func TestAuthzRoleValidation(t *testing.T) {
	r := setupAuthzRoleTest(t)
	created := callAuthzRole(t, r, http.MethodPost, "/roles", `{"key":"viewer","name":"Viewer","grants":{}}`)
	require.True(t, created.Success, created.Message)

	cases := []struct {
		name, method, path, body string
		message                  string // exact message; empty means any non-empty message
	}{
		{"create invalid key", http.MethodPost, "/roles", `{"key":"Bad Key","name":"x","grants":{}}`,
			"Role key must start with a lowercase letter and contain only lowercase letters, digits, hyphens, or underscores"},
		{"create duplicate key", http.MethodPost, "/roles", `{"key":"viewer","name":"x","grants":{}}`, "Role key already exists"},
		{"create empty name", http.MethodPost, "/roles", `{"key":"other","name":"","grants":{}}`, "Role name is required"},
		{"create empty body", http.MethodPost, "/roles", ``, ""},
		{"create invalid json", http.MethodPost, "/roles", `{`, ""},
		{"update unknown role", http.MethodPut, "/roles/nope", `{"name":"x","grants":{}}`, "Role not found"},
		{"update invalid json", http.MethodPut, "/roles/viewer", `{`, ""},
		{"delete unknown role", http.MethodDelete, "/roles/nope", "", "Role not found"},
		{"members unknown role", http.MethodGet, "/roles/nope/members", "", "Role not found"},
		{"set members unknown role", http.MethodPut, "/roles/nope/members", `{"user_ids":[5]}`, "Role not found"},
		{"set members wrong type", http.MethodPut, "/roles/viewer/members", `{"user_ids":"x"}`, ""},
		{"set members invalid json", http.MethodPut, "/roles/viewer/members", `{`, ""},
		{"set members zero id", http.MethodPut, "/roles/viewer/members", `{"user_ids":[0]}`, "Only administrators can be assigned roles"},
		{"set members negative id", http.MethodPut, "/roles/viewer/members", `{"user_ids":[-1]}`, "Only administrators can be assigned roles"},
		{"set members nonexistent id", http.MethodPut, "/roles/viewer/members", `{"user_ids":[999]}`, "Only administrators can be assigned roles"},
		{"set user roles non-numeric id", http.MethodPut, "/users/abc/roles", `{"role_keys":[]}`, "Invalid user ID"},
		{"set user roles invalid json", http.MethodPut, "/users/5/roles", `{`, ""},
		{"set user roles wrong type", http.MethodPut, "/users/5/roles", `{"role_keys":"x"}`, ""},
		{"set user roles unknown role", http.MethodPut, "/users/5/roles", `{"role_keys":["nope"]}`, "Role not found"},
		{"set user roles common user", http.MethodPut, "/users/8/roles", `{"role_keys":["viewer"]}`, "Only administrators can be assigned roles"},
		{"set user roles zero id", http.MethodPut, "/users/0/roles", `{"role_keys":["viewer"]}`, "Only administrators can be assigned roles"},
		{"set user roles negative id", http.MethodPut, "/users/-1/roles", `{"role_keys":["viewer"]}`, "Only administrators can be assigned roles"},
		{"set user roles nonexistent id", http.MethodPut, "/users/999/roles", `{"role_keys":["viewer"]}`, "Only administrators can be assigned roles"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := callAuthzRole(t, r, tc.method, tc.path, tc.body)
			assert.False(t, resp.Success)
			if tc.message == "" {
				assert.NotEmpty(t, resp.Message)
				return
			}
			assert.Equal(t, tc.message, resp.Message)
		})
	}

	resp := callAuthzRole(t, r, http.MethodGet, "/users/5/roles", "")
	require.True(t, resp.Success)
	assert.JSONEq(t, `[]`, string(resp.Data))

	resp = callAuthzRole(t, r, http.MethodPut, "/users/5/roles", `{"role_keys":["viewer"]}`)
	require.True(t, resp.Success, resp.Message)
	resp = callAuthzRole(t, r, http.MethodGet, "/users/5/roles", "")
	assert.JSONEq(t, `["viewer"]`, string(resp.Data))
	resp = callAuthzRole(t, r, http.MethodPut, "/users/5/roles", `{"role_keys":[]}`)
	require.True(t, resp.Success, resp.Message)
	resp = callAuthzRole(t, r, http.MethodGet, "/users/5/roles", "")
	assert.JSONEq(t, `[]`, string(resp.Data))
}
