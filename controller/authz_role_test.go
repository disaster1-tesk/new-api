package controller

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/QuantumNous/new-api/service/authz"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

type authzRoleResponse struct {
	Success bool            `json:"success"`
	Message string          `json:"message"`
	Code    string          `json:"code"`
	Data    json.RawMessage `json:"data"`
}

// authzRoleFixture drives the role handlers as the root operator signed in
// with a dashboard session, as RootAuth would leave the request.
type authzRoleFixture struct {
	t        *testing.T
	db       *gorm.DB
	router   *gin.Engine
	identity service.AuthIdentity
}

// setupAuthzRoleTest seeds admin 5, common user 8 and the root operator 9999.
func setupAuthzRoleTest(t *testing.T) *authzRoleFixture {
	t.Helper()
	db := setupManageUserTestDB(t)
	wasMaster := common.IsMasterNode
	common.IsMasterNode = true
	t.Cleanup(func() { common.IsMasterNode = wasMaster })
	require.NoError(t, db.Create(&[]model.User{
		{Id: 5, Username: "admin5", AffCode: "a5", Password: "password", Role: common.RoleAdminUser, Status: common.UserStatusEnabled, AuthVersion: 1},
		{Id: 8, Username: "common8", AffCode: "c8", Password: "password", Role: common.RoleCommonUser, Status: common.UserStatusEnabled, AuthVersion: 1},
	}).Error)
	require.NoError(t, authz.Init(db))

	operator := createQuotaTestOperator(t, db, common.RoleRootUser)
	require.NoError(t, model.PublishUserAuthCache(operator.Id))
	bundle, err := service.CreateLoginSession(operator.Id, "password", "127.0.0.1", "authz-role-test")
	require.NoError(t, err)
	identity, err := service.ParseAccessToken(bundle.AccessToken)
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("id", identity.UserID)
		c.Set("role", common.RoleRootUser)
		c.Set("username", operator.Username)
		c.Set("session_id", identity.SessionID)
		c.Set("auth_version", identity.UserAuthVersion)
		c.Set("session_version", identity.SessionVersion)
	})
	r.GET("/roles", ListAuthzRoles)
	r.POST("/roles", CreateAuthzRole)
	r.PUT("/roles/:key", UpdateAuthzRole)
	r.DELETE("/roles/:key", DeleteAuthzRole)
	r.GET("/roles/:key/members", GetAuthzRoleMembers)
	r.PUT("/roles/:key/members", SetAuthzRoleMembers)
	r.GET("/users/:id/roles", GetAuthzUserRoles)
	r.PUT("/users/:id/roles", SetAuthzUserRoles)
	r.DELETE("/user/:id", DeleteUser)
	r.POST("/user/manage", ManageUser)
	return &authzRoleFixture{t: t, db: db, router: r, identity: identity}
}

func roleWrite(action, key string) *service.VerificationOperation {
	return verificationOperation(service.VerificationScopeAuthzRoleWrite, service.AuthzRoleWriteContext{Action: action, RoleKey: key})
}

func userRolesWrite(userID int) *service.VerificationOperation {
	return verificationOperation(service.VerificationScopeAuthzRoleWrite, service.AuthzRoleWriteContext{Action: service.AuthzRoleWriteUserRoles, UserID: userID})
}

func verificationOperation(scope string, context any) *service.VerificationOperation {
	payload, err := common.Marshal(context)
	if err != nil {
		panic(err)
	}
	return &service.VerificationOperation{Scope: scope, Context: payload}
}

// proof issues a single-use password-method proof bound to operation.
func (f *authzRoleFixture) proof(operation service.VerificationOperation) string {
	f.t.Helper()
	binding, err := service.BindVerificationOperation(operation)
	require.NoError(f.t, err)
	proof, _, err := service.IssueSecurityProof(f.identity, service.VerificationMethodPassword, binding)
	require.NoError(f.t, err)
	return proof
}

// send performs a request, carrying a fresh proof for operation when given.
func (f *authzRoleFixture) send(method, path, body string, operation *service.VerificationOperation) (int, authzRoleResponse) {
	f.t.Helper()
	proof := ""
	if operation != nil {
		proof = f.proof(*operation)
	}
	return f.sendWithProof(method, path, body, proof)
}

func (f *authzRoleFixture) sendWithProof(method, path, body, proof string) (int, authzRoleResponse) {
	f.t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	if proof != "" {
		req.Header.Set("X-Security-Proof", proof)
	}
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, req)
	var resp authzRoleResponse
	require.NoError(f.t, common.Unmarshal(w.Body.Bytes(), &resp), w.Body.String())
	return w.Code, resp
}

// call expects the handler to answer with HTTP 200.
func (f *authzRoleFixture) call(method, path, body string, operation *service.VerificationOperation) authzRoleResponse {
	f.t.Helper()
	status, resp := f.send(method, path, body, operation)
	require.Equal(f.t, http.StatusOK, status, resp.Message)
	return resp
}

// auditParams returns the params of the only audit entry with action.
func (f *authzRoleFixture) auditParams(action string) string {
	f.t.Helper()
	var entries []model.AuditLog
	require.NoError(f.t, model.LOG_DB.Where("action = ?", action).Find(&entries).Error)
	require.Len(f.t, entries, 1, action)
	require.NotNil(f.t, entries[0].Other.Op)
	assert.Equal(f.t, 9999, entries[0].UserId)
	assert.True(f.t, entries[0].Success)
	params, err := common.Marshal(entries[0].Other.Op.Params)
	require.NoError(f.t, err)
	return string(params)
}

func TestAuthzRoleManagement(t *testing.T) {
	f := setupAuthzRoleTest(t)

	created := f.call(http.MethodPost, "/roles",
		`{"key":"viewer","name":"Viewer","description":"d","grants":{"channel":{"read":true}}}`,
		roleWrite(service.AuthzRoleWriteCreate, "viewer"))
	require.True(t, created.Success, created.Message)
	assert.JSONEq(t, `{"role_key":"viewer","permissions":["channel:read"],"verification_method":"password"}`, f.auditParams("authz.role_create"))

	listed := f.call(http.MethodGet, "/roles", "", nil)
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

	resp := f.call(http.MethodPut, "/roles/viewer", `{"name":"Viewer","grants":{"channel":{"read":true},"user":{"read":true}}}`,
		roleWrite(service.AuthzRoleWriteUpdate, "viewer"))
	require.True(t, resp.Success, resp.Message)
	assert.JSONEq(t, `{"role_key":"viewer","permissions":["user:read","channel:read"],"verification_method":"password"}`, f.auditParams("authz.role_update"))

	resp = f.call(http.MethodPut, "/roles/admin", `{"name":"x","grants":{}}`, roleWrite(service.AuthzRoleWriteUpdate, "admin"))
	assert.False(t, resp.Success)
	assert.Equal(t, "Built-in roles cannot be changed", resp.Message)

	resp = f.call(http.MethodPut, "/roles/viewer/members", `{"user_ids":[8]}`, roleWrite(service.AuthzRoleWriteMembers, "viewer"))
	assert.False(t, resp.Success)
	assert.Equal(t, "Only administrators can be assigned roles", resp.Message)

	resp = f.call(http.MethodPut, "/roles/viewer/members", `{"user_ids":[5]}`, roleWrite(service.AuthzRoleWriteMembers, "viewer"))
	require.True(t, resp.Success, resp.Message)
	assert.JSONEq(t, `{"role_key":"viewer","user_ids":[5],"verification_method":"password"}`, f.auditParams("authz.role_members"))
	resp = f.call(http.MethodGet, "/users/5/roles", "", nil)
	assert.JSONEq(t, `["viewer"]`, string(resp.Data))
	resp = f.call(http.MethodGet, "/users/abc/roles", "", nil)
	assert.Equal(t, "Invalid user ID", resp.Message)

	resp = f.call(http.MethodPut, "/users/5/roles", `{"role_keys":["viewer"]}`, userRolesWrite(5))
	require.True(t, resp.Success, resp.Message)
	assert.JSONEq(t, `{"target_user_id":5,"role_keys":["viewer"],"verification_method":"password"}`, f.auditParams("authz.user_roles_update"))

	resp = f.call(http.MethodDelete, "/roles/viewer", "", roleWrite(service.AuthzRoleWriteDelete, "viewer"))
	assert.False(t, resp.Success)
	assert.Equal(t, "Role still has members; remove them first or delete with force", resp.Message)

	resp = f.call(http.MethodDelete, "/roles/viewer?force=true", "", roleWrite(service.AuthzRoleWriteDelete, "viewer"))
	assert.True(t, resp.Success, resp.Message)
	assert.JSONEq(t, `{"role_key":"viewer","force":true,"verification_method":"password"}`, f.auditParams("authz.role_delete"))
}

func TestAuthzRoleValidation(t *testing.T) {
	f := setupAuthzRoleTest(t)
	created := f.call(http.MethodPost, "/roles", `{"key":"viewer","name":"Viewer","grants":{}}`, roleWrite(service.AuthzRoleWriteCreate, "viewer"))
	require.True(t, created.Success, created.Message)
	longName := strings.Repeat("名", 101)
	longDescription := strings.Repeat("d", 65536)

	cases := []struct {
		name, method, path, body string
		operation                *service.VerificationOperation
		message                  string // exact message; empty means any non-empty message
	}{
		{"create invalid key", http.MethodPost, "/roles", `{"key":"Bad Key","name":"x","grants":{}}`, roleWrite(service.AuthzRoleWriteCreate, "Bad Key"),
			"Role key must start with a lowercase letter and contain only lowercase letters, digits, hyphens, or underscores"},
		{"create duplicate key", http.MethodPost, "/roles", `{"key":"viewer","name":"x","grants":{}}`, roleWrite(service.AuthzRoleWriteCreate, "viewer"), "Role key already exists"},
		{"create empty name", http.MethodPost, "/roles", `{"key":"other","name":"","grants":{}}`, roleWrite(service.AuthzRoleWriteCreate, "other"), "Role name is required"},
		{"create long name", http.MethodPost, "/roles", `{"name":"` + longName + `","grants":{}}`, roleWrite(service.AuthzRoleWriteCreate, ""), "Role name must be at most 100 characters"},
		{"create long description", http.MethodPost, "/roles", `{"name":"x","description":"` + longDescription + `","grants":{}}`, roleWrite(service.AuthzRoleWriteCreate, ""), "Role description is too long"},
		{"create empty body", http.MethodPost, "/roles", ``, nil, ""},
		{"create invalid json", http.MethodPost, "/roles", `{`, nil, ""},
		{"update unknown role", http.MethodPut, "/roles/nope", `{"name":"x","grants":{}}`, roleWrite(service.AuthzRoleWriteUpdate, "nope"), "Role not found"},
		{"update long name", http.MethodPut, "/roles/viewer", `{"name":"` + longName + `","grants":{}}`, roleWrite(service.AuthzRoleWriteUpdate, "viewer"), "Role name must be at most 100 characters"},
		{"update invalid json", http.MethodPut, "/roles/viewer", `{`, nil, ""},
		{"delete unknown role", http.MethodDelete, "/roles/nope", "", roleWrite(service.AuthzRoleWriteDelete, "nope"), "Role not found"},
		{"members unknown role", http.MethodGet, "/roles/nope/members", "", nil, "Role not found"},
		{"set members unknown role", http.MethodPut, "/roles/nope/members", `{"user_ids":[5]}`, roleWrite(service.AuthzRoleWriteMembers, "nope"), "Role not found"},
		{"set members wrong type", http.MethodPut, "/roles/viewer/members", `{"user_ids":"x"}`, nil, ""},
		{"set members invalid json", http.MethodPut, "/roles/viewer/members", `{`, nil, ""},
		{"set members zero id", http.MethodPut, "/roles/viewer/members", `{"user_ids":[0]}`, roleWrite(service.AuthzRoleWriteMembers, "viewer"), "Only administrators can be assigned roles"},
		{"set members negative id", http.MethodPut, "/roles/viewer/members", `{"user_ids":[-1]}`, roleWrite(service.AuthzRoleWriteMembers, "viewer"), "Only administrators can be assigned roles"},
		{"set members nonexistent id", http.MethodPut, "/roles/viewer/members", `{"user_ids":[999]}`, roleWrite(service.AuthzRoleWriteMembers, "viewer"), "Only administrators can be assigned roles"},
		{"set user roles non-numeric id", http.MethodPut, "/users/abc/roles", `{"role_keys":[]}`, nil, "Invalid user ID"},
		{"set user roles invalid json", http.MethodPut, "/users/5/roles", `{`, nil, ""},
		{"set user roles wrong type", http.MethodPut, "/users/5/roles", `{"role_keys":"x"}`, nil, ""},
		{"set user roles unknown role", http.MethodPut, "/users/5/roles", `{"role_keys":["nope"]}`, userRolesWrite(5), "Role not found"},
		{"set user roles common user", http.MethodPut, "/users/8/roles", `{"role_keys":["viewer"]}`, userRolesWrite(8), "Only administrators can be assigned roles"},
		{"set user roles zero id", http.MethodPut, "/users/0/roles", `{"role_keys":["viewer"]}`, nil, "Only administrators can be assigned roles"},
		{"set user roles negative id", http.MethodPut, "/users/-1/roles", `{"role_keys":["viewer"]}`, nil, "Only administrators can be assigned roles"},
		{"set user roles nonexistent id", http.MethodPut, "/users/999/roles", `{"role_keys":["viewer"]}`, userRolesWrite(999), "Only administrators can be assigned roles"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := f.call(tc.method, tc.path, tc.body, tc.operation)
			assert.False(t, resp.Success)
			if tc.message == "" {
				assert.NotEmpty(t, resp.Message)
				return
			}
			assert.Equal(t, tc.message, resp.Message)
		})
	}

	resp := f.call(http.MethodGet, "/users/5/roles", "", nil)
	require.True(t, resp.Success)
	assert.JSONEq(t, `[]`, string(resp.Data))

	resp = f.call(http.MethodPut, "/users/5/roles", `{"role_keys":["viewer"]}`, userRolesWrite(5))
	require.True(t, resp.Success, resp.Message)
	resp = f.call(http.MethodGet, "/users/5/roles", "", nil)
	assert.JSONEq(t, `["viewer"]`, string(resp.Data))
	resp = f.call(http.MethodPut, "/users/5/roles", `{"role_keys":[]}`, userRolesWrite(5))
	require.True(t, resp.Success, resp.Message)
	resp = f.call(http.MethodGet, "/users/5/roles", "", nil)
	assert.JSONEq(t, `[]`, string(resp.Data))
}

func TestAuthzRoleWritesRequireMatchingSingleUseProof(t *testing.T) {
	f := setupAuthzRoleTest(t)
	created := f.call(http.MethodPost, "/roles", `{"key":"viewer","name":"Viewer","grants":{}}`, roleWrite(service.AuthzRoleWriteCreate, "viewer"))
	require.True(t, created.Success, created.Message)

	writes := []struct {
		name, method, path, body string
		operation                *service.VerificationOperation
		other                    *service.VerificationOperation // a proof for a different change
	}{
		{"create", http.MethodPost, "/roles", `{"key":"second","name":"Second","grants":{"user":{"read":true}}}`,
			roleWrite(service.AuthzRoleWriteCreate, "second"), roleWrite(service.AuthzRoleWriteCreate, "third")},
		{"update", http.MethodPut, "/roles/viewer", `{"name":"Changed","grants":{"user":{"read":true}}}`,
			roleWrite(service.AuthzRoleWriteUpdate, "viewer"), roleWrite(service.AuthzRoleWriteDelete, "viewer")},
		{"members", http.MethodPut, "/roles/viewer/members", `{"user_ids":[5]}`,
			roleWrite(service.AuthzRoleWriteMembers, "viewer"), roleWrite(service.AuthzRoleWriteMembers, "other")},
		{"user roles", http.MethodPut, "/users/5/roles", `{"role_keys":["viewer"]}`,
			userRolesWrite(5), userRolesWrite(6)},
		{"delete", http.MethodDelete, "/roles/viewer?force=true", "",
			roleWrite(service.AuthzRoleWriteDelete, "viewer"), roleWrite(service.AuthzRoleWriteUpdate, "viewer")},
	}
	for _, write := range writes {
		t.Run(write.name, func(t *testing.T) {
			before, err := authz.ListRoles()
			require.NoError(t, err)
			bindingsBefore := authz.UserRoleKeys(5)

			status, resp := f.send(write.method, write.path, write.body, nil)
			assert.Equal(t, http.StatusForbidden, status)
			assert.Equal(t, "SECURITY_PROOF_REQUIRED", resp.Code)

			status, resp = f.send(write.method, write.path, write.body, write.other)
			assert.Equal(t, http.StatusForbidden, status)
			assert.Equal(t, "SECURITY_PROOF_CONTEXT_MISMATCH", resp.Code)

			after, err := authz.ListRoles()
			require.NoError(t, err)
			assert.Equal(t, before, after, "a rejected proof must not change roles")
			assert.Equal(t, bindingsBefore, authz.UserRoleKeys(5))

			proof := f.proof(*write.operation)
			status, resp = f.sendWithProof(write.method, write.path, write.body, proof)
			require.Equal(t, http.StatusOK, status)
			require.True(t, resp.Success, resp.Message)

			status, resp = f.sendWithProof(write.method, write.path, write.body, proof)
			assert.Equal(t, http.StatusForbidden, status)
			assert.Equal(t, "SECURITY_PROOF_CONSUMED", resp.Code)
		})
	}
}

func TestAuthzRoleWriteProofIsRootSessionOnly(t *testing.T) {
	f := setupAuthzRoleTest(t)
	require.NoError(t, model.PublishUserAuthCache(5))
	bundle, err := service.CreateLoginSession(5, "password", "127.0.0.1", "authz-role-test")
	require.NoError(t, err)
	admin, err := service.ParseAccessToken(bundle.AccessToken)
	require.NoError(t, err)

	_, err = service.GetVerificationRequirements(admin, service.VerificationScopeAuthzRoleWrite)
	assert.ErrorIs(t, err, service.ErrVerificationForbidden)
	requirements, err := service.GetVerificationRequirements(f.identity, service.VerificationScopeAuthzRoleWrite)
	require.NoError(t, err)
	assert.Equal(t, []service.VerificationMethodOption{{Method: service.VerificationMethodPassword, Available: true}}, requirements.Methods)
	required, listed := service.AccessTokenVerificationScope(service.VerificationScopeAuthzRoleWrite)
	assert.True(t, listed)
	assert.Empty(t, required, "access tokens can never obtain a role change proof")
}

func TestAuthzRoleWriteContextValidation(t *testing.T) {
	cases := []struct {
		context string
		valid   bool
	}{
		{`{"action":"create"}`, true},
		{`{"action":"create","role_key":"viewer"}`, true},
		{`{"action":"update","role_key":"viewer"}`, true},
		{`{"action":"delete","role_key":"viewer"}`, true},
		{`{"action":"members","role_key":"viewer"}`, true},
		{`{"action":"user_roles","user_id":5}`, true},
		{`{"action":"create","user_id":5}`, false},
		{`{"action":"update"}`, false},
		{`{"action":"update","role_key":""}`, false},
		{`{"action":"update","role_key":"viewer","extra":1}`, false},
		{`{"action":"members","role_key":"viewer","user_id":5}`, false},
		{`{"action":"user_roles"}`, false},
		{`{"action":"user_roles","user_id":-1}`, false},
		{`{"action":"user_roles","user_id":5,"role_key":"viewer"}`, false},
		{`{"action":"rename","role_key":"viewer"}`, false},
		{`{"action":"update","role_key":"` + strings.Repeat("k", 65) + `"}`, false},
		{``, false},
	}
	for _, tc := range cases {
		t.Run(tc.context, func(t *testing.T) {
			_, err := service.BindVerificationOperation(service.VerificationOperation{Scope: service.VerificationScopeAuthzRoleWrite, Context: []byte(tc.context)})
			if tc.valid {
				assert.NoError(t, err)
				return
			}
			assert.ErrorIs(t, err, service.ErrVerificationContextInvalid)
		})
	}
}

func TestDeletingUserClearsAuthorization(t *testing.T) {
	for _, test := range []struct {
		name, method, path, body string
	}{
		{"hard delete", http.MethodDelete, "/user/5", ""},
		{"manage delete", http.MethodPost, "/user/manage", `{"id":5,"action":"delete"}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := setupAuthzRoleTest(t)
			require.NoError(t, f.db.AutoMigrate(&model.ExternalIdentityClaim{}, &model.UserOAuthBinding{}, &model.TwoFABackupCode{}, &model.Token{}))
			created := f.call(http.MethodPost, "/roles", `{"key":"viewer","name":"Viewer","grants":{"channel":{"read":true}}}`, roleWrite(service.AuthzRoleWriteCreate, "viewer"))
			require.True(t, created.Success, created.Message)
			require.NoError(t, authz.SetUserRoles(5, []string{"viewer"}))
			require.NoError(t, authz.SetUserPermissions(5, authz.PermissionsMap{authz.ResourceUser: {authz.ActionRead: true}}))

			resp := f.call(test.method, test.path, test.body, verificationOperation(service.VerificationScopeAdminUserDelete, service.AdminUserContext{UserID: 5}))
			require.True(t, resp.Success, resp.Message)

			var bindings, overrides int64
			require.NoError(t, f.db.Model(&model.AuthzUserRole{}).Where("user_id = ?", 5).Count(&bindings).Error)
			require.NoError(t, f.db.Model(&model.CasbinRule{}).Where("v0 = ?", authz.UserSubject(5)).Count(&overrides).Error)
			assert.Zero(t, bindings)
			assert.Zero(t, overrides)
			assert.Empty(t, authz.UserRoleKeys(5))
			assert.Empty(t, authz.ExplicitUserOverrides(5))
			members, err := authz.RoleMembers("viewer")
			require.NoError(t, err)
			assert.Empty(t, members)
		})
	}
}

func TestAuthzRoleAuditOmitsProof(t *testing.T) {
	f := setupAuthzRoleTest(t)
	proof := f.proof(*roleWrite(service.AuthzRoleWriteCreate, "viewer"))
	status, resp := f.sendWithProof(http.MethodPost, "/roles", `{"key":"viewer","name":"Viewer","grants":{}}`, proof)
	require.Equal(t, http.StatusOK, status)
	require.True(t, resp.Success, resp.Message)
	var entries []model.AuditLog
	require.NoError(t, model.LOG_DB.Find(&entries).Error)
	require.NotEmpty(t, entries)
	for _, entry := range entries {
		encoded, err := common.Marshal(entry)
		require.NoError(t, err)
		assert.NotContains(t, string(encoded), proof, fmt.Sprintf("audit entry %s", entry.Action))
	}
}
