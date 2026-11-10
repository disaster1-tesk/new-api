package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/QuantumNous/new-api/service/authz"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func initAuthzRouteTest(t *testing.T) *gorm.DB {
	t.Helper()
	wasMaster := common.IsMasterNode
	common.IsMasterNode = true
	t.Cleanup(func() { common.IsMasterNode = wasMaster })
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&model.CasbinRule{}, &model.AuthzRole{}, &model.User{}, &model.AuditLog{}))
	previousDB, previousLogDB, previousRedis := model.DB, model.LOG_DB, common.RedisEnabled
	model.DB, model.LOG_DB, common.RedisEnabled = db, db, false
	t.Cleanup(func() { model.DB, model.LOG_DB, common.RedisEnabled = previousDB, previousLogDB, previousRedis })
	users := []model.User{
		{Id: 1, Username: "root", AffCode: "r", Password: "password", Role: common.RoleRootUser},
		{Id: 5, Username: "admin5", AffCode: "a5", Password: "password", Role: common.RoleAdminUser},
		{Id: 6, Username: "admin6", AffCode: "a6", Password: "password", Role: common.RoleAdminUser},
		{Id: 7, Username: "admin7", AffCode: "a7", Password: "password", Role: common.RoleAdminUser},
		{Id: 8, Username: "common8", AffCode: "c8", Password: "password", Role: common.RoleCommonUser},
	}
	require.NoError(t, db.Create(&users).Error)
	require.NoError(t, authz.Init(db))
	return db
}

// routeAllowed runs dashboardRoleAllowed for a request matched to path.
func routeAllowed(t *testing.T, method, path string, userID, role, minRole int) bool {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Handle(method, path, func(c *gin.Context) {
		c.JSON(http.StatusOK, dashboardRoleAllowed(c, userID, role, minRole))
	})
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(method, path, nil))
	require.Equal(t, http.StatusOK, recorder.Code)
	return recorder.Body.String() == "true"
}

var permissionRouteOnce sync.Once

func TestDashboardRoleAllowed(t *testing.T) {
	initAuthzRouteTest(t)
	_, err := authz.CreateRole(authz.RoleInput{
		Key: "option-reader", Name: "Option reader",
		Grants: authz.PermissionsMap{authz.ResourceOption: {authz.ActionRead: true}},
	})
	require.NoError(t, err)
	_, err = authz.CreateRole(authz.RoleInput{
		Key: "channel-viewer", Name: "Channel viewer",
		Grants: authz.PermissionsMap{authz.ResourceChannel: {authz.ActionRead: true}},
	})
	require.NoError(t, err)
	require.NoError(t, authz.SetUserRoles(6, []string{"option-reader"}))
	require.NoError(t, authz.SetUserRoles(7, []string{"channel-viewer"}))
	require.NoError(t, authz.SetUserPermissions(5, authz.PermissionsMap{authz.ResourceChannel: {authz.ActionSecretView: true}}))
	permissionRouteOnce.Do(func() {
		DeclareAccessTokenPermissionRoute(http.MethodPost, "/api/rbac-test/permission-route", authz.ChannelSensitiveWrite)
	})

	tests := []struct {
		method, path          string
		userID, role, minRole int
		want                  bool
	}{
		{http.MethodGet, "/api/option/", 1, common.RoleRootUser, common.RoleRootUser, true},
		{http.MethodGet, "/api/option/", 5, common.RoleAdminUser, common.RoleRootUser, false},
		{http.MethodGet, "/api/option/", 6, common.RoleAdminUser, common.RoleRootUser, true},
		{http.MethodPut, "/api/option/", 6, common.RoleAdminUser, common.RoleRootUser, false},
		{http.MethodGet, "/api/user/", 5, common.RoleAdminUser, common.RoleAdminUser, true},
		{http.MethodGet, "/api/user/", 7, common.RoleAdminUser, common.RoleAdminUser, false},
		{http.MethodGet, "/api/authz/catalog", 7, common.RoleAdminUser, common.RoleAdminUser, true},
		{http.MethodGet, "/api/user/self", 8, common.RoleCommonUser, common.RoleCommonUser, true},
		{http.MethodGet, "/api/user/", 8, common.RoleCommonUser, common.RoleAdminUser, false},
		{http.MethodGet, "/api/not-declared", 5, common.RoleAdminUser, common.RoleAdminUser, true},
		{http.MethodGet, "/api/not-declared", 5, common.RoleAdminUser, common.RoleRootUser, false},
		{http.MethodPost, "/api/channel/:id/key", 5, common.RoleAdminUser, common.RoleRootUser, false},
		{http.MethodPost, "/api/rbac-test/permission-route", 6, common.RoleAdminUser, common.RoleAdminUser, true},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			assert.Equal(t, tt.want, routeAllowed(t, tt.method, tt.path, tt.userID, tt.role, tt.minRole))
		})
	}
}

// fullyGrantedRole binds admin 6 to a role holding every catalog permission.
func fullyGrantedRole(t *testing.T) {
	t.Helper()
	grants := authz.PermissionsMap{}
	for _, definition := range authz.Catalog() {
		grants[definition.Resource] = map[string]bool{}
		for _, action := range definition.Actions {
			grants[definition.Resource][action.Action] = true
		}
	}
	_, err := authz.CreateRole(authz.RoleInput{Key: "everything", Name: "Everything", Grants: grants})
	require.NoError(t, err)
	require.NoError(t, authz.SetUserRoles(6, []string{"everything"}))
}

func TestRoleManagementRoutesStayRootOnly(t *testing.T) {
	initAuthzRouteTest(t)
	fullyGrantedRole(t)

	checked := 0
	for _, key := range AccessTokenRouteRuleKeys() {
		method, path, _ := strings.Cut(key, " ")
		if !strings.HasPrefix(path, "/api/authz/roles") && !strings.HasPrefix(path, "/api/authz/users/") {
			continue
		}
		checked++
		assert.False(t, routeAllowed(t, method, path, 6, common.RoleAdminUser, common.RoleRootUser), key)
		assert.True(t, routeAllowed(t, method, path, 1, common.RoleRootUser, common.RoleRootUser), key)
	}
	assert.Equal(t, 8, checked)
}

func TestRootRouteWithAdminDefaultScopeStaysRootOnly(t *testing.T) {
	initAuthzRouteTest(t)
	fullyGrantedRole(t)
	const key = "GET /api/rbac-test/root-user-read"
	accessTokenRouteRules[key] = accessTokenScopeRule("user:read")
	t.Cleanup(func() { delete(accessTokenRouteRules, key) })

	for _, userID := range []int{5, 6} {
		assert.False(t, routeAllowed(t, http.MethodGet, "/api/rbac-test/root-user-read", userID, common.RoleAdminUser, common.RoleRootUser), userID)
		assert.True(t, routeAllowed(t, http.MethodGet, "/api/rbac-test/root-user-read", userID, common.RoleAdminUser, common.RoleAdminUser), userID)
	}
	assert.True(t, routeAllowed(t, http.MethodGet, "/api/rbac-test/root-user-read", 1, common.RoleRootUser, common.RoleRootUser))
}

func TestPermissionDenialIsAudited(t *testing.T) {
	db := initAuthzRouteTest(t)
	_, err := authz.CreateRole(authz.RoleInput{
		Key: "option-reader", Name: "Option reader",
		Grants: authz.PermissionsMap{authz.ResourceOption: {authz.ActionRead: true}},
	})
	require.NoError(t, err)
	require.NoError(t, authz.SetUserRoles(6, []string{"option-reader"}))

	require.True(t, routeAllowed(t, http.MethodGet, "/api/option/", 6, common.RoleAdminUser, common.RoleRootUser))
	require.False(t, routeAllowed(t, http.MethodGet, "/api/not-declared", 5, common.RoleAdminUser, common.RoleRootUser))
	var count int64
	require.NoError(t, db.Model(&model.AuditLog{}).Count(&count).Error)
	assert.Zero(t, count, "allowed requests and plain role floors write no denial entry")

	require.False(t, routeAllowed(t, http.MethodPut, "/api/option/", 6, common.RoleAdminUser, common.RoleRootUser))
	var entries []model.AuditLog
	require.NoError(t, db.Find(&entries).Error)
	require.Len(t, entries, 1)
	entry := entries[0]
	assert.Equal(t, "authz.permission_denied", entry.Action)
	assert.Equal(t, model.AuditCategoryOperation, entry.Category)
	assert.Equal(t, 6, entry.UserId)
	assert.Equal(t, "admin6", entry.Username)
	assert.Equal(t, common.RoleAdminUser, entry.ActorRole)
	assert.Equal(t, http.MethodPut, entry.Method)
	assert.Equal(t, "/api/option/", entry.Route)
	assert.Equal(t, http.StatusForbidden, entry.Status)
	assert.False(t, entry.Success)
	require.NotNil(t, entry.Other.Op)
	params, err := common.Marshal(entry.Other.Op.Params)
	require.NoError(t, err)
	assert.JSONEq(t, `{"method":"PUT","route":"/api/option/","scope":"option:write","user_id":6,"role":10}`, string(params))
	require.NotNil(t, entry.Other.AdminInfo)
	assert.Equal(t, "session", entry.Other.AdminInfo.AuthMethod)
}

func TestBuiltInAdminBaselineMatchesStaticMinRole(t *testing.T) {
	initAuthzRouteTest(t)
	checked := 0
	for _, key := range AccessTokenRouteRuleKeys() {
		rule, _ := AccessTokenRouteRule(key)
		permission, ok := authz.PermissionFromScope(rule.Scope())
		if !ok {
			continue
		}
		minRole, ok := service.AccessTokenStaticMinRole(permission.Resource)
		if !ok {
			continue
		}
		checked++
		assert.Equal(t, minRole <= common.RoleAdminUser, authz.Can(5, common.RoleAdminUser, permission), key)
	}
	assert.NotZero(t, checked)
}
