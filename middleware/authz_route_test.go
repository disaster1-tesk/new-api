package middleware

import (
	"net/http"
	"net/http/httptest"
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

func initAuthzRouteTest(t *testing.T) {
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
	users := []model.User{
		{Id: 1, Username: "root", AffCode: "r", Password: "password", Role: common.RoleRootUser},
		{Id: 5, Username: "admin5", AffCode: "a5", Password: "password", Role: common.RoleAdminUser},
		{Id: 6, Username: "admin6", AffCode: "a6", Password: "password", Role: common.RoleAdminUser},
		{Id: 7, Username: "admin7", AffCode: "a7", Password: "password", Role: common.RoleAdminUser},
		{Id: 8, Username: "common8", AffCode: "c8", Password: "password", Role: common.RoleCommonUser},
	}
	require.NoError(t, db.Create(&users).Error)
	require.NoError(t, authz.Init(db))
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
	gin.SetMode(gin.TestMode)
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			router := gin.New()
			router.Handle(tt.method, tt.path, func(c *gin.Context) {
				c.JSON(http.StatusOK, dashboardRoleAllowed(c, tt.userID, tt.role, tt.minRole))
			})
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, httptest.NewRequest(tt.method, tt.path, nil))
			assert.Equal(t, tt.want, recorder.Body.String() == "true")
		})
	}
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
