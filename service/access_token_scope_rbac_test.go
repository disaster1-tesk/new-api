package service

import (
	"slices"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service/authz"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func initAuthzForTest(t *testing.T) {
	t.Helper()
	wasMaster := common.IsMasterNode
	common.IsMasterNode = true
	t.Cleanup(func() { common.IsMasterNode = wasMaster })
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&model.CasbinRule{}, &model.AuthzRole{}))
	require.NoError(t, authz.Init(db))
}

func TestAdminResourcesMirrorStaticAccessTokenResources(t *testing.T) {
	initAuthzForTest(t)
	catalog := authz.Catalog()
	for _, static := range accessTokenStaticResources {
		if !authz.IsRegisteredResource(static.Resource) {
			continue
		}
		idx := slices.IndexFunc(catalog, func(d authz.ResourceDefinition) bool { return d.Resource == static.Resource })
		require.GreaterOrEqual(t, idx, 0, static.Resource)
		def := catalog[idx]
		assert.Equal(t, static.LabelKey, def.LabelKey, static.Resource)
		require.Len(t, def.Actions, len(static.Actions), static.Resource)
		for i, action := range static.Actions {
			assert.Equal(t, action.Action, def.Actions[i].Action, static.Resource)
			assert.Equal(t, action.LabelKey, def.Actions[i].LabelKey, static.Resource)
			assert.Equal(t, action.DescriptionKey, def.Actions[i].DescriptionKey, static.Resource)
		}
	}
	for _, name := range []string{"user", "billing", "model", "deployment", "group", "log", "redemption", "option", "plugin", "ops"} {
		assert.True(t, authz.IsRegisteredResource(name), name)
	}
}

func TestAccessTokenCatalogUsesCasbinGrantsForAdminResources(t *testing.T) {
	initAuthzForTest(t)
	scopes := func(userID, role int) (map[string]string, []string) {
		seen := map[string]int{}
		groupOf := map[string]string{}
		var all []string
		for _, group := range AccessTokenCatalog(userID, role) {
			for _, resource := range group.Resources {
				seen[resource.Resource]++
				groupOf[resource.Resource] = group.Group
				for _, action := range resource.Actions {
					all = append(all, resource.Resource+":"+action.Action)
				}
			}
		}
		for name, n := range seen {
			assert.Equal(t, 1, n, name)
		}
		return groupOf, all
	}

	_, admin := scopes(2, common.RoleAdminUser)
	assert.Contains(t, admin, "user:read")
	assert.Contains(t, admin, "user:write")
	assert.Contains(t, admin, "log:read")
	for _, scope := range admin {
		for _, prefix := range []string{"option:", "plugin:", "ops:"} {
			assert.NotContains(t, scope, prefix)
		}
	}

	groups, _ := scopes(1, common.RoleRootUser)
	assert.Equal(t, AccessTokenGroupSystem, groups["option"])
}

func TestPermissionFromScope(t *testing.T) {
	permission, ok := authz.PermissionFromScope("user:write")
	assert.True(t, ok)
	assert.Equal(t, authz.Permission{Resource: "user", Action: "write"}, permission)
	for _, scope := range []string{"api_key:read", "user", "nope:read"} {
		_, ok := authz.PermissionFromScope(scope)
		assert.False(t, ok, scope)
	}
}
