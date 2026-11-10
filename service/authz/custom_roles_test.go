package authz

import (
	"regexp"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

var userRead = Permission{Resource: ResourceUser, Action: ActionRead}

// newCustomRoleTestDB returns an initialized store with admins 5, 6 and 7,
// common user 8 and root user 1.
func newCustomRoleTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db := newAuthzTestDB(t)
	require.NoError(t, db.AutoMigrate(&model.User{}))
	users := []model.User{
		{Id: 1, Username: "root", AffCode: "r", Password: "password", Role: common.RoleRootUser},
		{Id: 5, Username: "admin5", AffCode: "a5", Password: "password", DisplayName: "Admin Five", Role: common.RoleAdminUser},
		{Id: 6, Username: "admin6", AffCode: "a6", Password: "password", Role: common.RoleAdminUser},
		{Id: 7, Username: "admin7", AffCode: "a7", Password: "password", Role: common.RoleAdminUser},
		{Id: 8, Username: "common8", AffCode: "c8", Password: "password", Role: common.RoleCommonUser},
	}
	require.NoError(t, db.Create(&users).Error)
	require.NoError(t, Init(db))
	return db
}

func createChannelViewer(t *testing.T) RoleView {
	t.Helper()
	view, err := CreateRole(RoleInput{
		Key:    "channel-viewer",
		Name:   "Channel viewer",
		Grants: PermissionsMap{ResourceChannel: {ActionRead: true}},
	})
	require.NoError(t, err)
	return view
}

func TestCustomRoleReplacesAdminBaseline(t *testing.T) {
	newCustomRoleTestDB(t)
	createChannelViewer(t)
	require.NoError(t, SetUserRoles(5, []string{"channel-viewer"}))

	assert.True(t, Can(5, common.RoleAdminUser, ChannelRead))
	assert.False(t, Can(5, common.RoleAdminUser, ChannelWrite))
	assert.False(t, Can(5, common.RoleAdminUser, userRead))
	assert.True(t, Can(6, common.RoleAdminUser, userRead))
	assert.Equal(t, []string{"channel-viewer"}, UserRoleKeys(5))
}

func TestMultipleRolesUnion(t *testing.T) {
	newCustomRoleTestDB(t)
	createChannelViewer(t)
	_, err := CreateRole(RoleInput{
		Key:    "user-reader",
		Name:   "User reader",
		Grants: PermissionsMap{ResourceUser: {ActionRead: true}},
	})
	require.NoError(t, err)
	require.NoError(t, SetUserRoles(5, []string{"channel-viewer", "user-reader"}))

	assert.True(t, Can(5, common.RoleAdminUser, ChannelRead))
	assert.True(t, Can(5, common.RoleAdminUser, userRead))
	assert.False(t, Can(5, common.RoleAdminUser, Permission{Resource: ResourceUser, Action: ActionWrite}))
}

func TestUserOverrideIsRelativeToBoundRoles(t *testing.T) {
	newCustomRoleTestDB(t)
	createChannelViewer(t)
	require.NoError(t, SetUserRoles(5, []string{"channel-viewer"}))

	require.NoError(t, SetUserPermissions(5, PermissionsMap{ResourceUser: {ActionRead: true}}))
	assert.True(t, Can(5, common.RoleAdminUser, userRead))

	require.NoError(t, SetUserPermissions(5, PermissionsMap{ResourceChannel: {ActionRead: false}}))
	assert.False(t, Can(5, common.RoleAdminUser, ChannelRead))
}

func TestRoleMembersMustBeAdmins(t *testing.T) {
	newCustomRoleTestDB(t)
	createChannelViewer(t)

	for _, ids := range [][]int{{8}, {1}, {5, 999}} {
		assert.ErrorIs(t, SetRoleMembers("channel-viewer", ids), ErrRoleMemberInvalid, ids)
	}
	for _, userID := range []int{8, 1, 999} {
		assert.ErrorIs(t, SetUserRoles(userID, []string{"channel-viewer"}), ErrRoleMemberInvalid, userID)
	}
	assert.ErrorIs(t, SetUserRoles(5, []string{"missing"}), ErrRoleNotFound)

	require.NoError(t, SetRoleMembers("channel-viewer", []int{5, 6}))
	members, err := RoleMembers("channel-viewer")
	require.NoError(t, err)
	assert.Equal(t, []RoleMember{{Id: 5, Username: "admin5", DisplayName: "Admin Five"}, {Id: 6, Username: "admin6"}}, members)
}

func TestRoleMembersExcludeSoftDeletedUsers(t *testing.T) {
	db := newCustomRoleTestDB(t)
	createChannelViewer(t)
	require.NoError(t, SetRoleMembers("channel-viewer", []int{5, 6}))
	require.NoError(t, db.Delete(&model.User{}, 6).Error)

	members, err := RoleMembers("channel-viewer")
	require.NoError(t, err)
	assert.Equal(t, []RoleMember{{Id: 5, Username: "admin5", DisplayName: "Admin Five"}}, members)
	roles, err := ListRoles()
	require.NoError(t, err)
	require.Len(t, roles, 3)
	assert.Equal(t, int64(1), roles[2].MemberCount)
}

func TestBuiltInRolesAreImmutable(t *testing.T) {
	newCustomRoleTestDB(t)
	createChannelViewer(t)

	_, err := UpdateRole(BuiltInRoleAdmin, RoleInput{Name: "Admin"})
	assert.ErrorIs(t, err, ErrRoleBuiltIn)
	assert.ErrorIs(t, DeleteRole(BuiltInRoleRoot, true), ErrRoleBuiltIn)
	for _, key := range []string{"root", "admin", "Bad Key"} {
		_, err := CreateRole(RoleInput{Key: key, Name: "Name"})
		assert.ErrorIs(t, err, ErrRoleKeyInvalid, key)
	}
	_, err = CreateRole(RoleInput{Key: "channel-viewer", Name: "Again"})
	assert.ErrorIs(t, err, ErrRoleKeyExists)
	_, err = CreateRole(RoleInput{Key: "nameless"})
	assert.ErrorIs(t, err, ErrRoleNameRequired)
	_, err = UpdateRole("missing", RoleInput{Name: "Missing"})
	assert.ErrorIs(t, err, ErrRoleNotFound)

	updated, err := UpdateRole("channel-viewer", RoleInput{
		Key:    "ignored",
		Name:   "Channel writer",
		Grants: PermissionsMap{ResourceChannel: {ActionWrite: true}},
	})
	require.NoError(t, err)
	assert.Equal(t, "channel-viewer", updated.Key)
	assert.Equal(t, "Channel writer", updated.Name)
	assert.False(t, updated.Grants[ResourceChannel][ActionRead])
	assert.True(t, updated.Grants[ResourceChannel][ActionWrite])
}

func TestCreateRoleGeneratesKeyFromName(t *testing.T) {
	newCustomRoleTestDB(t)

	first, err := CreateRole(RoleInput{Name: "Ops Team"})
	require.NoError(t, err)
	assert.Equal(t, "ops-team", first.Key)
	second, err := CreateRole(RoleInput{Name: "Ops Team"})
	require.NoError(t, err)
	assert.Equal(t, "ops-team-2", second.Key)
	reserved, err := CreateRole(RoleInput{Name: "Admin"})
	require.NoError(t, err)
	assert.Equal(t, "admin-2", reserved.Key)

	generated, err := CreateRole(RoleInput{Name: "渠道运维"})
	require.NoError(t, err)
	assert.Regexp(t, regexp.MustCompile(`^role-`), generated.Key)
	assert.Regexp(t, regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`), generated.Key)
}

func TestDeleteRoleWithMembersRequiresForce(t *testing.T) {
	db := newCustomRoleTestDB(t)
	createChannelViewer(t)
	require.NoError(t, SetRoleMembers("channel-viewer", []int{5}))
	require.False(t, Can(5, common.RoleAdminUser, userRead))

	assert.ErrorIs(t, DeleteRole("channel-viewer", false), ErrRoleHasMembers)
	require.NoError(t, DeleteRole("channel-viewer", true))

	var policies int64
	require.NoError(t, db.Model(&model.CasbinRule{}).Where("v0 = ?", RoleSubject("channel-viewer")).Count(&policies).Error)
	assert.Zero(t, policies)
	var bindings int64
	require.NoError(t, db.Model(&model.AuthzUserRole{}).Where("role_key = ?", "channel-viewer").Count(&bindings).Error)
	assert.Zero(t, bindings)
	assert.True(t, Can(5, common.RoleAdminUser, userRead))
	assert.ErrorIs(t, DeleteRole("channel-viewer", true), ErrRoleNotFound)
}

func TestUnknownGrantsAreIgnored(t *testing.T) {
	newCustomRoleTestDB(t)
	_, err := CreateRole(RoleInput{
		Key:  "odd",
		Name: "Odd",
		Grants: PermissionsMap{
			"nope":          {ActionRead: true},
			ResourceChannel: {"fly": true, ActionRead: true},
		},
	})
	require.NoError(t, err)

	roles, err := ListRoles()
	require.NoError(t, err)
	require.Len(t, roles, 3)
	assert.Equal(t, BuiltInRoleRoot, roles[0].Key)
	assert.True(t, roles[0].Superuser)
	assert.Equal(t, BuiltInRoleAdmin, roles[1].Key)
	odd := roles[2]
	assert.Equal(t, "odd", odd.Key)
	assert.False(t, odd.BuiltIn)
	assert.NotContains(t, odd.Grants, "nope")
	assert.NotContains(t, odd.Grants[ResourceChannel], "fly")
	assert.True(t, odd.Grants[ResourceChannel][ActionRead])
}

func TestReinitKeepsCustomRoles(t *testing.T) {
	db := newCustomRoleTestDB(t)
	createChannelViewer(t)
	require.NoError(t, SetUserRoles(5, []string{"channel-viewer"}))

	require.NoError(t, Init(db))

	assert.True(t, Can(5, common.RoleAdminUser, ChannelRead))
	assert.False(t, Can(5, common.RoleAdminUser, userRead))
	roles, err := ListRoles()
	require.NoError(t, err)
	require.Len(t, roles, 3)
	assert.Equal(t, "channel-viewer", roles[2].Key)
	assert.Equal(t, int64(1), roles[2].MemberCount)
}

func TestClearUserAuthorizationRemovesRoleBindings(t *testing.T) {
	db := newCustomRoleTestDB(t)
	createChannelViewer(t)
	require.NoError(t, SetUserRoles(5, []string{"channel-viewer"}))
	require.NoError(t, SetUserRoles(6, []string{"channel-viewer"}))
	require.NotEmpty(t, UserRoleKeys(5))

	require.NoError(t, db.Transaction(func(tx *gorm.DB) error {
		return ClearUserAuthorizationInTx(tx, 5)
	}))
	assert.Empty(t, UserRoleKeys(5))

	require.NoError(t, ClearUserAuthorization(6))
	assert.Empty(t, UserRoleKeys(6))
}

func TestResolverFallsBackWhenStoreUnavailable(t *testing.T) {
	db := newAuthzTestDB(t)
	require.NoError(t, Init(db))

	assert.True(t, Can(2, common.RoleAdminUser, ChannelRead))
	assert.False(t, Can(2, common.RoleAdminUser, ChannelSensitiveWrite))

	require.NoError(t, db.Migrator().DropTable(&model.AuthzUserRole{}))
	assert.Nil(t, UserRoleKeys(3))
	assert.True(t, Can(3, common.RoleAdminUser, ChannelRead))
}
