package authz

import (
	"errors"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"gorm.io/gorm"
)

var (
	ErrRoleNotFound      = errors.New("role not found")
	ErrRoleBuiltIn       = errors.New("built-in roles cannot be modified")
	ErrRoleKeyInvalid    = errors.New("invalid role key")
	ErrRoleKeyExists     = errors.New("role key already exists")
	ErrRoleNameRequired  = errors.New("role name is required")
	ErrRoleHasMembers    = errors.New("role still has members")
	ErrRoleMemberInvalid = errors.New("role members must be administrators below root")

	errRoleStoreUnavailable = errors.New("authz role store is not initialized")
)

const (
	customRoleSort   = 100
	maxRoleKeyLength = 64
)

var (
	roleKeyPattern     = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
	roleSlugSeparators = regexp.MustCompile(`[^a-z0-9]+`)
)

// RoleInput is the editable part of a custom role.
type RoleInput struct {
	Key         string
	Name        string
	Description string
	Grants      PermissionsMap
}

// RoleView is a role with its baseline grant matrix and live member count.
type RoleView struct {
	Key         string         `json:"key"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	BuiltIn     bool           `json:"built_in"`
	Superuser   bool           `json:"superuser"`
	Grants      PermissionsMap `json:"grants"`
	MemberCount int64          `json:"member_count"`
}

// RoleMember is a user bound to a custom role.
type RoleMember struct {
	Id          int    `json:"id"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
}

type roleBindingEntry struct {
	keys    []string
	expires time.Time
}

// customRoleDB is the store passed to Init. The binding cache is keyed by user
// id; roleBindingGen guards against caching a lookup that raced a write.
var (
	customRoleMu     sync.RWMutex
	customRoleDB     *gorm.DB
	roleBindingCache = map[int]roleBindingEntry{}
	roleBindingGen   uint64
)

func init() {
	resolveSubjectRoles = func(userID int, systemRole int) []string {
		switch {
		case systemRole >= common.RoleRootUser:
			return []string{BuiltInRoleRoot}
		case systemRole >= common.RoleAdminUser:
			keys, err := userRoleBindings(userID)
			if err != nil {
				// Fail closed: an unknown binding may be a restricted role.
				return nil
			}
			if len(keys) > 0 {
				return keys
			}
			return []string{BuiltInRoleAdmin}
		default:
			return nil
		}
	}
}

// initCustomRoles binds the role store to db and creates the binding table,
// which is owned by this package rather than the main migration list. Every
// node migrates it so a node never runs against a missing table.
func initCustomRoles(db *gorm.DB) error {
	if err := db.AutoMigrate(&model.AuthzUserRole{}); err != nil {
		return err
	}
	customRoleMu.Lock()
	customRoleDB = db
	customRoleMu.Unlock()
	invalidateRoleBindings()
	return nil
}

func currentRoleDB() *gorm.DB {
	customRoleMu.RLock()
	defer customRoleMu.RUnlock()
	return customRoleDB
}

func invalidateRoleBindings() {
	customRoleMu.Lock()
	roleBindingCache = map[int]roleBindingEntry{}
	roleBindingGen++
	customRoleMu.Unlock()
}

// UserRoleKeys returns the custom role keys bound to the user, or nil when the
// store is unavailable or the lookup failed.
func UserRoleKeys(userID int) []string {
	keys, _ := userRoleBindings(userID)
	return keys
}

// userRoleBindings returns the cached role keys of a user. It returns no error
// when the store is not initialized; a failed lookup is logged and not cached.
func userRoleBindings(userID int) ([]string, error) {
	customRoleMu.RLock()
	db := customRoleDB
	gen := roleBindingGen
	entry, cached := roleBindingCache[userID]
	customRoleMu.RUnlock()
	if cached && time.Now().Before(entry.expires) {
		return slices.Clone(entry.keys), nil
	}
	if db == nil {
		return nil, nil
	}

	keys, err := loadUserRoleKeys(db, userID)
	if err != nil {
		common.SysError(common.LogText("failed to load authz role bindings for user %d: %s", userID, err.Error()))
		return nil, err
	}
	ttl := time.Duration(common.SyncFrequency) * time.Second
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	customRoleMu.Lock()
	if roleBindingGen == gen {
		roleBindingCache[userID] = roleBindingEntry{keys: keys, expires: time.Now().Add(ttl)}
	}
	customRoleMu.Unlock()
	return slices.Clone(keys), nil
}

// adminRolesInTx resolves an administrator's roles from tx, so a transaction
// sees its own uncommitted bindings and never waits for a second connection.
func adminRolesInTx(tx *gorm.DB, userID int) ([]string, error) {
	keys, err := loadUserRoleKeys(tx, userID)
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return []string{BuiltInRoleAdmin}, nil
	}
	return keys, nil
}

func loadUserRoleKeys(db *gorm.DB, userID int) ([]string, error) {
	var keys []string
	err := db.Model(&model.AuthzUserRole{}).Where("user_id = ?", userID).Order("id asc").Pluck("role_key", &keys).Error
	return keys, err
}

// ListRoles returns root and admin followed by custom roles in creation order.
func ListRoles() ([]RoleView, error) {
	db := currentRoleDB()
	if db == nil {
		return nil, errRoleStoreUnavailable
	}
	var roles []model.AuthzRole
	if err := db.Where(map[string]any{"built_in": false}).Order("id asc").Find(&roles).Error; err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(roles))
	for _, role := range roles {
		keys = append(keys, role.Key)
	}
	counts, err := roleMemberCounts(db, keys)
	if err != nil {
		return nil, err
	}

	views := make([]RoleView, 0, len(builtInRoles)+len(roles))
	for _, descriptor := range Roles() {
		spec, _ := roleSpec(descriptor.Key)
		views = append(views, RoleView{
			Key:         descriptor.Key,
			Name:        descriptor.Name,
			Description: spec.Description,
			BuiltIn:     descriptor.BuiltIn,
			Superuser:   descriptor.Superuser,
			Grants:      descriptor.Grants,
		})
	}
	for _, role := range roles {
		views = append(views, customRoleView(role, counts[role.Key]))
	}
	return views, nil
}

// CreateRole stores a custom role. An empty key is derived from the name.
func CreateRole(input RoleInput) (RoleView, error) {
	db := currentRoleDB()
	if db == nil {
		return RoleView{}, errRoleStoreUnavailable
	}
	name := strings.TrimSpace(input.Name)
	if name == "" {
		return RoleView{}, ErrRoleNameRequired
	}
	if input.Key != "" && !isCustomRoleKey(input.Key) {
		return RoleView{}, ErrRoleKeyInvalid
	}

	role := model.AuthzRole{
		Key:         input.Key,
		Name:        name,
		Description: strings.TrimSpace(input.Description),
		BuiltIn:     false,
		Enabled:     true,
		Sort:        customRoleSort,
	}
	err := db.Transaction(func(tx *gorm.DB) error {
		if role.Key != "" {
			exists, err := roleKeyExists(tx, role.Key)
			if err != nil {
				return err
			}
			if exists {
				return ErrRoleKeyExists
			}
		} else {
			base := roleSlug(name)
			for n := 1; role.Key == ""; n++ {
				candidate := base
				if n > 1 {
					suffix := "-" + strconv.Itoa(n)
					candidate = base[:min(len(base), maxRoleKeyLength-len(suffix))] + suffix
				}
				if !isCustomRoleKey(candidate) {
					continue
				}
				exists, err := roleKeyExists(tx, candidate)
				if err != nil {
					return err
				}
				if !exists {
					role.Key = candidate
				}
			}
		}
		if err := tx.Create(&role).Error; err != nil {
			return err
		}
		return replaceRolePolicies(tx, role.Key, input.Grants)
	})
	if err != nil {
		return RoleView{}, err
	}
	invalidateRoleBindings()
	if err := ReloadPolicy(); err != nil {
		return RoleView{}, err
	}
	return customRoleView(role, 0), nil
}

// UpdateRole replaces a custom role's name, description and grants. The key in
// input is ignored.
func UpdateRole(key string, input RoleInput) (RoleView, error) {
	db := currentRoleDB()
	if db == nil {
		return RoleView{}, errRoleStoreUnavailable
	}
	name := strings.TrimSpace(input.Name)
	var role model.AuthzRole
	err := db.Transaction(func(tx *gorm.DB) error {
		var err error
		role, err = findCustomRole(tx, key)
		if err != nil {
			return err
		}
		if name == "" {
			return ErrRoleNameRequired
		}
		role.Name = name
		role.Description = strings.TrimSpace(input.Description)
		if err := tx.Save(&role).Error; err != nil {
			return err
		}
		return replaceRolePolicies(tx, role.Key, input.Grants)
	})
	if err != nil {
		return RoleView{}, err
	}
	invalidateRoleBindings()
	if err := ReloadPolicy(); err != nil {
		return RoleView{}, err
	}
	counts, err := roleMemberCounts(db, []string{role.Key})
	if err != nil {
		return RoleView{}, err
	}
	return customRoleView(role, counts[role.Key]), nil
}

// DeleteRole removes a custom role with its policies and bindings. A role that
// still has members is only removed when force is set.
func DeleteRole(key string, force bool) error {
	db := currentRoleDB()
	if db == nil {
		return errRoleStoreUnavailable
	}
	err := db.Transaction(func(tx *gorm.DB) error {
		if _, err := findCustomRole(tx, key); err != nil {
			return err
		}
		if !force {
			counts, err := roleMemberCounts(tx, []string{key})
			if err != nil {
				return err
			}
			if counts[key] > 0 {
				return ErrRoleHasMembers
			}
		}
		if err := tx.Where("role_key = ?", key).Delete(&model.AuthzUserRole{}).Error; err != nil {
			return err
		}
		if err := tx.Where("ptype = ? AND v0 = ?", "p", RoleSubject(key)).Delete(&model.CasbinRule{}).Error; err != nil {
			return err
		}
		return tx.Where(map[string]any{"key": key, "built_in": false}).Delete(&model.AuthzRole{}).Error
	})
	if err != nil {
		return err
	}
	invalidateRoleBindings()
	return ReloadPolicy()
}

// RoleMembers lists the users bound to a custom role, excluding deleted users.
func RoleMembers(key string) ([]RoleMember, error) {
	db := currentRoleDB()
	if db == nil {
		return nil, errRoleStoreUnavailable
	}
	if _, err := findCustomRole(db, key); err != nil {
		return nil, err
	}
	members := make([]RoleMember, 0)
	err := db.Model(&model.User{}).
		Select("id", "username", "display_name").
		Where("id IN (?)", db.Model(&model.AuthzUserRole{}).Select("user_id").Where("role_key = ?", key)).
		Order("id asc").
		Scan(&members).Error
	if err != nil {
		return nil, err
	}
	return members, nil
}

// SetRoleMembers replaces the users bound to a custom role.
func SetRoleMembers(key string, userIDs []int) error {
	db := currentRoleDB()
	if db == nil {
		return errRoleStoreUnavailable
	}
	ids := slices.Compact(slices.Sorted(slices.Values(userIDs)))
	err := db.Transaction(func(tx *gorm.DB) error {
		if _, err := findCustomRole(tx, key); err != nil {
			return err
		}
		if err := validateRoleMembers(tx, ids); err != nil {
			return err
		}
		if err := tx.Where("role_key = ?", key).Delete(&model.AuthzUserRole{}).Error; err != nil {
			return err
		}
		if len(ids) == 0 {
			return nil
		}
		bindings := make([]model.AuthzUserRole, 0, len(ids))
		for _, id := range ids {
			bindings = append(bindings, model.AuthzUserRole{UserId: id, RoleKey: key})
		}
		return tx.Create(&bindings).Error
	})
	if err != nil {
		return err
	}
	invalidateRoleBindings()
	return nil
}

// SetUserRoles replaces the custom roles bound to a user.
func SetUserRoles(userID int, roleKeys []string) error {
	db := currentRoleDB()
	if db == nil {
		return errRoleStoreUnavailable
	}
	keys := slices.Compact(slices.Sorted(slices.Values(roleKeys)))
	err := db.Transaction(func(tx *gorm.DB) error {
		if err := validateRoleMembers(tx, []int{userID}); err != nil {
			return err
		}
		if len(keys) > 0 {
			var found int64
			if err := tx.Model(&model.AuthzRole{}).Where(map[string]any{"key": keys, "built_in": false}).Count(&found).Error; err != nil {
				return err
			}
			if found != int64(len(keys)) {
				return ErrRoleNotFound
			}
		}
		if err := tx.Where("user_id = ?", userID).Delete(&model.AuthzUserRole{}).Error; err != nil {
			return err
		}
		if len(keys) == 0 {
			return nil
		}
		bindings := make([]model.AuthzUserRole, 0, len(keys))
		for _, key := range keys {
			bindings = append(bindings, model.AuthzUserRole{UserId: userID, RoleKey: key})
		}
		return tx.Create(&bindings).Error
	})
	if err != nil {
		return err
	}
	invalidateRoleBindings()
	return nil
}

// ClearUserRolesInTx removes every custom role binding of the user.
func ClearUserRolesInTx(tx *gorm.DB, userID int) error {
	if err := tx.Where("user_id = ?", userID).Delete(&model.AuthzUserRole{}).Error; err != nil {
		return err
	}
	invalidateRoleBindings()
	return nil
}

func isCustomRoleKey(key string) bool {
	_, builtIn := roleSpec(key)
	return !builtIn && roleKeyPattern.MatchString(key)
}

// roleSlug derives a role key candidate from a display name.
func roleSlug(name string) string {
	slug := strings.Trim(roleSlugSeparators.ReplaceAllString(strings.ToLower(name), "-"), "-")
	slug = slug[:min(len(slug), maxRoleKeyLength)]
	if slug == "" || slug[0] < 'a' || slug[0] > 'z' {
		id := strconv.FormatInt(time.Now().UnixNano(), 36)
		slug = "role-" + id[max(0, len(id)-8):]
	}
	return slug
}

func roleKeyExists(db *gorm.DB, key string) (bool, error) {
	var count int64
	err := db.Model(&model.AuthzRole{}).Where(map[string]any{"key": key}).Count(&count).Error
	return count > 0, err
}

func findCustomRole(db *gorm.DB, key string) (model.AuthzRole, error) {
	if _, builtIn := roleSpec(key); builtIn {
		return model.AuthzRole{}, ErrRoleBuiltIn
	}
	var role model.AuthzRole
	result := db.Where(map[string]any{"key": key, "built_in": false}).Limit(1).Find(&role)
	if result.Error != nil {
		return model.AuthzRole{}, result.Error
	}
	if result.RowsAffected == 0 {
		return model.AuthzRole{}, ErrRoleNotFound
	}
	return role, nil
}

// validateRoleMembers requires every id to be a live administrator below root.
// ids must be free of duplicates.
func validateRoleMembers(db *gorm.DB, ids []int) error {
	if len(ids) == 0 {
		return nil
	}
	var count int64
	err := db.Model(&model.User{}).
		Where("id IN ?", ids).
		Where("role >= ? AND role < ?", common.RoleAdminUser, common.RoleRootUser).
		Count(&count).Error
	if err != nil {
		return err
	}
	if count != int64(len(ids)) {
		return ErrRoleMemberInvalid
	}
	return nil
}

// roleMemberCounts counts bindings of users that are not soft-deleted.
func roleMemberCounts(db *gorm.DB, keys []string) (map[string]int64, error) {
	counts := make(map[string]int64, len(keys))
	if len(keys) == 0 {
		return counts, nil
	}
	var rows []struct {
		RoleKey     string
		MemberCount int64
	}
	err := db.Model(&model.AuthzUserRole{}).
		Select("role_key, COUNT(*) AS member_count").
		Where("role_key IN ?", keys).
		Where("user_id IN (?)", db.Model(&model.User{}).Select("id")).
		Group("role_key").
		Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		counts[row.RoleKey] = row.MemberCount
	}
	return counts, nil
}

// replaceRolePolicies rewrites the allow policies of a custom role. Grants for
// unregistered resources or actions are dropped.
func replaceRolePolicies(tx *gorm.DB, key string, grants PermissionsMap) error {
	subject := RoleSubject(key)
	if err := tx.Where("ptype = ? AND v0 = ?", "p", subject).Delete(&model.CasbinRule{}).Error; err != nil {
		return err
	}
	rules := make([]model.CasbinRule, 0)
	for _, resource := range registry {
		for _, action := range resource.Actions {
			if grants[resource.Resource][action.Action] {
				rules = append(rules, newRule("p", []string{subject, resource.Resource, action.Action, EffectAllow}))
			}
		}
	}
	if len(rules) == 0 {
		return nil
	}
	return tx.Create(&rules).Error
}

func customRoleView(role model.AuthzRole, memberCount int64) RoleView {
	e := currentEnforcer()
	grants := make(PermissionsMap, len(registry))
	for _, resource := range registry {
		actions := make(map[string]bool, len(resource.Actions))
		for _, action := range resource.Actions {
			permission := Permission{Resource: resource.Resource, Action: action.Action}
			actions[action.Action] = e != nil && roleBaselineAllows(e, role.Key, permission)
		}
		grants[resource.Resource] = actions
	}
	return RoleView{
		Key:         role.Key,
		Name:        role.Name,
		Description: role.Description,
		Grants:      grants,
		MemberCount: memberCount,
	}
}
