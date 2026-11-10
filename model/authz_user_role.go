package model

// AuthzUserRole binds an administrator to a custom authorization role.
type AuthzUserRole struct {
	Id        uint   `json:"id" gorm:"primaryKey;autoIncrement"`
	UserId    int    `json:"user_id" gorm:"not null;uniqueIndex:idx_authz_user_roles_user_role,priority:1"`
	RoleKey   string `json:"role_key" gorm:"size:64;not null;uniqueIndex:idx_authz_user_roles_user_role,priority:2;index:idx_authz_user_roles_role_key"`
	CreatedAt int64  `json:"created_at" gorm:"autoCreateTime;column:created_at"`
}

func (AuthzUserRole) TableName() string {
	return "authz_user_roles"
}
