package authutil

const CtxKeyAuthData = "auth_data"

const (
	RedisAppConf = "cache:config:app"
	RedisDbConf  = "cache:config:db"
)

const (
	RoleSuperAdmin = "superadmin"
	RoleAdmin      = "admin"
	RoleStaff      = "staff"
	RoleMember     = "member"
	RoleViewer     = "viewer"
)
