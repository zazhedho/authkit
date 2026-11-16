package authkit

import "github.com/gin-gonic/gin"

// Mount registers every users, auth and RBAC route on r, normally
// engine.Group("/api"). Paths, methods, middleware and permission names are the
// ones of the original router. Session routes are mounted only when the Kit was
// built with Redis. Call it once per Kit and group; mounting the same group
// twice registers duplicate routes, which gin rejects with a panic.
func (k *Kit) Mount(r gin.IRouter) {
	k.mountUsers(r)
	k.mountRoles(r)
	k.mountPermissions(r)
	k.mountMenus(r)
	k.mountAppConfigs(r)
	k.mountAudits(r)
	k.mountSessions(r)
}

func (k *Kit) mountUsers(r gin.IRouter) {
	h, mdw := k.userHandler, k.middleware

	user := r.Group("/user")
	{
		user.GET("/register/status", h.GetRegisterStatus)
		user.POST("/register", k.registerLimiter, h.Register)
		user.POST("/register/otp/send", k.registerLimiter, h.SendRegisterOTP)
		user.POST("/login", h.Login)
		user.POST("/google/login", h.GoogleLogin)
		user.POST("/refresh-token", h.RefreshToken)
		user.POST("/forgot-password", h.ForgotPassword)
		user.POST("/reset-password", h.ResetPassword)

		userPriv := user.Group("").Use(mdw.AuthMiddleware())
		{
			userPriv.POST("/logout", h.Logout)
			userPriv.GET("", h.GetUserByAuth)
			userPriv.GET("/:id", mdw.PermissionMiddleware("users", "view"), h.GetUserById)
			userPriv.POST("/:id/impersonate", mdw.PermissionMiddleware("users", "impersonate"), h.ImpersonateUser)
			userPriv.POST("/stop-impersonation", h.StopImpersonation)
			userPriv.PUT("", h.Update)
			userPriv.PUT("/:id", mdw.PermissionMiddleware("users", "update"), h.UpdateUserById)
			userPriv.PUT("/change/password", h.ChangePassword)
			userPriv.DELETE("", h.Delete)
			userPriv.DELETE("/:id", mdw.PermissionMiddleware("users", "delete"), h.DeleteUserById)

			// Admin create user endpoint (with role selection)
			userPriv.POST("", mdw.PermissionMiddleware("users", "create"), h.AdminCreateUser)
		}
	}

	r.GET("/users", mdw.AuthMiddleware(), mdw.PermissionMiddleware("users", "list"), h.GetAllUsers)
}

func (k *Kit) mountRoles(r gin.IRouter) {
	h, mdw := k.roleHandler, k.middleware

	r.GET("/roles", mdw.AuthMiddleware(), mdw.PermissionMiddleware("roles", "list"), h.GetAll)

	role := r.Group("/role").Use(mdw.AuthMiddleware())
	{
		role.POST("", mdw.PermissionMiddleware("roles", "create"), h.Create)
		role.GET("/:id", mdw.PermissionMiddleware("roles", "view"), h.GetByID)
		role.PUT("/:id", mdw.PermissionMiddleware("roles", "update"), h.Update)
		role.DELETE("/:id", mdw.PermissionMiddleware("roles", "delete"), h.Delete)

		role.POST("/:id/permissions", mdw.PermissionMiddleware("roles", "assign_permissions"), h.AssignPermissions)
	}
}

func (k *Kit) mountPermissions(r gin.IRouter) {
	h, mdw := k.permissionHandler, k.middleware

	r.GET("/permissions", mdw.AuthMiddleware(), mdw.PermissionMiddleware("permissions", "list"), h.GetAll)

	// Current user's permissions: authentication only.
	r.GET("/permissions/me", mdw.AuthMiddleware(), h.GetUserPermissions)

	permission := r.Group("/permission").Use(mdw.AuthMiddleware())
	{
		permission.POST("", mdw.PermissionMiddleware("permissions", "create"), h.Create)
		permission.GET("/:id", mdw.PermissionMiddleware("permissions", "view"), h.GetByID)
		permission.PUT("/:id", mdw.PermissionMiddleware("permissions", "update"), h.Update)
		permission.DELETE("/:id", mdw.PermissionMiddleware("permissions", "delete"), h.Delete)
	}
}

func (k *Kit) mountMenus(r gin.IRouter) {
	h, mdw := k.menuHandler, k.middleware

	// Available to any authenticated user.
	r.GET("/menus/active", mdw.AuthMiddleware(), h.GetActiveMenus)
	r.GET("/menus/me", mdw.AuthMiddleware(), h.GetUserMenus)

	r.GET("/menus", mdw.AuthMiddleware(), mdw.PermissionMiddleware("menus", "list"), h.GetAll)

	menu := r.Group("/menu").Use(mdw.AuthMiddleware())
	{
		menu.GET("/:id", mdw.PermissionMiddleware("menus", "view"), h.GetByID)
		menu.PUT("/:id", mdw.PermissionMiddleware("menus", "update"), h.Update)
	}
}

func (k *Kit) mountAppConfigs(r gin.IRouter) {
	h, mdw := k.appConfigHandler, k.middleware

	r.GET("/configs", mdw.AuthMiddleware(), mdw.PermissionMiddleware("configs", "list"), h.GetAll)

	appConfig := r.Group("/config").Use(mdw.AuthMiddleware())
	{
		appConfig.GET("/:id", mdw.PermissionMiddleware("configs", "view"), h.GetByID)
		appConfig.PUT("/:id", mdw.PermissionMiddleware("configs", "update"), h.Update)
	}
}

func (k *Kit) mountAudits(r gin.IRouter) {
	h, mdw := k.auditHandler, k.middleware

	r.GET("/audits", mdw.AuthMiddleware(), mdw.PermissionMiddleware("audits", "list"), h.GetAll)

	audit := r.Group("/audit").Use(mdw.AuthMiddleware())
	{
		audit.GET("/:id", mdw.PermissionMiddleware("audits", "view"), h.GetByID)
	}
}

// mountSessions registers session management (authenticated users only). It is
// skipped without Redis, as in the original router.
func (k *Kit) mountSessions(r gin.IRouter) {
	if k.sessionHandler == nil {
		return
	}
	h := k.sessionHandler

	sessionGroup := r.Group("/user").Use(k.middleware.AuthMiddleware())
	{
		sessionGroup.GET("/sessions", h.GetActiveSessions)
		sessionGroup.DELETE("/session/:session_id", h.RevokeSession)
		sessionGroup.POST("/sessions/revoke-others", h.RevokeAllOtherSessions)
	}
}
