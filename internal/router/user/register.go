// Package user mounts the user routes. Alias routeruser.
package user

import (
	"github.com/gin-gonic/gin"

	"github.com/zazhedho/authkit/internal/router/module"
)

// Register mounts the user routes under r.
func Register(r gin.IRouter, d module.Deps) {
	h := d.User

	user := r.Group("/user")
	{
		user.GET("/register/status", h.GetRegisterStatus)
		user.POST("/register", d.RegisterLimit, h.Register)
		user.POST("/register/otp/send", d.RegisterLimit, h.SendRegisterOTP)
		user.POST("/login", h.Login)
		user.POST("/google/login", d.AuthLimit, h.GoogleLogin)
		user.POST("/refresh-token", d.AuthLimit, h.RefreshToken)
		user.POST("/forgot-password", d.AuthLimit, h.ForgotPassword)
		user.POST("/reset-password", d.AuthLimit, h.ResetPassword)

		userPriv := user.Group("").Use(d.Auth)
		{
			userPriv.POST("/logout", h.Logout)
			userPriv.GET("", h.GetUserByAuth)
			userPriv.GET("/:id", d.Can("users", "view"), h.GetUserByID)
			userPriv.POST("/:id/impersonate", d.Can("users", "impersonate"), h.ImpersonateUser)
			userPriv.POST("/stop-impersonation", h.StopImpersonation)
			userPriv.PUT("", h.Update)
			userPriv.PUT("/:id", d.Can("users", "update"), h.UpdateUserByID)
			userPriv.PUT("/change/password", d.AuthLimit, h.ChangePassword)
			userPriv.DELETE("", h.Delete)
			userPriv.DELETE("/:id", d.Can("users", "delete"), h.DeleteUserByID)

			// Admin create user endpoint (with role selection)
			userPriv.POST("", d.Can("users", "create"), h.AdminCreateUser)
		}
	}

	r.GET("/users", d.Auth, d.Can("users", "list"), h.GetAllUsers)
}
