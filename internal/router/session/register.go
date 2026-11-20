// Package session mounts the session routes. Alias routersession.
package session

import (
	"github.com/gin-gonic/gin"

	"github.com/zazhedho/authkit/internal/router/module"
)

// Register mounts session management (authenticated users only). It mounts
// nothing without Redis, when Deps.Session is nil.
func Register(r gin.IRouter, d module.Deps) error {
	h := d.Session
	if h == nil {
		return nil
	}

	sessionGroup := r.Group("/user").Use(d.Auth)
	{
		sessionGroup.GET("/sessions", h.GetActiveSessions)
		sessionGroup.DELETE("/session/:session_id", h.RevokeSession)
		sessionGroup.POST("/sessions/revoke-others", h.RevokeAllOtherSessions)
	}
	return nil
}
