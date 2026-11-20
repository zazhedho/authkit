// Package module holds what every router/<module> package shares: the Deps its
// Register function mounts routes from, and the Entry that lists it. It imports
// no feature module.
package module

import (
	"github.com/gin-gonic/gin"

	httpappconfig "github.com/zazhedho/authkit/internal/handlers/http/appconfig"
	httpaudit "github.com/zazhedho/authkit/internal/handlers/http/audit"
	httpmenu "github.com/zazhedho/authkit/internal/handlers/http/menu"
	httppermission "github.com/zazhedho/authkit/internal/handlers/http/permission"
	httprole "github.com/zazhedho/authkit/internal/handlers/http/role"
	httpsession "github.com/zazhedho/authkit/internal/handlers/http/session"
	httpuser "github.com/zazhedho/authkit/internal/handlers/http/user"
)

// Deps is everything a module mounts its routes from: the handlers, the auth
// middleware and the rate limiters. Session is nil without Redis.
type Deps struct {
	// Auth requires a valid access token. Can requires a (resource, action)
	// permission and runs after Auth.
	Auth gin.HandlerFunc
	Can  func(resource, action string) gin.HandlerFunc

	// RegisterLimit limits the registration routes and AuthLimit the auth
	// routes that have no limiter of their own; both are no-ops when off.
	RegisterLimit gin.HandlerFunc
	AuthLimit     gin.HandlerFunc

	User       *httpuser.Handler
	Role       *httprole.Handler
	Permission *httppermission.Handler
	Menu       *httpmenu.Handler
	AppConfig  *httpappconfig.Handler
	Audit      *httpaudit.Handler
	Session    *httpsession.Handler
}

// Entry mounts one module's routes. Register takes the group the kit is mounted
// on and uses paths relative to it.
type Entry struct {
	Name     string
	Register func(r gin.IRouter, d Deps)
}
