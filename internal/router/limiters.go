package router

import (
	"github.com/gin-gonic/gin"
	"github.com/zazhedho/gokit"

	"github.com/zazhedho/authkit/internal/config"
)

// registerRateLimit limits the registration endpoints per client IP.
func registerRateLimit(cfg config.Config) gin.HandlerFunc {
	return ipRateLimit(cfg, "user_register", cfg.Register)
}

// authRateLimit limits the auth routes that have no limiter of their own.
func authRateLimit(cfg config.Config) gin.HandlerFunc {
	return ipRateLimit(cfg, "user_auth", cfg.AuthRate)
}

// ipRateLimit is a per-IP limit under its own Redis prefix. It is off without
// Redis or with a non-positive limit or window (gokit panics on those). A Redis
// failure lets the request through unless Config.FailClosedLimiters is set.
func ipRateLimit(cfg config.Config, prefix string, limit config.RateLimit) gin.HandlerFunc {
	if cfg.Redis == nil || limit.Limit <= 0 || limit.Window <= 0 {
		return func(c *gin.Context) { c.Next() }
	}
	return gokit.IPRateLimit(gokit.RateLimitOptions{
		Redis:      cfg.Redis,
		Prefix:     prefix,
		Limit:      limit.Limit,
		Window:     limit.Window,
		FailClosed: cfg.FailClosedLimiters,
	})
}
