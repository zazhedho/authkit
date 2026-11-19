package middleware

import (
	"fmt"
	"net/http"
	"time"

	"github.com/zazhedho/logus"

	domainauth "github.com/zazhedho/authkit/internal/domain/auth"

	"github.com/gin-gonic/gin"
)

func RequestLogger() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		start := time.Now()

		ctx.Next()

		status := ctx.Writer.Status()
		latency := time.Since(start)
		path := ctx.FullPath()
		if path == "" {
			path = ctx.Request.URL.Path
		}

		userID := domainauth.FromContext(ctx.Request.Context()).UserID

		msg := fmt.Sprintf(
			"[Request]; %s %s; status=%d; latency_ms=%d; ip=%s; user_id=%s",
			ctx.Request.Method,
			path,
			status,
			latency.Milliseconds(),
			ctx.ClientIP(),
			userID,
		)

		switch {
		case status >= http.StatusInternalServerError:
			logus.LogContext(ctx, logus.LevelError, msg)
		case status >= http.StatusBadRequest:
			logus.LogContext(ctx, logus.LevelWarn, msg)
		default:
			logus.LogContext(ctx, logus.LevelInfo, msg)
		}
	}
}
