package shared

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/zazhedho/gokit"
	"github.com/zazhedho/logus"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// Flow is the per-request state every handler method starts with: the gin
// context, a fresh log id, and the "[Handler][Method]" log prefix.
type Flow struct {
	Ctx    *gin.Context
	LogID  uuid.UUID
	Prefix string
	quiet  bool
}

// NewFlow starts a flow for one handler method.
func NewFlow(ctx *gin.Context, prefix string) Flow {
	return Flow{Ctx: ctx, LogID: gokit.GenerateLogId(ctx), Prefix: prefix}
}

// NewQuietFlow starts a flow that does not write the debug request and
// response log lines.
func NewQuietFlow(ctx *gin.Context, prefix string) Flow {
	f := NewFlow(ctx, prefix)
	f.quiet = true
	return f
}

// ReqCtx is the request's standard context, the one services take.
func (f Flow) ReqCtx() context.Context {
	return f.Ctx.Request.Context()
}

// ID is the raw :id path parameter.
func (f Flow) ID() string {
	return f.Ctx.Param("id")
}

// UUIDParam returns the :id path parameter once it is a valid UUID. When it is
// not, the 400 response is already written and ok is false.
func (f Flow) UUIDParam() (id string, ok bool) {
	id, err := gokit.ValidateUUIDParam(f.Ctx, f.LogID)
	return id, err == nil
}

// LogError logs a failed step as "<prefix>; <step>; Error: <err>".
func (f Flow) LogError(step string, err error) {
	logus.WriteLogWithContext(f.Ctx, logus.LogLevelError, fmt.Sprintf("%s; %s; Error: %+v", f.Prefix, step, err))
}

// LogRequest writes the debug line for a bound request body.
func (f Flow) LogRequest(req any) {
	if f.quiet {
		return
	}
	logus.WriteLogWithContext(f.Ctx, logus.LogLevelDebug, fmt.Sprintf("%s; Request: %+v;", f.Prefix, gokit.JsonEncode(req)))
}

// LogResponse writes the debug line for a successful response body.
func (f Flow) LogResponse(data any) {
	if f.quiet {
		return
	}
	logus.WriteLogWithContext(f.Ctx, logus.LogLevelDebug, fmt.Sprintf("%s; Response: %+v;", f.Prefix, gokit.JsonEncode(data)))
}

// LogResponseText writes the debug line for a response that has no body.
func (f Flow) LogResponseText(text string) {
	if f.quiet {
		return
	}
	logus.WriteLogWithContext(f.Ctx, logus.LogLevelDebug, fmt.Sprintf("%s; Response: %s", f.Prefix, text))
}

// RespondInternalError writes the generic 500 response.
func RespondInternalError(ctx *gin.Context, logID uuid.UUID) {
	ctx.JSON(http.StatusInternalServerError, gokit.InternalServerError(logID))
}

// RespondUnauthorized writes the plain 401 response.
func RespondUnauthorized(ctx *gin.Context, logID uuid.UUID) {
	ctx.JSON(http.StatusUnauthorized, gokit.Response(http.StatusUnauthorized, "Unauthorized", logID, nil))
}

// RespondNotFound writes the 404 response for a missing resource, for example
// "Role not found" with the public error "role not found".
func RespondNotFound(ctx *gin.Context, logID uuid.UUID, name string) {
	res := gokit.Response(http.StatusNotFound, capitalize(name)+" not found", logID, nil)
	res.Error = gokit.Errors{Code: http.StatusNotFound, Message: name + " not found"}
	ctx.JSON(http.StatusNotFound, res)
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
