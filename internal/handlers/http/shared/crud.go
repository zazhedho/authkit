package shared

import (
	"context"
	"net/http"

	"github.com/zazhedho/gokit"
	"github.com/zazhedho/logus"

	domainaudit "github.com/zazhedho/authkit/internal/domain/audit"
	domainauth "github.com/zazhedho/authkit/internal/domain/auth"
	dtoshared "github.com/zazhedho/authkit/internal/dto/shared"

	"github.com/google/uuid"
)

// Resource describes one CRUD resource to the generic handler flows below.
type Resource[T any] struct {
	// Name is the lower-case display name used in messages, such as "role".
	Name string
	// Audit is the resource value written to audit entries.
	Audit string
	// ID reads the identifier off a service result.
	ID func(T) string
	// MutationError maps a failed create, update or delete to its response.
	MutationError func(logID uuid.UUID, err error) (int, *gokit.APIResponse)
}

// InternalErrorResponse is a MutationError that hides every failure behind a
// 500.
func InternalErrorResponse(logID uuid.UUID, _ error) (int, *gokit.APIResponse) {
	return http.StatusInternalServerError, gokit.InternalServerError(logID)
}

// Bind decodes and validates the JSON body and logs it. When the body is
// invalid the 400 response is already written and ok is false.
func Bind[Req any](f Flow) (req Req, ok bool) {
	if !gokit.BindJSON(f.Ctx, f.LogID, f.Prefix, &req) {
		return req, false
	}
	f.LogRequest(req)
	return req, true
}

// GetByID looks a resource up and answers 404 when the service fails. step is
// the log label of the service call.
func GetByID[T any](f Flow, name, step, id string, get func(context.Context, string) (T, error)) {
	data, err := get(f.ReqCtx(), id)
	if err != nil {
		f.LogError(step, err)
		RespondNotFound(f.Ctx, f.LogID, name)
		return
	}

	res := gokit.Response(http.StatusOK, "Get "+name+" successfully", f.LogID, data)
	f.LogResponse(data)
	f.Ctx.JSON(http.StatusOK, res)
}

// ListOptions are the query defaults of one list endpoint.
type ListOptions struct {
	OrderBy   string
	Direction string
	Limit     int
	// Policy is the page-size policy the module's repository applies. The zero
	// value means dtoshared.PagedList.
	Policy dtoshared.ListPolicy
	// FilterKeys, when set, drops every query filter outside the list.
	FilterKeys []string
}

// List parses the query, fetches one page and writes the paginated response.
func List[T any](f Flow, opts ListOptions, fetch func(context.Context, dtoshared.ListRequest) ([]T, int64, error)) {
	params, err := gokit.GetBaseParams(f.Ctx.Request.URL.Query(), opts.OrderBy, opts.Direction, opts.Limit)
	if err != nil {
		f.LogError("GetBaseParams", err)
		res := gokit.ErrorResponse(http.StatusBadRequest, gokit.MsgInvalidRequest, f.LogID, "invalid query parameters")
		f.Ctx.JSON(http.StatusBadRequest, res)
		return
	}
	if len(opts.FilterKeys) > 0 {
		params.Filters = gokit.WhitelistStringFilter(params.Filters, opts.FilterKeys)
	}

	data, total, err := fetch(f.ReqCtx(), ListRequest(params))
	if err != nil {
		f.LogError("Service.GetAll", err)
		RespondInternalError(f.Ctx, f.LogID)
		return
	}

	res := gokit.PaginationResponse(http.StatusOK, total, params.Page, PageSize(opts.Policy, params), f.LogID, data)
	f.LogResponse(data)
	f.Ctx.JSON(http.StatusOK, res)
}

// ForCurrentUser loads data for the authenticated caller and answers 401 when
// the request has no user. step is the log label of the service call.
func ForCurrentUser[T any](f Flow, step, message string, load func(context.Context, string) (T, error)) {
	scope := domainauth.FromContext(f.ReqCtx())
	if scope.UserID == "" {
		logus.LogContextf(f.Ctx, logus.LevelError, "%s; User ID not found in context", f.Prefix)
		RespondUnauthorized(f.Ctx, f.LogID)
		return
	}

	data, err := load(f.ReqCtx(), scope.UserID)
	if err != nil {
		f.LogError(step, err)
		RespondInternalError(f.Ctx, f.LogID)
		return
	}

	res := gokit.Response(http.StatusOK, message, f.LogID, data)
	f.LogResponse(data)
	f.Ctx.JSON(http.StatusOK, res)
}

// Create runs the service, audits the outcome and answers 201.
func Create[Req, T any](f Flow, w AuditWriter, r Resource[T], req Req, create func(context.Context, Req) (T, error)) {
	data, err := create(f.ReqCtx(), req)
	if err != nil {
		w.WriteAudit(f.Ctx, domainaudit.AuditEvent{
			Action:       domainaudit.ActionCreate,
			Resource:     r.Audit,
			Status:       domainaudit.StatusFailed,
			Message:      "Failed to create " + r.Name,
			ErrorMessage: err.Error(),
			AfterData:    req,
		})
		respondMutationError(f, r, "Service.Create", err)
		return
	}
	w.WriteAudit(f.Ctx, domainaudit.AuditEvent{
		Action:     domainaudit.ActionCreate,
		Resource:   r.Audit,
		ResourceID: r.ID(data),
		Status:     domainaudit.StatusSuccess,
		Message:    "Created " + r.Name,
		AfterData:  data,
	})

	res := gokit.Response(http.StatusCreated, capitalize(r.Name)+" created successfully", f.LogID, data)
	f.LogResponse(data)
	f.Ctx.JSON(http.StatusCreated, res)
}

// Update reads the current state, runs the service and audits before and after.
func Update[Req, T, B any](
	f Flow, w AuditWriter, r Resource[T], id string, req Req,
	before func(context.Context, string) (B, error),
	update func(context.Context, string, Req) (T, error),
) {
	reqCtx := f.ReqCtx()
	beforeData, _ := before(reqCtx, id)
	data, err := update(reqCtx, id, req)
	if err != nil {
		w.WriteAudit(f.Ctx, domainaudit.AuditEvent{
			Action:       domainaudit.ActionUpdate,
			Resource:     r.Audit,
			ResourceID:   id,
			Status:       domainaudit.StatusFailed,
			Message:      "Failed to update " + r.Name,
			ErrorMessage: err.Error(),
			BeforeData:   beforeData,
			AfterData:    req,
		})
		respondMutationError(f, r, "Service.Update", err)
		return
	}
	w.WriteAudit(f.Ctx, domainaudit.AuditEvent{
		Action:     domainaudit.ActionUpdate,
		Resource:   r.Audit,
		ResourceID: r.ID(data),
		Status:     domainaudit.StatusSuccess,
		Message:    "Updated " + r.Name,
		BeforeData: beforeData,
		AfterData:  data,
	})

	res := gokit.Response(http.StatusOK, capitalize(r.Name)+" updated successfully", f.LogID, data)
	f.LogResponse(data)
	f.Ctx.JSON(http.StatusOK, res)
}

// Delete reads the current state, runs the service and audits the removal.
func Delete[T, B any](
	f Flow, w AuditWriter, r Resource[T], id string,
	before func(context.Context, string) (B, error),
	remove func(context.Context, string) error,
) {
	reqCtx := f.ReqCtx()
	beforeData, _ := before(reqCtx, id)
	if err := remove(reqCtx, id); err != nil {
		w.WriteAudit(f.Ctx, domainaudit.AuditEvent{
			Action:       domainaudit.ActionDelete,
			Resource:     r.Audit,
			ResourceID:   id,
			Status:       domainaudit.StatusFailed,
			Message:      "Failed to delete " + r.Name,
			ErrorMessage: err.Error(),
			BeforeData:   beforeData,
		})
		respondMutationError(f, r, "Service.Delete", err)
		return
	}
	w.WriteAudit(f.Ctx, domainaudit.AuditEvent{
		Action:     domainaudit.ActionDelete,
		Resource:   r.Audit,
		ResourceID: id,
		Status:     domainaudit.StatusSuccess,
		Message:    "Deleted " + r.Name,
		BeforeData: beforeData,
	})

	res := gokit.Response(http.StatusOK, capitalize(r.Name)+" deleted successfully", f.LogID, nil)
	f.LogResponseText(capitalize(r.Name) + " deleted")
	f.Ctx.JSON(http.StatusOK, res)
}

// respondMutationError logs the failed service step and writes the resource's
// mapped error response.
func respondMutationError[T any](f Flow, r Resource[T], step string, err error) {
	f.LogError(step, err)
	statusCode, res := r.MutationError(f.LogID, err)
	f.Ctx.JSON(statusCode, res)
}
