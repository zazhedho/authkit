package shared

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zazhedho/gokit"

	domainaudit "github.com/zazhedho/authkit/internal/domain/audit"
	domainauth "github.com/zazhedho/authkit/internal/domain/auth"
	dtoshared "github.com/zazhedho/authkit/internal/dto/shared"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type widget struct {
	Id   string `json:"id"`
	Name string `json:"name"`
}

type widgetRequest struct {
	Name string `json:"name" binding:"required"`
}

var widgetResource = Resource[widget]{
	Name:          "widget",
	Audit:         "widget_audit",
	ID:            func(w widget) string { return w.Id },
	MutationError: InternalErrorResponse,
}

func newTestFlow(method, target, body string) (Flow, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(method, target, strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Params = gin.Params{{Key: "id", Value: "w-1"}}
	return NewFlow(ctx, "[WidgetHandler][Test]"), rec
}

func decode(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not JSON: %v (%q)", err, rec.Body.String())
	}
	return body
}

func errorMessage(t *testing.T, body map[string]any) string {
	t.Helper()
	switch e := body["error"].(type) {
	case map[string]any:
		msg, _ := e["message"].(string)
		return msg
	case string:
		return e
	}
	return ""
}

func TestBindDecodesAndRejectsInvalidBodies(t *testing.T) {
	f, rec := newTestFlow(http.MethodPost, "/widgets", `{"name":"gear"}`)
	req, ok := Bind[widgetRequest](f)
	if !ok || req.Name != "gear" {
		t.Fatalf("expected a decoded request, got ok=%v req=%+v", ok, req)
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("a valid body must not write a response, got %q", rec.Body.String())
	}

	f, rec = newTestFlow(http.MethodPost, "/widgets", `{}`)
	if _, ok := Bind[widgetRequest](f); ok {
		t.Fatal("expected validation to fail")
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestGetByIDAnswersFoundAndNotFound(t *testing.T) {
	f, rec := newTestFlow(http.MethodGet, "/widgets/w-1", "")
	GetByID(f, "widget", "Service.GetByID", f.ID(), func(_ context.Context, id string) (widget, error) {
		return widget{Id: id, Name: "gear"}, nil
	})
	body := decode(t, rec)
	if rec.Code != http.StatusOK || body["message"] != "Get widget successfully" {
		t.Fatalf("unexpected success response %d %v", rec.Code, body)
	}
	if data := body["data"].(map[string]any); data["id"] != "w-1" {
		t.Fatalf("unexpected data %v", data)
	}

	f, rec = newTestFlow(http.MethodGet, "/widgets/w-1", "")
	GetByID(f, "audit trail", "Service.GetByID", f.ID(), func(context.Context, string) (widget, error) {
		return widget{}, errors.New("boom")
	})
	body = decode(t, rec)
	if rec.Code != http.StatusNotFound || body["message"] != "Not Found" || errorMessage(t, body) != "audit trail not found" {
		t.Fatalf("unexpected not-found response %d %v", rec.Code, body)
	}
}

func TestListWritesPaginatedResponseAndMapsFailures(t *testing.T) {
	opts := ListOptions{OrderBy: "name", Direction: "asc", Limit: 5, FilterKeys: []string{"kind"}}

	f, rec := newTestFlow(http.MethodGet, "/widgets?page=2&limit=3&filters[kind]=a&filters[other]=b", "")
	var got dtoshared.ListRequest
	List(f, opts, func(_ context.Context, req dtoshared.ListRequest) ([]widget, int64, error) {
		got = req
		return []widget{{Id: "w-1"}}, 7, nil
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if got.Page != 2 || got.Limit != 3 || got.OrderBy != "name" {
		t.Fatalf("unexpected list request %+v", got)
	}
	if _, kept := got.Filters["other"]; kept {
		t.Fatalf("expected filters outside FilterKeys to be dropped, got %v", got.Filters)
	}
	if _, kept := got.Filters["kind"]; !kept {
		t.Fatalf("expected the allowed filter to be kept, got %v", got.Filters)
	}
	if body := decode(t, rec); body["data"] == nil {
		t.Fatalf("expected data in the paginated response, got %v", body)
	}

	f, rec = newTestFlow(http.MethodGet, "/widgets", "")
	List(f, opts, func(context.Context, dtoshared.ListRequest) ([]widget, int64, error) {
		return nil, 0, errors.New("db down")
	})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 for a service failure, got %d", rec.Code)
	}

	f, rec = newTestFlow(http.MethodGet, "/widgets?page=abc", "")
	called := false
	List(f, opts, func(context.Context, dtoshared.ListRequest) ([]widget, int64, error) {
		called = true
		return nil, 0, nil
	})
	body := decode(t, rec)
	if rec.Code != http.StatusBadRequest || errorMessage(t, body) != "invalid query parameters" || called {
		t.Fatalf("expected 400 without calling the service, got %d %v called=%v", rec.Code, body, called)
	}
}

func TestCreateAuditsSuccessAndFailure(t *testing.T) {
	audit := &auditServiceMock{}
	w := NewAuditWriter(audit, "WidgetHandler")
	req := widgetRequest{Name: "gear"}

	f, rec := newTestFlow(http.MethodPost, "/widgets", "")
	Create(f, w, widgetResource, req, func(_ context.Context, r widgetRequest) (widget, error) {
		return widget{Id: "w-9", Name: r.Name}, nil
	})
	body := decode(t, rec)
	if rec.Code != http.StatusCreated || body["message"] != "Widget created successfully" {
		t.Fatalf("unexpected response %d %v", rec.Code, body)
	}
	ev := audit.stored
	if ev.Action != domainaudit.ActionCreate || ev.Resource != "widget_audit" || ev.ResourceID != "w-9" ||
		ev.Status != domainaudit.StatusSuccess || ev.Message != "Created widget" || ev.ErrorMessage != "" {
		t.Fatalf("unexpected success audit %+v", ev)
	}
	if after, ok := ev.AfterData.(widget); !ok || after.Name != "gear" {
		t.Fatalf("expected the created widget as after data, got %#v", ev.AfterData)
	}

	f, rec = newTestFlow(http.MethodPost, "/widgets", "")
	Create(f, w, widgetResource, req, func(context.Context, widgetRequest) (widget, error) {
		return widget{}, errors.New("insert failed")
	})
	ev = audit.stored
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected the mapped 500, got %d", rec.Code)
	}
	if ev.Status != domainaudit.StatusFailed || ev.Message != "Failed to create widget" || ev.ErrorMessage != "insert failed" ||
		ev.ResourceID != "" || ev.AfterData != req {
		t.Fatalf("unexpected failure audit %+v", ev)
	}
}

func TestUpdateAuditsBeforeAndAfter(t *testing.T) {
	audit := &auditServiceMock{}
	w := NewAuditWriter(audit, "WidgetHandler")
	req := widgetRequest{Name: "new"}
	before := func(_ context.Context, id string) (widget, error) { return widget{Id: id, Name: "old"}, nil }

	f, rec := newTestFlow(http.MethodPut, "/widgets/w-1", "")
	Update(f, w, widgetResource, f.ID(), req, before, func(_ context.Context, id string, r widgetRequest) (widget, error) {
		return widget{Id: id, Name: r.Name}, nil
	})
	body := decode(t, rec)
	if rec.Code != http.StatusOK || body["message"] != "Widget updated successfully" {
		t.Fatalf("unexpected response %d %v", rec.Code, body)
	}
	ev := audit.stored
	if ev.Action != domainaudit.ActionUpdate || ev.ResourceID != "w-1" || ev.Status != domainaudit.StatusSuccess || ev.Message != "Updated widget" {
		t.Fatalf("unexpected success audit %+v", ev)
	}
	if b, _ := ev.BeforeData.(widget); b.Name != "old" {
		t.Fatalf("expected the loaded widget as before data, got %#v", ev.BeforeData)
	}
	if a, _ := ev.AfterData.(widget); a.Name != "new" {
		t.Fatalf("expected the updated widget as after data, got %#v", ev.AfterData)
	}

	f, rec = newTestFlow(http.MethodPut, "/widgets/w-1", "")
	Update(f, w, widgetResource, f.ID(), req, before, func(context.Context, string, widgetRequest) (widget, error) {
		return widget{}, errors.New("update failed")
	})
	ev = audit.stored
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected the mapped 500, got %d", rec.Code)
	}
	if ev.Status != domainaudit.StatusFailed || ev.Message != "Failed to update widget" || ev.ErrorMessage != "update failed" ||
		ev.ResourceID != "w-1" || ev.AfterData != req {
		t.Fatalf("unexpected failure audit %+v", ev)
	}
	if b, _ := ev.BeforeData.(widget); b.Name != "old" {
		t.Fatalf("expected before data on failure, got %#v", ev.BeforeData)
	}
}

func TestDeleteAuditsBeforeStateAndUsesResourceErrorMapping(t *testing.T) {
	audit := &auditServiceMock{}
	w := NewAuditWriter(audit, "WidgetHandler")
	before := func(_ context.Context, id string) (widget, error) { return widget{Id: id, Name: "old"}, nil }

	f, rec := newTestFlow(http.MethodDelete, "/widgets/w-1", "")
	Delete(f, w, widgetResource, f.ID(), before, func(context.Context, string) error { return nil })
	body := decode(t, rec)
	if rec.Code != http.StatusOK || body["message"] != "Widget deleted successfully" {
		t.Fatalf("unexpected response %d %v", rec.Code, body)
	}
	ev := audit.stored
	if ev.Action != domainaudit.ActionDelete || ev.ResourceID != "w-1" || ev.Status != domainaudit.StatusSuccess || ev.Message != "Deleted widget" {
		t.Fatalf("unexpected success audit %+v", ev)
	}

	conflict := widgetResource
	conflict.MutationError = func(logID uuid.UUID, err error) (int, *gokit.ApiResponse) {
		return http.StatusConflict, gokit.ErrorResponse(http.StatusConflict, "conflict", logID, err.Error())
	}
	f, rec = newTestFlow(http.MethodDelete, "/widgets/w-1", "")
	Delete(f, w, conflict, f.ID(), before, func(context.Context, string) error { return errors.New("in use") })
	ev = audit.stored
	if rec.Code != http.StatusConflict {
		t.Fatalf("expected the resource's mapped status, got %d", rec.Code)
	}
	if ev.Status != domainaudit.StatusFailed || ev.Message != "Failed to delete widget" || ev.ErrorMessage != "in use" || ev.ResourceID != "w-1" {
		t.Fatalf("unexpected failure audit %+v", ev)
	}
	if b, _ := ev.BeforeData.(widget); b.Name != "old" {
		t.Fatalf("expected before data on failure, got %#v", ev.BeforeData)
	}
}

func TestForCurrentUserRequiresAScopeUser(t *testing.T) {
	load := func(_ context.Context, userID string) ([]string, error) { return []string{userID}, nil }

	f, rec := newTestFlow(http.MethodGet, "/me/widgets", "")
	ForCurrentUser(f, "Service.Load", "Get widgets successfully", load)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without a user, got %d", rec.Code)
	}

	f, rec = newTestFlow(http.MethodGet, "/me/widgets", "")
	f.Ctx.Request = f.Ctx.Request.WithContext(domainauth.WithContext(f.Ctx.Request.Context(), domainauth.New("user-1", "Jane", "staff", nil)))
	ForCurrentUser(f, "Service.Load", "Get widgets successfully", load)
	body := decode(t, rec)
	if rec.Code != http.StatusOK || body["message"] != "Get widgets successfully" {
		t.Fatalf("unexpected response %d %v", rec.Code, body)
	}

	f, rec = newTestFlow(http.MethodGet, "/me/widgets", "")
	f.Ctx.Request = f.Ctx.Request.WithContext(domainauth.WithContext(f.Ctx.Request.Context(), domainauth.New("user-1", "Jane", "staff", nil)))
	ForCurrentUser(f, "Service.Load", "Get widgets successfully", func(context.Context, string) ([]string, error) {
		return nil, errors.New("boom")
	})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 for a service failure, got %d", rec.Code)
	}
}

func TestInternalErrorResponseHidesTheCause(t *testing.T) {
	status, res := InternalErrorResponse(uuid.New(), errors.New("secret detail"))
	if status != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", status)
	}
	raw, _ := json.Marshal(res)
	if strings.Contains(string(raw), "secret detail") {
		t.Fatalf("response leaks the cause: %s", raw)
	}
}
