package audit

import (
	"context"
	"encoding/json"
	"errors"
	domainaudit "github.com/zazhedho/authkit/internal/domain/audit"
	dtoaudit "github.com/zazhedho/authkit/internal/dto/audit"
	dtoshared "github.com/zazhedho/authkit/internal/dto/shared"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

type auditServiceTestDouble struct {
	rows  []dtoaudit.AuditTrailResponse
	row   dtoaudit.AuditTrailResponse
	total int64
	err   error
	got   dtoshared.ListRequest
}

func (m *auditServiceTestDouble) Store(ctx context.Context, req domainaudit.AuditEvent) error {
	return nil
}
func (m *auditServiceTestDouble) GetAll(ctx context.Context, req dtoshared.ListRequest) ([]dtoaudit.AuditTrailResponse, int64, error) {
	m.got = req
	if m.err != nil {
		return nil, 0, m.err
	}
	return m.rows, m.total, nil
}
func (m *auditServiceTestDouble) GetByID(ctx context.Context, id string) (dtoaudit.AuditTrailResponse, error) {
	if m.err != nil {
		return dtoaudit.AuditTrailResponse{}, m.err
	}
	return m.row, nil
}

func performAuditRequest(method, routePath, requestPath string, handler gin.HandlerFunc) *httptest.ResponseRecorder {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Handle(method, routePath, handler)
	req := httptest.NewRequest(method, requestPath, nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func TestAuditGetAllReturnsPagination(t *testing.T) {
	handler := New(&auditServiceTestDouble{
		rows:  []dtoaudit.AuditTrailResponse{{ID: "audit-1", Resource: "users"}},
		total: 1,
	})

	rec := performAuditRequest(http.MethodGet, "/audits", "/audits?page=1&limit=20", handler.GetAll)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var decoded map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if decoded["total_data"].(float64) != 1 {
		t.Fatalf("expected total_data 1, got %+v", decoded)
	}
}

func TestAuditGetAllMapsServiceError(t *testing.T) {
	handler := New(&auditServiceTestDouble{err: errors.New("database down")})

	rec := performAuditRequest(http.MethodGet, "/audits", "/audits", handler.GetAll)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAuditGetByIDValidatesUUIDAndReturnsNotFound(t *testing.T) {
	handler := New(&auditServiceTestDouble{})

	rec := performAuditRequest(http.MethodGet, "/audits/:id", "/audits/not-a-uuid", handler.GetByID)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}

	handler = New(&auditServiceTestDouble{err: errors.New("not found")})
	rec = performAuditRequest(http.MethodGet, "/audits/:id", "/audits/550e8400-e29b-41d4-a716-446655440000", handler.GetByID)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAuditGetAllPassesParsedQueryAsListRequest(t *testing.T) {
	service := &auditServiceTestDouble{}
	handler := New(service)

	rec := performAuditRequest(http.MethodGet, "/audits", "/audits?page=2&limit=5&search=login&order_by=action&order_direction=asc", handler.GetAll)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	got := service.got
	if got.Search != "login" || got.OrderBy != "action" || got.Page != 2 || got.Limit != 5 || got.Offset != 5 {
		t.Fatalf("unexpected list request: %+v", got)
	}
}
