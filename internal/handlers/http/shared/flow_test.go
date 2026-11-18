package shared

import (
	"net/http"
	"testing"

	"github.com/google/uuid"
)

func TestFlowReadsRequestValues(t *testing.T) {
	f, _ := newTestFlow(http.MethodGet, "/widgets/w-1", "")
	if f.ID() != "w-1" {
		t.Fatalf("expected the :id parameter, got %q", f.ID())
	}
	if f.ReqCtx() != f.Ctx.Request.Context() {
		t.Fatal("expected the request context")
	}
	if f.LogID == uuid.Nil || f.Prefix != "[WidgetHandler][Test]" {
		t.Fatalf("unexpected flow %+v", f)
	}
}

func TestUUIDParamValidatesTheIDParameter(t *testing.T) {
	f, rec := newTestFlow(http.MethodGet, "/widgets/not-a-uuid", "")
	if _, ok := f.UUIDParam(); ok {
		t.Fatal("expected an invalid UUID to be rejected")
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}

	f, rec = newTestFlow(http.MethodGet, "/widgets/x", "")
	want := uuid.NewString()
	f.Ctx.Params[0].Value = want
	got, ok := f.UUIDParam()
	if !ok || got != want {
		t.Fatalf("expected the UUID back, got %q ok=%v", got, ok)
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("a valid id must not write a response, got %q", rec.Body.String())
	}
}

func TestQuietFlowKeepsErrorLogging(t *testing.T) {
	f, _ := newTestFlow(http.MethodGet, "/widgets/w-1", "")
	if f.quiet {
		t.Fatal("NewFlow must not be quiet")
	}
	q := NewQuietFlow(f.Ctx, "[Quiet]")
	if !q.quiet || q.LogID == uuid.Nil {
		t.Fatalf("unexpected quiet flow %+v", q)
	}
	// Must not panic with debug logging suppressed.
	q.LogRequest(map[string]string{"a": "b"})
	q.LogResponse(map[string]string{"a": "b"})
	q.LogResponseText("done")
}

func TestRespondHelpersWriteTheStandardEnvelopes(t *testing.T) {
	f, rec := newTestFlow(http.MethodGet, "/", "")
	RespondUnauthorized(f.Ctx, f.LogID)
	if body := decode(t, rec); rec.Code != http.StatusUnauthorized || body["message"] != "Unauthorized" {
		t.Fatalf("unexpected unauthorized response %d %v", rec.Code, body)
	}

	f, rec = newTestFlow(http.MethodGet, "/", "")
	RespondInternalError(f.Ctx, f.LogID)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}

	f, rec = newTestFlow(http.MethodGet, "/", "")
	RespondNotFound(f.Ctx, f.LogID, "user")
	body := decode(t, rec)
	if rec.Code != http.StatusNotFound || body["message"] != "Not Found" || errorMessage(t, body) != "user not found" {
		t.Fatalf("unexpected not-found response %d %v", rec.Code, body)
	}
}

func TestCapitalizeUppercasesTheFirstLetterOnly(t *testing.T) {
	for in, want := range map[string]string{"": "", "role": "Role", "audit trail": "Audit trail", "Menu": "Menu"} {
		if got := capitalize(in); got != want {
			t.Errorf("capitalize(%q) = %q, want %q", in, got, want)
		}
	}
}
