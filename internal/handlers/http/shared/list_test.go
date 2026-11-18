package shared

import (
	"context"
	"reflect"
	"testing"

	domainauth "github.com/zazhedho/authkit/internal/domain/auth"
	dtoaudit "github.com/zazhedho/authkit/internal/dto/audit"
	dtorole "github.com/zazhedho/authkit/internal/dto/role"
	"github.com/zazhedho/gokit"
)

func TestListRequestCopiesEveryField(t *testing.T) {
	params := gokit.BaseParams{
		Search: "x", Filters: map[string]any{"a": 1}, OrderBy: "name", OrderDirection: "DESC",
		Page: 3, Limit: 10, Offset: 20, Columns: []string{"ignored"},
	}

	role := ListRequest[dtorole.ListRequest](params)
	want := dtorole.ListRequest{Search: "x", Filters: map[string]any{"a": 1}, OrderBy: "name", OrderDirection: "DESC", Page: 3, Limit: 10, Offset: 20}
	if !reflect.DeepEqual(role, want) {
		t.Fatalf("expected %+v, got %+v", want, role)
	}

	audit := ListRequest[dtoaudit.ListRequest](params)
	if audit.Search != "x" || audit.Limit != 10 || audit.Offset != 20 {
		t.Fatalf("unexpected audit request %+v", audit)
	}
}

func TestActorFromReadsTheRequestScope(t *testing.T) {
	scope := domainauth.New("user-1", "Jane", "staff", []string{"users:list"})
	actor := ActorFrom(domainauth.WithContext(context.Background(), scope))
	if actor.UserID != "user-1" || actor.Role != "staff" || !actor.Has("users", "list") {
		t.Fatalf("unexpected actor %+v", actor)
	}
	if got := ActorFrom(context.Background()); got.UserID != "" || got.Has("users", "list") {
		t.Fatalf("expected an empty actor without a scope, got %+v", got)
	}
}
