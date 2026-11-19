package shared

import (
	"context"
	"reflect"
	"testing"

	dtoshared "github.com/zazhedho/authkit/internal/dto/shared"

	"github.com/zazhedho/gokit"

	domainauth "github.com/zazhedho/authkit/internal/domain/auth"
)

func TestListRequestCopiesEveryField(t *testing.T) {
	params := gokit.BaseParams{
		Search: "x", Filters: map[string]any{"a": 1}, OrderBy: "name", OrderDirection: "DESC",
		Page: 3, Limit: 10, Offset: 20,
	}

	got := ListRequest(params)
	want := dtoshared.ListRequest{Search: "x", Filters: map[string]any{"a": 1}, OrderBy: "name", OrderDirection: "DESC", Page: 3, Limit: 10, Offset: 20}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected %+v, got %+v", want, got)
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
