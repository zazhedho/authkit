package shared

import (
	"reflect"
	"testing"

	dtouser "github.com/zazhedho/authkit/internal/dto/user"
	"github.com/zazhedho/gokit"
)

func TestBaseParamsCopiesEveryListField(t *testing.T) {
	got := BaseParams(dtouser.ListRequest{
		Search: "jane", Filters: map[string]any{"role": "admin"}, OrderBy: "name", OrderDirection: "ASC",
		Page: 2, Limit: 25, Offset: 25,
	})
	want := gokit.BaseParams{
		Search: "jane", Filters: map[string]any{"role": "admin"}, OrderBy: "name", OrderDirection: "ASC",
		Page: 2, Limit: 25, Offset: 25,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected %+v, got %+v", want, got)
	}
}
