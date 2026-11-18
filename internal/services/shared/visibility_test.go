package shared

import (
	"errors"
	"reflect"
	"testing"

	domainauth "github.com/zazhedho/authkit/internal/domain/auth"
	domainuser "github.com/zazhedho/authkit/internal/domain/user"
)

func isSecret(s string) bool { return s == "secret" }

func TestHideSuperAdminDropsRowsAndAdjustsTotalForOrdinaryCallers(t *testing.T) {
	got, total, err := HideSuperAdmin(domainauth.Actor{Role: "staff"}, []string{"a", "secret", "b", "secret"}, 10, nil, isSecret)
	if err != nil || !reflect.DeepEqual(got, []string{"a", "b"}) || total != 8 {
		t.Fatalf("unexpected result %v total=%d err=%v", got, total, err)
	}
}

func TestHideSuperAdminShowsEverythingToASuperAdmin(t *testing.T) {
	items := []string{"a", "secret"}
	got, total, err := HideSuperAdmin(domainauth.Actor{Role: domainuser.RoleSuperAdmin}, items, 2, nil, isSecret)
	if err != nil || !reflect.DeepEqual(got, items) || total != 2 {
		t.Fatalf("unexpected result %v total=%d err=%v", got, total, err)
	}
}

func TestHideSuperAdminReturnsAnEmptySliceNotNil(t *testing.T) {
	got, total, err := HideSuperAdmin(domainauth.Actor{Role: "staff"}, []string{"secret"}, 1, nil, isSecret)
	if err != nil || got == nil || len(got) != 0 || total != 0 {
		t.Fatalf("expected an empty non-nil slice, got %#v total=%d err=%v", got, total, err)
	}
}

func TestHideSuperAdminPassesQueryFailuresThrough(t *testing.T) {
	boom := errors.New("db down")
	got, total, err := HideSuperAdmin(domainauth.Actor{Role: "staff"}, []string{"a"}, 1, boom, isSecret)
	if !errors.Is(err, boom) || got != nil || total != 0 {
		t.Fatalf("unexpected result %v total=%d err=%v", got, total, err)
	}
}
