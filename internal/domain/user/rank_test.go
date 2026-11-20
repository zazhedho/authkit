package user

import (
	"errors"
	"testing"
)

func set(keys ...string) map[string]struct{} {
	m := map[string]struct{}{}
	for _, k := range keys {
		m[k] = struct{}{}
	}
	return m
}

func TestCheckRoleCoverage(t *testing.T) {
	tests := []struct {
		name        string
		actorRole   string
		actorKeys   map[string]struct{}
		targetRole  string
		targetKeys  []string
		wantErr     error
		wantSuccess bool
	}{
		{name: "superadmin covers everything", actorRole: RoleSuperAdmin, targetRole: RoleAdmin, targetKeys: []string{"x:y"}, wantSuccess: true},
		{name: "superadmin may manage superadmin", actorRole: RoleSuperAdmin, targetRole: RoleSuperAdmin, wantSuccess: true},
		{name: "nobody else may touch superadmin", actorRole: RoleAdmin, actorKeys: set("a:b"), targetRole: RoleSuperAdmin, targetKeys: nil, wantErr: ErrRoleAboveActor},
		{name: "equal sets pass", actorRole: "staff", actorKeys: set("a:b", "c:d"), targetRole: "viewer", targetKeys: []string{"a:b", "c:d"}, wantSuccess: true},
		{name: "strict subset passes", actorRole: "admin", actorKeys: set("a:b", "c:d"), targetRole: "viewer", targetKeys: []string{"a:b"}, wantSuccess: true},
		{name: "missing one permission fails", actorRole: "staff", actorKeys: set("a:b"), targetRole: "admin", targetKeys: []string{"a:b", "c:d"}, wantErr: ErrRoleAboveActor},
		{name: "empty target role passes", actorRole: "staff", actorKeys: set(), targetRole: "viewer", wantSuccess: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckRoleCoverage(tt.actorRole, tt.actorKeys, tt.targetRole, tt.targetKeys)
			if tt.wantSuccess && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Fatalf("got %v, want %v", err, tt.wantErr)
			}
		})
	}
}
