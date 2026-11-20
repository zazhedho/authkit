package role

import "testing"

func TestTableNames(t *testing.T) {
	tests := map[string]string{
		"roles":            (Role{}).TableName(),
		"role_permissions": (Permission{}).TableName(),
		"role_menus":       (Menu{}).TableName(),
	}

	for want, got := range tests {
		if got != want {
			t.Fatalf("expected %q, got %q", want, got)
		}
	}
}
