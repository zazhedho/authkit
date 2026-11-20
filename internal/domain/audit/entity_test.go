package audit

import "testing"

func TestTableName(t *testing.T) {
	if got := (Trail{}).TableName(); got != "audit_trails" {
		t.Fatalf("expected audit_trails, got %q", got)
	}
}
