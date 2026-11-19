package menu

import "testing"

func TestTableName(t *testing.T) {
	if got := (Item{}).TableName(); got != "menu_items" {
		t.Fatalf("expected menu_items, got %q", got)
	}
}
