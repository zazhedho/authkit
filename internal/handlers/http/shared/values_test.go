package shared

import "testing"

func TestNormalizeKey(t *testing.T) {
	if got := NormalizeKey("  Production "); got != "production" {
		t.Fatalf("NormalizeKey = %q", got)
	}
}

func TestInterfaceBool(t *testing.T) {
	cases := []struct {
		in   any
		want bool
	}{
		{nil, false},
		{true, true},
		{false, false},
		{" TRUE ", true},
		{"no", false},
		{[]byte("true"), false},
		{1, false},
	}
	for _, c := range cases {
		if got := InterfaceBool(c.in); got != c.want {
			t.Errorf("InterfaceBool(%#v) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestMergeMetadata(t *testing.T) {
	if got := MergeMetadata(nil, map[string]any{}); got != nil {
		t.Fatalf("empty inputs gave %v, want nil", got)
	}
	base := map[string]any{"a": 1, "b": 2}
	got := MergeMetadata(base, map[string]any{"b": 3, "c": 4})
	if got["a"] != 1 || got["b"] != 3 || got["c"] != 4 {
		t.Fatalf("merged = %v", got)
	}
	if base["b"] != 2 {
		t.Fatal("base was modified")
	}
}
