package devenv

import "testing"

func TestIsDev(t *testing.T) {
	for in, want := range map[string]bool{
		"development": true, "local": true, "test": true,
		" Development ": true, "LOCAL": true, "Test": true,
		"": false, "production": false, "prod": false, "staging": false, "testing": false,
	} {
		if got := IsDev(in); got != want {
			t.Errorf("IsDev(%q) = %v, want %v", in, got, want)
		}
	}
}
