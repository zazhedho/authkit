package reset

import "testing"

func TestIsDevEnv(t *testing.T) {
	for in, want := range map[string]bool{
		"development": true, "local": true, "test": true,
		" Development ": true, "LOCAL": true, "Test": true,
		"": false, "production": false, "prod": false, "staging": false, "testing": false,
	} {
		if got := IsDevEnv(in); got != want {
			t.Errorf("IsDevEnv(%q) = %v, want %v", in, got, want)
		}
	}
}
