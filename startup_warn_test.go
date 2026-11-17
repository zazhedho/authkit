package authkit

import (
	"strings"
	"testing"
)

func TestStartupWarnings(t *testing.T) {
	cases := []struct {
		env       string
		redisNil  bool
		wantDev   bool
		wantRedis bool
	}{
		{"development", true, true, true},
		{"Local", false, true, false},
		{"test", false, true, false},
		{"production", true, false, true},
		{"", false, false, false},
	}
	for _, c := range cases {
		got := startupWarnings(c.env, c.redisNil)
		if (len(got) > 0 && hasDevWarning(got)) != c.wantDev {
			t.Errorf("env %q: dev warning = %v, want %v (%v)", c.env, !c.wantDev, c.wantDev, got)
		}
		wantN := 0
		if c.wantDev {
			wantN++
		}
		if c.wantRedis {
			wantN++
		}
		if len(got) != wantN {
			t.Errorf("env %q redisNil=%v: %d warnings, want %d", c.env, c.redisNil, len(got), wantN)
		}
	}
	for _, w := range startupWarnings("development", true) {
		for _, secret := range []string{testJWTKey} {
			if strings.Contains(w, secret) {
				t.Errorf("warning leaks a secret: %q", w)
			}
		}
	}
}

func hasDevWarning(ws []string) bool {
	for _, w := range ws {
		if strings.Contains(w, "/user/forgot-password") && strings.Contains(w, "never") {
			return true
		}
	}
	return false
}
