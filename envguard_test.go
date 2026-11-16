package authkit

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// goSources returns the non-test Go files under the repo root (slash paths).
func goSources(t *testing.T) map[string]string {
	t.Helper()
	files := map[string]string{}
	repoFS := os.DirFS(".")
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", ".superpowers":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		raw, err := fs.ReadFile(repoFS, path)
		if err != nil {
			return err
		}
		files[filepath.ToSlash(path)] = string(raw)
		return nil
	})
	if err != nil {
		t.Fatalf("walk repo: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no Go sources found; test must run from the repo root")
	}
	return files
}

func TestNoEnvReadsOutsideAllowedFiles(t *testing.T) {
	forbidden := []string{"GetEnv(", "DurationFromEnv(", "os.Getenv(", "os.LookupEnv("}
	allowed := func(path string) bool {
		return path == "config_env.go" || path == "mailer/brevo_env.go" || strings.HasPrefix(path, "cmd/")
	}
	for path, src := range goSources(t) {
		if allowed(path) {
			continue
		}
		for _, needle := range forbidden {
			if strings.Contains(src, needle) {
				t.Errorf("%s reads the environment via %q; only config_env.go, mailer/brevo_env.go and cmd/ may", path, needle)
			}
		}
	}
}

func TestNoBuiltInSecretLiterals(t *testing.T) {
	for path, src := range goSources(t) {
		for _, needle := range []string{"otp-secret", "reset-secret"} {
			if strings.Contains(src, needle) {
				t.Errorf("%s contains the built-in secret literal %q", path, needle)
			}
		}
	}
}
