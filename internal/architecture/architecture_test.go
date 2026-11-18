// Package architecture holds repository-wide guard tests: the import rule
// between layers, the public/internal boundary and a few hygiene rules. It has
// no non-test files.
package architecture

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const modulePath = "github.com/zazhedho/authkit"

// skipDir names directories that hold no module source.
func skipDir(name string) bool {
	return name == ".git" || name == ".idea" || name == ".superpowers" || name == "testdata"
}

func repoFiles(t *testing.T, visit func(path string, data []byte)) {
	t.Helper()
	root := filepath.Join("..", "..")
	repo := os.DirFS(root)
	err := fs.WalkDir(repo, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDir(d.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := fs.ReadFile(repo, path)
		if err != nil {
			return err
		}
		visit(path, data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// fatalUses lists the process-ending calls in a source file outside cmd/.
func fatalUses(p string, data []byte) []string {
	if strings.HasPrefix(p, "cmd/") {
		return nil
	}
	var out []string
	for _, banned := range []string{"log.Fatal", "os.Exit("} {
		if strings.Contains(string(data), banned) {
			out = append(out, banned)
		}
	}
	return out
}

func TestNoFatalOutsideCmd(t *testing.T) {
	repoFiles(t, func(p string, data []byte) {
		for _, banned := range fatalUses(p, data) {
			t.Errorf("%s uses %s outside cmd/", p, banned)
		}
	})
}

func TestFatalRuleDetectsViolations(t *testing.T) {
	cases := []struct {
		name, path, src string
		want            int
	}{
		{"log.Fatal in a service", "internal/services/user/s.go", "log.Fatal(err)", 1},
		{"os.Exit in the root package", "authkit.go", "os.Exit(1)", 1},
		{"both calls", "internal/config/c.go", "log.Fatal(err)\nos.Exit(2)", 2},
		{"os.Exit in cmd", "cmd/module-seed/main.go", "os.Exit(1)", 0},
		{"log.Fatal in cmd", "cmd/module-seed/main.go", "log.Fatal(err)", 0},
		{"no fatal call", "internal/services/user/s.go", "return err", 0},
	}
	for _, c := range cases {
		if got := len(fatalUses(c.path, []byte(c.src))); got != c.want {
			t.Errorf("%s: %d uses, want %d", c.name, got, c.want)
		}
	}
}

// connectionVars lists package-level variables whose type is a database or
// cache client; connections are built in the root package and passed down.
func connectionVars(file *ast.File) []string {
	banned := map[string]bool{"redis.Client": true, "gorm.DB": true, "sql.DB": true}
	var out []string
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.VAR {
			continue
		}
		for _, spec := range gen.Specs {
			vs := spec.(*ast.ValueSpec)
			if vs.Type == nil {
				continue
			}
			expr := vs.Type
			if star, ok := expr.(*ast.StarExpr); ok {
				expr = star.X
			}
			sel, ok := expr.(*ast.SelectorExpr)
			if !ok {
				continue
			}
			if pkg, ok := sel.X.(*ast.Ident); ok && banned[pkg.Name+"."+sel.Sel.Name] {
				out = append(out, pkg.Name+"."+sel.Sel.Name)
			}
		}
	}
	return out
}

func TestNoPackageLevelConnections(t *testing.T) {
	repoFiles(t, func(p string, data []byte) {
		file, err := parser.ParseFile(token.NewFileSet(), p, data, 0)
		if err != nil {
			t.Errorf("parse %s: %v", p, err)
			return
		}
		for _, name := range connectionVars(file) {
			t.Errorf("%s declares a package-level %s", p, name)
		}
	})
}

func TestConnectionRuleDetectsViolations(t *testing.T) {
	cases := []struct {
		name, src string
		want      int
	}{
		{"gorm pointer", "var db *gorm.DB", 1},
		{"redis pointer", "var rdb *redis.Client", 1},
		{"sql pointer", "var conn *sql.DB", 1},
		{"gorm value", "var db gorm.DB", 1},
		{"inside a var block", "var (\n\tdb *gorm.DB\n\tn int\n)", 1},
		{"a local variable is fine", "func f() { var db *gorm.DB; _ = db }", 0},
		{"a struct field is fine", "type T struct{ db *gorm.DB }", 0},
		{"another type", "var re *regexp.Regexp", 0},
		{"inferred type", "var db = open()", 0},
	}
	for _, c := range cases {
		files := parseSources(t, "package p\n"+c.src)
		if got := len(connectionVars(files[0])); got != c.want {
			t.Errorf("%s: %d violations, want %d", c.name, got, c.want)
		}
	}
}

// rule lists what one package tree under internal/ must not import; internal
// entries are module-relative prefixes, external entries import-path prefixes.
type rule struct {
	tree           string
	forbidInternal []string
	forbidExternal []string
	// internalAllowed, when non-nil, replaces forbidInternal: only these
	// prefixes of the module's own packages may be imported.
	internalAllowed []string
	// externalAllowed, when non-nil, replaces forbidExternal: only the standard
	// library plus these import paths (and their subpackages) may be imported.
	externalAllowed []string
	// testInternalAllowed are internal prefixes only _test.go files of the tree
	// may import on top of the rule above, for fixtures the tests genuinely need.
	testInternalAllowed []string
	// exceptTrees are subtrees of tree the rule does not apply to.
	exceptTrees []string
	// testsToo applies the external rules to _test.go files as well.
	testsToo bool
}

var (
	ginPkg   = "github.com/gin-gonic/gin"
	gormPkg  = "gorm.io/gorm"
	redisPkg = "github.com/redis/go-redis"
)

var rules = []rule{
	{
		// Entities import nothing of the module; gorm.DeletedAt is the single
		// documented third-party type.
		tree:            "internal/domain",
		internalAllowed: []string{"internal/domain"},
		externalAllowed: []string{gormPkg},
		testsToo:        true,
	},
	{
		tree:            "internal/dto",
		internalAllowed: []string{"internal/domain"},
		externalAllowed: []string{}, // standard library only
		testsToo:        true,
	},
	{
		// An allow-list, so a new framework import fails until it is decided on.
		tree:            "internal/services",
		internalAllowed: []string{"internal/domain", "internal/dto", "internal/services/shared"},
		externalAllowed: []string{
			"github.com/zazhedho/logus",
			"github.com/google/uuid",
			"golang.org/x/crypto",
			"golang.org/x/text",
		},
		testsToo:            true,
		testInternalAllowed: []string{"internal/infrastructure/token"},
	},
	{
		tree:                "internal/handlers",
		forbidInternal:      []string{"internal/services", "internal/repositories", "internal/infrastructure", "internal/config", "internal/moduleseed", "internal/migrations", "internal/testutil"},
		forbidExternal:      []string{gormPkg, redisPkg},
		testsToo:            true,
		testInternalAllowed: []string{"internal/infrastructure/token", "internal/infrastructure/cache/permission", "internal/config"},
	},
	{
		tree:                "internal/repositories",
		forbidInternal:      []string{"internal/services", "internal/handlers", "internal/infrastructure", "internal/config", "internal/moduleseed", "internal/migrations"},
		forbidExternal:      []string{ginPkg},
		testInternalAllowed: []string{"internal/testutil"},
	},
	{
		tree:           "internal/infrastructure",
		forbidInternal: []string{"internal/services", "internal/handlers", "internal/repositories", "internal/moduleseed", "internal/migrations"},
	},
	{
		// Infrastructure owns its own types. The one exception is
		// infrastructure/cache/<module>, which implements that module's port.
		tree:           "internal/infrastructure",
		forbidInternal: []string{"internal/domain"},
		exceptTrees:    []string{"internal/infrastructure/cache"},
	},
	{
		tree:           "internal/config",
		forbidInternal: []string{"internal/"},
	},
	{
		// The middleware is a transport-level leaf, not a business module: it
		// sees the request context (domain) and the shared helpers, never a
		// service, a repository or another handler module.
		tree:                middlewareLeaf,
		internalAllowed:     []string{"internal/domain", "internal/handlers/http/shared"},
		testInternalAllowed: []string{"internal/infrastructure/token", "internal/infrastructure/cache/permission"},
	},
}

// knownLayers is every top-level directory of internal/. A new layer needs a
// rule in rules above and a line in the README's dependency rule before it is
// added here.
var knownLayers = []string{"architecture", "config", "domain", "dto", "handlers", "infrastructure", "migrations", "moduleseed", "repositories", "services", "testutil"}

// layerProblems compares the directories found under internal/ with knownLayers.
func layerProblems(found []string) []string {
	known := map[string]bool{}
	for _, l := range knownLayers {
		known[l] = true
	}
	seen := map[string]bool{}
	var out []string
	for _, d := range found {
		seen[d] = true
		if !known[d] {
			out = append(out, "internal/"+d+" is an unknown layer: a new layer needs a rule in rules (architecture_test.go) plus a line in the README's dependency rule, then an entry in knownLayers")
		}
	}
	for _, l := range knownLayers {
		if !seen[l] {
			out = append(out, "internal/"+l+" is in knownLayers but missing on disk; remove it from the list (and its rule and README line)")
		}
	}
	return out
}

func TestLayerProblemsDetectsViolations(t *testing.T) {
	all := append([]string{}, knownLayers...)
	cases := []struct {
		name  string
		found []string
		want  int
	}{
		{"exactly the known set", all, 0},
		{"unknown layer", append(append([]string{}, all...), "workers"), 1},
		{"known layer removed", all[1:], 1},
		{"interfaces layer", append(append([]string{}, all...), "interfaces"), 1},
		{"renamed layer", append(append([]string{}, all[1:]...), "apps"), 2},
	}
	for _, c := range cases {
		if got := layerProblems(c.found); len(got) != c.want {
			t.Errorf("%s: %v, want %d problems", c.name, got, c.want)
		}
	}
}

func TestInternalLayersAreKnown(t *testing.T) {
	entries, err := os.ReadDir(filepath.Join("..", "..", "internal"))
	if err != nil {
		t.Fatal(err)
	}
	var found []string
	for _, e := range entries {
		if e.IsDir() {
			found = append(found, e.Name())
		}
	}
	for _, p := range layerProblems(found) {
		t.Error(p)
	}
}

func isStdlib(importPath string) bool {
	first, _, _ := strings.Cut(importPath, "/")
	return !strings.Contains(first, ".")
}

// applies reports whether r governs the package in dir.
func applies(r rule, dir string) bool {
	if !underTree(dir, r.tree) {
		return false
	}
	for _, e := range r.exceptTrees {
		if underTree(dir, e) {
			return false
		}
	}
	return true
}

func underTree(dir, tree string) bool {
	return dir == tree || strings.HasPrefix(dir, tree+"/")
}

// pathUnder reports whether importPath is prefix or one of its subpackages.
func pathUnder(importPath, prefix string) bool {
	return importPath == prefix || strings.HasPrefix(importPath, prefix+"/")
}

func matchesPrefix(importPath, prefix string) bool {
	return importPath == prefix || strings.HasPrefix(importPath, prefix+"/") || strings.HasPrefix(importPath, prefix+"-") || strings.HasPrefix(importPath, prefix+"@")
}

func collectViolations(t *testing.T) map[string]bool {
	t.Helper()
	found := map[string]bool{}
	root := filepath.Join("..", "..")
	err := fs.WalkDir(os.DirFS(root), "internal", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ".go") {
			return nil
		}
		isTest := strings.HasSuffix(p, "_test.go")
		dir := path.Dir(p)
		file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(root, p), nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imp := range file.Imports {
			ip, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				return err
			}
			for _, r := range rules {
				if !applies(r, dir) {
					continue
				}
				if bad := violates(r, ip, isTest); bad {
					found[dir+" -> "+ip] = true
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return found
}

func violates(r rule, ip string, isTest bool) bool {
	if internal, ok := strings.CutPrefix(ip, modulePath+"/"); ok {
		if isTest {
			for _, a := range r.testInternalAllowed {
				if matchesPrefix(internal, a) {
					return false
				}
			}
		}
		if r.internalAllowed != nil {
			for _, a := range r.internalAllowed {
				if matchesPrefix(internal, a) {
					return false
				}
			}
			return true
		}
		for _, f := range r.forbidInternal {
			if f == "internal/" {
				return true
			}
			if matchesPrefix(internal, f) {
				return true
			}
		}
		return false
	}
	if isTest && !r.testsToo {
		return false
	}
	if isStdlib(ip) {
		return false
	}
	if r.externalAllowed != nil {
		for _, a := range r.externalAllowed {
			if pathUnder(ip, a) {
				return false
			}
		}
		return true
	}
	for _, f := range r.forbidExternal {
		if matchesPrefix(ip, f) {
			return true
		}
	}
	return false
}

func TestImportRule(t *testing.T) {
	violations := collectViolations(t)
	found := make([]string, 0, len(violations))
	for v := range violations {
		found = append(found, v)
	}
	sort.Strings(found)
	for _, v := range found {
		t.Errorf("import-rule violation: %s", v)
	}
}

// TestInfrastructureDoesNotImportDomain: infrastructure owns its own types; only
// infrastructure/cache/<module>, which implements a module's port, may name a
// domain type.
func TestInfrastructureDoesNotImportDomain(t *testing.T) {
	cases := []struct {
		name string
		dir  string
		ip   string
		want bool
	}{
		{"token imports a domain", "internal/infrastructure/token", "github.com/zazhedho/authkit/internal/domain/user", true},
		{"mailer imports a domain", "internal/infrastructure/mailer", "github.com/zazhedho/authkit/internal/domain/auth", true},
		{"cache of a module imports its domain", "internal/infrastructure/cache/permission", "github.com/zazhedho/authkit/internal/domain/permission", false},
		{"mailer imports config", "internal/infrastructure/mailer", "github.com/zazhedho/authkit/internal/config", false},
		{"mailer imports a service", "internal/infrastructure/mailer", "github.com/zazhedho/authkit/internal/services/user", true},
		{"token imports stdlib", "internal/infrastructure/token", "context", false},
	}
	for _, c := range cases {
		got := false
		for _, r := range rules {
			if applies(r, c.dir) && violates(r, c.ip, false) {
				got = true
			}
		}
		if got != c.want {
			t.Errorf("%s: violated=%v, want %v", c.name, got, c.want)
		}
	}
}

// TestSharedRespectsLayerRules: a shared package belongs to its tree, so the
// layer rules still apply to it and to importers of it.
func TestSharedRespectsLayerRules(t *testing.T) {
	cases := []struct {
		name, dir, ip string
		want          bool
	}{
		{"services shared imports domain", "internal/services/shared", "github.com/zazhedho/authkit/internal/domain/permission", false},
		{"services shared imports gin", "internal/services/shared", "github.com/gin-gonic/gin", true},
		{"services shared imports a repository", "internal/services/shared", "github.com/zazhedho/authkit/internal/repositories/shared", true},
		{"service imports services shared", "internal/services/user", "github.com/zazhedho/authkit/internal/services/shared", false},
		{"service imports repositories shared", "internal/services/user", "github.com/zazhedho/authkit/internal/repositories/shared", true},
		{"service imports handlers shared", "internal/services/user", "github.com/zazhedho/authkit/internal/handlers/http/shared", true},
		{"http handler imports services shared", "internal/handlers/http/user", "github.com/zazhedho/authkit/internal/services/shared", true},
		{"http handler imports http shared", "internal/handlers/http/user", "github.com/zazhedho/authkit/internal/handlers/http/shared", false},
		{"repository imports handlers shared", "internal/repositories/user", "github.com/zazhedho/authkit/internal/handlers/http/shared", true},
		{"repository imports repositories shared", "internal/repositories/user", "github.com/zazhedho/authkit/internal/repositories/shared", false},
	}
	for _, c := range cases {
		got := false
		for _, r := range rules {
			if applies(r, c.dir) && violates(r, c.ip, false) {
				got = true
			}
		}
		if got != c.want {
			t.Errorf("%s: violated=%v, want %v", c.name, got, c.want)
		}
	}
}

func TestRulesDetectViolations(t *testing.T) {
	byTree := map[string]rule{}
	for _, r := range rules {
		if r.exceptTrees == nil {
			byTree[r.tree] = r
		}
	}
	services, domain, dto := byTree["internal/services"], byTree["internal/domain"], byTree["internal/dto"]
	handlers, repos, leaf := byTree["internal/handlers"], byTree["internal/repositories"], byTree[middlewareLeaf]
	cfg := byTree["internal/config"]
	cases := []struct {
		name   string
		r      rule
		ip     string
		isTest bool
		want   bool
	}{
		{"service imports gorm", services, "gorm.io/gorm", false, true},
		{"service imports redis", services, "github.com/redis/go-redis/v9", false, true},
		{"service imports gin", services, "github.com/gin-gonic/gin", false, true},
		{"service imports gokit", services, "github.com/zazhedho/gokit", false, true},
		{"service imports jwt", services, "github.com/golang-jwt/jwt/v5", false, true},
		{"service imports an unlisted module", services, "github.com/example/newframework", false, true},
		{"service imports the root module", services, "github.com/zazhedho/authkit", false, true},
		{"service test imports gokit", services, "github.com/zazhedho/gokit", true, true},
		{"service test imports gorm", services, "gorm.io/gorm", true, true},
		{"service test imports a repository", services, "github.com/zazhedho/authkit/internal/repositories/menu", true, true},
		{"service test imports infrastructure", services, "github.com/zazhedho/authkit/internal/infrastructure/mailer", true, true},
		{"service test imports the token fixture", services, "github.com/zazhedho/authkit/internal/infrastructure/token", true, false},
		{"service non-test imports the token fixture", services, "github.com/zazhedho/authkit/internal/infrastructure/token", false, true},
		{"service test imports domain", services, "github.com/zazhedho/authkit/internal/domain/menu", true, false},
		{"handler test imports a service", handlers, "github.com/zazhedho/authkit/internal/services/menu", true, true},
		{"handler test imports shared", handlers, "github.com/zazhedho/authkit/internal/handlers/http/shared", true, false},
		{"repository test imports a handler", repos, "github.com/zazhedho/authkit/internal/handlers/http/user", true, true},
		{"domain test imports a service", domain, "github.com/zazhedho/authkit/internal/services/user", true, true},
		{"service imports infrastructure", services, "github.com/zazhedho/authkit/internal/infrastructure/token", false, true},
		{"service imports repositories", services, "github.com/zazhedho/authkit/internal/repositories/user", false, true},
		{"service imports handlers", services, "github.com/zazhedho/authkit/internal/handlers/http/shared", false, true},
		{"service imports config", services, "github.com/zazhedho/authkit/internal/config", false, true},
		{"service imports domain", services, "github.com/zazhedho/authkit/internal/domain/user", false, false},
		{"service imports dto", services, "github.com/zazhedho/authkit/internal/dto/user", false, false},
		{"service imports services shared", services, "github.com/zazhedho/authkit/internal/services/shared", false, false},
		{"service imports stdlib", services, "context", false, false},
		{"service imports uuid", services, "github.com/google/uuid", false, false},
		{"service imports logus", services, "github.com/zazhedho/logus", false, false},
		{"service imports bcrypt", services, "golang.org/x/crypto/bcrypt", false, false},
		{"service imports x/text cases", services, "golang.org/x/text/cases", false, false},
		{"service imports x/net", services, "golang.org/x/net/html", false, true},
		{"service imports a lookalike of an allowed path", services, "github.com/google/uuidx", false, true},
		{"domain imports gorm", domain, "gorm.io/gorm", false, false},
		{"domain imports gin", domain, "github.com/gin-gonic/gin", false, true},
		{"domain imports dto", domain, "github.com/zazhedho/authkit/internal/dto/user", false, true},
		{"domain imports config", domain, "github.com/zazhedho/authkit/internal/config", false, true},
		{"dto imports domain", dto, "github.com/zazhedho/authkit/internal/domain/user", false, false},
		{"dto imports stdlib", dto, "time", false, false},
		{"dto imports services", dto, "github.com/zazhedho/authkit/internal/services/user", false, true},
		{"dto imports config", dto, "github.com/zazhedho/authkit/internal/config", false, true},
		{"dto imports uuid", dto, "github.com/google/uuid", false, true},
		{"dto imports gin", dto, "github.com/gin-gonic/gin", false, true},
		{"handler imports a service", handlers, "github.com/zazhedho/authkit/internal/services/user", false, true},
		{"handler imports a repository", handlers, "github.com/zazhedho/authkit/internal/repositories/user", false, true},
		{"handler imports infrastructure", handlers, "github.com/zazhedho/authkit/internal/infrastructure/token", false, true},
		{"handler imports config", handlers, "github.com/zazhedho/authkit/internal/config", false, true},
		{"handler imports gorm", handlers, "gorm.io/gorm", false, true},
		{"handler imports redis", handlers, "github.com/redis/go-redis/v9", false, true},
		{"handler imports domain", handlers, "github.com/zazhedho/authkit/internal/domain/user", false, false},
		{"handler imports dto", handlers, "github.com/zazhedho/authkit/internal/dto/user", false, false},
		{"handler imports gin", handlers, "github.com/gin-gonic/gin", false, false},
		{"repository imports a service", repos, "github.com/zazhedho/authkit/internal/services/user", false, true},
		{"repository imports a handler", repos, "github.com/zazhedho/authkit/internal/handlers/http/user", false, true},
		{"repository imports infrastructure", repos, "github.com/zazhedho/authkit/internal/infrastructure/token", false, true},
		{"repository imports gin", repos, "github.com/gin-gonic/gin", false, true},
		{"repository imports gorm", repos, "gorm.io/gorm", false, false},
		{"repository imports domain", repos, "github.com/zazhedho/authkit/internal/domain/user", false, false},
		{"config imports any internal package", cfg, "github.com/zazhedho/authkit/internal/domain/user", false, true},
		{"config imports stdlib", cfg, "time", false, false},
		{"middleware imports a service", leaf, "github.com/zazhedho/authkit/internal/services/user", false, true},
		{"middleware imports a repository", leaf, "github.com/zazhedho/authkit/internal/repositories/auth", false, true},
		{"middleware imports a handler module", leaf, "github.com/zazhedho/authkit/internal/handlers/http/user", false, true},
		{"middleware imports infrastructure", leaf, "github.com/zazhedho/authkit/internal/infrastructure/token", false, true},
		{"middleware imports dto", leaf, "github.com/zazhedho/authkit/internal/dto/user", false, true},
		{"middleware imports domain", leaf, "github.com/zazhedho/authkit/internal/domain/permission", false, false},
		{"middleware imports handlers shared", leaf, "github.com/zazhedho/authkit/internal/handlers/http/shared", false, false},
		{"middleware imports gin", leaf, "github.com/gin-gonic/gin", false, false},
	}
	for _, c := range cases {
		if got := violates(c.r, c.ip, c.isTest); got != c.want {
			t.Errorf("%s: violates=%v, want %v", c.name, got, c.want)
		}
	}
}

// Interfaces are declared by their consumer (ports.go), never in a producer-side
// package, and carry no "Interface" suffix.
func TestInterfacesLiveWithTheirConsumer(t *testing.T) {
	if _, err := os.Stat(filepath.Join("..", "..", "internal", "interfaces")); err == nil {
		t.Error("internal/interfaces must not exist: declare interfaces in the consuming package (ports.go)")
	}
	repoFiles(t, func(p string, data []byte) {
		file, err := parser.ParseFile(token.NewFileSet(), p, data, 0)
		if err != nil {
			t.Errorf("parse %s: %v", p, err)
			return
		}
		for _, name := range interfaceSuffixViolations(file) {
			t.Errorf("%s: interface %s has an Interface suffix; name it for the role (Service, Repository, ...)", p, name)
		}
	})
}

// interfaceSuffixViolations lists interface types named with an Interface suffix.
func interfaceSuffixViolations(file *ast.File) []string {
	var out []string
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.TYPE {
			continue
		}
		for _, spec := range gen.Specs {
			ts := spec.(*ast.TypeSpec)
			if _, isIface := ts.Type.(*ast.InterfaceType); isIface && strings.HasSuffix(ts.Name.Name, "Interface") {
				out = append(out, ts.Name.Name)
			}
		}
	}
	return out
}

func TestInterfaceRuleDetectsViolations(t *testing.T) {
	cases := []struct {
		name, src string
		want      int
	}{
		{"suffixed interface", "type RepoUserInterface interface{ Do() }", 1},
		{"suffixed interface in a block", "type (\n\tServiceInterface interface{}\n\tRepository interface{}\n)", 1},
		{"role-named interface", "type Repository interface{ Do() }", 0},
		{"struct with the suffix", "type FooInterface struct{}", 0},
	}
	for _, c := range cases {
		files := parseSources(t, "package p\n"+c.src)
		if got := len(interfaceSuffixViolations(files[0])); got != c.want {
			t.Errorf("%s: %d violations, want %d", c.name, got, c.want)
		}
	}
	// An internal/interfaces directory is not a known layer.
	if got := layerProblems(append(append([]string{}, knownLayers...), "interfaces")); len(got) != 1 {
		t.Errorf("an interfaces layer: %v, want 1 problem", got)
	}
}

// moduleAliasPrefix maps each per-module tree to its import-alias prefix
// (domainuser, servicerole). Handler trees derive theirs from the transport
// directory (internal/handlers/<transport>/<module>), so a new transport needs no edit.
var moduleAliasPrefix = map[string]string{
	"internal/domain":               "domain",
	"internal/dto":                  "dto",
	"internal/services":             "service",
	"internal/repositories":         "repository",
	"internal/infrastructure/cache": "cache",
}

const (
	handlersTree = "internal/handlers"
	// middlewareLeaf is the transport-level package that guards routes. It is
	// not a business module: it has no alias prefix and is skipped by the
	// cross-module rule.
	middlewareLeaf = "internal/handlers/http/middleware"
	// sharedName is the one reserved directory name in a per-module tree
	// (<tree>/shared). It holds helpers every module of the tree may import, is
	// not a business module, and must not import one. Alias: prefix + "shared".
	sharedName = "shared"
)

// moduleTree splits a module-relative path under a per-module tree into alias
// prefix, module and the path below it ("" for the module's own package). ok is
// false outside those trees and for the middleware leaf; shared comes back as a module.
func moduleTree(p string) (prefix, module, rest string, ok bool) {
	if p == middlewareLeaf || strings.HasPrefix(p, middlewareLeaf+"/") {
		return "", "", "", false
	}
	if below, found := strings.CutPrefix(p, handlersTree+"/"); found {
		transport, inside, found := strings.Cut(below, "/")
		if !found || inside == "" {
			return "", "", "", false
		}
		module, rest, _ = strings.Cut(inside, "/")
		return transport, module, rest, true
	}
	for tree, prefix := range moduleAliasPrefix {
		if below, found := strings.CutPrefix(p, tree+"/"); found {
			module, rest, _ = strings.Cut(below, "/")
			return prefix, module, rest, true
		}
	}
	return "", "", "", false
}

// expectedAlias returns the alias the import convention demands for importPath,
// or "" when importPath is not a module package.
func expectedAlias(importPath string) string {
	internal, ok := strings.CutPrefix(importPath, modulePath+"/")
	if !ok {
		return ""
	}
	prefix, module, rest, ok := moduleTree(internal)
	if !ok || rest != "" {
		return ""
	}
	return prefix + module
}

// goFiles calls visit for every .go file (tests included) of the module,
// parsed with imports only.
func goFiles(t *testing.T, visit func(p string, file *ast.File)) {
	t.Helper()
	root := filepath.Join("..", "..")
	err := fs.WalkDir(os.DirFS(root), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDir(d.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(root, p), nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		visit(p, file)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// aliasWrong reports whether importing importPath under the name got (""
// for no alias) breaks the alias convention.
func aliasWrong(importPath, got string) bool {
	want := expectedAlias(importPath)
	return want != "" && got != want
}

func TestAliasRuleDetectsViolations(t *testing.T) {
	cases := []struct {
		name, ip, got string
		want          bool
	}{
		{"correct domain alias", "github.com/zazhedho/authkit/internal/domain/user", "domainuser", false},
		{"no alias on a module package", "github.com/zazhedho/authkit/internal/domain/user", "", true},
		{"old repo prefix", "github.com/zazhedho/authkit/internal/repositories/shared", "reposhared", true},
		{"old handler prefix", "github.com/zazhedho/authkit/internal/handlers/http/user", "handleruser", true},
		{"another module's alias", "github.com/zazhedho/authkit/internal/services/role", "serviceuser", true},
		{"correct shared alias", "github.com/zazhedho/authkit/internal/handlers/http/shared", "httpshared", false},
		{"the middleware leaf needs none", "github.com/zazhedho/authkit/internal/handlers/http/middleware", "", false},
		{"a package outside the module trees", "github.com/zazhedho/authkit/internal/infrastructure/token", "", false},
		{"a third party", "github.com/gin-gonic/gin", "", false},
	}
	for _, c := range cases {
		if got := aliasWrong(c.ip, c.got); got != c.want {
			t.Errorf("%s: aliasWrong = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestImportAliasConvention(t *testing.T) {
	goFiles(t, func(p string, file *ast.File) {
		for _, imp := range file.Imports {
			ip, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				t.Errorf("%s: %v", p, err)
				continue
			}
			want := expectedAlias(ip)
			if want == "" {
				continue
			}
			got := ""
			if imp.Name != nil {
				got = imp.Name.Name
			}
			if aliasWrong(ip, got) {
				t.Errorf("%s imports %s as %q; the convention is the alias %q", p, ip, got, want)
			}
		}
	})
}

func TestExpectedAlias(t *testing.T) {
	cases := map[string]string{
		"github.com/zazhedho/authkit/internal/domain/user":                     "domainuser",
		"github.com/zazhedho/authkit/internal/dto/role":                        "dtorole",
		"github.com/zazhedho/authkit/internal/services/menu":                   "servicemenu",
		"github.com/zazhedho/authkit/internal/repositories/audit":              "repositoryaudit",
		"github.com/zazhedho/authkit/internal/handlers/http/permission":        "httppermission",
		"github.com/zazhedho/authkit/internal/infrastructure/cache/permission": "cachepermission",
		"github.com/zazhedho/authkit/internal/infrastructure/token":            "",
		"github.com/zazhedho/authkit/internal/infrastructure/mailer":           "",
		"github.com/zazhedho/authkit/internal/config":                          "",
		"github.com/gin-gonic/gin":                                             "",
		"github.com/zazhedho/authkit/internal/handlers/http":                   "",
		"github.com/zazhedho/authkit/internal/handlers/http/middleware":        "", // reserved leaf, imported as middleware
		"github.com/zazhedho/authkit/internal/handlers/grpc/user":              "grpcuser",
		"github.com/zazhedho/authkit/internal/handlers/grpc":                   "",
		"github.com/zazhedho/authkit/internal/services/shared":                 "serviceshared",
		"github.com/zazhedho/authkit/internal/repositories/shared":             "repositoryshared",
		"github.com/zazhedho/authkit/internal/handlers/http/shared":            "httpshared",
		"github.com/zazhedho/authkit/internal/services/shared/page":            "",
	}
	for ip, want := range cases {
		if got := expectedAlias(ip); got != want {
			t.Errorf("expectedAlias(%q) = %q, want %q", ip, got, want)
		}
	}
}

// TestPackageNameMatchesDirectory enforces the Go convention that a package is
// named after its directory (an external test package may add _test).
func TestPackageNameMatchesDirectory(t *testing.T) {
	goFiles(t, func(p string, file *ast.File) {
		// The root package is the public facade and keeps the module's name.
		if strings.HasPrefix(p, "cmd/") || path.Dir(p) == "." {
			return
		}
		if packageNameWrong(p, file.Name.Name) {
			t.Errorf("%s declares package %s; the directory name is %s", p, file.Name.Name, path.Base(path.Dir(p)))
		}
	})
}

// packageNameWrong reports whether a file at p declares a package named
// differently from its directory (an external test package may add _test).
func packageNameWrong(p, name string) bool {
	return strings.TrimSuffix(name, "_test") != path.Base(path.Dir(p))
}

func TestPackageNameRuleDetectsViolations(t *testing.T) {
	cases := []struct {
		name, path, pkg string
		want            bool
	}{
		{"matches the directory", "internal/services/role/service.go", "role", false},
		{"layer-prefixed name", "internal/services/role/service.go", "servicerole", true},
		{"external test package", "internal/services/role/service_test.go", "role_test", false},
		{"wrong test package", "internal/services/role/service_test.go", "servicerole_test", true},
		{"nested directory", "internal/handlers/http/shared/x.go", "shared", false},
		{"nested directory mismatch", "internal/handlers/http/shared/x.go", "httpshared", true},
	}
	for _, c := range cases {
		if got := packageNameWrong(c.path, c.pkg); got != c.want {
			t.Errorf("%s: packageNameWrong = %v, want %v", c.name, got, c.want)
		}
	}
}

// moduleOf returns the business module a module-relative path belongs to, or ""
// outside the per-module trees and for a reserved shared package (see moduleTree).
func moduleOf(p string) string {
	_, module, _, _ := moduleTree(p)
	if module == sharedName {
		return ""
	}
	return module
}

// isShared reports whether the module-relative path is a reserved shared package
// (or below one) of a per-module tree.
func isShared(p string) bool {
	_, module, _, ok := moduleTree(p)
	return ok && module == sharedName
}

// kernelTrees are the inward-most layers. authkit's modules form one RBAC
// model, so these two trees are the only place modules may meet.
var kernelTrees = []string{"internal/domain", "internal/dto"}

func isKernel(p string) bool {
	for _, tree := range kernelTrees {
		if underTree(p, tree) {
			return true
		}
	}
	return false
}

// crossesModules reports whether a file in directory dir (module-relative)
// imports a package of a different business module. A shared package may be
// imported by any module but may import no business module at all.
func crossesModules(dir, importPath string) bool {
	internal, ok := strings.CutPrefix(importPath, modulePath+"/")
	if !ok {
		return false
	}
	from, to := moduleOf(dir), moduleOf(internal)
	if to == "" {
		return false
	}
	// The entities and request shapes are one shared model (users, roles,
	// permissions, menus and audit trails reference each other), so every
	// layer above them may name any module's domain or dto package.
	if isKernel(internal) && !isKernel(dir) {
		return false
	}
	return from != to && (from != "" || isShared(dir))
}

// Modules must not import each other in any layer, tests included; they meet only
// in the root package, which wires them.
func TestModulesDoNotImportEachOther(t *testing.T) {
	goFiles(t, func(p string, file *ast.File) {
		for _, imp := range file.Imports {
			ip, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				t.Errorf("%s: %v", p, err)
				continue
			}
			if crossesModules(path.Dir(p), ip) {
				t.Errorf("%s imports %s: a module must not import another module", p, ip)
			}
		}
	})
}

func TestCrossModuleRuleDetectsViolations(t *testing.T) {
	cases := []struct {
		name, dir, ip string
		want          bool
	}{
		{"role service imports user service", "internal/services/role", "github.com/zazhedho/authkit/internal/services/user", true},
		{"role handler imports user handler", "internal/handlers/http/role", "github.com/zazhedho/authkit/internal/handlers/http/user", true},
		{"user repository imports role repository", "internal/repositories/user", "github.com/zazhedho/authkit/internal/repositories/role", true},
		{"role handler imports user domain", "internal/handlers/http/role", "github.com/zazhedho/authkit/internal/domain/user", false},
		{"user repository imports role dto", "internal/repositories/user", "github.com/zazhedho/authkit/internal/dto/role", false},
		{"cache of permission imports user domain", "internal/infrastructure/cache/permission", "github.com/zazhedho/authkit/internal/domain/user", false},
		{"role domain imports user domain", "internal/domain/role", "github.com/zazhedho/authkit/internal/domain/user", true},
		{"role dto imports user dto", "internal/dto/role", "github.com/zazhedho/authkit/internal/dto/user", true},
		{"role dto imports user domain", "internal/dto/role", "github.com/zazhedho/authkit/internal/domain/user", true},
		{"role service imports user dto", "internal/services/role", "github.com/zazhedho/authkit/internal/dto/user", false},
		{"role service imports its own domain", "internal/services/role", "github.com/zazhedho/authkit/internal/domain/role", false},
		{"nested package imports its own module", "internal/services/role/export", "github.com/zazhedho/authkit/internal/domain/role", false},
		{"role service imports infrastructure", "internal/services/role", "github.com/zazhedho/authkit/internal/infrastructure/token", false},
		{"role service imports a third party", "internal/services/role", "github.com/google/uuid", false},
		{"role handler imports the middleware leaf", "internal/handlers/http/role", "github.com/zazhedho/authkit/internal/handlers/http/middleware", false},
		{"middleware imports a module", "internal/handlers/http/middleware", "github.com/zazhedho/authkit/internal/domain/permission", false},
		{"middleware imports handlers shared", "internal/handlers/http/middleware", "github.com/zazhedho/authkit/internal/handlers/http/shared", false},
		{"service imports the middleware leaf", "internal/services/role", "github.com/zazhedho/authkit/internal/handlers/http/middleware", false},
		{"grpc handler imports another module's domain", "internal/handlers/grpc/role", "github.com/zazhedho/authkit/internal/domain/user", false},
		{"grpc handler imports http handler of the same module", "internal/handlers/grpc/role", "github.com/zazhedho/authkit/internal/handlers/http/role", false},
		{"grpc handler imports http handler of another module", "internal/handlers/grpc/role", "github.com/zazhedho/authkit/internal/handlers/http/user", true},
		{"transport root package", "internal/handlers/grpc", "github.com/zazhedho/authkit/internal/domain/user", false},
		{"http handler imports its tree's shared", "internal/handlers/http/user", "github.com/zazhedho/authkit/internal/handlers/http/shared", false},
		{"nested module package imports shared", "internal/services/role/export", "github.com/zazhedho/authkit/internal/services/shared", false},
		{"service imports another tree's shared", "internal/services/role", "github.com/zazhedho/authkit/internal/repositories/shared", false},
		{"shared imports a module of its tree", "internal/handlers/http/shared", "github.com/zazhedho/authkit/internal/handlers/http/user", true},
		{"shared imports a module's domain", "internal/services/shared", "github.com/zazhedho/authkit/internal/domain/permission", false},
		{"shared imports a module of another tree", "internal/services/shared", "github.com/zazhedho/authkit/internal/repositories/role", true},
		{"shared imports a module's own subpackage", "internal/services/shared", "github.com/zazhedho/authkit/internal/services/role/export", true},
		{"shared imports another shared", "internal/handlers/http/shared", "github.com/zazhedho/authkit/internal/services/shared", false},
		{"shared imports the middleware leaf", "internal/services/shared", "github.com/zazhedho/authkit/internal/handlers/http/middleware", false},
		{"shared imports a third party", "internal/handlers/http/shared", "github.com/gin-gonic/gin", false},
		{"nested package under shared imports a module", "internal/repositories/shared/page", "github.com/zazhedho/authkit/internal/repositories/role", true},
	}
	for _, c := range cases {
		if got := crossesModules(c.dir, c.ip); got != c.want {
			t.Errorf("%s: crossesModules=%v, want %v", c.name, got, c.want)
		}
	}
}

// constructorTrees are the layers whose exported New* must return a concrete type;
// internal/infrastructure factories may return an interface.
var constructorTrees = []string{"internal/services", "internal/repositories", "internal/handlers"}

// constructorDirSkipped reports whether the constructor rule leaves dir alone:
// only the reserved top-level <tree>/shared holds helpers rather than a
// module's Service, Repository or Handler (NewID returns a string).
func constructorDirSkipped(dir string) bool {
	_, module, rest, ok := moduleTree(dir)
	return ok && module == sharedName && rest == ""
}

func TestConstructorRuleSkipsOnlySharedDirs(t *testing.T) {
	cases := map[string]bool{
		"internal/services/shared":           true,
		"internal/handlers/http/shared":      true,
		"internal/services/user":             false,
		"internal/handlers/http/middleware":  false,
		"internal/repositories/shared/extra": false,
		"internal/services/user/shared":      false,
		"internal/handlers/http/user/shared": false,
	}
	for dir, want := range cases {
		if got := constructorDirSkipped(dir); got != want {
			t.Errorf("constructorDirSkipped(%q) = %v, want %v", dir, got, want)
		}
	}
}

// TestConstructorRuleFlagsNestedSharedDir: a package that merely happens to be
// called shared inside a module is still checked.
func TestConstructorRuleFlagsNestedSharedDir(t *testing.T) {
	dir := "internal/services/user/shared"
	if constructorDirSkipped(dir) {
		t.Fatalf("%s must not be skipped", dir)
	}
	files := parseSources(t, "package shared\ntype I interface{}\nfunc NewI() I { return nil }")
	if got := constructorViolations(files); len(got) != 1 {
		t.Errorf("NewI() I: %v, want 1 violation", got)
	}
}

func isConstructorName(name string) bool {
	rest, ok := strings.CutPrefix(name, "New")
	return ok && (rest == "" || rest[0] >= 'A' && rest[0] <= 'Z')
}

// constructorViolations reports New* functions that do not return a pointer to a
// struct of the package, optionally followed by an error.
func constructorViolations(files []*ast.File) []string {
	structs := map[string]bool{}
	for _, f := range files {
		for _, decl := range f.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.TYPE {
				continue
			}
			for _, spec := range gen.Specs {
				if ts := spec.(*ast.TypeSpec); ts != nil {
					_, isStruct := ts.Type.(*ast.StructType)
					structs[ts.Name.Name] = isStruct
				}
			}
		}
	}

	var out []string
	for _, f := range files {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || !fn.Name.IsExported() || !isConstructorName(fn.Name.Name) {
				continue
			}
			var results []ast.Expr
			if fn.Type.Results != nil {
				for _, field := range fn.Type.Results.List {
					n := max(len(field.Names), 1)
					for range n {
						results = append(results, field.Type)
					}
				}
			}
			if !returnsConcretePointer(results, structs) {
				out = append(out, fn.Name.Name)
			}
		}
	}
	return out
}

func returnsConcretePointer(results []ast.Expr, structs map[string]bool) bool {
	if len(results) == 0 || len(results) > 2 {
		return false
	}
	star, ok := results[0].(*ast.StarExpr)
	if !ok {
		return false
	}
	target, ok := star.X.(*ast.Ident)
	if !ok || !structs[target.Name] {
		return false
	}
	if len(results) == 2 {
		errIdent, ok := results[1].(*ast.Ident)
		return ok && errIdent.Name == "error"
	}
	return true
}

func parseSources(t *testing.T, sources ...string) []*ast.File {
	t.Helper()
	fset := token.NewFileSet()
	files := make([]*ast.File, 0, len(sources))
	for _, src := range sources {
		f, err := parser.ParseFile(fset, "x.go", src, 0)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	return files
}

// TestConstructorsReturnConcreteTypes: a service, repository or handler
// constructor hands back *Struct (and optionally an error), never an interface.
func TestConstructorsReturnConcreteTypes(t *testing.T) {
	root := filepath.Join("..", "..")
	for _, tree := range constructorTrees {
		err := fs.WalkDir(os.DirFS(root), tree, func(p string, d fs.DirEntry, err error) error {
			if err != nil || !d.IsDir() {
				return err
			}
			entries, err := os.ReadDir(filepath.Join(root, p))
			if err != nil {
				return err
			}
			if constructorDirSkipped(p) {
				return nil
			}
			fset := token.NewFileSet()
			var files []*ast.File
			for _, e := range entries {
				if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
					continue
				}
				f, err := parser.ParseFile(fset, filepath.Join(root, p, e.Name()), nil, 0)
				if err != nil {
					return err
				}
				files = append(files, f)
			}
			for _, name := range constructorViolations(files) {
				t.Errorf("%s: %s must return a pointer to a struct (and optionally an error), not an interface", p, name)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestConstructorRuleDetectsViolations(t *testing.T) {
	const decls = "package p\ntype Service interface{ Do() }\ntype impl struct{}\ntype Options struct{}\n"
	cases := []struct {
		name string
		fn   string
		want int
	}{
		{"pointer to struct", "func NewService() *impl { return nil }", 0},
		{"pointer to struct and error", "func NewService() (*impl, error) { return nil, nil }", 0},
		{"unexported constructor is ignored", "func newService() Service { return nil }", 0},
		{"not a constructor name", "func Newest() Service { return nil }", 0},
		{"method is ignored", "func (i *impl) NewThing() Service { return nil }", 0},
		{"returns an interface", "func NewService() Service { return nil }", 1},
		{"returns an interface and an error", "func NewService() (Service, error) { return nil, nil }", 1},
		{"returns a struct value", "func NewOptions() Options { return Options{} }", 1},
		{"returns a pointer to an interface", "func NewService() *Service { return nil }", 1},
		{"returns an interface from another package", "func New() io.Reader { return nil }", 1},
		{"returns nothing", "func New() {}", 1},
		{"error comes first", "func NewService() (error, *impl) { return nil, nil }", 1},
	}
	for _, c := range cases {
		files := parseSources(t, decls+c.fn)
		if got := len(constructorViolations(files)); got != c.want {
			t.Errorf("%s: %d violations, want %d", c.name, got, c.want)
		}
	}
}

// importsRoot reports whether importPath is the module's root package, the
// public facade that internal code must never depend on.
func importsRoot(importPath string) bool {
	return importPath == modulePath
}

// TestInternalDoesNotImportRoot: the public package wires internal/, so an
// internal package importing it would be an import cycle waiting to happen.
func TestInternalDoesNotImportRoot(t *testing.T) {
	goFiles(t, func(p string, file *ast.File) {
		if !strings.HasPrefix(p, "internal/") {
			return
		}
		for _, imp := range file.Imports {
			if ip, err := strconv.Unquote(imp.Path.Value); err == nil && importsRoot(ip) {
				t.Errorf("%s imports the root package %s", p, ip)
			}
		}
	})
}

func TestRootImportRuleDetectsViolations(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{modulePath, true},
		{modulePath + "/internal/domain/user", false},
		{modulePath + "/cmd/module-seed", false},
		{modulePath + "x", false},
		{"github.com/zazhedho/gokit", false},
		{"context", false},
	}
	for _, c := range cases {
		if got := importsRoot(c.ip); got != c.want {
			t.Errorf("importsRoot(%q) = %v, want %v", c.ip, got, c.want)
		}
	}
}

// cmdImportViolation reports whether a file under cmd/ imports a package of
// this module other than internal/moduleseed.
func cmdImportViolation(importPath string) bool {
	if importPath != modulePath && !strings.HasPrefix(importPath, modulePath+"/") {
		return false
	}
	return !pathUnder(importPath, modulePath+"/internal/moduleseed")
}

// TestCmdImportsOnlyModuleseed: the seed command is a thin entry point over
// internal/moduleseed; the rest of the module stays behind the public API.
func TestCmdImportsOnlyModuleseed(t *testing.T) {
	goFiles(t, func(p string, file *ast.File) {
		if !strings.HasPrefix(p, "cmd/") {
			return
		}
		for _, imp := range file.Imports {
			if ip, err := strconv.Unquote(imp.Path.Value); err == nil && cmdImportViolation(ip) {
				t.Errorf("%s imports %s; cmd/ may import only internal/moduleseed of this module", p, ip)
			}
		}
	})
}

func TestCmdImportRuleDetectsViolations(t *testing.T) {
	cases := []struct {
		name, ip string
		want     bool
	}{
		{"moduleseed", modulePath + "/internal/moduleseed", false},
		{"root package", modulePath, true},
		{"a service", modulePath + "/internal/services/user", true},
		{"migrations", modulePath + "/internal/migrations", true},
		{"a lookalike of moduleseed", modulePath + "/internal/moduleseedx", true},
		{"stdlib", "flag", false},
		{"a third party", "github.com/zazhedho/gokit", false},
	}
	for _, c := range cases {
		if got := cmdImportViolation(c.ip); got != c.want {
			t.Errorf("%s: cmdImportViolation = %v, want %v", c.name, got, c.want)
		}
	}
}
