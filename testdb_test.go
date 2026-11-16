package authkit

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// fakeDriver is a tiny database/sql driver that answers the queries the kit
// issues from an in-memory model, so route tests run without a database.
type fakeDriver struct {
	mu sync.Mutex

	// users maps user id to its model.
	users map[string]*fakeUser
	// loginUsers maps a lower-case email to a user id.
	loginUsers map[string]string
	// enabledConfigs holds the app-config keys that read as active and "true".
	enabledConfigs map[string]string
	// queries records every statement, for diagnostics.
	queries []string
}

type fakeUser struct {
	ID           string
	Email        string
	Role         string
	PasswordHash string
	Permissions  []string // "resource:action"
}

func newFakeDriver() *fakeDriver {
	return &fakeDriver{
		users:          map[string]*fakeUser{},
		loginUsers:     map[string]string{},
		enabledConfigs: map[string]string{},
	}
}

func (d *fakeDriver) addUser(u fakeUser) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.users[u.ID] = &u
	if u.Email != "" {
		d.loginUsers[strings.ToLower(u.Email)] = u.ID
	}
}

// setConfig makes the app-config key read as active with the given value.
func (d *fakeDriver) setConfig(key, value string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.enabledConfigs[key] = value
}

type fakeResult struct {
	cols []string
	rows [][]driver.Value
}

func (d *fakeDriver) answer(query string, args []driver.NamedValue) fakeResult {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.queries = append(d.queries, query)
	q := strings.ToLower(query)
	argStr := func(i int) string {
		if i < len(args) {
			if s, ok := args[i].Value.(string); ok {
				return s
			}
		}
		return ""
	}

	switch {
	case strings.Contains(q, "count("):
		return fakeResult{cols: []string{"count"}, rows: [][]driver.Value{{int64(0)}}}
	case strings.HasPrefix(q, "select role_id, role from") || strings.Contains(q, "select role_id, role"):
		if u, ok := d.users[argStr(0)]; ok {
			return fakeResult{cols: []string{"role_id", "role"}, rows: [][]driver.Value{{"role-" + u.ID, u.Role}}}
		}
		return fakeResult{}
	case strings.Contains(q, "from permissions p"):
		roleID := argStr(0)
		for _, u := range d.users {
			if "role-"+u.ID != roleID {
				continue
			}
			var rows [][]driver.Value
			for _, p := range u.Permissions {
				parts := strings.SplitN(p, ":", 2)
				rows = append(rows, []driver.Value{p, parts[0], parts[1], time.Now()})
			}
			return fakeResult{cols: []string{"id", "resource", "action", "created_at"}, rows: rows}
		}
		return fakeResult{}
	case strings.Contains(q, `from "app_configs"`):
		for _, a := range args {
			if key, ok := a.Value.(string); ok {
				if value, found := d.enabledConfigs[key]; found {
					return fakeResult{
						cols: []string{"id", "config_key", "value", "is_active", "created_at"},
						rows: [][]driver.Value{{"cfg-" + key, key, value, true, time.Now()}},
					}
				}
			}
		}
		return fakeResult{}
	case strings.Contains(q, `from "roles"`):
		name := argStr(0)
		return fakeResult{cols: []string{"id", "name", "created_at"}, rows: [][]driver.Value{{"role-" + name, name, time.Now()}}}
	case strings.Contains(q, `from "users"`) && strings.Contains(q, "email"):
		if id, ok := d.loginUsers[strings.ToLower(argStr(0))]; ok {
			u := d.users[id]
			return fakeResult{
				cols: []string{"id", "name", "email", "password", "role", "created_at"},
				rows: [][]driver.Value{{u.ID, "Fake " + u.ID, u.Email, u.PasswordHash, u.Role, time.Now()}},
			}
		}
		return fakeResult{}
	}
	return fakeResult{}
}

// --- database/sql plumbing ---

type fakeConnector struct{ d *fakeDriver }

func (c fakeConnector) Connect(context.Context) (driver.Conn, error) { return &fakeConn{d: c.d}, nil }
func (c fakeConnector) Driver() driver.Driver                        { return fakeSQLDriver(c) }

type fakeSQLDriver struct{ d *fakeDriver }

func (f fakeSQLDriver) Open(string) (driver.Conn, error) { return &fakeConn{d: f.d}, nil }

type fakeConn struct{ d *fakeDriver }

func (c *fakeConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepare not supported")
}
func (c *fakeConn) Close() error              { return nil }
func (c *fakeConn) Begin() (driver.Tx, error) { return fakeTx{}, nil }
func (c *fakeConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return fakeTx{}, nil
}

func (c *fakeConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	res := c.d.answer(query, args)
	return &fakeRows{res: res}, nil
}

func (c *fakeConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	c.d.answer(query, args)
	return driver.RowsAffected(1), nil
}

type fakeTx struct{}

func (fakeTx) Commit() error   { return nil }
func (fakeTx) Rollback() error { return nil }

type fakeRows struct {
	res fakeResult
	i   int
}

func (r *fakeRows) Columns() []string { return r.res.cols }
func (r *fakeRows) Close() error      { return nil }
func (r *fakeRows) Next(dest []driver.Value) error {
	if r.i >= len(r.res.rows) {
		return io.EOF
	}
	copy(dest, r.res.rows[r.i])
	r.i++
	return nil
}

// newFakeDB returns a gorm DB backed by the fake driver.
func newFakeDB(t *testing.T) (*gorm.DB, *fakeDriver) {
	t.Helper()
	d := newFakeDriver()
	sqlDB := sql.OpenDB(fakeConnector{d})
	t.Cleanup(func() { _ = sqlDB.Close() })

	db, err := gorm.Open(postgres.New(postgres.Config{Conn: sqlDB, PreferSimpleProtocol: true}), &gorm.Config{
		SkipDefaultTransaction: true,
	})
	if err != nil {
		t.Fatalf("open gorm: %v", err)
	}
	return db, d
}

func mustHash(t *testing.T, password string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	return string(h)
}
