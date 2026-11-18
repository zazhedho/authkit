# authkit

Users, authentication and RBAC for Go services built on gin and gorm, extracted
from an existing project into a module you import. It provides registration and
login (password and Google), JWT access and refresh tokens, optional registration
OTP and password reset e-mail, roles, permissions, menus, runtime app
configuration, audit trails, an HTTP route set, and the middleware to protect
your own routes. Database tables ship as embedded migrations.

Everything is imported from one path, `github.com/zazhedho/authkit`; all
implementation lives under `internal/` and is not importable. Upgrading from
v0.1.x? See "Upgrading from v0.1.x" at the end.

authkit builds on two sibling modules: [`github.com/zazhedho/gokit`](https://github.com/zazhedho/gokit)
(request ids, rate limiting, response helpers, generic repositories) and
[`github.com/zazhedho/logus`](https://github.com/zazhedho/logus) (logging). Read the "Security defaults"
section of gokit's README (trusted proxies, fail-open rate limiting, `limit=-1`,
CORS) before exposing the routes; it applies to authkit unchanged.

Requires PostgreSQL 13 or newer. Redis and a mailer are optional. Read
"Security notes and known limitations" below before deploying.

## Quick start

```go
package main

import (
	"context"
	"log"
	"os"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/zazhedho/authkit"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func main() {
	db, err := gorm.Open(postgres.Open("postgres://user:password@localhost:5432/app?sslmode=disable"), &gorm.Config{})
	if err != nil {
		log.Fatal(err)
	}

	cfg := authkit.ConfigFromEnv() // optional: fill the Config yourself instead
	cfg.DB = db
	cfg.Redis = redis.NewClient(&redis.Options{Addr: "localhost:6379"}) // optional
	port, _ := strconv.Atoi(os.Getenv("SMTP_PORT"))
	if m, err := authkit.NewBrevoMailer(authkit.BrevoConfig{ // optional
		Host: os.Getenv("SMTP_HOST"), Port: port, User: os.Getenv("SMTP_USER"),
		Pass: os.Getenv("SMTP_PASS"), From: os.Getenv("SMTP_FROM"),
	}); err == nil {
		cfg.Mailer = m
	}

	kit, err := authkit.New(cfg) // validates the config; never touches the database
	if err != nil {
		log.Fatal(err)
	}
	if err := kit.Migrate(context.Background()); err != nil { // before your own migrations
		log.Fatal(err)
	}

	r := gin.New()
	// Set your reverse proxy CIDRs instead when behind a proxy; rate limits and
	// audit IPs depend on it.
	r.SetTrustedProxies(nil)
	kit.Mount(r.Group("/api"))
	log.Fatal(r.Run(":8080"))
}
```

Order matters: build the `Kit`, run `Migrate`, then run your own migrations
(they may reference `users` and `roles`), then `Mount`.

## Protecting your own routes

Routes, as a fragment of your `main` (after `kit.Mount`):

```go
api := r.Group("/api")

// Any authenticated user.
api.GET("/trips", kit.Auth(), listTrips)

// Authenticated and holding the (resource, action) permission.
api.POST("/trips", kit.Auth(), kit.Can("trips", "create"), createTrip)

// Authenticated, with the permissions loaded but none required: the handler
// branches on scope.Has (for example a "list_any" permission).
api.GET("/files", kit.Auth(), kit.LoadPermissions(), listFiles)

// Authenticated and one of the given roles.
api.GET("/reports", kit.Auth(), kit.Role("admin", "staff"), reports)
```

A handler, as a complete function (add `net/http`, `github.com/gin-gonic/gin`
and `github.com/zazhedho/authkit` to your imports):

```go
func listTrips(c *gin.Context) {
	scope := authkit.ScopeFrom(c.Request.Context()) // UserID, Username, Role, impersonation fields
	// After kit.Auth() alone the permission set is EMPTY, so scope.Has is false
	// for every non-superadmin. kit.Can(...) or kit.LoadPermissions() loads them; behind it,
	// scope.Has("trips", "create") reflects the user's real grants.
	c.JSON(http.StatusOK, gin.H{"user": scope.UserID, "role": scope.Role})
}
```

`Can`, `LoadPermissions` and `Role` must come after `Auth`. Superadmin bypasses
`Can` and `Role`, and passes every `Has` check. `LoadPermissions` fills the
scope's permissions like `Can` does (403 for a deleted user, 500 on a lookup
error) but never rejects a user for lacking one. `ScopeFrom` returns identity
and role after `Auth`; permissions are only populated by `Can` or
`LoadPermissions`. Permissions are
plain rows (`resource`, `action`); add yours with `cmd/module-seed` (see
Extending). `kit.Audit()` and `kit.AppConfig()` expose the audit and app-config
services (`authkit.AuditService`, `authkit.AppConfigService`).
`kit.IssueAccessToken(userID, name, role)` issues a normal access token for a
user through the Kit's own token service; it is meant for tests and tooling.

## Public types

Besides `Kit` and `Config`, the root package exports these helpers (all in
`types.go`).

`Scope`, `NewScope`, `WithScope`: the authenticated identity of a request.

```go
ctx := authkit.WithScope(context.Background(),
	authkit.NewScope("user-1", "Ada", authkit.RoleStaff, []string{"trips:view"}))
scope := authkit.ScopeFrom(ctx)
ok := scope.Has("trips", "view") // true
```

`AuditEvent`, `Action*`, `Status*`, `AuditService`, `AuditWriter`,
`NewAuditWriter`: write audit trail entries from your own handlers.

```go
audit := authkit.NewAuditWriter(kit.Audit(), "TripHandler")

func createTrip(c *gin.Context) {
	// ... create the trip ...
	audit.WriteAudit(c, authkit.AuditEvent{
		Action:   authkit.ActionCreate,
		Resource: "trips",
		Status:   authkit.StatusSuccess,
	})
}
```

`RequestLogger`: a gin middleware that logs every request.

```go
r.Use(authkit.RequestLogger())
```

`RoleSuperAdmin`, `RoleAdmin`, `RoleStaff`, `RoleMember`, `RoleViewer`: the
built-in role names.

```go
api.GET("/reports", kit.Auth(), kit.Role(authkit.RoleAdmin, authkit.RoleStaff), reports)
```

`Mailer`, `BrevoConfig`, `NewBrevoMailer`: send OTP and password reset e-mail.

```go
m, err := authkit.NewBrevoMailer(authkit.BrevoConfig{
	Host: "smtp-relay.brevo.com", User: "login", Pass: "key", From: "no-reply@example.com",
})
```

`AppConfigService`: read and update runtime app configuration.

```go
var appConfig authkit.AppConfigService = kit.AppConfig()
```

## Configuration

The nested config types (`OTPConfig`, `PasswordResetConfig`, `LoginLimit`,
`RateLimit`, `FlagKeys`) are exported by the root package. Printing a `Config` with `%v`, `%+v`
or `%#v` redacts `JWTKey`, `OTP.Secret` and `Reset.Secret`.

`authkit.Config` is explicit; `authkit.ConfigFromEnv()` fills it from environment
variables and is the only code in the module that reads the environment (plus
nothing else in the public API). `DB`, `Redis` and `Mailer` are
never read from the environment. Zero or negative numbers and durations mean
"use the default": a limiter can not be disabled by setting its variable to 0.
When both durations and seconds variables exist, the duration form wins.
A value that cannot be parsed falls back to its default and is reported by
`gokit.EnvErrors()`. Call it after `ConfigFromEnv` and refuse to start when it is non-nil.

| Config field | Env variable | Default | Required |
|---|---|---|---|
| `DB` | - | - | yes |
| `Redis` | - | nil | no |
| `Mailer` | - | nil | no |
| `AppName` | `APP_NAME` | - | yes |
| `AppEnv` | `APP_ENV` | empty | no |
| `JWTKey` | `JWT_KEY` | - | yes, at least 32 characters |
| `AccessTokenTTL` | `JWT_EXP` (hours) | 24h | no |
| `RefreshTokenTTL` | `REFRESH_TOKEN_EXP_HOURS` | 168h | no |
| `DefaultRole` | - | `viewer` | no (not `superadmin` or `admin`) |
| `GoogleClientIDs` | `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_IDS` (comma list) | none (Google login off) | no |
| `EmailAppName` | `AUTH_EMAIL_APP_NAME` | `AppName` | no |
| `PermissionCacheTTL` | `PERMISSION_CACHE_TTL`, `PERMISSION_CACHE_TTL_SECONDS` | 300s | no |
| `Login.Limit` | `LOGIN_ATTEMPT_LIMIT` | 5 | no |
| `Login.Window` | `LOGIN_ATTEMPT_WINDOW_SECONDS` | 60s | no |
| `Login.BlockDuration` | `LOGIN_BLOCK_DURATION_SECONDS` | 300s | no |
| `Register.Limit` | `REGISTER_RATE_LIMIT` | 5 | no |
| `Register.Window` | `REGISTER_RATE_WINDOW_SECONDS` | 60s | no |
| `OTP.Secret` | `OTP_SECRET` | none | yes when Redis and Mailer are set |
| `OTP.TTL` | `OTP_TTL`, `OTP_TTL_SECONDS` | 300s | no |
| `OTP.Cooldown` | `OTP_COOLDOWN`, `OTP_COOLDOWN_SECONDS` | 60s | no |
| `OTP.RateLimit` | `OTP_RATE_LIMIT` | 5 | no |
| `OTP.RateWindow` | `OTP_RATE_WINDOW`, `OTP_RATE_WINDOW_SECONDS` | `OTP.TTL` | no |
| `OTP.MaxAttempts` | `OTP_MAX_ATTEMPTS` | 5 | no |
| `Reset.Secret` | `RESET_SECRET` | none | yes when Redis and Mailer are set |
| `Reset.TTL` | `RESET_TTL`, `RESET_TTL_SECONDS` | 900s | no |
| `Reset.Cooldown` | `RESET_COOLDOWN`, `RESET_COOLDOWN_SECONDS` | 60s | no |
| `Reset.RateLimit` | `RESET_RATE_LIMIT` | 5 | no |
| `Reset.RateWindow` | `RESET_RATE_WINDOW`, `RESET_RATE_WINDOW_SECONDS` | `Reset.TTL` | no |
| `Reset.URLTemplate` | `RESET_URL_TEMPLATE`, else `RESET_URL` | empty | no |
| `Flags.PublicRegistration` | `CONFIG_PUBLIC_REGISTRATION` | `auth.public_registration_enabled` | no |
| `Flags.RegisterOTP` | `CONFIG_REGISTER_OTP` | `auth.register_otp_enabled` | no |
| `Flags.PasswordResetEmail` | `CONFIG_PASSWORD_RESET_EMAIL` | `auth.password_reset_email_enabled` | no |

The `Flags` values are keys of rows in `app_configs`, which admins change at
runtime through the `/config` routes. The Brevo mailer has its own variables
(`SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM`, `SMTP_SUBJECT`,
`RESET_SUBJECT`); read them yourself and pass an `authkit.BrevoConfig` to
`authkit.NewBrevoMailer` (the module no longer reads them for you), or implement the `authkit.Mailer` interface yourself. Custom mailers implement
both `SendOTP(to, code, appName string, ttl time.Duration) error` (`ttl` is the
configured `OTP.TTL`; state it in the message) and
`SendPasswordReset(to, token, appName, resetURL string, ttl time.Duration) error`.

### What needs Redis

Without Redis there is no login limiter, no session management (the session
routes are not mounted), registration rate limiting lets everything through,
and OTP and e-mail password reset are inactive. With Redis but no mailer, the
limiter and sessions work and OTP and reset e-mail stay inactive.

## Mounted routes

`kit.Mount(r)` registers these under `r` (for example `/api`).

| Method and path | Access |
|---|---|
| `GET /user/register/status` | public |
| `POST /user/register` | public, register rate limit |
| `POST /user/register/otp/send` | public, register rate limit |
| `POST /user/login` | public |
| `POST /user/google/login` | public |
| `POST /user/refresh-token` | public |
| `POST /user/forgot-password` | public |
| `POST /user/reset-password` | public |
| `POST /user/logout` | authenticated |
| `GET /user` | authenticated |
| `PUT /user` | authenticated |
| `PUT /user/change/password` | authenticated |
| `DELETE /user` | authenticated |
| `POST /user/stop-impersonation` | authenticated |
| `GET /user/:id` | `users:view` |
| `POST /user/:id/impersonate` | `users:impersonate` |
| `PUT /user/:id` | `users:update` |
| `DELETE /user/:id` | `users:delete` |
| `POST /user` | `users:create` |
| `GET /users` | `users:list` |
| `GET /user/sessions`, `DELETE /user/session/:session_id`, `POST /user/sessions/revoke-others` | authenticated; only with Redis |
| `GET /roles` | `roles:list` |
| `POST /role` | `roles:create` |
| `GET /role/:id` | `roles:view` |
| `PUT /role/:id` | `roles:update` |
| `DELETE /role/:id` | `roles:delete` |
| `POST /role/:id/permissions` | `roles:assign_permissions` |
| `GET /permissions` | `permissions:list` |
| `GET /permissions/me` | authenticated |
| `POST /permission` | `permissions:create` |
| `GET /permission/:id` | `permissions:view` |
| `PUT /permission/:id` | `permissions:update` |
| `DELETE /permission/:id` | `permissions:delete` |
| `GET /menus/active`, `GET /menus/me` | authenticated |
| `GET /menus` | `menus:list` |
| `GET /menu/:id` | `menus:view` |
| `PUT /menu/:id` | `menus:update` |
| `GET /configs` | `configs:list` |
| `GET /config/:id` | `configs:view` |
| `PUT /config/:id` | `configs:update` |
| `GET /audits` | `audits:list` |
| `GET /audit/:id` | `audits:view` |

Call `Mount` once per group; mounting twice makes gin panic on duplicate routes.

## Security notes and known limitations

- **Tokens are bound to `AppName`.** Access, refresh and reset tokens carry
  `AppName` as `iss` and `aud` and are rejected unless both match. Tokens issued
  before adopting authkit do not have them, so every user logs in again once
  after the upgrade. Give each application its own `AppName`, so a token from
  one application is not accepted by another that shares a `JWTKey`. Changing
  `AppName` later invalidates every issued token.
- **No built-in secrets.** `OTP.Secret` and `Reset.Secret` are required when
  both Redis and a mailer are configured, and `New` fails without them. The OTP
  and reset services also refuse to work with an empty secret. Generate long
  random values and keep them out of the repository.
- **`JWTKey`** must be at least 32 characters.
- **`DefaultRole`** is the role public registrations receive. It can not be
  `superadmin` or `admin`, and registration fails if the role does not exist in
  the database.
- **Rate limiting fails open** if Redis is unavailable, and proxy and CORS
  behaviour come from gokit; see its "Security defaults" section.

- **Development password-reset path.** When `AppEnv` is `development`, `local`
  or `test` and the `auth.password_reset_email_enabled` flag is off,
  `POST /user/forgot-password` returns a valid reset token in the response for
  any registered email. Never set those values on a reachable deployment.
- **Logout and sessions.** Logout blacklists only the presented access token.
  Without Redis sessions the refresh token stays valid until it expires.
  Password reset revokes only Redis sessions.
- **Access token claims are trusted until expiry.** The `role` claim (including
  the superadmin bypass) is trusted until the token expires; role changes and
  account deletion do not revoke issued tokens. The default access token
  lifetime is 24h, so set a short `AccessTokenTTL`. `expires_in_hours` in
  responses is whole hours and reports 0 for lifetimes under an hour.
- **Permission cache.** Permission checks for non-superadmin roles are cached in
  Redis for `PermissionCacheTTL` (default 300s). Changes made outside the API
  (direct SQL, seeds) can be stale for up to that long.
- **Redis keys are not namespaced per application.** Use a separate Redis
  database (or ACL key prefix) per application. Sharing one Redis DB shares the
  login and register limiter counters and the OTP and reset throttling state,
  and one application's permission-cache invalidation evicts the others'.
- **Rate limiting.** Limiters key on the client IP as gin reports it (see
  `SetTrustedProxies` in the quick start). Without Redis there is no login or
  register limiting.
- **Runtime flags.** Public registration is ON by default (the baseline seeds
  `auth.public_registration_enabled = true`). Email password reset is OFF until
  `auth.password_reset_email_enabled` is true AND Redis, a mailer and
  `Reset.Secret` are configured; with the flag off and a non-development
  `AppEnv`, `POST /user/forgot-password` responds 503.
- **Startup warnings.** `New` logs one warning when `AppEnv` is a development
  value and one when `Redis` is nil.
- **Deferred to a later release.** Live account and session checks on every
  request; refresh-token revocation on logout and credential change;
  exact-algorithm and required-expiry JWT validation; per-account login
  limiting; hashing of stored tokens.

## Migrations

`kit.Migrate(ctx)` applies the embedded migrations (`internal/migrations/`, nine tables:
`users`, `blacklist`, `roles`, `permissions`, `menu_items`, `role_permissions`,
`role_menus`, `audit_trails`, `app_configs`, plus the seed rows for the system
roles, menus and permissions). It keeps its own version table,
`authkit_schema_migrations`, in the connection's current schema, so it never
collides with your project's `schema_migrations`. It is idempotent and safe to
call on every start. Instances that start at the same time serialize on the
migration library's advisory lock: one applies the migrations and the others
wait, then find nothing to do, and all return nil (covered by
`TestMigrateConcurrentFirstStart`).

What it does depends on the database:

| Database | Behavior |
|---|---|
| Empty (no `users` table, no version record) | Applies all migrations; version table ends at 4. |
| Existing, from before authkit (has `users`, no version record), schema complete | Records version 4 **without running the baseline SQL**, then applies any later authkit migration. |
| Existing, schema incomplete | Returns an error wrapping `ErrLegacySchemaIncomplete` that lists the missing `table` or `table.column`. Nothing is changed and no version table is created. |
| Has a version record | Applies pending migrations. A dirty record, reported once the lock is held, returns `ErrMigrationsDirty` naming the table; authkit never repairs it. |

The baseline is not replayed on existing databases because its seed is not
idempotent: it computes role grants from whatever is in `permissions` when it
runs. Replaying it would give `staff` and `viewer` newly added permissions,
restore permissions an admin revoked, and bring back deleted roles and menus.
Existing and "complete" is judged against the schema the connection actually
uses (`current_schema()`), by comparing the expected columns, not by trusting
that a `users` table exists. An empty version table next to existing data (an
interrupted stamp) is treated like a missing one.

Run `Migrate` before your own migrations. `Migrate` runs on its own connection
from your pool and leaves your `*sql.DB` open.

- **Use a direct database connection.** The advisory lock is session-level, which
  does not work through transaction-pooling proxies such as pgbouncer in
  transaction mode.
- **`ctx` does not bound the lock wait.** It bounds the schema inspection and the
  connection checkout; waiting for another instance's lock, and a migration that
  has started, are not cancelled by it.
- **The legacy check compares table and column names only**, not types, indexes
  or constraints. Table presence is read from the PostgreSQL catalog, so it does
  not depend on the role's privileges.
- **PostgreSQL 13 or newer** is required (the baseline uses `gen_random_uuid()`).
- **Adopting projects must delete their own copies of the baseline migrations**
  (users, RBAC, audit trails, app configs). Re-running those files replays the
  seed data. Keep only your own migrations in your directory.
- **Dirty record.** If `ErrMigrationsDirty` is returned, repair the database by
  hand, then set the record in `authkit_schema_migrations` to the last fully
  applied version and clear the dirty flag. Never delete the record: a missing
  record next to existing tables makes the database look unmigrated to authkit.

## Extending

- **Default role.** Set `Config.DefaultRole` to a role that exists in `roles`
  (the seed provides `viewer` and `staff`).
- **Per-user data.** `users.metadata` is a `jsonb` column for small extras. For
  anything structured, add your own profile table with a foreign key to
  `users(id)` in your own migrations, which run after `Migrate`.
- **New modules.** `go run github.com/zazhedho/authkit/cmd/module-seed -name
  trips -display-name Trips -path /trips` prints SQL that inserts the menu,
  permissions and role grants for a module (`-actions`, `-grant-roles`,
  `-icon`, `-order-index` and `-parent-name` adjust it). Put the output in your own
  migration.
- **Without `Mount`.** The handlers, services and repositories are internal
  and not importable. Use `Mount` for the route set and `Auth`, `Can`,
  `LoadPermissions` and `Role` for your own routes; mount it on a group (for example `/api`) to place
  it in your path layout.

## Development

```
go build ./... && go vet ./... && go test -race -count=1 ./...
```

The module layout is the root package (`authkit.go`, `config.go`, `mount.go`,
`migrate.go`, `types.go`), `cmd/module-seed`, and everything else under
`internal/`.

Integration tests for `Migrate` need a disposable PostgreSQL and are skipped
without `AUTHKIT_TEST_DATABASE_URL`, for example
`postgres://postgres:test@127.0.0.1:55432/postgres?sslmode=disable`. Each test
creates and drops its own schema.

## Internal layout

For contributors. Callers use only the root package; the code below it is
organised by layer, and tests enforce the layering.

```text
internal/
  architecture/                 guard tests
  config/                       plain settings values
  domain/<module>/              entities, domain errors
  dto/<module>/                 request and response shapes
  services/<module>/            business logic, ports.go
  services/shared/              helpers shared by services
  repositories/<module>/        database access
  handlers/http/<module>/       gin handlers, ports.go
  handlers/http/middleware/     Auth, Can, LoadPermissions, Role, RequestLogger
  handlers/http/shared/         audit writer and request helpers
  infrastructure/               cache/permission, mailer, ratelimit, token
  migrations/  moduleseed/      embedded SQL, `cmd/module-seed` logic
  testutil/                     test helpers
```

**Dependency rule.** Everything depends inward on `domain` and `dto`; the
middle layers never import each other. A consumer declares the interface it
needs (`ports.go`) and the root package wires the concrete types. Services use
only the standard library, `domain`, `dto`, `services/shared`, logus, uuid,
`golang.org/x/crypto` and `golang.org/x/text`. Handlers and the middleware do
not import services, repositories, infrastructure or `config`.
Infrastructure imports no `domain`, except `infrastructure/cache/<module>`.
Modules do not import each other, apart from the shared `domain` and `dto`
model.

**What `internal/architecture` enforces.** The import rule per layer, the list
of known layers, the reserved `shared` directories, no module-to-module
imports, the import alias convention (`domainuser`, `servicerole`,
`repositoryshared`, `httpshared`, ...), package name equal to directory name,
constructors returning concrete types, interfaces declared by their consumer
without an `Interface` suffix, no `log.Fatal` or `os.Exit` outside `cmd/`, no
package-level database or Redis clients, no `internal/` import of the root
package, and `cmd/` importing only `internal/moduleseed`. Each guard has a
test that proves it fires.

**Public API snapshot.** `TestPublicAPI` compares the exported root API with
`testdata/public_api.golden`. After an intended addition, regenerate it with

```
go test -run TestPublicAPI -update .
```

A change to the golden file is a change to the public API: review it as one.

## Upgrading from v0.1.x

v0.2.0 is a breaking release: every sub-package became `internal/`, and the
public API is the root package only. Change imports to
`github.com/zazhedho/authkit` and rename:

| v0.1.x import path and name | v0.2.0 |
|---|---|
| `authscope.Scope` | `authkit.Scope` |
| `authscope.New(...)` | `authkit.NewScope(...)` |
| `authscope.WithContext(ctx, scope)` | `authkit.WithScope(ctx, scope)` |
| `authscope.FromContext(ctx)` | `authkit.ScopeFrom(ctx)` |
| `domain/audit` `AuditEvent` | `authkit.AuditEvent` |
| `domain/audit` `ActionCreate`, `ActionUpdate`, `ActionDelete`, `ActionAssign`, `ActionLogin`, `ActionLogout`, `ActionRefresh` | `authkit.Action*` |
| `domain/audit` `StatusSuccess`, `StatusFailed` | `authkit.Status*` |
| `interfaces/audit` `ServiceAuditInterface` | `authkit.AuditService` |
| `interfaces/appconfig` `ServiceAppConfigInterface` | `authkit.AppConfigService` |
| `handlers/auditwriter` `AuditWriter`, `NewAuditWriter` | `authkit.AuditWriter`, `authkit.NewAuditWriter` |
| `middlewares.RequestLogger` | `authkit.RequestLogger` |
| `authutil.RoleSuperAdmin`, `RoleAdmin`, `RoleStaff`, `RoleMember`, `RoleViewer` | `authkit.Role*` |
| `mailer.BrevoConfig` | `authkit.BrevoConfig` |
| `mailer.NewBrevoSender` | `authkit.NewBrevoMailer` (returns `authkit.Mailer`) |
| `mailer.NewBrevoSenderFromEnv` | removed; read the `SMTP_*` variables yourself and call `authkit.NewBrevoMailer` |
| `settings.OTPConfig`, `PasswordResetConfig`, `LoginLimit`, `RateLimit`, `FlagKeys` | `authkit.OTPConfig`, `PasswordResetConfig`, `LoginLimit`, `RateLimit`, `FlagKeys` |
| `Kit.Users()` | removed |
| `Kit.Tokens()` | removed; use `Kit.IssueAccessToken(userID, name, role)` to get an access token for tests and tooling |
| `moduleseed` | internal; use `go run github.com/zazhedho/authkit/cmd/module-seed` |

Everything else (`domain`, `dto`, `handlers`, `interfaces`, `repositories`,
`services`, `security`, `cache`, `authutil`, `configvalue`, `middlewares`) is
internal and no longer importable. Behavior, routes, permissions, JSON,
migrations, configuration defaults and environment variable names are
unchanged. The module now requires `github.com/zazhedho/gokit` v0.2.0 (one
package) and `github.com/zazhedho/logus` v0.1.1.
