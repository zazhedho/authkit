# authkit

Users, JWT authentication, sessions, RBAC, menus, audit trails and runtime app configuration for gin + GORM/Postgres services, as one importable Go module.

## Features

- Registration and login with email or phone and password, plus Google sign-in.
- HS256 JWT access and refresh tokens with rotation, logout and a token blacklist.
- Optional registration OTP and password reset by e-mail (Redis and SMTP).
- Login and register rate limiting, and Redis-backed session management.
- Roles, permissions and menus, with middleware to protect your own routes.
- User impersonation for support staff, with the original identity audited.
- Audit trail for every change, and an `AuditWriter` for your own handlers.
- Runtime feature flags stored in the database (`app_configs`).
- Embedded SQL migrations with their own version table, and a SQL generator for new modules.
- A ready-made HTTP route set, mounted on any gin router group.

## Install

```sh
go get github.com/zazhedho/authkit
```

Requires Go 1.27 (the `go` line of `go.mod`).

| Dependency | Needed for |
|---|---|
| PostgreSQL 13 or newer (required) | all data; migrations use `gen_random_uuid()` |
| Redis (`*redis.Client`, optional) | login limiter, register limiter, sessions, permission cache, OTP, e-mail password reset |
| SMTP (optional) | OTP and password reset e-mail; with Redis only, those two stay inactive |

Without Redis the module still works, but there is no login or register rate limiting, no session routes, and no OTP or e-mail password reset. `New` logs a warning in that case.

## Quick start

A complete service with Postgres only. Set `APP_NAME`, `JWT_KEY` (at least 32 characters) and `DATABASE_URL`, and optionally `APP_ENV`.

```go
package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/zazhedho/authkit"
	"github.com/zazhedho/gokit"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func main() {
	cfg := authkit.ConfigFromEnv()
	// ConfigFromEnv reads through gokit and falls back to defaults on values it
	// cannot parse; EnvErrors reports them so a typo does not go unnoticed.
	if err := gokit.EnvErrors(); err != nil {
		log.Fatal(err)
	}

	db, err := gorm.Open(postgres.Open(os.Getenv("DATABASE_URL")), &gorm.Config{})
	if err != nil {
		log.Fatal(err)
	}
	cfg.DB = db

	kit, err := authkit.New(cfg) // validates the config; never touches the database
	if err != nil {
		log.Fatal(err)
	}
	if err := kit.Migrate(context.Background()); err != nil { // before your own migrations
		log.Fatal(err)
	}

	r := gin.New()
	r.Use(gin.Recovery(), authkit.RequestLogger())
	// The limiters and audit trail use the client IP; see Security notes.
	if err := r.SetTrustedProxies(nil); err != nil {
		log.Fatal(err)
	}

	api := r.Group("/api")
	kit.Mount(api) // /api/user/login, /api/roles, ...

	// Your own routes: any signed-in user, then one that holds trips:list.
	api.GET("/me", kit.Auth(), func(c *gin.Context) {
		scope := authkit.ScopeFrom(c.Request.Context())
		c.JSON(http.StatusOK, gin.H{"id": scope.UserID, "role": scope.Role})
	})
	api.GET("/trips", kit.Auth(), kit.Can("trips", "list"), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"trips": []string{}})
	})

	log.Fatal(r.Run(":8080"))
}
```

Order matters: `New`, then `Migrate`, then your own migrations (they may reference `users` and `roles`), then `Mount`. Call `Mount` once per group; mounting twice makes gin panic on duplicate routes.

No user is seeded. Register one, then promote it:

```sql
UPDATE users
SET role = 'superadmin', role_id = (SELECT id FROM roles WHERE name = 'superadmin')
WHERE email = 'you@example.com';
```

The superadmin passes every `Can` and `Role` check, so `/api/trips` works for it even before a `trips` permission exists; see [Migrations](#migrations-and-module-seed) to add one.

Add Redis and a mailer to the `Config` before `New`:

```go
package main

import (
	"github.com/redis/go-redis/v9"
	"github.com/zazhedho/authkit"
)

func withRedisAndMailer(cfg authkit.Config) (authkit.Config, error) {
	cfg.Redis = redis.NewClient(&redis.Options{Addr: "localhost:6379"})

	mailer, err := authkit.NewBrevoMailer(authkit.BrevoConfig{
		Host: "smtp-relay.brevo.com", // Host, Pass and From are required
		Port: 587,                    // default 587
		User: "login",                // default "apikey"
		Pass: "smtp-key",
		From: "no-reply@example.com",
	})
	if err != nil {
		return cfg, err
	}
	cfg.Mailer = mailer

	// Required once both Redis and a Mailer are set. Long random values.
	cfg.OTP.Secret = "..."
	cfg.Reset.Secret = "..."
	return cfg, nil
}

func main() {}
```

## Usage

### Authentication flows

Send the access token as `Authorization: Bearer <token>`. Token responses carry `access_token`, `token_type`, `expires_in_hours` and, where a refresh token is issued, `refresh_token` and `refresh_expires_in_hours`.

- **Register.** `POST /user/register` with `name`, `email`, `phone`, `password` (8 to 64 characters with a lowercase letter, an uppercase letter, a digit and a symbol) and `otp_code`. The user gets `Config.DefaultRole`. It is allowed while the `auth.public_registration_enabled` flag is on (the default); otherwise it answers 403. `GET /user/register/status` reports `enabled`, `otp_enabled` and `otp_cooldown`.
- **Registration OTP.** When the `auth.register_otp_enabled` flag is on, call `POST /user/register/otp/send` with `email` first; the 6 digit code is then required as `otp_code` on register. Needs Redis, a mailer and `OTP.Secret`; otherwise those routes answer 503.
- **Login.** `POST /user/login` with `identifier` (e-mail or phone, or the older `email` field) and `password`. Failures are counted per client IP and identifier; after `Login.Limit` failures within `Login.Window` the pair is blocked for `Login.BlockDuration` and gets 429 with `Retry-After`. Needs Redis.
- **Google.** `POST /user/google/login` with `id_token`. Requires `GoogleClientIDs`, otherwise 503. A first-time Google user is registered only while public registration is on.
- **Refresh.** `POST /user/refresh-token` with `refresh_token` issues a new pair and blacklists the old refresh token. With Redis the token must belong to a live session.
- **Logout.** `POST /user/logout` blacklists the presented access token and destroys its session.
- **Passwords.** `PUT /user/change/password` takes `current_password` and `new_password`. With the `auth.password_reset_email_enabled` flag on, `POST /user/forgot-password` with `email` mails a reset token (Redis, a mailer and `Reset.Secret` required) and always answers success, so it does not reveal which e-mails exist. `POST /user/reset-password` takes `token` and `new_password` and ends all of the user's sessions. If `Reset.URLTemplate` is set, the mail links to it: `{token}` is replaced, otherwise `?token=` (or `&token=`) is appended.
- **Sessions** (Redis only). `GET /user/sessions` lists the caller's sessions, `DELETE /user/session/:session_id` revokes one, `POST /user/sessions/revoke-others` revokes all but the current one.
- **Admin-created users.** `POST /user` (`users:create`) takes a `role`; assigning one needs `users:assign_role`.

### Protecting routes

```go
package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/zazhedho/authkit"
)

func registerRoutes(api gin.IRouter, kit *authkit.Kit) {
	// Any signed-in user.
	api.GET("/trips/mine", kit.Auth(), listMine)

	// Signed in and holding the trips:create permission.
	api.POST("/trips", kit.Auth(), kit.Can("trips", "create"), createTrip)

	// Signed in and one of these roles.
	api.GET("/reports", kit.Auth(), kit.Role(authkit.RoleAdmin, authkit.RoleStaff), reports)

	// Permissions loaded but none required: the handler decides.
	api.GET("/trips", kit.Auth(), kit.LoadPermissions(), listTrips)
}

// listTrips shows the caller's trips, or everyone's with trips:list_any.
func listTrips(c *gin.Context) {
	scope := authkit.ScopeFrom(c.Request.Context())
	if scope.Has("trips", "list_any") {
		c.JSON(http.StatusOK, gin.H{"scope": "all"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"scope": "own", "user_id": scope.UserID})
}

func listMine(c *gin.Context)   { c.Status(http.StatusNoContent) }
func createTrip(c *gin.Context) { c.Status(http.StatusCreated) }
func reports(c *gin.Context)    { c.Status(http.StatusNoContent) }

func main() {}
```

- `Can`, `LoadPermissions` and `Role` must come after `Auth`.
- `Auth` verifies the token and checks it against the blacklist. After `Auth` alone, `ScopeFrom(ctx)` carries `UserID`, `Username`, `Role` and the impersonation fields, but an empty permission set, so `Has` is false for everyone except superadmin.
- `Can(resource, action)` loads the permissions and answers 403 without the permission. `LoadPermissions` loads them and never rejects for a missing permission, for handlers that branch on `Has` (own data versus a `<action>_any` permission).
- The superadmin role bypasses `Can` and `Role`, and `Has` is always true for it.
- Permissions are plain rows of (`resource`, `action`). `kit.Can("trips", "create")` checks `trips:create`. Add your own with `cmd/module-seed`.
- Permission checks for non-superadmin users are cached in Redis for `PermissionCacheTTL`. Grants changed through the API invalidate the cache; changes made directly in SQL can be stale for up to that long.
- `Scope`, `NewScope` and `WithScope` build a scope by hand, for tests: `authkit.WithScope(ctx, authkit.NewScope("u1", "Ada", authkit.RoleStaff, []string{"trips:view"}))`.
- `kit.IssueAccessToken(userID, name, role)` signs an access token that passes `Auth`, without checking the user exists. It is meant for tests and tooling.
- Roles: `RoleSuperAdmin`, `RoleAdmin`, `RoleStaff` and `RoleViewer` exist after `Migrate`. `RoleMember` is only a name; create that role before using it.

### Impersonation

`POST /user/:id/impersonate` (`users:impersonate`) returns an access token for the target user; no refresh token or session is created. The token records the original identity, so `Scope.IsImpersonated`, `OriginalUserID`, `OriginalUsername` and `OriginalRole` are set, and `ActorUserID()` and `ActorRole()` return the original actor. `POST /user/stop-impersonation` blacklists that token and returns one for the original user. Nested impersonation, impersonating yourself and impersonating a superadmin as a non-superadmin are refused. The audit trail records the actor and the impersonation metadata.

### Audit

Every route in the set writes audit entries. For your own handlers, build an `AuditWriter` from `kit.Audit()`; it fills the actor, request id, client IP and user agent from the request.

```go
package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/zazhedho/authkit"
)

func newTripHandler(kit *authkit.Kit) gin.HandlerFunc {
	audit := authkit.NewAuditWriter(kit.Audit(), "TripHandler")

	return func(c *gin.Context) {
		// ... create the trip ...
		audit.WriteAudit(c, authkit.AuditEvent{
			Action:     authkit.ActionCreate,
			Resource:   "trips",
			ResourceID: "trip-1",
			Status:     authkit.StatusSuccess,
			Message:    "Created trip",
			AfterData:  map[string]any{"name": "Bali"},
		})
		c.Status(http.StatusCreated)
	}
}

func main() {}
```

Actions are `ActionCreate`, `ActionUpdate`, `ActionDelete`, `ActionAssign`, `ActionLogin`, `ActionLogout` and `ActionRefresh`; statuses are `StatusSuccess` and `StatusFailed`. A failed store is logged and never fails the request. Entries are read through `GET /audits` and `GET /audit/:id`, or `kit.Audit()` directly.

### App config flags

`app_configs` holds runtime settings that admins change through `GET /configs`, `GET /config/:id` and `PUT /config/:id` (`value`, `is_active`). Three rows are seeded and drive the auth flows:

| Config key (default) | Seeded value | Effect |
|---|---|---|
| `auth.public_registration_enabled` | `true` | Public registration and first-time Google sign-up |
| `auth.register_otp_enabled` | `false` | Require an e-mailed OTP to register |
| `auth.password_reset_email_enabled` | `false` | Password reset by e-mail |

The key names are configurable through `Config.Flags` (`PublicRegistration`, `RegisterOTP`, `PasswordResetEmail`). A row with `is_active = false`, or a missing row, falls back to the code default shown by the seeded value. Read your own settings from `kit.AppConfig()`:

```go
package main

import (
	"context"
	"time"

	"github.com/zazhedho/authkit"
)

func checkFlags(ctx context.Context, kit *authkit.Kit) error {
	cfg := kit.AppConfig()

	beta, err := cfg.IsEnabled(ctx, "trips.beta_enabled", false)
	if err != nil {
		return err
	}
	_ = beta

	limit, err := cfg.GetInt(ctx, "trips.max_per_user", 10)
	if err != nil {
		return err
	}
	_ = limit

	_, err = cfg.GetDuration(ctx, "trips.hold_time", 15*time.Minute)
	return err
}

func main() {}
```

`AppConfigService` also has `GetString`, `GetBool`, `DecodeJSON`, `GetByKey`, `GetByID`, `GetAll` and `Update`. Add your own rows with a migration.

### Mailer

`Config.Mailer` is the `authkit.Mailer` interface. `NewBrevoMailer` returns a Brevo SMTP implementation (`BrevoConfig`: `Host`, `Port`, `User`, `Pass`, `From` and optional `OTPSubject`, `ResetSubject`, `AppName`). To send through another provider, implement the interface:

```go
package main

import (
	"time"

	"github.com/zazhedho/authkit"
)

type logMailer struct{}

// ttl is the configured OTP.TTL; state it in the message.
func (logMailer) SendOTP(to, code, appName string, ttl time.Duration) error { return nil }

// resetURL is Reset.URLTemplate with the token filled in, or empty.
func (logMailer) SendPasswordReset(to, token, appName, resetURL string, ttl time.Duration) error {
	return nil
}

var _ authkit.Mailer = logMailer{}

func main() {}
```

### Migrations and module-seed

`kit.Migrate(ctx)` applies the embedded migrations: the tables `users`, `blacklist`, `roles`, `permissions`, `menu_items`, `role_permissions`, `role_menus`, `audit_trails` and `app_configs`, plus seed rows for the system roles, menus, permissions and the three flags. It keeps its own version table, `authkit_schema_migrations` (the constant `authkit.MigrationsTable`), in the connection's current schema, so it never collides with your own `schema_migrations`. It is idempotent and safe on every start; instances starting together serialize on an advisory lock.

| Database state | Behavior |
|---|---|
| Empty (no `users` table, no version record) | Applies all migrations; the version table ends at 4 (`authkit.BaselineVersion`). |
| `users` exists, no version record, schema complete | Records version 4 without running the baseline SQL, then applies later migrations. |
| `users` exists, no version record, schema incomplete | Returns an error wrapping `authkit.ErrLegacySchemaIncomplete` listing the missing `table` or `table.column`. Nothing changes. |
| Has a version record | Applies pending migrations. A dirty record returns `authkit.ErrMigrationsDirty`. |

The baseline seed is not idempotent (it computes role grants from `permissions` as they are), so it is never replayed on an existing database. "Complete" compares expected table and column names (not types or indexes) against `current_schema()`.

```go
package main

import (
	"context"
	"errors"
	"log"

	"github.com/zazhedho/authkit"
)

func migrate(ctx context.Context, kit *authkit.Kit) {
	err := kit.Migrate(ctx)
	switch {
	case errors.Is(err, authkit.ErrLegacySchemaIncomplete):
		log.Fatalf("existing schema lacks authkit tables or columns: %v", err)
	case errors.Is(err, authkit.ErrMigrationsDirty):
		log.Fatalf("repair authkit_schema_migrations by hand: %v", err)
	case err != nil:
		log.Fatal(err)
	}
}

func main() {}
```

- Use a direct database connection. The advisory lock is session-level and does not work through transaction-pooling proxies such as pgbouncer in transaction mode.
- `ctx` bounds schema inspection and the connection checkout, not the wait for another instance's lock or a running migration.
- If `ErrMigrationsDirty` is returned, repair the database by hand, set the record in `authkit_schema_migrations` to the last fully applied version and clear the dirty flag. Never delete the record: a missing record next to existing tables looks like a pre-authkit database.
- Keep your own tables in your own migrations, run after `Migrate`. Per-user extras fit in the `users.metadata` jsonb column; anything structured belongs in your own table with a foreign key to `users(id)`.

**New modules.** `cmd/module-seed` prints SQL that inserts a menu, its permissions and the role grants for a module. Put the output in your own migration.

```sh
go run github.com/zazhedho/authkit/cmd/module-seed \
  -name trips -display-name Trips -path /trips
```

| Flag | Default | Meaning |
|---|---|---|
| `-name` | required | Menu and module name |
| `-display-name` | required | Menu display name |
| `-path` | required | Frontend path |
| `-resource` | `-name` | Permission resource |
| `-actions` | `list,view,create,update,delete` | Comma-separated actions |
| `-grant-roles` | `admin,superadmin` | Roles that receive the permissions; empty skips grants |
| `-icon` | `bi-folder` | Bootstrap icon name |
| `-order-index` | `900` | Menu order |
| `-parent-name` | empty | Parent menu |

### Routes

`kit.Mount(r)` registers these under `r`. The permission is `resource:action`; "signed in" means `Auth` only.

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
| `POST /user/logout` | signed in |
| `GET /user` | signed in |
| `PUT /user` | signed in |
| `PUT /user/change/password` | signed in |
| `DELETE /user` | signed in |
| `POST /user/stop-impersonation` | signed in |
| `GET /user/:id` | `users:view` |
| `POST /user/:id/impersonate` | `users:impersonate` |
| `PUT /user/:id` | `users:update` |
| `DELETE /user/:id` | `users:delete` |
| `POST /user` | `users:create` |
| `GET /users` | `users:list` |
| `GET /user/sessions` | signed in, Redis only |
| `DELETE /user/session/:session_id` | signed in, Redis only |
| `POST /user/sessions/revoke-others` | signed in, Redis only |
| `GET /roles` | `roles:list` |
| `POST /role` | `roles:create` |
| `GET /role/:id` | `roles:view` |
| `PUT /role/:id` | `roles:update` |
| `DELETE /role/:id` | `roles:delete` |
| `POST /role/:id/permissions` | `roles:assign_permissions` |
| `GET /permissions` | `permissions:list` |
| `GET /permissions/me` | signed in |
| `POST /permission` | `permissions:create` |
| `GET /permission/:id` | `permissions:view` |
| `PUT /permission/:id` | `permissions:update` |
| `DELETE /permission/:id` | `permissions:delete` |
| `GET /menus/active` | signed in |
| `GET /menus/me` | signed in |
| `GET /menus` | `menus:list` |
| `GET /menu/:id` | `menus:view` |
| `PUT /menu/:id` | `menus:update` |
| `GET /configs` | `configs:list` |
| `GET /config/:id` | `configs:view` |
| `PUT /config/:id` | `configs:update` |
| `GET /audits` | `audits:list` |
| `GET /audit/:id` | `audits:view` |

List endpoints take `page`, `limit`, `search`, `order_by`, `order_direction` and `filters[<key>]`.

## Configuration

`authkit.Config` is explicit. `authkit.ConfigFromEnv()` fills it from the environment and is the only code in the module that reads it. `DB`, `Redis` and `Mailer` are never read from the environment.

- Zero or negative numbers and durations mean "use the default", so a limiter cannot be disabled by setting its variable to 0.
- Variables ending in `_SECONDS` are whole seconds. The duration-form variables (`OTP_TTL`, ...) accept `30s`, `5m`, `1h` or bare seconds, and win over their `_SECONDS` form when positive.
- A value that cannot be parsed falls back to its default and is reported by `gokit.EnvErrors()`. Call it after `ConfigFromEnv` and refuse to start when it is non-nil.
- Printing a `Config` with `%v`, `%+v` or `%#v` reports `JWTKey`, `OTP.Secret` and `Reset.Secret` only as set or unset.
- `Config.Validate()` runs inside `New`.

| Config field | Env variable | Default | Required |
|---|---|---|---|
| `DB` | none | none | yes |
| `Redis` | none | nil | no |
| `Mailer` | none | nil | no |
| `AppName` | `APP_NAME` | none | yes |
| `AppEnv` | `APP_ENV` | empty | no |
| `JWTKey` | `JWT_KEY` | none | yes, at least 32 characters |
| `AccessTokenTTL` | `JWT_EXP` (hours) | 24h | no |
| `RefreshTokenTTL` | `REFRESH_TOKEN_EXP_HOURS` | 168h | no |
| `DefaultRole` | none | `viewer` | no (not `superadmin` or `admin`) |
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

`Flags.*` are keys of rows in `app_configs`, not on/off values. Log output goes through `github.com/zazhedho/logus`: set the threshold (default info) with the `LOG_LEVEL` environment variable or `logus.SetLevel` before the first log line. Debug level logs request and response payloads, so keep it off in production.

## Security notes

Read these before exposing the routes.

- **Trusted proxies and client IP.** The login limiter (keyed by client IP plus identifier), the register limiter (keyed by client IP), the audit trail's `ip_address` and the request log all use gin's `c.ClientIP()`. gin trusts every proxy by default and then believes `X-Forwarded-For` and `X-Real-IP`, so any client can pick its own IP: it dodges both limiters and forges audit IPs. Call `engine.SetTrustedProxies(nil)` when clients connect directly, or pass the CIDRs of your reverse proxies.
- **Rate limiting fails open.** If Redis is unreachable, the register limiter lets the request through and the login limiter treats the caller as not blocked and does not count failures; both only log. Without Redis there is no login or register limiting at all. Password reset and OTP requests return an error response instead of skipping their throttling. Permission-cache errors fall back to the database.
- **`limit=-1` and page size.** Every list caps the page size at 100. Only the small reference lists a UI loads whole, `GET /roles`, `/permissions` and `/menus`, accept `limit=-1`, which returns every matching row. On `/users`, `/configs` and `/audits`, `-1` and any limit above 100 are clamped to 100, and the response `limit` field reports the page size actually applied. The routes still need their `:list` permission.
- **CORS.** authkit sets no CORS headers. Configure CORS in your application and allow only your own origins. If you use gokit's `gokit.CORS()` helper, note that it answers `Access-Control-Allow-Origin: *` and allows only `GET, POST, PUT, DELETE`.
- **Token revocation.** Revocation is a blacklist in the `blacklist` table, checked on every `Auth`. Logout blacklists only the presented access token, and refresh blacklists the old refresh token. Not revoked: tokens of a user whose password changed (password reset ends Redis sessions, a password change does not), whose role changed, who was deleted, or whose session was revoked through the session routes; they work until they expire. `Auth` does not look the user up, and the permission lookup used by `Can` does not exclude soft-deleted users. Without Redis sessions, a refresh token stays valid after logout until it expires. Refresh fails for a deleted user. The `role` claim, including the superadmin bypass, is trusted until expiry, so keep `AccessTokenTTL` short (the default is 24h). `expires_in_hours` is in whole hours and reads 0 below one hour.
- **JWT key.** Tokens are HS256. `JWTKey` must be at least 32 characters (checked after trimming whitespace); use 32 or more random bytes, not a phrase, and keep it out of the repository. Tokens carry `AppName` as `iss` and `aud` and are rejected unless both match, so give each application its own `AppName`: a token from one application is then not accepted by another that shares a key. Changing `AppName` or `JWTKey` invalidates every issued token.
- **OTP and reset secrets.** Registration OTPs (6 digits) and reset tokens are stored in Redis only as `sha256(value + secret)`, so `OTP.Secret` and `Reset.Secret` are what keep a leaked Redis from being brute-forced; a 6 digit code is trivial to recover without the secret. They are required when both Redis and a mailer are set (`New` fails without them), and the services refuse to work with an empty one. Use long random values, distinct from `JWTKey`, outside the repository. Changing one invalidates pending codes or tokens. Wrong OTP guesses are capped by `OTP.MaxAttempts`.
- **Development password reset.** When `AppEnv` is `development`, `local` or `test` and `auth.password_reset_email_enabled` is off, `POST /user/forgot-password` returns a valid reset token in the response for any registered e-mail. Never use those values on a reachable deployment. With a production `AppEnv` and the flag off the route answers 503, and with the flag on but Redis, a mailer or `Reset.Secret` missing it answers 503 too. `New` logs a warning for a development `AppEnv`.
- **`DefaultRole`.** It is what public registrations receive. It cannot be `superadmin` or `admin`, and registration fails if the role does not exist.
- **Redis keys are not namespaced.** Use a separate Redis database, or an ACL key prefix, per application. Sharing one shares the limiter counters and the OTP and reset throttling, and one application's permission-cache invalidation evicts the others'.
- **Stored tokens.** Blacklisted tokens and Redis session tokens are stored as issued, not hashed. Treat database and Redis access as access to live tokens.

## Versioning

authkit follows semantic versioning but is pre-1.0: a minor bump (`v0.x`) may break the API, and a patch release never will. The public API is the exported surface of the root package, pinned by `TestPublicAPI` against `testdata/public_api.golden`. Everything under `internal/` is not importable.

## Development

```sh
make test   # go test -race ./...
make lint   # golangci-lint v2.14.0; run `make lint-install` first
```

`Migrate` integration tests need a disposable PostgreSQL and are skipped unless `AUTHKIT_TEST_DATABASE_URL` is set, for example `postgres://postgres:test@127.0.0.1:55432/postgres?sslmode=disable`. Each test creates and drops its own schema.

### Internal layout

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

Everything depends inward on `domain` and `dto`; the middle layers never import each other. A consumer declares the interface it needs in `ports.go` and the root package wires the concrete types. Modules do not import each other apart from the shared `domain` and `dto` model.

`internal/architecture` guard tests enforce the import rule per layer, the list of known layers, the reserved `shared` directories, no module-to-module imports, the import alias convention (`domainuser`, `servicerole`, `repositoryshared`, `httpshared`, ...), package name equal to directory name, constructors returning concrete types, interfaces declared by their consumer without an `Interface` suffix, no `log.Fatal` or `os.Exit` outside `cmd/`, no package-level database or Redis clients, no `internal/` import of the root package, and `cmd/` importing only `internal/moduleseed`. Each guard has a test that proves it fires.

### Public API golden file

After an intended change to the exported API, regenerate the snapshot and review the diff as an API change:

```sh
go test -run TestPublicAPI -update .
```

## License

MIT. See [LICENSE](LICENSE).
