# authkit

Users, authentication and RBAC for Go services built on gin and gorm, extracted
from an existing project into a module you import. It provides registration and
login (password and Google), JWT access and refresh tokens, optional registration
OTP and password reset e-mail, roles, permissions, menus, runtime app
configuration, audit trails, an HTTP route set, and the middleware to protect
your own routes. Database tables ship as embedded migrations.

authkit builds on two sibling modules: [`github.com/zazhedho/gokit`](../gokit)
(request ids, rate limiting, response helpers, generic repositories) and
[`github.com/zazhedho/logus`](../logus) (logging). Read the "Security defaults"
section of gokit's README (trusted proxies, fail-open rate limiting, `limit=-1`,
CORS) before exposing the routes; it applies to authkit unchanged.

Requires PostgreSQL. Redis and a mailer are optional.

## Quick start

```go
package main

import (
	"context"
	"log"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/zazhedho/authkit"
	"github.com/zazhedho/authkit/mailer"
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
	if m, err := mailer.NewBrevoSenderFromEnv(); err == nil {          // optional
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
	kit.Mount(r.Group("/api"))
	log.Fatal(r.Run(":8080"))
}
```

Order matters: build the `Kit`, run `Migrate`, then run your own migrations
(they may reference `users` and `roles`), then `Mount`.

## Protecting your own routes

```go
api := r.Group("/api")

// Any authenticated user.
api.GET("/trips", kit.Auth(), listTrips)

// Authenticated and holding the (resource, action) permission.
api.POST("/trips", kit.Auth(), kit.Can("trips", "create"), createTrip)

// Authenticated and one of the given roles.
api.GET("/reports", kit.Auth(), kit.Role("admin", "staff"), reports)

func listTrips(c *gin.Context) {
	scope := authkit.ScopeFrom(c.Request.Context()) // UserID, Username, Role, Permissions, impersonation fields
	_ = scope
}
```

`Can` and `Role` must come after `Auth`. Superadmin bypasses both. Permissions are
plain rows (`resource`, `action`); add yours with the `moduleseed` helper (see
Extending). `kit.Users()`, `kit.Audit()`, `kit.AppConfig()` and `kit.Tokens()`
expose the underlying services.

## Configuration

`authkit.Config` is explicit; `authkit.ConfigFromEnv()` fills it from environment
variables and is the only code in the module that reads the environment (plus
the optional `mailer.NewBrevoSenderFromEnv`). `DB`, `Redis` and `Mailer` are
never read from the environment. Zero or negative numbers and durations mean
"use the default": a limiter can not be disabled by setting its variable to 0.
When both durations and seconds variables exist, the duration form wins.

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
`RESET_SUBJECT`); see `mailer.BrevoConfig` to build it without the environment,
or implement the `authkit.Mailer` interface yourself.

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

## Security notes

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

## Migrations

`kit.Migrate(ctx)` applies the embedded migrations (`migrations/`, nine tables:
`users`, `blacklist`, `roles`, `permissions`, `menu_items`, `role_permissions`,
`role_menus`, `audit_trails`, `app_configs`, plus the seed rows for the system
roles, menus and permissions). It keeps its own version table,
`authkit_schema_migrations`, in the connection's current schema, so it never
collides with your project's `schema_migrations`. It is idempotent and safe to
call on every start, also from several instances at once (it takes the
migration library's advisory lock).

What it does depends on the database:

| Database | Behavior |
|---|---|
| Empty (no `users` table, no version record) | Applies all migrations; version table ends at 4. |
| Existing, from before authkit (has `users`, no version record), schema complete | Records version 4 **without running the baseline SQL**, then applies any later authkit migration. |
| Existing, schema incomplete | Returns an error wrapping `ErrLegacySchemaIncomplete` that lists the missing `table` or `table.column`. Nothing is changed and no version table is created. |
| Has a version record | Applies pending migrations. A dirty record returns `ErrMigrationsDirty` naming the table; authkit never repairs it. |

The baseline is not replayed on existing databases because its seed is not
idempotent: it computes role grants from whatever is in `permissions` when it
runs. Replaying it would give `staff` and `viewer` newly added permissions,
restore permissions an admin revoked, and bring back deleted roles and menus.
Existing and "complete" is judged against the schema the connection actually
uses (`current_schema()`), by comparing the expected columns, not by trusting
that a `users` table exists. An empty version table next to existing data (an
interrupted stamp) is treated like a missing one.

Run `Migrate` before your own migrations. `ctx` bounds the schema inspection and
the connection checkout; once the migration step starts it is not cancellable
mid-statement. `Migrate` runs on its own connection from your pool and leaves
your `*sql.DB` open.

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
  migration. The same is available as `moduleseed.RenderSQL`.
- **Without `Mount`.** Everything `Mount` wires is built from exported
  packages: `services/...`, `handlers/...`, `repositories/...` and
  `middlewares`. Construct the handlers you want and register them on your own
  router and path layout.

## Development

```
go build ./... && go vet ./... && go test -race -count=1 ./...
```

Integration tests for `Migrate` need a disposable PostgreSQL and are skipped
without `AUTHKIT_TEST_DATABASE_URL`, for example
`postgres://postgres:test@127.0.0.1:55432/postgres?sslmode=disable`. Each test
creates and drops its own schema. `AUTHKIT_STARTER_KIT_DIR` enables a test that
compares the embedded migrations with the original project's copy.
