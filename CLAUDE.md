# authkit

Public Go library (`github.com/zazhedho/authkit`) for users, JWT auth, Redis sessions, RBAC, menus, audit, app config, OTP and password reset, and Google login, built on gin + GORM/Postgres.

## Working rules (owner decisions)
- **Never read `.env` files.** Use fake values in throwaway shells or containers. Run anything that loads config from a `git archive` copy, which has no `.env`.
- **Git and pull requests.**
  - Branch from an up-to-date `main` and open a PR; `main` is protected and nothing is pushed to it directly.
  - Use Conventional Commits with no attribution lines.
  - Stage files by path; `git add -A`, `--all` and `.` are not allowed.
  - Never use `git stash`.
- **Merge only when every CI check is green, including `zero-issues`:**
  - **SonarCloud must have 0 open issues and 0 hotspots to review**, on the PR and on `main`.
  - Fix issues for real. Use `// NOSONAR <rule> <reason>` only for a proven false positive.
- **Dependencies.**
  - Keep them on the latest versions: `go get -u ./... && go mod tidy`.
  - Write the Go version as the minor line only: `go 1.27` with no toolchain line, and `golang:1.27-alpine` for Docker. Move to the next minor when it ships.
- **Comments.**
  - Write none unless one is truly needed: a security reason, a library or protocol quirk, or an ordering or concurrency rule the code cannot show.
  - Keep each one to 1–2 lines.
  - Do not write doc comments that restate the declaration, narrative comments or section dividers. Prefer clearer names or a small function.
- **README.** It must stand alone: no history, no "upgrading from" sections, no "see another project's README". Migration notes go in the GitHub Release.
- **Process.**
  - Use TDD for behaviour changes: write the failing test first.
  - Run an independent review, with a security review when auth, input or infrastructure is touched, before merging.
  - Batch changes so each repo gets one release, not a string of small ones.

## Library rules
- **One import path.** The root package is a thin facade: aliases, constructors and one-line wrappers. All logic lives in `internal/`. Never split into subpackages.
- **Root files.** Exactly one facade file named after the library, plus `config.go` when the library has config. Root tests are only the public API golden test and one facade test.
- **Public API is pinned** by `TestPublicAPI` and `testdata/public_api.golden`.
  - If the golden changes, the API changed: regenerate it with `go test -run TestPublicAPI -update .` only on purpose.
  - Before v1, a breaking change bumps the minor version. Settle all breaking changes in a single release.
- **Release.** Merge to `main`, tag `vX.Y.Z`, then run `gh release create` with migration notes. Internal-only changes go to `main` without a new tag.

## authkit specifics
- **Layout** mirrors the starter-kit template:
  - `internal/{domain,dto,services,repositories}/<module>`;
  - `internal/handlers/http/<module>`, plus `middleware` and `shared`;
  - `internal/router/<module>/register.go`, `internal/infrastructure/*`, `internal/config` and `internal/migrate`.
  - Interfaces live in each consumer's `ports.go`. Constructors are `New`, `NewService` and `NewRepository`. Package names match their directories. `internal/architecture` enforces all of this.
- **Routes** are pinned by `internal/router/testdata/routes.golden` (method, path and middleware chain).
- **Authorization: the permission-subset rule.** An actor may update, delete, impersonate or assign a role only when it holds every permission of the target role. No one may change their own role. The last superadmin is protected by a row lock.
- **Tokens.**
  - Per-user revocation uses `tokens_valid_after` against the database clock, compared with the `iat_ms` claim.
  - `Auth` checks the live user and role on every request. With Redis it also requires a live session.
  - Refresh tokens rotate with compare-and-swap, and reuse revokes the session.
- **Migrations.** Four files named `YYYYMMDDHHMMSS_<area>_<change>`. While nothing is released, edit them in place instead of adding files. Seeds use `ON CONFLICT ... WHERE deleted_at IS NULL`, matching the partial indexes.
- **Tests.** Postgres tests run when `AUTHKIT_TEST_DATABASE_URL` is set (CI sets it). Locally, use a throwaway `postgres:latest` container on a free port and stop it afterwards.
- **Gate:** `go build ./... && go vet ./... && go test -race -count=1 ./... && make lint` (0 issues), and `gofmt -l .` empty.
