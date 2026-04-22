# Changelog

All notable changes to the GetLicense API are recorded here. Dates use
ISO 8601 and versions follow [Semantic Versioning](https://semver.org/).

## [0.4.0] — sqlc rewrite + audit hardening — 2026-04-22

Full internal rewrite of the database layer onto sqlc, a latent bug fix
on `/v1/auth/switch`, and a backend-QA sweep that closed eight
pre-existing issues. The public `domain.*Repository` interfaces and
`domain.*` struct shapes are unchanged; JSON wire contracts are stable
byte-for-byte with the intentional exceptions called out below.

### Database layer (internal)

- Every hand-written pgx repository under `internal/db/` replaced with
  a thin adapter that wraps sqlc-generated queries.
  `internal/db/sqlc/queries/*.sql` is the source of truth;
  `make sqlc` regenerates `internal/db/sqlc/gen/` which is committed.
- 3-layer design: `sqlcgen` emits native pgx types (`pgtype.UUID`,
  `string`, `[]byte`, `time.Time`); repo adapters translate to
  `domain.*` types through a per-table `xFromRow` seam. `sqlcgen` has
  zero JSON tags and no `domain`/`core` imports — structural isolation
  that makes secret-field leaks impossible by construction.
- `sqlc.yaml` uses a single override (`timestamptz → time.Time`)
  instead of the ~60 per-column overrides an "aliased" design would
  need. Upgrade-proof and boring.
- New `internal/db/helpers.go` holds generic converters keyed on
  `~[16]byte` (matching every `core.*ID` alias): `idFromPgUUID[T]`,
  `nullableIDFromPgUUID[T]`, `pgUUIDFromID[T]`, `pgUUIDFromIDPtr[T]`,
  `pgUUIDSliceFromIDs[T]`, plus `currentAccountID(ctx, db)` for repos
  that need the RLS GUC as an explicit query param.
- `internal/db/constraints.go` catalogs every named DB constraint the
  repos classify on — any rename in SQL without updating here yields
  silent misclassification, so the file is the single point of truth.
- Migration `028_sqlc_pagination_indexes.sql` adds composite
  `(scope_col, created_at DESC, id DESC)` indexes for every paginated
  list whose index was missing: customers, policies, entitlements,
  webhook_events, domain_events.
- `make sqlc`, `make sqlc-verify`, `make sqlc-lint` targets; CI
  workflow now installs pinned sqlc v1.29.0 and fails on generated-
  code drift.

### `/v1/auth/switch` — bug fix (breaking for any client that was coincidentally working)

- Request body renamed `account_id` → `membership_id` (aligns with the
  OpenAPI spec). The old field never worked: `Switch()` would validate
  the membership existed but then silently return `memberships[0]`
  regardless of the requested account. Multi-account identities got
  the oldest-joined account back every time.
- `Switch` now loads the membership by ID, verifies it belongs to the
  authenticated identity AND is active, and reissues tokens scoped to
  that specific membership. Fails with `403 permission_denied` for
  bogus IDs, another identity's ID, or suspended memberships.
- Body-type errors (`{"membership_id": 42}`) now return `422
  validation_error` (was `400`) — matches the rest of the validation
  surface; error envelope unchanged.

### Backend-QA hardening (pre-existing bugs closed)

Eight issues surfaced by a pre-push audit against a running instance:

- **`POST /v1/customers` duplicate email** now returns `409
  customer_already_exists` instead of `500`. Repo classifies SQLSTATE
  `23505` on `customers_account_email_ci`.
- **`POST /v1/products/{id}/policies` with missing/cross-tenant
  product** now returns `404 product_not_found` instead of `500`.
  Two-part fix: repo classifies the FK violation (catches bogus UUIDs),
  handler adds an RLS-scoped `products.Get` pre-check (catches
  cross-tenant — FK constraints bypass RLS).
- **`GET /v1/products/{id}/policies` with missing/cross-tenant
  product** now returns `404` instead of `200 {data:[]}`.
- **Policy creation input validation** tightened: empty `name`,
  non-positive `max_machines`/`max_seats`/`duration_seconds`, and
  negative checkout fields now reject with `422 validation_error`.
- **pgx session timezone** pinned to UTC at pool setup AND an
  `AfterConnect` hook registers `TimestamptzCodec{ScanLocation: UTC}`
  (the binary-format decode path is independent of `RuntimeParams`).
  Every timestamp in every response is now UTC-suffixed; no more
  server-local-TZ drift on read paths.
- **Unknown HTTP verbs** (QUERY, LINK, UNLINK, LOCK, ...) now return
  `405 method_not_allowed` with the typed envelope instead of bare
  `501`.
- **Malformed cursor** now returns `400 invalid_cursor` (new error
  code) instead of `422 validation_error`. Semantic: client sent
  garbage → 400, not a validation failure on well-formed input.
- **Error envelope consistency**: JSON bind errors and pg SQLSTATE
  errors route through `AppError.HTTPStatus()` uniformly instead of
  hard-coded `400`.

### Audit coverage

- Added 9 e2e hurl scenarios to close OpenAPI-spec coverage gaps;
  every endpoint in `api/openapi.yaml` now has at least one happy-path
  + documented-error test.
- Added regression hurl tests for every bug closed in this release.
- e2e suite: **28 scenarios, 368 requests, 100%** pass at cut.
- Backend-QA verdict (captured in `/tmp/backend-qa/sqlc-prepush/`):
  0 Critical, 0 High, 0 Medium unresolved after fixes. Verified PASS
  on RLS cross-tenant reads, license state machine (including
  concurrent-suspend race), JWT attack vectors, bulk operation
  atomicity, pagination under bulk seed, BOLA on nested resources,
  mass assignment on PATCH, and empty-slice JSON consistency.

### Breaking changes (full list)

1. `POST /v1/auth/switch` request body field renamed `account_id` →
   `membership_id`. Clients that were sending `account_id` (matching
   the old Go code but not the spec) now get `422`. Clients that were
   sending `membership_id` (matching the spec) now work correctly for
   the first time.
2. Body-type validation errors on `/v1/auth/switch` are `422` instead
   of `400`. Error envelope (`error.code == "validation_error"`) is
   unchanged.
3. Empty-name / non-positive-quantity `POST /v1/products/{id}/
   policies` now rejects `422` where previously it created a row with
   invalid data.

## [0.3.0] — Release 1: Foundations — 2026-04-15

Release 1 is a ground-up overhaul of the auth, tenancy, and pagination
layers. It is **not** backward compatible with 0.2.x — every JWT,
signup response, and list endpoint changes shape. There is no upgrade
path; run `make db-reset` and re-signup.

### Identity, Membership, Roles

- New `identities` table holds global login records. An identity can
  belong to many accounts; the old `users` table is gone.
- New `account_memberships` table joins identities to accounts and
  carries the membership's role and status.
- New `roles` table seeds four presets at migration time: `owner`,
  `admin`, `developer`, `operator`. Tenants can add custom
  roles that live alongside the presets.
- JWTs now carry `{identity_id, acting_account_id, membership_id,
  role_slug}` and are re-resolved against the DB on every request — a
  stolen JWT can never forge elevated permissions.
- New `/auth/switch` endpoint lets a multi-account identity change
  `acting_account_id` without re-entering credentials.

### RBAC

- New `internal/rbac` package owns flat permission constants
  (`license:create`, `grant:issue`, ...) and a `Checker` that gates
  each handler via `authz(c, rbac.Perm)`.
- Handlers no longer duplicate role checks; permission enforcement is
  uniform across the tree.
- API key callers are bound to a single cached `admin` role at
  startup, eliminating a DB round-trip per API-key request.

### TOTP (Two-Step Login)

- New `internal/crypto/totp.go` covers secret generation, code
  verification, and 64-bit recovery codes.
- `POST /auth/login` on a TOTP-enabled identity returns a short-lived
  pending token; `POST /auth/login/totp` exchanges it for the full
  access + refresh pair.
- TOTP enroll / activate / verify / disable endpoints under
  `/v1/identity/totp`.
- Pending-login store has a bounded sweep goroutine with a lifecycle
  `Close()` method so tests don't leak.

### Invitations

- New `invitations` table powers two flows via one schema:
  `kind='membership'` (invite an identity to join an account with a
  role) and `kind='grant'` (invite an account to receive a delegated
  capability grant).
- `POST /v1/invitations` creates either kind; `GET /v1/invitations/lookup`
  is an unauthenticated token preview; `POST /v1/invitations/:id/accept`
  finalizes both branches.
- Accepting a `grant` invitation atomically creates the grant inside a
  transaction; retries are deduped via a partial unique index.
- Pluggable `Mailer` interface with a `LogMailer` fallback for
  development; production wiring is out of scope for this release.

### Capability Grants

- New `grants` table lets an account delegate a narrow slice of
  licensing capability to another account (internal team, channel
  partner, OEM).
- Grantor specifies capabilities
  (`license.create`, `license.suspend`, `license.revoke`, ...) and a
  typed `GrantConstraints` blob: `max_licenses_total`,
  `max_licenses_per_month`, `allowed_policy_ids`,
  `allowed_entitlement_codes`, and an `@exact` / `*.suffix` email
  pattern match.
- New `ResolveGrant` middleware on `/v1/grants/:id/...` routes
  switches `AuthContext.TargetAccountID` from the grantee to the
  grantor so license writes land in the grantor's tenant.
- Licenses gain `grant_id` and `created_by_account_id` columns for
  attribution; dashboards can now answer "which partner sold this
  license" without joining on anything fragile.
- `grant.Service.CheckLicenseCreateConstraints` enforces declarative
  quotas inside the grantor's tenant transaction — the license
  counting query is RLS-scoped to prevent TOCTOU races.

### Three-ID Request Model

- `AuthContext` now carries `IdentityID`, `ActingAccountID`, and
  `TargetAccountID` as three distinct fields. On every standard route
  they are equal; they diverge only inside grant routes.
- `TxManager.WithTenant` renamed to `WithTargetAccount(ctx, accountID,
  env, fn)` to reflect which ID it actually sets as the RLS GUC.
- Handlers that scope DB writes must use `TargetAccountID`; audit
  logs and rate limits use `ActingAccountID`.

### Cursor Pagination

- Every list endpoint (products, licenses, api keys, webhook
  endpoints, memberships, invitations, grants, environments) now uses
  opaque cursor pagination.
- Request: `?cursor=<opaque>&limit=<1..200>` (default 50).
- Response: `{"data": [...], "has_more": bool, "next_cursor": "opaque" | null}`.
- Ordering is `(created_at DESC, id DESC)` — the `id DESC` tiebreaker
  prevents page-flicker when bulk-inserted rows share a `created_at`
  to the microsecond.
- New composite indexes on `products`, `licenses`, `api_keys`,
  `webhook_endpoints`, and `webhook_events` covering the keyset sort
  keys so the planner can walk in order and stop at `LIMIT`.
- `core.Cursor{CreatedAt, ID}` with base64-JSON encoding;
  `core.Page[T]` as the generic response wrapper.

### Environments

- New first-class `environments` table replaces the 2-row `live`/`test`
  enum. Each account gets up to 5 environments (`live` and `test`
  auto-seeded at signup).
- New `POST /v1/environments` and `DELETE /v1/environments/:id`
  endpoints.
- Environment deletion runs in two transactions: one to validate the
  "at least one environment per account" invariant in the account's
  context, and one inside the target environment's RLS GUC to check
  the blocking-license invariant without races.

### Removed

- `middleware.FromContext`, `domain.AuthenticatedAccount`, and all old
  `WithTenant` call sites.
- `domain.Pagination`, `domain.ListResponse[T]`, and every
  offset/limit repo method (`ProductRepo.List`, `LicenseRepo.List`,
  `LicenseRepo.ListByProduct`, `APIKeyRepo.ListByAccount`,
  `WebhookRepo.ListEndpoints`) along with their service wrappers.
- `core.UserRole` — RBAC permission strings replaced the role enum.
- `domain.Role.HasPermission` — `rbac.Checker.Can` owns this now.
- The word "reseller" throughout comments and code in favor of
  vendor-neutral grantor/grantee terminology.

### Migrations

Database schema spans migrations 001 through 019. Because this is a
pre-1.0 release with no backward-compatibility guarantee, several
existing migrations were edited in place. Upgrading from 0.2.x
requires `make db-reset`; there is no forward-migration path.

### Internal

- Two-stage subagent review gate (spec compliance → code quality)
  caught atomicity bugs, column-ambiguity errors, side-effect-before-
  success patterns, and typed-error translation gaps that unit tests
  missed. This process is now documented in the project CLAUDE.md.
- `db.IsUniqueViolation(err, constraint)` helper translates pgx
  errors into typed `*core.AppError` at the repo boundary.
- `handler/helpers.go` adds `cursorParams(c)` and
  `pageFromCursor[T](...)` to keep cursor plumbing out of individual
  handlers.
- The grants RLS policy has two branches (grantor-match and
  grantee-match) so both sides of a delegation can read their own
  rows.

### Stats

- **88 commits** across 5 bundles
- **~8,500 lines** added, **~3,200 lines** removed
- **18 e2e hurl scenarios**, **156 requests**, all green on every
  bundle checkpoint
