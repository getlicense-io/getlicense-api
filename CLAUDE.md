# GetLicense API — Project Conventions

## Quick Start

```bash
make run          # start Postgres + run migrations + start server (development mode)
make e2e          # drop+recreate getlicense_e2e DB only, then run hurl scenarios
make test         # unit tests (no DB required)
make test-all     # unit + integration tests (requires Postgres)
make db-reset     # NUKE EVERYTHING — drops the Postgres volume (dev + e2e). Use only when local state is corrupted.
```

### Database layout
The Postgres container hosts two databases on one volume:

- **`getlicense`** — dev data (products, licenses, accounts). Persisted across `make run` restarts; never touched by e2e.
- **`getlicense_e2e`** — scratch database used by `make e2e`. Dropped and recreated on every e2e run.

Running `make e2e` does NOT wipe your dev signup, products, or licenses anymore. If you need a truly fresh slate (corrupted migrations, etc.), `make db-reset` is the escape hatch.

## Architecture: Service/Repository Pattern

```
HTTP Request → Handler (parse, auth) → Service (business logic) → Repository (data access) → PostgreSQL
```

- **Handlers** (`server/handler/`) — thin HTTP adapters, 5-15 lines, no business logic
- **Services** (`auth/`, `product/`, `licensing/`, `webhook/`) — own all business logic, depend on repository interfaces
- **Repositories** (`db/`) — implement interfaces from `domain/`, all SQL via pgx

## Package Layout

```
cmd/server/main.go              # Cobra CLI — composition root, serve + migrate commands
internal/
├── core/                        # System language (IDs, Cursor, Page[T], enums, errors) — zero deps
├── domain/                      # Business contracts (models, repo interfaces, TxManager)
├── crypto/                      # Ed25519, AES-GCM, HMAC, HKDF, JWT, TOTP, password
├── db/                          # PostgreSQL — pool, TxManager impl, all repo implementations
├── rbac/                        # Permission constants + Checker (flat role.permission strings)
├── auth/                        # AuthService — signup, login (+ TOTP step2), refresh, switch, API keys
├── identity/                    # IdentityService — TOTP enroll/activate/verify/disable
├── product/                     # ProductService — CRUD with Ed25519 keypair generation; auto-creates Default policy on Create
├── policy/                      # PolicyService — CRUD + pure Resolve(policy, overrides) effective-value resolution
├── licensing/                   # LicenseService — policy-aware create, validate, suspend, revoke, machines, freeze, attach-policy
├── environment/                 # EnvironmentService — per-account partitions (max 5)
├── invitation/                  # InvitationService — membership + grant invitations with tokens
├── grant/                       # GrantService — capability delegation (issue/accept/suspend/revoke)
├── webhook/                     # WebhookService — endpoint CRUD, dispatch, delivery with retries
└── server/                      # Fiber v3 app, middleware, handlers, routes, background jobs
    ├── middleware/               # RequireAuth (dual-mode), ResolveGrant, rate limit
    └── handler/                  # HTTP handlers grouped by domain
migrations/                      # goose SQL migrations
e2e/scenarios/                   # hurl e2e test scenarios
```

## Three-ID Request Model

Every authenticated request carries three distinct IDs on the `AuthContext`:

- **IdentityID** — global login identity (nil for API-key auth). One identity can belong to many accounts.
- **ActingAccountID** — the account the caller is authenticating as. Audit logs and rate limits key on this.
- **TargetAccountID** — the account whose data is being read/written. Equal to `ActingAccountID` on every standard route; mutated by the grant routing middleware on `/v1/grants/:id/...` routes so a grantee can manage licenses in the grantor's tenant.

Handlers that scope DB writes (e.g. `license.Create`) MUST use `auth.TargetAccountID`. Everything audit/billing-shaped uses `auth.ActingAccountID`.

## Data Flow

```go
// Handler: authorize + get auth, call service, return JSON
func (h *ProductHandler) Create(c fiber.Ctx) error {
    var req product.CreateRequest
    if err := c.Bind().Body(&req); err != nil { return err }
    auth, err := authz(c, rbac.ProductCreate)
    if err != nil { return err }
    result, err := h.svc.Create(c.Context(), auth.TargetAccountID, auth.Environment, req)
    if err != nil { return err }
    return c.Status(fiber.StatusCreated).JSON(result)
}

// Service: business logic, runs inside an RLS-scoped tx
func (s *Service) Create(ctx context.Context, accountID core.AccountID, env core.Environment, req CreateRequest) (*domain.Product, error) {
    var result *domain.Product
    err := s.txManager.WithTargetAccount(ctx, accountID, env, func(ctx context.Context) error {
        // ... business logic, repo calls within transaction
    })
    return result, err
}
```

## Transactions & RLS

- `domain.TxManager` interface: `WithTargetAccount(ctx, accountID, env, fn)` and `WithTx(ctx, fn)`
- `WithTargetAccount` sets both `app.current_account_id` and `app.current_environment` via `set_config()` so every statement in `fn` runs under the tenant's RLS policy
- Repos extract tx from context via `conn(ctx, pool)` — falls back to pool if no tx
- Global queries (login, API key lookup, validate) skip tenant context — the `NULLIF(..., '') IS NULL` escape hatch in RLS policies allows NULL
- Background jobs run without environment context — the `IS NULL` branch processes all environments

**Critical RLS pattern** in migrations:
```sql
(NULLIF(current_setting('app.current_account_id', true), '') IS NULL
 OR account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid)
AND
(NULLIF(current_setting('app.current_environment', true), '') IS NULL
 OR environment = current_setting('app.current_environment', true))
```

## Environment Isolation (test/live + custom)

- API keys carry an `environment` field (`live`, `test`, or a user-created slug)
- Auth middleware populates `AuthContext.Environment` from the API key; JWT callers opt in per request via the `X-Environment` header, defaulting to `live`
- All service methods pass `env` through to `WithTargetAccount` → RLS filters by environment automatically
- Licenses, machines, webhook endpoints, and webhook events have an `environment` column
- Products are environment-agnostic — they exist in every environment under the account
- Environments are first-class rows in the `environments` table, capped at 5 per account

## Pagination

All list endpoints use opaque cursor pagination via `core.Cursor` + `core.Page[T]`:

- Request: `?cursor=<opaque>&limit=<1..200>` (default 50)
- Response: `{"data": [...], "has_more": bool, "next_cursor": "opaque" | null}`
- Ordering: `(created_at DESC, id DESC)` — the `id DESC` tiebreaker is required because bulk-inserted rows share a `created_at` to the microsecond
- Handlers use the `cursorParams(c)` + `pageFromCursor[T](items, hasMore, getCursor)` helpers in `server/handler/helpers.go`

## RBAC

- `internal/rbac` owns flat permission constants (e.g. `rbac.LicenseCreate = "license:create"`) and a `Checker` bound to a role
- Four preset roles seeded in migration `016_memberships_and_roles.sql`:
  - `owner` — all permissions; only account owner can invite new owners / remove members
  - `admin` — full management minus account ownership transfers
  - `developer` — product, license, webhook, api-key CRUD
  - `operator` — license / machine lifecycle (suspend, revoke, activate, deactivate), no product or webhook write
- Handlers call `authz(c, rbac.Perm)` which returns the `AuthContext` after validating the caller's role has the permission
- Identity JWTs re-resolve membership+role from the DB every request (single JOIN via `GetByIDWithRole`); stolen JWTs can't forge elevated permissions
- L1 adds `policy:read` / `policy:write` / `policy:delete` on top of Release 1's preset bundles (owner/admin/developer get all three, operator gets read only). Seeded in migration `020_policies.sql`.

## Policies & Effective Values (L1)

Licenses own lifecycle configuration through a `policy_id` FK and a sparse `overrides` jsonb column. **Enforcement paths never read raw policy or override fields directly — always go through `policy.Resolve(policy, overrides)`**, which returns an `Effective` struct. This is the invariant that makes the cascade model work: a policy update rolls out instantly to every referencing license without copying values, and overrides layer on top per-license.

- **Overridable fields are quantitative only:** `MaxMachines`, `MaxSeats`, `CheckoutIntervalSec`, `MaxCheckoutDurationSec`. Nothing else.
- **Behavioral flags are policy-only:** `Floating`, `Strict`, `ExpirationStrategy`, `ExpirationBasis`, `RequireCheckout`. If you need different behavior, clone the policy and attach.
- **Expiration is a first-class column, not cascaded.** `licenses.expires_at` is materialized at creation (or first activation for `FROM_FIRST_ACTIVATION` policies) from `policy.duration_seconds`. Policy duration changes affect NEW licenses only. Vendors who want to extend existing licenses PATCH the license's `expires_at` directly. `LicenseOverrides` does NOT contain an expires_at field.
- **`POST /v1/licenses/:id/freeze`** snapshots the current `Effective` values into the license's `overrides` so future policy changes stop affecting that license. `AttachPolicy` moves the license to a different policy within the same product, optionally clearing overrides.
- **Expiration strategies on past `expires_at`:**
  - `REVOKE_ACCESS` (default) — background job transitions license to `expired`; validate returns `license_expired`; activate/checkin reject.
  - `RESTRICT_ACCESS` — license stays `active`; validate returns `license_expired`; activate/checkin reject. Client SDK decides what to do.
  - `MAINTAIN_ACCESS` — license stays `active`; validate returns valid. Pure informational expiration (useful for "perpetual with support expiry" model).
- **Default policy per product.** Every product auto-gets a `is_default=true` policy on creation (same tx as product insert). A partial unique index on `policies(product_id) WHERE is_default=true` enforces at most one default per product. Delete of the default is refused with `policy_is_default` (422) — promote another first via `POST /v1/policies/:id/set-default`. Delete of a policy in use is refused with `policy_in_use` (422) unless `?force=true`, which reassigns referencing licenses to the product's default inside the same tx.
- **Grants respect `AllowedPolicyIDs`.** When a grant's `GrantConstraints.AllowedPolicyIDs` is non-empty, grant-scoped license creation rejects any request whose effective policy ID (explicit or resolved default) is not a member, returning `grant_policy_not_allowed` (403).
- **Design spec:** `docs/superpowers/specs/2026-04-15-l1-policies-design.md`.
- **Implementation plan:** `docs/superpowers/plans/2026-04-15-l1-policies.md`.

## Webhook Dispatch

- `domain.EventDispatcher` interface with `Dispatch(ctx, accountID, env, eventType, payload)`
- `licensing.Service` fires events after successful operations: `license.created`, `license.suspended`, `license.revoked`, `license.reinstated`, `machine.activated`, `machine.deactivated`
- Dispatch is fire-and-forget — errors are logged, never returned to the caller

## Import Conventions

```go
import (
    "github.com/getlicense-io/getlicense-api/internal/core"     // IDs, enums, errors
    "github.com/getlicense-io/getlicense-api/internal/domain"   // models, repo interfaces
)
```

- `core.AccountID`, `core.NewAppError`, `core.LicenseStatusActive` — system language
- `domain.Account`, `domain.ProductRepository`, `domain.TxManager` — business contracts

## Environment Variables

```bash
DATABASE_URL=postgres://...              # required
GETLICENSE_MASTER_KEY=<64-hex-chars>     # required, min 64 chars (32 bytes)
GETLICENSE_HOST=0.0.0.0                  # default
GETLICENSE_PORT=3000                     # default
GETLICENSE_ENV=development               # optional — enables:
                                         #   - human-readable logs (vs JSON)
                                         #   - HTTP/localhost webhook URLs
```

## Crypto Key Derivation

All derived from `GETLICENSE_MASTER_KEY` via HKDF-SHA256 with fixed context strings:
- `"getlicense-hmac-key"` — API key, license key, refresh token hashing
- `"getlicense-encryption-key"` — product private key encryption at rest
- `"getlicense-jwt-signing-key"` — JWT access token signing

## DevSecOps

- **CI**: GitHub Actions on push/PR — `go vet`, `golangci-lint`, `go test -short`, `go build`
- **Pre-commit hook**: `make hooks` installs `gofmt` check + `go vet`
- **Linting**: `.golangci.yml` — errcheck, govet, staticcheck, unused, ineffassign, gosimple

## Auth — Dual-Mode

Single middleware detects by prefix:
- `gl_live_*` / `gl_test_*` → API key auth (HMAC lookup, account-wide)
- Otherwise → JWT auth (verify, extract user + role)

Use `core.APIKeyPrefixLive` and `core.APIKeyPrefixTest` — never hardcode prefix strings.

## CLI

```bash
getlicense-server              # start API server (default)
getlicense-server serve        # same as above
getlicense-server migrate      # run migrations and exit
```

## Gotchas & Debugging

- **Fiber v3 requestLogger status is unreliable on error paths.** `internal/server/app.go`'s `requestLogger` reads `c.Response().StatusCode()` BEFORE the ErrorHandler rewrites it with the final status from the returned `*core.AppError`. When a handler returns an error, server logs may show `status=200 latency_ms=1` while the client actually received 401/403/etc. with a populated error envelope. During debugging, trust the client-side `curl -w "HTTP=%{http_code}"` output or the response body (which contains the typed `error.code`), not the request log.
- **Never reuse bare-column `xColumns` constants inside JOIN queries.** The shared constants like `membershipColumns = "id, account_id, ..."` work fine for single-table SELECTs, but if you concatenate them into a JOIN against a table with overlapping column names (e.g. `roles` also has `id`/`account_id`/`created_at`/`updated_at`), Postgres emits `ERROR: column reference "id" is ambiguous (SQLSTATE 42702)`. Solution: spell out the columns inline with the table alias prefix in JOIN queries. See `MembershipRepo.GetByIDWithRole` for the pattern. Keep the shared constant for every other method that only hits the base table.
