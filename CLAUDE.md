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
├── analytics/                   # Analytics — read-only aggregate metrics (Snapshot: license/machine/customer/grant counts + daily event buckets)
├── audit/                       # audit.Writer + Attribution — domain event recording with three-ID attribution
├── rbac/                        # Permission constants + Checker (flat role.permission strings)
├── auth/                        # AuthService — signup, login (+ TOTP step2), refresh, switch, API keys
├── identity/                    # IdentityService — TOTP enroll/activate/verify/disable
├── product/                     # ProductService — CRUD with Ed25519 keypair generation; auto-creates Default policy on Create
├── policy/                      # PolicyService — CRUD + pure Resolve(policy, overrides) effective-value resolution
├── customer/                    # CustomerService — CRUD + email normalization + UpsertForLicense (L4)
├── entitlement/                 # EntitlementService — registry CRUD + code validation + attach/detach + effective resolution (L3)
├── licensing/                   # LicenseService — policy+customer+entitlement-aware create, validate, suspend, revoke, machines, freeze, attach-policy
├── environment/                 # EnvironmentService — per-account partitions (max 5)
├── invitation/                  # InvitationService — membership + grant invitations with tokens
├── grant/                       # GrantService — capability delegation (issue/accept/suspend/revoke)
├── search/                      # Search — DSL parser + parallel sub-query fan-out across licenses/machines/customers/products (O5)
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

## SQL Query Conventions (sqlc)

All database queries are codegenned by **sqlc v1.29.0** from `.sql` files in `internal/db/sqlc/queries/`. Repo files in `internal/db/` are thin adapters that translate between the generated `sqlcgen` package and the public `domain.*Repository` interfaces. See `sqlc.yaml` at repo root for codegen config.

### 3-layer architecture

```
┌──────────────┐    ┌──────────────────┐    ┌──────────────┐
│   domain/*   │ ←─ │ <table>_repo.go  │ ←─ │ sqlcgen/*    │
│ (public API) │    │ explicit mapping │    │ (DB plumbing)│
└──────────────┘    └──────────────────┘    └──────────────┘
  hand-written       hand-written,           generated;
  immutable shape    mechanical conversions  native pgx types
  json tags          via xFromRow seam       (pgtype.UUID, string,
  deliberate         (uuid→core.XID,         []byte, time.Time,
  secrets safe       string→core.Status,     etc.)
                     json.Unmarshal, etc.)
```

`sqlcgen` has NO json tags and imports neither `core` nor `domain` — it's internal plumbing, never marshaled to API responses. The only override in `sqlc.yaml` is `timestamptz` → `time.Time` (saves ~150 LoC of `.Time`/`.Valid` unwrapping across 20+ tables).

### Workflow

```bash
# Edit or add a query
1. Edit internal/db/sqlc/queries/<table>.sql
2. make sqlc                 # regenerates internal/db/sqlc/gen/
3. Call r.q.<QueryName> in the repo adapter
4. Commit the .sql, gen/, and repo.go together

# Add a migration
1. migrations/NNN_feature.sql (goose format)
2. make sqlc-lint            # verifies schema parses
3. Update existing queries or add new ones
4. make sqlc && make test-all
```

### Core conventions

- **One `.sql` file per table.** Method names are globally unique (sqlc requirement) — prefix with entity: `GetLicenseByID`, `GetProductByID`.
- **Explicit column lists in SELECTs**, never `SELECT *`. Locks field order; makes additive migrations deliberate.
- **Column order in SELECTs must match `sqlcgen.X` field order** from `gen/models.go`. When the column list matches the model, sqlc reuses the top-level struct for all `:one`/`:many` queries. If the list diverges (even just reorder), sqlc emits per-query `GetXByIDRow`, `ListXRow`, etc. — harmless but noisy.
- **`xFromRow` translation seam.** Each repo has ONE helper like `accountFromRow(row sqlcgen.Account) domain.Account` that every `Get*` / `List*` / `*-returning-row` path shares. Signature is non-fallible by default (`func xFromRow(row) domain.X`); becomes fallible (`func xFromRow(row) (domain.X, error)`) only when the table has a jsonb column that decodes into a typed Go struct (e.g. `licenseFromRow` unmarshals `Overrides` into `domain.LicenseOverrides`). See `license_repo.go` for the fallible pattern.
- **Explicit `::type` casts on every `sqlc.narg` value.** Postgres can't infer the type in some contexts (tuple compares, `COALESCE`, `ANY`). Always write `sqlc.narg('x')::text`, `sqlc.narg('x')::uuid`, `sqlc.narg('x')::timestamptz`, `sqlc.narg('x')::jsonb`. Without the cast the narg may emit as the WRONG Go type (inferred from a sibling narg) or the query may fail to plan.
- **Cursor pagination requires BOTH casts inside the tuple.** Every paginated list includes:
  ```sql
  AND (sqlc.narg('cursor_ts')::timestamptz IS NULL
       OR (created_at, id) < (sqlc.narg('cursor_ts')::timestamptz, sqlc.narg('cursor_id')::uuid))
  ORDER BY created_at DESC, id DESC
  LIMIT sqlc.arg('limit_plus_one');
  ```
  Without the `::uuid` cast sqlc infers `cursor_id` as `*time.Time` (matched to the sibling narg). Repos use `cursorParams(cursor)` + `sliceHasMore(rows, limit)` helpers from `internal/db/pagination.go`.
- **Named `sqlc.arg('foo')` whenever auto-naming would be ambiguous.** Default auto-naming produces `Column2`, `Lower`, `Limit`, `PolicyID_2`. Use `sqlc.arg('from_policy_id')::uuid` / `sqlc.arg('limit_rows')` / `sqlc.arg('email')::text` / `sqlc.arg('entitlement_ids')::uuid[]` for a clean generated struct.
- **Classify unique violations on Create ONLY when the raw conflict is user-visible.** Examples:
  - `products.Create` → classifies (`ConstraintProductSlugUnique` → `ErrProductAlreadyExists`). Direct user create.
  - `customers.Create` / `entitlements.Create` → do NOT classify. Service pre-checks via `UpsertByEmail` / `GetByCodes`; raw pg error is an internal race, not user-facing.
  - `api_keys.Create` / `refresh_tokens.Create` → do NOT classify (hash collision is crypto-level, not user-caused).
- **Explicit 4-line ErrNoRows branch on Get*.** Do NOT use `notFoundOrNil` (doesn't compose with `xFromRow` between nil-check and return). Shape:
  ```go
  row, err := r.q.GetXByID(ctx, conn(ctx, r.pool), pgUUIDFromID(id))
  if errors.Is(err, pgx.ErrNoRows) { return nil, nil }
  if err != nil { return nil, err }
  x := xFromRow(row)  // or: x, err := xFromRow(row); handle err
  return &x, nil
  ```
- **Type conversion helpers** in `internal/db/helpers.go` (all generic, constrained by `~[16]byte` for ID helpers):
  - `idFromPgUUID[T](row.X)` / `pgUUIDFromID(id)` — NOT NULL uuid ↔ typed-ID
  - `nullableIDFromPgUUID[T](row.X)` / `pgUUIDFromIDPtr(ptr)` — nullable uuid ↔ `*T`
  - `pgUUIDSliceFromIDs[T](ids)` — `[]core.XID` → `[]pgtype.UUID` for `ANY($1::uuid[])` params
  - `intPtrToInt32Ptr(p)` / `int32PtrToIntPtr(p)` — `*int` ↔ `*int32` for nullable int columns
  - `nilIfEmpty`, `nilIfZero`, `nilIfZeroID` — convert zero values to `nil` for sqlc.narg NULL
  - `cursorParams(cursor)` + `sliceHasMore(rows, limit)` — paginator helpers
  - `currentAccountID(ctx, db)` — read `app.current_account_id` GUC as an explicit query param (used by `grant_repo.go` where RLS-filter needs to be a SQL parameter rather than an implicit policy)

### Test patterns

- Integration tests (`*_repo_test.go`) use rollback-only top-level txs; `make test-all` exercises real Postgres.
- Unit tests against `sqlcgen.DBTX` mocks are OK for narrow behavior (e.g. `license_repo_test.go` tests the `UpdateStatus` 2-query classification).

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
- L4 adds `customer:read` / `customer:write` / `customer:delete` with the same preset distribution. Seeded in migration `021_customers.sql`.

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

## Validation TTL (P3)

Runtime SDKs need a signed, server-authoritative hint for how long a cached `gl1` license token may be trusted before re-checking. `policy.validation_ttl_sec` + `license.overrides.validation_ttl_sec` cascade to an effective value via the standard `policy.Resolve` merge; the default comes from `GETLICENSE_DEFAULT_VALIDATION_TTL_SEC` (default 3600, bounds 60..2592000).

- **Signed claim, not response mirror.** The effective TTL is embedded as the `ttl` claim in the `gl1` token so a MITM can't extend or reduce the value. `ValidateResult.validation_ttl_sec` mirrors the claim as a convenience for callers that decode without verifying — SDK caching must verify the token and read the signed claim.
- **Token re-minting on `POST /v1/validate`.** `/v1/validate` re-signs the license token with the current effective TTL and returns it in `license.token` on the response. Every other endpoint (`GET /v1/licenses/:id`, list, create) returns the stored `licenses.token` from the DB (with TTL-at-creation). The stored column is never updated by this feature — only Validate returns a fresh token. This is the only design that makes policy TTL updates cascade to existing licenses without re-issuing license keys.
- **`gl2` lease tokens are unaffected.** P3 is `gl1`-only; lease tokens have independent expiry via `max_checkout_duration_sec` / `checkout_grace_sec`.
- **Bounds.** 60 ≤ TTL ≤ 2592000 enforced at policy CRUD (`ErrPolicyInvalidTTL`, 422), license override writes (POST/PATCH, same error code), Postgres CHECK constraint `policies_validation_ttl_sec_range`, and config load.
- **Migration:** `027_validation_ttl.sql` — additive nullable column on `policies`.
- **Implementation plan:** `docs/superpowers/plans/2026-04-17-p3-validation-ttl.md`.

## Customers (L4)

Every license references a first-class customer via `customer_id` FK. Customers are account-scoped (shared across environments) and have no login in v1 — the customer portal is explicit v2 (FEATURES.md §6).

- **Naming discipline:** the word `user` never appears in code referring to customers. `Identity` = logs in, `Customer` = license owner, `Membership` = join between identity and account. The word `reseller` also never appears — delegated creation is a **grant** from a **grantor account** to a **grantee account**.
- **Creation:** `POST /v1/licenses` accepts exactly one of `customer_id` (attach existing) or `customer: {email, name, metadata}` (inline upsert). Both provided → 422 `customer_ambiguous`. Neither provided → 422 `customer_required`. Email is normalized (trim + lowercase) and matched case-insensitively via the unique `customers(account_id, lower(email))` index.
- **First-write-wins for name/metadata.** License creation never mutates an existing customer's name or metadata. Use `PATCH /v1/customers/:id` to update those explicitly.
- **Grant-scoped creation** upserts into the grantor's tenant and writes `customers.created_by_account_id = acting account (grantee)`. Requires `CUSTOMER_CREATE` capability on the grant for inline customers; `CUSTOMER_READ` for attaching to an existing customer by id.
- **Grant-scoped visibility:** `GET /v1/grants/:id/customers` returns only customers where `created_by_account_id = acting account`. A grantee hitting `GET /v1/customers/:id` directly for a customer they did not create returns 404 (not 403 — no existence leak). The vendor's direct `GET /v1/customers` sees ALL customers in their account, with `created_by_account_id` populated to show attribution.
- **`GrantConstraints.CustomerEmailPattern`** (renamed from `LicenseeEmailPattern` in L4) is a Go RE2 regexp matched against the resolved customer email. The server wraps it as `(?i)^(?:<pattern>)$` for full-match case-insensitive semantics — unanchored patterns like `@acme\.com` cannot be bypassed by suffixes. Enforced in `licensing.Service.Create` after the customer is resolved, not in `grant.Service`.
- **Delete** is blocked with 409 `customer_in_use` when the customer has licenses (regardless of status — revoked licenses still pin the customer). Reassign licenses via `PATCH /v1/licenses/:id` body `{customer_id: ...}` first.
- **Tx discipline:** `customer.Service` is pure — no internal transactions. Handlers open `WithTargetAccount` and call service methods. This mirrors `policy.Service` and lets `licensing.Service.Create` call `customers.UpsertForLicense` inside its own tx without nesting.
- **Design spec:** `docs/superpowers/specs/2026-04-15-l4-customers-design.md`.
- **Implementation plan:** `docs/superpowers/plans/2026-04-15-l4-customers.md`.

## Domain Event Log & Webhook Dispatch (O2)

Every domain mutation records a `domain_event` with three-ID attribution via `audit.Writer.Record`, called synchronously in the service layer. The `domain.EventDispatcher` interface from Release 1 is retired.

- **Attribution:** `acting_account_id`, `identity_id`, `api_key_id`, `grant_id`, `actor_kind`, `actor_label` (denormalized at write time), `request_id`, `ip_address`.
- **HTTP surface:** `GET /v1/events` (cursor-paginated, filterable by resource_type, resource_id, event_type, identity_id, grant_id, from, to) + `GET /v1/events/:id`.
- **Webhook delivery** is now a background consumer: the 60s ticker in `background.go` polls `domain_events` via `ListSince` and fans out to matching webhook endpoints. In-process `Dispatch` is retired.
- **Event types:** license.created, license.suspended, license.revoked, license.reinstated, machine.activated, machine.deactivated, machine.checked_in.
- **Package:** `internal/audit/` — Writer + Attribution helper. `internal/db/domain_event_repo.go`.

## Webhook Delivery Log (O3)

Webhook deliveries are surfaced as a sub-resource under `/v1/webhooks/:id/deliveries`. Each `webhook_event` row now carries a `domain_event_id` FK, captured response body (truncated to 2 KiB), response headers, and `next_retry_at`.

- **HTTP surface:** `GET /v1/webhooks/:id/deliveries` (cursor-paginated, filterable by `event_type`, `status`) + `GET /v1/webhooks/:id/deliveries/:delivery_id` + `POST /v1/webhooks/:id/deliveries/:delivery_id/redeliver`.
- **Redeliver:** loads the linked `domain_event`, creates a new `webhook_event` row, dispatches synchronously. Returns 422 `delivery_predates_event_log` if the original delivery has no `domain_event_id`.
- **RBAC:** `webhook:read` for list/get, `webhook:update` for redeliver (existing permissions, no new ones).
- **Migration:** `025_webhook_delivery_log.sql` — extends `webhook_events` with 5 columns + 1 index.

## Metrics Snapshot (O4)

Read-only analytics endpoint returning KPI counts and daily event buckets. No new tables -- uses existing `licenses`, `machines`, `customers`, `grants`, and `domain_events`.

- **HTTP surface:** `GET /v1/metrics?from=<iso>&to=<iso>` -- default 30 days, max 365 days.
- **RBAC:** `metrics:read` (seeded in migration 016 for all preset roles).
- **Architecture:** `internal/analytics/Service` uses `*pgxpool.Pool` directly for read-only aggregate queries. Env-scoped queries (licenses, machines, events) use per-goroutine transactions with RLS session variables. Account-only queries (customers, grants) use direct pool queries with explicit `WHERE account_id = $1`.
- **Parallel fan-out:** License stats, machine stats, customer count, and grant stats run concurrently via `errgroup`. Daily event buckets run sequentially after.
- **Migration:** `026_metrics_indexes.sql` adds partial indexes on `licenses(account_id, environment, status)` and `machines(account_id, environment, status)`.

## Global Search (O5)

`GET /v1/search?q=<query>&types=license,machine,customer,product` -- simple DSL for prefix-match search across resource types with parallel sub-queries.

- **DSL syntax:** `type:X` restricts to one type, `field:value` filters on a whitelisted field, bare words route to each type's primary field (license→key, customer→email, product→slug, machine→fingerprint).
- **Whitelisted fields:** license: key/email/customer_id/status; machine: fingerprint/hostname/license_id; customer: email/name; product: slug/name.
- **Architecture:** `internal/search/` package. Parser (~100 LoC) tokenizes on whitespace. Service fans out sub-queries via `errgroup`, each in its own `WithTargetAccount` tx for RLS scoping. Uses existing repo `List` methods (licenses, customers) or new `Search` methods (products, machines). Limit 10 per type.
- **Auth:** Any authenticated caller can search -- RLS scopes results. No dedicated RBAC permission.
- **No results:** 200 with empty/omitted fields, not 404.

## Lease-Based Machine Liveness (L2)

L2 replaces heartbeat with cryptographically signed lease tokens. Every machine activation issues a `gl2` lease bound to the fingerprint and policy. Clients call `POST /v1/licenses/:id/machines/:fingerprint/checkin` to renew before the lease expires.

- **States:** `active` → `stale` → `dead`. The background `expire_leases` job (60s ticker in `internal/server/background.go`) sweeps via `policies.checkout_grace_sec`. Stale still counts toward `max_machines`; dead does not.
- **Resurrection:** re-activating a dead fingerprint reuses the existing machine row (same ID, audit history preserved). Status flips to active.
- **Lease token format:** `gl2.<base64-payload>.<base64-sig>` — sister to the existing `gl1.` license token. Same Ed25519 product key, same `internal/crypto/` signing pattern. NOT JWT — the spec says JWT but Release 1's actual format is custom; L2 follows Release 1.
- **Test vector** for SDK verifiers lives at `testdata/lease_token_vector.json` — deterministic Ed25519 seed + signed token + decoded payload. Regenerate with `go test -run TestGenerateLeaseTokenVector ./internal/crypto/`.
- **`require_checkout=false` policies:** every machine still gets a lease, but its expiry is bound to `license.expires_at` (or `9999-01-01` for perpetual). The background sweep filters by `require_checkout=true` so these machines never transition to stale/dead.
- **Heartbeat is fully gone:** no endpoint, no service method, no `last_seen_at` column. The `/v1/licenses/:id/heartbeat` endpoint returns 404.
- **`POST /v1/validate`** is unchanged — license-only validation, no lease issuance. Use activate/checkin for machine context.
- **Design spec:** `docs/superpowers/specs/2026-04-15-l2-checkout-design.md`.
- **Implementation plan:** `docs/superpowers/plans/2026-04-15-l2-checkout.md`.

## Entitlements (L3)

First-class entitlement registry with stable `code` values. Entitlements attach to policies (inherited by every license) and optionally per-license (add-only). Effective set = sorted union. Embedded in `gl2` lease tokens and returned in `POST /v1/validate` responses.

- **Code format:** `^[A-Z][A-Z0-9_]{0,63}$`, unique per `(account_id, lower(code))`. Immutable after creation — to rename, delete + recreate. Callers use codes in public APIs, not IDs.
- **Three tables:** `entitlements` (registry), `policy_entitlements` (join, ON DELETE RESTRICT), `license_entitlements` (join, ON DELETE RESTRICT). All account-scoped, env-agnostic.
- **Attach semantics:** POST = idempotent add; PUT = replace entire set; DELETE /:code = single detach. Unknown codes → 422. Attach to policy requires `policy:write`; attach to license requires `license:update`; registry CRUD requires `entitlement:read/write/delete`.
- **Three-set response:** `GET /v1/licenses/:id/entitlements` returns `{policy: [...], license: [...], effective: [...]}`.
- **Lease token population:** `ResolveEffective` (one UNION SQL query) runs on every Activate and Checkin, populating `LeaseClaims.ent`. Newly-attached entitlements are visible at the next checkin.
- **Validate response:** `POST /v1/validate` returns `entitlements: [codes...]` alongside the license.
- **Grant enforcement:** `GrantConstraints.AllowedEntitlementCodes` checks every inline-attached code at license creation time. Rejection → 403 `grant_entitlement_not_allowed`.
- **Delete guard:** 409 `entitlement_in_use` if any policy or license references the entitlement (FK RESTRICT). Detach first.
- **Known limitation:** `require_checkout=false` machines hold long-lived leases. Newly-attached entitlements are not visible to those machines until their next checkin (which may be never). Document explicitly in API guides.
- **Design spec:** `docs/superpowers/specs/2026-04-15-l3-entitlements-design.md`.
- **Implementation plan:** `docs/superpowers/plans/2026-04-15-l3-entitlements.md`.

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
- **Linting**: `.golangci.yml` — errcheck, govet, staticcheck, unused, ineffassign

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
- **Column-list constants are gone (sqlc rewrite, April 2026).** All SELECT lists are generated by sqlc from `.sql` query files; the old `const xColumns = "id, account_id, ..."` pattern that invited ambiguous-column errors in JOINs has been retired. When writing a new JOIN query in sqlc, spell columns with their table alias (`m.id, m.account_id AS membership_account_id, r.id AS role_id_full, ...`) — sqlc uses the aliases as generated struct field names. See `memberships.sql:GetAccountMembershipByIDWithRole` for the canonical JOIN pattern.
- **Stale LSP diagnostics after `make sqlc`.** After regenerating the sqlc files, your editor's language server may continue to report "undefined" errors against the old type shapes for 5-30 seconds. Don't trust `<new-diagnostics>` system messages on freshly-ported code; run `go build ./...` in the terminal to confirm — if the build passes, the LSP is just catching up. This is especially common right after a commit that touches `internal/db/sqlc/gen/`.
