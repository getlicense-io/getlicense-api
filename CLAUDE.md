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
├── core/                        # System language (IDs, enums, errors) — zero deps
├── domain/                      # Business contracts (models, repo interfaces, TxManager)
├── crypto/                      # Ed25519, AES-GCM, HMAC, HKDF, token format, password, JWT
├── db/                          # PostgreSQL — pool, TxManager impl, all repo implementations
├── auth/                        # AuthService — signup, login, refresh, logout, me, API keys
├── product/                     # ProductService — CRUD with Ed25519 keypair generation
├── licensing/                   # LicenseService — create, validate, suspend, revoke, machines
├── webhook/                     # WebhookService — endpoint CRUD, dispatch, delivery with retries
└── server/                      # Fiber v3 app, middleware, handlers, routes, background jobs
    ├── middleware/               # Dual-mode auth extractor (API key + JWT)
    └── handler/                  # HTTP handlers grouped by domain
migrations/                      # goose SQL migrations (001-012)
e2e/scenarios/                   # hurl e2e test scenarios
```

## Data Flow

```go
// Handler: parse request, get auth, call service, return JSON
func (h *ProductHandler) Create(c fiber.Ctx) error {
    var req product.CreateRequest
    if err := c.Bind().Body(&req); err != nil { return err }
    a := middleware.FromContext(c)
    result, err := h.svc.Create(c.Context(), a.AccountID, a.Environment, req)
    if err != nil { return err }
    return c.Status(fiber.StatusCreated).JSON(result)
}

// Service: business logic, uses TxManager for transactions
func (s *Service) Create(ctx context.Context, accountID core.AccountID, env core.Environment, req CreateRequest) (*domain.Product, error) {
    var result *domain.Product
    err := s.txManager.WithTenant(ctx, accountID, env, func(ctx context.Context) error {
        // ... business logic, repo calls within transaction
    })
    return result, err
}
```

## Transactions & RLS

- `domain.TxManager` interface: `WithTenant(ctx, accountID, env, fn)` and `WithTx(ctx, fn)`
- `WithTenant` sets both `app.current_account_id` and `app.current_environment` via `set_config()` for RLS enforcement
- Repos extract tx from context via `conn(ctx, pool)` — falls back to pool if no tx
- Global queries (login, API key lookup, validate) skip tenant context — RLS allows NULL
- Background jobs run without environment context — the `IS NULL` escape hatch processes all environments

**Critical RLS pattern** in migrations:
```sql
(NULLIF(current_setting('app.current_account_id', true), '') IS NULL
 OR account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid)
AND
(NULLIF(current_setting('app.current_environment', true), '') IS NULL
 OR environment = current_setting('app.current_environment', true))
```

## Environment Isolation (test/live)

- API keys carry an `environment` field (`live` or `test`)
- Auth middleware populates `AuthenticatedAccount.Environment` from the API key; JWT defaults to `live`
- All service methods pass `env` through to `WithTenant` → RLS filters by environment automatically
- Licenses, machines, webhook endpoints, and webhook events have an `environment` column
- Products are environment-agnostic — they exist in both environments

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
