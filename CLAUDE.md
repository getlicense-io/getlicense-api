# GetLicense API — Project Conventions

## Quick Start

```bash
make run          # start Postgres + run migrations + start server (development mode)
make e2e          # full teardown + fresh DB + hurl e2e tests (9 scenarios)
make test         # unit tests (no DB required)
make test-all     # unit + integration tests (requires Postgres)
```

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
migrations/                      # goose SQL migrations (001-010)
e2e/scenarios/                   # hurl e2e test scenarios
```

## Data Flow

```go
// Handler: parse request, get auth, call service, return JSON
func (h *ProductHandler) Create(c fiber.Ctx) error {
    var req product.CreateRequest
    if err := c.Bind().Body(&req); err != nil { return err }
    auth := middleware.FromContext(c)
    result, err := h.svc.Create(c.Context(), auth.AccountID, req)
    if err != nil { return err }
    return c.Status(fiber.StatusCreated).JSON(result)
}

// Service: business logic, uses TxManager for transactions
func (s *Service) Create(ctx context.Context, accountID core.AccountID, req CreateRequest) (*domain.Product, error) {
    var result *domain.Product
    err := s.txManager.WithTenant(ctx, accountID, func(ctx context.Context) error {
        // ... business logic, repo calls within transaction
    })
    return result, err
}
```

## Transactions & RLS

- `domain.TxManager` interface: `WithTenant(ctx, accountID, fn)` and `WithTx(ctx, fn)`
- `WithTenant` sets `SET LOCAL app.current_account_id = '<uuid>'` for RLS enforcement
- Repos extract tx from context via `conn(ctx, pool)` — falls back to pool if no tx
- Global queries (login, API key lookup, validate) skip tenant context — RLS allows NULL

**Critical RLS pattern** in migrations:
```sql
NULLIF(current_setting('app.current_account_id', true), '') IS NULL
OR account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid
```

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
