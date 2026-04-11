# Service/Repository Pattern Design

## Summary

Redesign the GetLicense API Go project to use a service/repository pattern with clean separation between HTTP handlers, business logic, and data access. This replaces the original plan where handlers called repositories directly.

## Key Decisions

1. **Handlers separate from services (Option B)** — Services contain pure business logic with no HTTP framework imports. Handlers live in `internal/server/handler/` as thin HTTP adapters.
2. **Repository interfaces in `internal/core/` (Option 1)** — Alongside the models they operate on. One canonical interface per entity.
3. **Transactions via context (Option A)** — `TxManager` wraps operations in transactions, repos extract tx from context. Falls back to pool when no tx is present.

## Package Layout

```
internal/
  core/                    # Shared types, errors, IDs, models, repo interfaces
    errors.go              # ErrorCode, AppError
    ids.go                 # Typed UUID v7 wrappers
    enums.go               # LicenseType, LicenseStatus, UserRole, EventType, etc.
    models.go              # Account, Product, License, Machine, APIKey, etc.
    repositories.go        # All repository interfaces
    tx.go                  # TxManager interface

  crypto/                  # Ed25519, AES-GCM, HMAC, HKDF, token format
    masterkey.go           # HKDF key derivation
    hmac.go                # HMAC-SHA256
    aes.go                 # AES-256-GCM encrypt/decrypt
    ed25519.go             # Keypair gen, sign, verify, encode/decode
    token.go               # gl1 license token sign/verify

  db/                      # All repository implementations + tx manager (PostgreSQL/pgx)
    pool.go                # pgxpool setup
    tx.go                  # TxManager impl (WithTenant, WithTx, context helpers)
    account_repo.go        # implements core.AccountRepository
    user_repo.go           # implements core.UserRepository
    product_repo.go        # implements core.ProductRepository
    license_repo.go        # implements core.LicenseRepository
    machine_repo.go        # implements core.MachineRepository
    apikey_repo.go         # implements core.APIKeyRepository
    webhook_repo.go        # implements core.WebhookRepository
    refresh_token_repo.go  # implements core.RefreshTokenRepository
    migrate.go             # goose migration runner

  auth/                    # AuthService — signup, login, refresh, logout
    service.go             # Service struct + constructor + methods

  product/                 # ProductService — CRUD with keypair generation
    service.go

  licensing/               # LicenseService — create, validate, suspend, revoke
    service.go
    keygen.go              # GETL-XXXX key generation + validation helpers

  machine/                 # MachineService — activate, deactivate, heartbeat
    service.go

  webhook/                 # WebhookService — dispatch + HTTP delivery
    service.go
    deliver.go             # HTTP delivery with retry logic

  server/                  # Fiber app, middleware, route wiring
    app.go                 # Fiber config, error handler, middleware stack
    config.go              # Env var loading
    routes.go              # Route registration (wires handlers to paths)
    background.go          # License expiry background loop
    middleware/
      auth.go              # Dual-mode auth extractor (API key + JWT)
    handler/               # Thin HTTP handlers
      auth.go              # signup, login, refresh, logout, me
      products.go          # product CRUD
      licenses.go          # license lifecycle + machines
      validate.go          # public validation endpoint
      apikeys.go           # API key management
      webhooks.go          # webhook endpoint management
      helpers.go           # pagination params, ID parsing
```

### What Changed From the Original Plan

| Original | New | Why |
|----------|-----|-----|
| `internal/db/` with repos + pool + tenant | `internal/db/` with repos + pool + tx manager | Same package name, but repos now implement interfaces from core |
| `internal/identity/` (password, API key, JWT) | `internal/auth/service.go` + crypto helpers | Identity logic becomes part of auth service; password/JWT helpers stay in crypto |
| `internal/licensing/` (keygen only) | `internal/licensing/service.go` + keygen.go | Service wraps keygen + validation + repo calls |
| `internal/machines/` (enforcement only) | `internal/machine/service.go` | Service wraps enforcement + repo calls |
| `internal/webhook/` (delivery only) | `internal/webhook/service.go` + deliver.go | Service handles dispatch + delivery |
| `internal/server/handlers/` calling repos directly | `internal/server/handler/` calling services | Handlers are thin; all logic in services |
| No service layer | Service per domain | Business logic has a proper home |

### Packages Removed

- `internal/identity/` — password hashing (`HashPassword`, `VerifyPassword`) and API key generation (`GenerateAPIKey`, `GenerateRefreshToken`) move to `internal/crypto/` as utility functions. JWT signing/verification also lives in `internal/crypto/jwt.go`. The `auth` service consumes these directly.
- `internal/server/middleware/` handler sub-package for middleware stays, but middleware is simpler since auth resolution no longer does DB lookups — it delegates to the auth service or directly uses crypto utilities.

## Core Interfaces

### TxManager

```go
// internal/core/tx.go
package core

import "context"

// TxManager provides transactional boundaries for service operations.
type TxManager interface {
    // WithTenant runs fn in a transaction with RLS tenant context set.
    // All repository calls within fn that use the returned context
    // will execute within this transaction and be scoped to the tenant.
    WithTenant(ctx context.Context, accountID AccountID, fn func(ctx context.Context) error) error

    // WithTx runs fn in a plain transaction without tenant context.
    // Used for global operations like signup where no tenant exists yet.
    WithTx(ctx context.Context, fn func(ctx context.Context) error) error
}
```

### Repository Interfaces

```go
// internal/core/repositories.go
package core

import "context"

type AccountRepository interface {
    Create(ctx context.Context, account *Account) error
    GetByID(ctx context.Context, id AccountID) (*Account, error)
    GetBySlug(ctx context.Context, slug string) (*Account, error)
}

type UserRepository interface {
    Create(ctx context.Context, user *User) error
    GetByID(ctx context.Context, id UserID) (*User, error)
    GetByEmail(ctx context.Context, email string) (*User, error)
}

type ProductRepository interface {
    Create(ctx context.Context, product *Product) error
    GetByID(ctx context.Context, id ProductID) (*Product, error)
    List(ctx context.Context, limit, offset int) ([]Product, int, error)
    Update(ctx context.Context, id ProductID, params UpdateProductParams) (*Product, error)
    Delete(ctx context.Context, id ProductID) error
}

type LicenseRepository interface {
    Create(ctx context.Context, license *License) error
    GetByID(ctx context.Context, id LicenseID) (*License, error)
    GetByKeyHash(ctx context.Context, keyHash string) (*License, error)
    List(ctx context.Context, limit, offset int) ([]License, int, error)
    UpdateStatus(ctx context.Context, id LicenseID, status LicenseStatus) error
    ExpireActive(ctx context.Context) ([]License, error)
}

type MachineRepository interface {
    Create(ctx context.Context, machine *Machine) error
    GetByFingerprint(ctx context.Context, licenseID LicenseID, fingerprint string) (*Machine, error)
    CountByLicense(ctx context.Context, licenseID LicenseID) (int, error)
    DeleteByFingerprint(ctx context.Context, licenseID LicenseID, fingerprint string) error
    UpdateHeartbeat(ctx context.Context, licenseID LicenseID, fingerprint string) (*Machine, error)
}

type APIKeyRepository interface {
    Create(ctx context.Context, key *APIKey) error
    GetByHash(ctx context.Context, keyHash string) (*APIKey, error)
    ListByAccount(ctx context.Context, limit, offset int) ([]APIKey, int, error)
    Delete(ctx context.Context, id APIKeyID) error
}

type WebhookRepository interface {
    CreateEndpoint(ctx context.Context, ep *WebhookEndpoint) error
    ListEndpoints(ctx context.Context, limit, offset int) ([]WebhookEndpoint, int, error)
    DeleteEndpoint(ctx context.Context, id WebhookEndpointID) error
    GetActiveEndpointsByEvent(ctx context.Context, eventType EventType) ([]WebhookEndpoint, error)
    CreateEvent(ctx context.Context, event *WebhookEvent) error
    UpdateEventStatus(ctx context.Context, id WebhookEventID, status DeliveryStatus, attempts int, responseStatus *int) error
}

type RefreshTokenRepository interface {
    Create(ctx context.Context, token *RefreshToken) error
    GetByHash(ctx context.Context, tokenHash string) (*RefreshToken, error)
    DeleteByHash(ctx context.Context, tokenHash string) error
    DeleteByUserID(ctx context.Context, userID UserID) error
}
```

### UpdateProductParams

```go
// internal/core/models.go (add to existing file)

// UpdateProductParams holds optional fields for a product update.
type UpdateProductParams struct {
    Name          *string
    ValidationTTL *int
    GracePeriod   *int
    Metadata      *json.RawMessage
}
```

## Data Flow

### Request Flow

```
HTTP Request
  → Fiber middleware (auth extractor)
  → Handler (parse request, extract auth)
  → Service method (business logic, calls txManager + repos)
  → Repository (SQL via pgx, tx from context)
  → PostgreSQL (RLS enforced)
```

### Transaction Flow

```
Service.Method(ctx, accountID, req)
  → txManager.WithTenant(ctx, accountID, func(ctx) {
       repo.GetByID(ctx, ...)    // uses tx from ctx, scoped to tenant
       repo.Create(ctx, ...)     // same tx, same tenant
     })
  → tx committed on nil error, rolled back on error
```

### Auth Middleware Flow

```
Request with "Authorization: Bearer <token>"
  → If prefix "gl_live_" or "gl_test_": HMAC hash → apiKeyRepo.GetByHash(ctx) → AuthenticatedAccount
  → If JWT: verify with masterKey.JWTSigningKey → AuthenticatedAccount
  → Store in Fiber locals for handlers to access
```

Note: The auth middleware needs the `APIKeyRepository` and `MasterKey` directly (not via a service) because it runs before any service call. This is the one place where a repo is used outside a service — it's acceptable because auth middleware IS infrastructure, not business logic.

## Service Contracts

### AuthService

```go
type Service struct {
    txManager   core.TxManager
    accounts    core.AccountRepository
    users       core.UserRepository
    apiKeys     core.APIKeyRepository
    refreshTkns core.RefreshTokenRepository
    masterKey   *crypto.MasterKey
}

// Methods:
Signup(ctx, SignupRequest) → (*SignupResult, error)
Login(ctx, LoginRequest) → (*LoginResult, error)
Refresh(ctx, refreshToken string) → (*LoginResult, error)
Logout(ctx, refreshToken string) → error
GetMe(ctx, accountID, *userID) → (*MeResult, error)
```

### ProductService

```go
type Service struct {
    txManager core.TxManager
    products  core.ProductRepository
    masterKey *crypto.MasterKey
}

// Methods:
Create(ctx, accountID, CreateProductRequest) → (*Product, error)
List(ctx, accountID, limit, offset) → ([]Product, int, error)
Get(ctx, accountID, productID) → (*Product, error)
Update(ctx, accountID, productID, UpdateProductRequest) → (*Product, error)
Delete(ctx, accountID, productID) → error
```

### LicenseService

```go
type Service struct {
    txManager core.TxManager
    licenses  core.LicenseRepository
    products  core.ProductRepository
    machines  core.MachineRepository
    masterKey *crypto.MasterKey
}

// Methods:
Create(ctx, accountID, productID, CreateLicenseRequest) → (*CreateLicenseResult, error)
List(ctx, accountID, limit, offset) → ([]License, int, error)
Get(ctx, accountID, licenseID) → (*License, error)
Revoke(ctx, accountID, licenseID) → error
Suspend(ctx, accountID, licenseID) → (*License, error)
Reinstate(ctx, accountID, licenseID) → (*License, error)
Validate(ctx, licenseKey string) → (*ValidateResult, error)
Activate(ctx, accountID, licenseID, ActivateRequest) → (*Machine, error)
Deactivate(ctx, accountID, licenseID, DeactivateRequest) → error
Heartbeat(ctx, accountID, licenseID, HeartbeatRequest) → (*Machine, error)
```

Note: `Validate` is a global operation (no accountID) — it uses `GetByKeyHash` which works without tenant context. Machine operations live on LicenseService because they're tightly coupled to license state (checking machine limits, license status).

### WebhookService

```go
type Service struct {
    txManager core.TxManager
    webhooks  core.WebhookRepository
}

// Methods:
CreateEndpoint(ctx, accountID, CreateWebhookRequest) → (*WebhookEndpoint, error)
ListEndpoints(ctx, accountID, limit, offset) → ([]WebhookEndpoint, int, error)
DeleteEndpoint(ctx, accountID, endpointID) → error
Dispatch(ctx, accountID, eventType, payload) → error   // async delivery
```

### APIKeyService (or just methods on AuthService)

API key management is thin enough to live on AuthService. If it grows, it can be extracted.

## db Package — Context-Based Transaction Extraction

```go
// internal/db/tx.go

type ctxKey struct{}

// TxManager implements core.TxManager using pgxpool.
type TxManager struct {
    pool *pgxpool.Pool
}

func (m *TxManager) WithTenant(ctx context.Context, accountID core.AccountID, fn func(context.Context) error) error {
    tx, err := m.pool.Begin(ctx)
    if err != nil {
        return err
    }
    defer tx.Rollback(ctx)

    _, err = tx.Exec(ctx, "SET LOCAL app.current_account_id = $1", accountID.String())
    if err != nil {
        return err
    }

    ctx = context.WithValue(ctx, ctxKey{}, tx)
    if err := fn(ctx); err != nil {
        return err
    }
    return tx.Commit(ctx)
}

func (m *TxManager) WithTx(ctx context.Context, fn func(context.Context) error) error {
    tx, err := m.pool.Begin(ctx)
    if err != nil {
        return err
    }
    defer tx.Rollback(ctx)

    ctx = context.WithValue(ctx, ctxKey{}, tx)
    if err := fn(ctx); err != nil {
        return err
    }
    return tx.Commit(ctx)
}

// conn returns the tx from context, or falls back to the pool.
// This allows repos to work both within and outside transactions.
func conn(ctx context.Context, pool *pgxpool.Pool) querier {
    if tx, ok := ctx.Value(ctxKey{}).(pgx.Tx); ok {
        return tx
    }
    return pool
}
```

Repository implementations use `conn(ctx, r.pool)` for every query:

```go
// internal/db/product_repo.go
type ProductRepo struct {
    pool *pgxpool.Pool
}

func (r *ProductRepo) GetByID(ctx context.Context, id core.ProductID) (*core.Product, error) {
    q := conn(ctx, r.pool)
    row := q.QueryRow(ctx, "SELECT ... FROM products WHERE id = $1", id.UUID)
    // scan and return
}
```

## Handler Pattern

Every handler follows the same shape:

```go
// internal/server/handler/products.go
type ProductHandler struct {
    svc *product.Service
}

func NewProductHandler(svc *product.Service) *ProductHandler {
    return &ProductHandler{svc: svc}
}

func (h *ProductHandler) Create(c fiber.Ctx) error {
    var req product.CreateRequest
    if err := c.Bind().Body(&req); err != nil {
        return err
    }
    auth := middleware.FromContext(c)

    result, err := h.svc.Create(c.Context(), auth.AccountID, req)
    if err != nil {
        return err  // AppError flows to Fiber ErrorHandler
    }
    return c.Status(fiber.StatusCreated).JSON(result)
}
```

Handlers are 5-15 lines: parse, auth, call service, respond. No business logic.

## Route Wiring

```go
// internal/server/routes.go
func registerRoutes(app *fiber.App, deps *Deps) {
    v1 := app.Group("/v1")

    authMw := middleware.RequireAuth(deps.APIKeyRepo, deps.MasterKey)

    // Auth (public)
    ah := handler.NewAuthHandler(deps.AuthService)
    v1.Post("/auth/signup", ah.Signup)
    v1.Post("/auth/login", ah.Login)
    v1.Post("/auth/refresh", ah.Refresh)
    v1.Post("/auth/logout", ah.Logout)
    v1.Get("/auth/me", authMw, ah.Me)

    // Products
    ph := handler.NewProductHandler(deps.ProductService)
    products := v1.Group("/products", authMw)
    products.Post("/", ph.Create)
    products.Get("/", ph.List)
    // ...

    // Validate (public)
    vh := handler.NewValidateHandler(deps.LicenseService)
    v1.Post("/validate", vh.Validate)
}
```

## Composition Root

```go
// cmd/server/main.go (serve command)
pool := db.NewPool(ctx, cfg.DatabaseURL)
txManager := db.NewTxManager(pool)

// Repos
accountRepo := db.NewAccountRepo(pool)
userRepo := db.NewUserRepo(pool)
productRepo := db.NewProductRepo(pool)
licenseRepo := db.NewLicenseRepo(pool)
machineRepo := db.NewMachineRepo(pool)
apiKeyRepo := db.NewAPIKeyRepo(pool)
webhookRepo := db.NewWebhookRepo(pool)
refreshTokenRepo := db.NewRefreshTokenRepo(pool)

// Services
authSvc := auth.NewService(txManager, accountRepo, userRepo, apiKeyRepo, refreshTokenRepo, masterKey)
productSvc := product.NewService(txManager, productRepo, masterKey)
licenseSvc := licensing.NewService(txManager, licenseRepo, productRepo, machineRepo, masterKey)
machineSvc := machine.NewService(txManager, machineRepo, licenseRepo)
webhookSvc := webhook.NewService(txManager, webhookRepo)

// Wire into Fiber app
deps := server.Deps{...all services + apiKeyRepo + masterKey for auth middleware...}
app := server.NewApp(deps)
```

## Testing Strategy

Services are testable with mock repositories (generated or hand-written). Handlers are testable with mock services. Integration tests hit real Postgres.

```go
// Unit test a service
func TestLicenseService_Create(t *testing.T) {
    productRepo := &mockProductRepo{...}
    licenseRepo := &mockLicenseRepo{...}
    txManager := &mockTxManager{...}  // just calls fn(ctx) directly
    svc := licensing.NewService(txManager, licenseRepo, productRepo, nil, testMasterKey)

    result, err := svc.Create(ctx, accountID, req)
    assert.NoError(t, err)
    assert.Equal(t, "active", string(result.License.Status))
}
```

## Crypto Utility Functions (Moved From identity/)

The following functions live in `internal/crypto/` as package-level utilities:

- `HashPassword(password string) (string, error)` — Argon2id
- `VerifyPassword(encoded, password string) bool`
- `GenerateAPIKey(environment string) (raw, prefix string, err error)`
- `GenerateRefreshToken() (string, error)`
- `SignJWT(claims JWTClaims, key []byte, ttl time.Duration) (string, error)`
- `VerifyJWT(token string, key []byte) (*JWTClaims, error)`

These are stateless crypto operations. They don't need their own package — `crypto` is their natural home.
