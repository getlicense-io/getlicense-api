# GetLicense API (Go) Implementation Plan v2

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the GetLicense API — a self-hostable software licensing platform — as a Go modular monolith using a service/repository pattern with Fiber v3, pgx v5, and stdlib crypto.

**Architecture:** Service/Repository pattern. Handlers (thin HTTP adapters in `server/handler/`) → Services (business logic in domain packages) → Repositories (interfaces in `core/`, implementations in `db/`). Transactions via context — `TxManager.WithTenant()` sets RLS tenant context, repos extract tx from context. No business logic in handlers.

**Tech Stack:** Go 1.24+, Fiber v3 (gofiber/fiber), pgx v5, goose migrations, cobra CLI, go-playground/validator, golang.org/x/crypto (argon2, hkdf), google/uuid v7, stretchr/testify

**Module:** `github.com/getlicense-io/getlicense-api`

**Working directory:** `/Users/netf/Projects/getlicense/getlicense-api`

**Completed work:** Tasks 1-3 from the original plan are done — project scaffolding, core types (errors, IDs), and domain models/enums exist in `internal/core/`.

**Design spec:** `docs/superpowers/specs/2026-04-11-service-repo-pattern-design.md`

---

## File Map

### Already exists (DO NOT recreate)
- `cmd/server/main.go` — minimal placeholder
- `internal/core/errors.go` — ErrorCode, AppError, HTTP status mapping
- `internal/core/ids.go` — AccountID, UserID, ProductID, LicenseID, MachineID, APIKeyID, WebhookEndpointID, WebhookEventID
- `internal/core/enums.go` — LicenseType, LicenseStatus, UserRole, APIKeyScope, DeliveryStatus, EventType, prefix constants
- `internal/core/models.go` — Account, User, Product, License, Machine, APIKey, WebhookEndpoint, WebhookEvent, RefreshToken, Pagination, ListResponse
- `internal/core/*_test.go` — all tests for above
- `Makefile`, `docker/Dockerfile`, `docker/docker-compose.yml`, `.env.example`, `.gitignore`

### To create
```
internal/
  core/
    repositories.go          # Task 1: all repository interfaces
    tx.go                    # Task 1: TxManager interface

  crypto/
    masterkey.go             # Task 2: HKDF-SHA256 key derivation
    masterkey_test.go        # Task 2
    hmac.go                  # Task 2: HMAC-SHA256
    hmac_test.go             # Task 2
    aes.go                   # Task 2: AES-256-GCM encrypt/decrypt
    aes_test.go              # Task 2
    ed25519.go               # Task 2: keypair, sign, verify, encode/decode
    ed25519_test.go          # Task 2
    token.go                 # Task 3: gl1 license token format
    token_test.go            # Task 3
    password.go              # Task 4: Argon2id hash/verify
    password_test.go         # Task 4
    apikey.go                # Task 4: API key + refresh token generation
    apikey_test.go           # Task 4
    jwt.go                   # Task 4: JWT sign/verify
    jwt_test.go              # Task 4

  db/
    pool.go                  # Task 6: pgxpool setup
    tx.go                    # Task 6: TxManager impl, conn() helper
    tx_test.go               # Task 6
    account_repo.go          # Task 7: implements core.AccountRepository
    user_repo.go             # Task 7: implements core.UserRepository
    apikey_repo.go           # Task 7: implements core.APIKeyRepository
    refresh_token_repo.go    # Task 7: implements core.RefreshTokenRepository
    product_repo.go          # Task 7: implements core.ProductRepository
    license_repo.go          # Task 7: implements core.LicenseRepository
    machine_repo.go          # Task 7: implements core.MachineRepository
    webhook_repo.go          # Task 7: implements core.WebhookRepository
    migrate.go               # Task 6: goose runner

  auth/
    service.go               # Task 8: signup, login, refresh, logout, me, create/list/delete API keys
    service_test.go          # Task 8

  product/
    service.go               # Task 9: CRUD with keypair generation
    service_test.go          # Task 9

  licensing/
    service.go               # Task 10: create, validate, suspend, revoke, activate, deactivate, heartbeat
    service_test.go          # Task 10
    keygen.go                # Task 10: GETL-XXXX key generation
    keygen_test.go           # Task 10

  webhook/
    service.go               # Task 11: endpoint CRUD + dispatch
    deliver.go               # Task 11: HTTP delivery with retries
    deliver_test.go          # Task 11

  server/
    app.go                   # Task 12: Fiber app, error handler, middleware stack
    config.go                # Task 12: env loading
    deps.go                  # Task 12: Deps container
    routes.go                # Task 14: route registration
    background.go            # Task 14: license expiry loop
    middleware/
      auth.go                # Task 13: dual-mode auth extractor
    handler/
      helpers.go             # Task 14: pagination, ID parsing
      auth.go                # Task 14: auth handlers
      products.go            # Task 14: product handlers
      licenses.go            # Task 14: license + machine handlers
      validate.go            # Task 14: public validation handler
      apikeys.go             # Task 14: API key handlers
      webhooks.go            # Task 14: webhook handlers

migrations/
  001_accounts.sql           # Task 5
  002_users.sql              # Task 5
  003_products.sql           # Task 5
  004_api_keys.sql           # Task 5
  005_licenses.sql           # Task 5
  006_machines.sql           # Task 5
  007_webhook_endpoints.sql  # Task 5
  008_webhook_events.sql     # Task 5
  009_refresh_tokens.sql     # Task 5
  010_rls_policies.sql       # Task 5

e2e/scenarios/*.hurl         # Task 17
```

### To clean up
- Delete: `internal/identity/.gitkeep` (package removed)
- Delete: `internal/machines/.gitkeep` (no longer used; machine service is separate)
- Delete: `internal/crypto/.gitkeep`, `internal/db/.gitkeep`, `internal/server/.gitkeep`, `internal/webhook/.gitkeep` (replaced by real files)

---

## Phase A: Core Interfaces

### Task 1: Core — Repository Interfaces and TxManager

**Files:**
- Create: `internal/core/repositories.go`
- Create: `internal/core/tx.go`
- Modify: `internal/core/models.go` (add UpdateProductParams)

- [ ] **Step 1: Create TxManager interface**

`internal/core/tx.go`:
```go
package core

import "context"

// TxManager provides transactional boundaries for service operations.
type TxManager interface {
	// WithTenant runs fn in a transaction with RLS tenant context set.
	WithTenant(ctx context.Context, accountID AccountID, fn func(ctx context.Context) error) error

	// WithTx runs fn in a plain transaction without tenant context.
	// Used for global operations like signup where no tenant exists yet.
	WithTx(ctx context.Context, fn func(ctx context.Context) error) error
}
```

- [ ] **Step 2: Create repository interfaces**

`internal/core/repositories.go`:
```go
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

- [ ] **Step 3: Add UpdateProductParams to models.go**

Add to end of `internal/core/models.go`:
```go
// UpdateProductParams holds optional fields for a product update.
type UpdateProductParams struct {
	Name          *string          `json:"name,omitempty"`
	ValidationTTL *int             `json:"validation_ttl,omitempty"`
	GracePeriod   *int             `json:"grace_period,omitempty"`
	Metadata      *json.RawMessage `json:"metadata,omitempty"`
}
```

- [ ] **Step 4: Verify compilation**

```bash
go vet ./internal/core/...
go test ./internal/core/ -count=1
```

Expected: all pass, no errors.

- [ ] **Step 5: Commit**

```bash
git add internal/core/repositories.go internal/core/tx.go internal/core/models.go
git commit -m "feat(core): repository interfaces and TxManager interface"
```

---

## Phase B: Crypto

### Task 2: Crypto — Master Key, HMAC, AES-GCM, Ed25519

**Files:**
- Create: `internal/crypto/masterkey.go`, `internal/crypto/masterkey_test.go`
- Create: `internal/crypto/hmac.go`, `internal/crypto/hmac_test.go`
- Create: `internal/crypto/aes.go`, `internal/crypto/aes_test.go`
- Create: `internal/crypto/ed25519.go`, `internal/crypto/ed25519_test.go`
- Delete: `internal/crypto/.gitkeep`

This task implements four crypto primitives. All pure Go, no CGO.

**masterkey.go** — `MasterKey` struct with `HMACKey`, `EncryptionKey`, `JWTSigningKey` (each 32 bytes). `NewMasterKey(hexKey string) (*MasterKey, error)` — hex key must be >= 64 chars (32 bytes). Derive via HKDF-SHA256 with context strings: `"getlicense-hmac-key"`, `"getlicense-encryption-key"`, `"getlicense-jwt-signing-key"`. No salt (nil). Uses `golang.org/x/crypto/hkdf`.

**hmac.go** — `HMACSHA256(key []byte, data string) string` returns hex digest. `HMACSHA256Sign(key, payload []byte) string` returns hex digest. Uses `crypto/hmac` + `crypto/sha256`.

**aes.go** — `EncryptAESGCM(key, plaintext []byte) ([]byte, error)` — 32-byte key, 12-byte random nonce, output format `[nonce (12)] || [ciphertext + tag]`. `DecryptAESGCM(key, ciphertext []byte) ([]byte, error)`. Uses `crypto/aes` + `crypto/cipher` + `crypto/rand`.

**ed25519.go** — `GenerateEd25519Keypair() (ed25519.PublicKey, ed25519.PrivateKey, error)`, `Ed25519Sign(priv, msg) []byte`, `Ed25519Verify(pub, msg, sig) bool`, `EncodePublicKey(pub) string` (base64url, no padding), `DecodePublicKey(encoded) (PublicKey, error)`. Uses `crypto/ed25519`.

**Tests (table-driven):**
- MasterKey: valid key, too short, invalid hex, deterministic, derived keys differ
- HMAC: deterministic, different inputs/keys → different output, 64-char hex output
- AES-GCM: roundtrip, different ciphertext each time, wrong key fails, tampered fails, format length check
- Ed25519: key sizes, sign/verify, tampered fails, wrong key fails, encode/decode roundtrip

- [ ] **Step 1: Write all test files**
- [ ] **Step 2: Run tests — verify compilation failure**
- [ ] **Step 3: Implement all four files**
- [ ] **Step 4: Run tests — all pass**

```bash
go get golang.org/x/crypto
go test ./internal/crypto/ -v -count=1
```

- [ ] **Step 5: Commit**

```bash
git add internal/crypto/
git commit -m "feat(crypto): master key derivation, HMAC-SHA256, AES-256-GCM, Ed25519"
```

---

### Task 3: Crypto — License Token Format

**Files:**
- Create: `internal/crypto/token.go`, `internal/crypto/token_test.go`

**token.go** — Format: `gl1.<base64url-payload>.<base64url-signature>`

```go
type TokenPayload struct {
	Version      int              `json:"v"`
	ProductID    string           `json:"pid"`
	LicenseID    string           `json:"lid"`
	Type         string           `json:"type"`
	Status       string           `json:"status"`
	Entitlements json.RawMessage  `json:"ent,omitempty"`
	MaxMachines  *int             `json:"max_m,omitempty"`
	IssuedAt     int64            `json:"iat"`
	ExpiresAt    *int64           `json:"exp,omitempty"`
	TTL          int              `json:"ttl"`
}

func SignToken(payload TokenPayload, priv ed25519.PrivateKey) (string, error)
func VerifyToken(token string, pub ed25519.PublicKey) (*TokenPayload, error)
```

Signing: JSON marshal → base64url encode → sign the base64url string → `gl1.{payload_b64}.{sig_b64}`.
Verification: split on `.`, check `gl1` prefix, verify signature against payload_b64, decode payload JSON.

**Tests:** roundtrip, invalid prefix, tampered payload, wrong key.

- [ ] **Step 1: Write test file**
- [ ] **Step 2: Implement**
- [ ] **Step 3: Run tests**

```bash
go test ./internal/crypto/ -v -count=1 -run TestToken
```

- [ ] **Step 4: Commit**

```bash
git add internal/crypto/token.go internal/crypto/token_test.go
git commit -m "feat(crypto): gl1 license token signing and verification"
```

---

### Task 4: Crypto — Password Hashing, API Key Gen, JWT

**Files:**
- Create: `internal/crypto/password.go`, `internal/crypto/password_test.go`
- Create: `internal/crypto/apikey.go`, `internal/crypto/apikey_test.go`
- Create: `internal/crypto/jwt.go`, `internal/crypto/jwt_test.go`

**password.go** — Argon2id with parameters: time=1, memory=64*1024, threads=4, keyLen=32, saltLen=16.

```go
func HashPassword(password string) (string, error)       // returns $argon2id$... encoded string
func VerifyPassword(encoded, password string) bool        // constant-time comparison
```

**apikey.go** — API key and refresh token generation.

```go
func GenerateAPIKey(environment string) (raw, prefix string, err error)
// "live" → "gl_live_" + 64 hex chars (32 bytes entropy)
// "test" → "gl_test_" + 64 hex chars
// prefix = first 20 chars of raw key

func GenerateRefreshToken() (string, error)
// "rt_" + 64 hex chars (32 bytes entropy)
```

Uses `core.APIKeyPrefixLive`, `core.APIKeyPrefixTest`, `core.RefreshTokenPrefix` constants.

**jwt.go** — JWT access tokens with HMAC-SHA256.

```go
type JWTClaims struct {
	UserID    core.UserID
	AccountID core.AccountID
	Role      core.UserRole
}

func SignJWT(claims JWTClaims, signingKey []byte, ttl time.Duration) (string, error)
func VerifyJWT(tokenStr string, signingKey []byte) (*JWTClaims, error)
```

Uses `github.com/golang-jwt/jwt/v5`.

**Tests:**
- Password: roundtrip, wrong password fails, unique hashes (different salt)
- API key: live/test format, prefix length 20, key length, uniqueness, refresh token format
- JWT: roundtrip, expired fails, wrong key fails

- [ ] **Step 1: Write all test files**
- [ ] **Step 2: Implement all three files**
- [ ] **Step 3: Run tests**

```bash
go get github.com/golang-jwt/jwt/v5
go test ./internal/crypto/ -v -count=1
```

- [ ] **Step 4: Commit**

```bash
git add internal/crypto/
git commit -m "feat(crypto): Argon2id password hashing, API key generation, JWT sign/verify"
```

---

## Phase C: Database

### Task 5: Database Migrations

**Files:**
- Create: `migrations/001_accounts.sql` through `migrations/010_rls_policies.sql`
- Delete: `migrations/.gitkeep`

10 SQL migrations using goose format (`-- +goose Up` / `-- +goose Down`). Tables: accounts, users, products, api_keys, licenses, machines, webhook_endpoints, webhook_events, refresh_tokens. Final migration enables RLS on all tenant-scoped tables with the `NULLIF(current_setting('app.current_account_id', true), '')` pattern.

Exact SQL for each migration:

**001_accounts.sql:**
```sql
-- +goose Up
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE TABLE accounts (
    id UUID PRIMARY KEY, name TEXT NOT NULL, slug TEXT NOT NULL UNIQUE, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
-- +goose Down
DROP TABLE IF EXISTS accounts;
```

**002_users.sql:**
```sql
-- +goose Up
CREATE TABLE users (
    id UUID PRIMARY KEY, account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'member',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_users_account_id ON users (account_id);
-- +goose Down
DROP TABLE IF EXISTS users;
```

**003_products.sql:**
```sql
-- +goose Up
CREATE TABLE products (
    id UUID PRIMARY KEY, account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    name TEXT NOT NULL, slug TEXT NOT NULL, public_key TEXT NOT NULL, private_key_enc BYTEA NOT NULL,
    validation_ttl INTEGER NOT NULL DEFAULT 86400, grace_period INTEGER NOT NULL DEFAULT 604800,
    metadata JSONB, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (account_id, slug)
);
CREATE INDEX idx_products_account_id ON products (account_id);
-- +goose Down
DROP TABLE IF EXISTS products;
```

**004_api_keys.sql:**
```sql
-- +goose Up
CREATE TABLE api_keys (
    id UUID PRIMARY KEY, account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    product_id UUID REFERENCES products(id) ON DELETE CASCADE,
    prefix TEXT NOT NULL, key_hash TEXT NOT NULL UNIQUE, scope TEXT NOT NULL DEFAULT 'account_wide',
    label TEXT, environment TEXT NOT NULL DEFAULT 'live', expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_api_keys_account_id ON api_keys (account_id);
CREATE INDEX idx_api_keys_key_hash ON api_keys (key_hash);
-- +goose Down
DROP TABLE IF EXISTS api_keys;
```

**005_licenses.sql:**
```sql
-- +goose Up
CREATE TABLE licenses (
    id UUID PRIMARY KEY, account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    product_id UUID NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    key_prefix TEXT NOT NULL, key_hash TEXT NOT NULL UNIQUE, token TEXT NOT NULL,
    license_type TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active',
    max_machines INTEGER, max_seats INTEGER, entitlements JSONB,
    licensee_name TEXT, licensee_email TEXT, expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_licenses_account_id ON licenses (account_id);
CREATE INDEX idx_licenses_product_id ON licenses (product_id);
CREATE INDEX idx_licenses_status ON licenses (status);
CREATE INDEX idx_licenses_active_expiry ON licenses (expires_at) WHERE status = 'active' AND expires_at IS NOT NULL;
-- +goose Down
DROP TABLE IF EXISTS licenses;
```

**006_machines.sql:**
```sql
-- +goose Up
CREATE TABLE machines (
    id UUID PRIMARY KEY, account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    license_id UUID NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL, hostname TEXT, metadata JSONB,
    last_seen_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (license_id, fingerprint)
);
CREATE INDEX idx_machines_account_id ON machines (account_id);
CREATE INDEX idx_machines_license_id ON machines (license_id);
-- +goose Down
DROP TABLE IF EXISTS machines;
```

**007_webhook_endpoints.sql:**
```sql
-- +goose Up
CREATE TABLE webhook_endpoints (
    id UUID PRIMARY KEY, account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    url TEXT NOT NULL, events TEXT[] NOT NULL DEFAULT '{}', signing_secret TEXT NOT NULL,
    active BOOLEAN NOT NULL DEFAULT true, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_webhook_endpoints_account_id ON webhook_endpoints (account_id);
-- +goose Down
DROP TABLE IF EXISTS webhook_endpoints;
```

**008_webhook_events.sql:**
```sql
-- +goose Up
CREATE TABLE webhook_events (
    id UUID PRIMARY KEY, account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    endpoint_id UUID NOT NULL REFERENCES webhook_endpoints(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL, payload JSONB NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0, last_attempted_at TIMESTAMPTZ,
    response_status INTEGER, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_webhook_events_endpoint_id ON webhook_events (endpoint_id);
CREATE INDEX idx_webhook_events_status ON webhook_events (status);
-- +goose Down
DROP TABLE IF EXISTS webhook_events;
```

**009_refresh_tokens.sql:**
```sql
-- +goose Up
CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY, user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE, expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_refresh_tokens_token_hash ON refresh_tokens (token_hash);
-- +goose Down
DROP TABLE IF EXISTS refresh_tokens;
```

**010_rls_policies.sql:**
```sql
-- +goose Up
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE products ENABLE ROW LEVEL SECURITY;
ALTER TABLE licenses ENABLE ROW LEVEL SECURITY;
ALTER TABLE machines ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhook_endpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhook_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE refresh_tokens ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_users ON users USING (
    NULLIF(current_setting('app.current_account_id', true), '') IS NULL
    OR account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid);
CREATE POLICY tenant_api_keys ON api_keys USING (
    NULLIF(current_setting('app.current_account_id', true), '') IS NULL
    OR account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid);
CREATE POLICY tenant_products ON products USING (
    NULLIF(current_setting('app.current_account_id', true), '') IS NULL
    OR account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid);
CREATE POLICY tenant_licenses ON licenses USING (
    NULLIF(current_setting('app.current_account_id', true), '') IS NULL
    OR account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid);
CREATE POLICY tenant_machines ON machines USING (
    NULLIF(current_setting('app.current_account_id', true), '') IS NULL
    OR account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid);
CREATE POLICY tenant_webhook_endpoints ON webhook_endpoints USING (
    NULLIF(current_setting('app.current_account_id', true), '') IS NULL
    OR account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid);
CREATE POLICY tenant_webhook_events ON webhook_events USING (
    NULLIF(current_setting('app.current_account_id', true), '') IS NULL
    OR account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid);
CREATE POLICY tenant_refresh_tokens ON refresh_tokens USING (
    NULLIF(current_setting('app.current_account_id', true), '') IS NULL
    OR account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid);

-- +goose Down
DROP POLICY IF EXISTS tenant_users ON users;
DROP POLICY IF EXISTS tenant_api_keys ON api_keys;
DROP POLICY IF EXISTS tenant_products ON products;
DROP POLICY IF EXISTS tenant_licenses ON licenses;
DROP POLICY IF EXISTS tenant_machines ON machines;
DROP POLICY IF EXISTS tenant_webhook_endpoints ON webhook_endpoints;
DROP POLICY IF EXISTS tenant_webhook_events ON webhook_events;
DROP POLICY IF EXISTS tenant_refresh_tokens ON refresh_tokens;
ALTER TABLE users DISABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys DISABLE ROW LEVEL SECURITY;
ALTER TABLE products DISABLE ROW LEVEL SECURITY;
ALTER TABLE licenses DISABLE ROW LEVEL SECURITY;
ALTER TABLE machines DISABLE ROW LEVEL SECURITY;
ALTER TABLE webhook_endpoints DISABLE ROW LEVEL SECURITY;
ALTER TABLE webhook_events DISABLE ROW LEVEL SECURITY;
ALTER TABLE refresh_tokens DISABLE ROW LEVEL SECURITY;
```

- [ ] **Step 1: Create all 10 migration files**
- [ ] **Step 2: Commit**

```bash
git add migrations/
git commit -m "feat(db): 10 SQL migrations with RLS policies"
```

---

### Task 6: DB — Pool, TxManager, Migration Runner

**Files:**
- Create: `internal/db/pool.go`
- Create: `internal/db/tx.go`
- Create: `internal/db/tx_test.go`
- Create: `internal/db/migrate.go`
- Delete: `internal/db/.gitkeep`

**pool.go** — `NewPool(ctx, databaseURL) (*pgxpool.Pool, error)` — max 20 conns, 2 min, 30s acquire timeout, 5min idle timeout, ping on connect.

**tx.go** — Implements `core.TxManager`. Key components:
- `ctxKey` struct for context values
- `TxManager` struct with `pool *pgxpool.Pool`
- `WithTenant(ctx, accountID, fn)` — begin tx, `SET LOCAL app.current_account_id`, put tx in ctx, call fn, commit
- `WithTx(ctx, fn)` — begin tx, put tx in ctx, call fn, commit (no tenant)
- `conn(ctx, pool) querier` — extract tx from ctx or fall back to pool
- `querier` interface — shared interface for `pgxpool.Pool` and `pgx.Tx` (QueryRow, Query, Exec)

```go
// querier is the common interface between pgxpool.Pool and pgx.Tx
type querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}
```

**tx_test.go** — Unit test for `conn()` function: returns pool when no tx in context.

**migrate.go** — `RunMigrations(databaseURL string, migrationsFS fs.FS) error` — opens `database/sql` with pgx stdlib driver, runs goose up.

- [ ] **Step 1: Implement pool.go, tx.go, tx_test.go, migrate.go**
- [ ] **Step 2: Run test**

```bash
go get github.com/jackc/pgx/v5
go get github.com/pressly/goose/v3
go test ./internal/db/ -v -count=1 -short
```

- [ ] **Step 3: Commit**

```bash
git add internal/db/
git commit -m "feat(db): connection pool, TxManager with RLS tenant context, migration runner"
```

---

### Task 7: DB — All Repository Implementations

**Files:**
- Create: `internal/db/account_repo.go`
- Create: `internal/db/user_repo.go`
- Create: `internal/db/apikey_repo.go`
- Create: `internal/db/refresh_token_repo.go`
- Create: `internal/db/product_repo.go`
- Create: `internal/db/license_repo.go`
- Create: `internal/db/machine_repo.go`
- Create: `internal/db/webhook_repo.go`

Each repo struct has a `pool *pgxpool.Pool` field. Every method uses `conn(ctx, r.pool)` to get the querier (tx from context or pool fallback). Each repo has a constructor `NewXxxRepo(pool) *XxxRepo`.

**ID scanning pattern** — since our IDs are `type AccountID uuid.UUID` (defined types, not struct wrappers), repos must scan into `uuid.UUID` then cast:

```go
var rawID uuid.UUID
err := q.QueryRow(ctx, "SELECT id FROM accounts WHERE slug = $1", slug).Scan(&rawID)
account := &core.Account{ID: core.AccountID(rawID), ...}
```

**Passing IDs to queries** — convert to `uuid.UUID` for pgx:

```go
q.Exec(ctx, "INSERT INTO accounts (id, ...) VALUES ($1, ...)", uuid.UUID(account.ID), ...)
```

**Each repo implements the corresponding `core.XxxRepository` interface exactly.** Return `nil, nil` for not-found (check `pgx.ErrNoRows`). Return `*core.AppError` for business errors (not found on delete/update). Log and wrap DB errors for 500s.

**Key implementation details:**

- `AccountRepo.GetBySlug` — global query (no tenant context needed), uses pool directly via `conn(ctx, r.pool)` which falls back to pool
- `UserRepo.GetByEmail` — global query (used in login), returns nil for not-found
- `APIKeyRepo.GetByHash` — global query (used in auth middleware), returns nil for not-found
- `LicenseRepo.GetByKeyHash` — global query (used in public validate endpoint)
- `LicenseRepo.ExpireActive` — global query, `UPDATE ... WHERE status = 'active' AND expires_at < NOW() RETURNING ...`
- `MachineRepo.UpdateHeartbeat` — `UPDATE ... SET last_seen_at = NOW() WHERE license_id = $1 AND fingerprint = $2 RETURNING ...`
- `ProductRepo.Update` — uses `COALESCE` for optional fields
- `WebhookRepo.GetActiveEndpointsByEvent` — `WHERE active = true AND ($1 = ANY(events) OR events = '{}')`

Ensure every repo method has a `var _ core.XxxRepository = (*XxxRepo)(nil)` compile-time check at package level.

- [ ] **Step 1: Implement all 8 repo files**
- [ ] **Step 2: Verify compilation**

```bash
go vet ./internal/db/...
```

- [ ] **Step 3: Commit**

```bash
git add internal/db/
git commit -m "feat(db): all repository implementations (account, user, product, license, machine, apikey, webhook, refresh_token)"
```

---

## Phase D: Services

### Task 8: Auth Service

**Files:**
- Create: `internal/auth/service.go`
- Create: `internal/auth/service_test.go`
- Delete: `internal/identity/.gitkeep`

**Service struct:**
```go
type Service struct {
	txManager   core.TxManager
	accounts    core.AccountRepository
	users       core.UserRepository
	apiKeys     core.APIKeyRepository
	refreshTkns core.RefreshTokenRepository
	masterKey   *crypto.MasterKey
}
```

**Request/Result types** (defined in same file):

```go
type SignupRequest struct {
	AccountName string `json:"account_name" validate:"required,min=1,max=100"`
	Email       string `json:"email" validate:"required,email"`
	Password    string `json:"password" validate:"required,min=8"`
}

type SignupResult struct {
	Account *core.Account `json:"account"`
	User    *core.User    `json:"user"`
	APIKey  string        `json:"api_key"`
}

type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type LoginResult struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

type MeResult struct {
	User    *core.User    `json:"user,omitempty"`
	Account *core.Account `json:"account"`
}

type CreateAPIKeyRequest struct {
	Label       *string `json:"label"`
	Environment string  `json:"environment" validate:"required,oneof=live test"`
}

type CreateAPIKeyResult struct {
	APIKey *core.APIKey `json:"api_key"`
	RawKey string       `json:"raw_key"`
}
```

**Methods:**

- `Signup(ctx, SignupRequest) (*SignupResult, error)` — uses `txManager.WithTx` (global, no tenant yet). Checks email uniqueness, hashes password, creates account + user (role=owner) + API key (live, account_wide). Returns result with raw API key.
- `Login(ctx, LoginRequest) (*LoginResult, error)` — looks up user by email (global), verifies password, signs JWT (15min), generates refresh token, stores hashed refresh token via `txManager.WithTx`. Returns access + refresh tokens.
- `Refresh(ctx, refreshToken string) (*LoginResult, error)` — HMAC hash the token, look up in DB (global), delete old, look up user via `txManager.WithTenant`, issue new JWT + refresh token.
- `Logout(ctx, refreshToken string) error` — HMAC hash, delete from DB.
- `GetMe(ctx, accountID, *userID) (*MeResult, error)` — uses `txManager.WithTenant`. Gets account, optionally gets user.
- `CreateAPIKey(ctx, accountID, CreateAPIKeyRequest) (*CreateAPIKeyResult, error)` — uses `txManager.WithTenant`. Generates key, stores hashed.
- `ListAPIKeys(ctx, accountID, limit, offset) ([]core.APIKey, int, error)` — uses `txManager.WithTenant`.
- `DeleteAPIKey(ctx, accountID, id) error` — uses `txManager.WithTenant`.

**Helper:** `slugify(name string) string` — lowercase, spaces → hyphens, strip non-alphanumeric.

**Tests:** Unit tests with mock repos and a passthrough TxManager (just calls fn(ctx) directly). Test signup flow, login success/failure, refresh token rotation, API key generation.

- [ ] **Step 1: Write service_test.go with mock repos**
- [ ] **Step 2: Implement service.go**
- [ ] **Step 3: Run tests**

```bash
go test ./internal/auth/ -v -count=1
```

- [ ] **Step 4: Commit**

```bash
git add internal/auth/ && rm -f internal/identity/.gitkeep
git commit -m "feat(auth): auth service — signup, login, refresh, logout, me, API key management"
```

---

### Task 9: Product Service

**Files:**
- Create: `internal/product/service.go`
- Create: `internal/product/service_test.go`

**Service struct:**
```go
type Service struct {
	txManager core.TxManager
	products  core.ProductRepository
	masterKey *crypto.MasterKey
}
```

**Request types:**
```go
type CreateRequest struct {
	Name          string           `json:"name" validate:"required,min=1,max=100"`
	Slug          string           `json:"slug" validate:"required,min=1,max=100"`
	ValidationTTL *int             `json:"validation_ttl"`
	GracePeriod   *int             `json:"grace_period"`
	Metadata      *json.RawMessage `json:"metadata"`
}

type UpdateRequest struct {
	Name          *string          `json:"name"`
	ValidationTTL *int             `json:"validation_ttl"`
	GracePeriod   *int             `json:"grace_period"`
	Metadata      *json.RawMessage `json:"metadata"`
}
```

**Methods** — all use `txManager.WithTenant(ctx, accountID, ...)`:
- `Create(ctx, accountID, CreateRequest) (*core.Product, error)` — generates Ed25519 keypair, encrypts private key with AES-GCM using `masterKey.EncryptionKey`, creates product. Defaults: validation_ttl=86400, grace_period=604800.
- `List(ctx, accountID, limit, offset) ([]core.Product, int, error)`
- `Get(ctx, accountID, productID) (*core.Product, error)` — returns `ErrProductNotFound` if nil.
- `Update(ctx, accountID, productID, UpdateRequest) (*core.Product, error)` — converts to `core.UpdateProductParams`.
- `Delete(ctx, accountID, productID) error`

- [ ] **Step 1: Write service_test.go**
- [ ] **Step 2: Implement service.go**
- [ ] **Step 3: Run tests**
- [ ] **Step 4: Commit**

```bash
git add internal/product/
git commit -m "feat(product): product service — CRUD with Ed25519 keypair generation"
```

---

### Task 10: Licensing Service

**Files:**
- Create: `internal/licensing/service.go`
- Create: `internal/licensing/service_test.go`
- Create: `internal/licensing/keygen.go`
- Create: `internal/licensing/keygen_test.go`
- Delete: `internal/licensing/.gitkeep`, `internal/machines/.gitkeep`

**keygen.go:**
```go
const KeyAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789" // 32 chars, no 0/O/1/I/L

func GenerateLicenseKey() (fullKey, prefix string, err error)
// Format: GETL-XXXX-XXXX-XXXX (12 random chars from KeyAlphabet in 3 groups of 4)
// Rejection sampling: byte & 0x1F for unbiased index into 32-char alphabet
// prefix = first 9 chars ("GETL-XXXX")

const MaxFingerprintLength = 256

func ValidateFingerprint(fp string) error
// empty → ErrValidationError, > 256 chars → ErrValidationError

func ValidateLicenseStatus(status core.LicenseStatus, expiresAt *time.Time) error
// revoked → ErrLicenseRevoked, suspended → ErrLicenseSuspended, inactive → ErrLicenseInactive
// expired → ErrLicenseExpired, active + past expiry → ErrLicenseExpired, active → nil
```

**Service struct:**
```go
type Service struct {
	txManager core.TxManager
	licenses  core.LicenseRepository
	products  core.ProductRepository
	machines  core.MachineRepository
	masterKey *crypto.MasterKey
}
```

**Request/Result types:**
```go
type CreateRequest struct {
	LicenseType   string           `json:"license_type" validate:"required,oneof=perpetual timed subscription trial"`
	MaxMachines   *int             `json:"max_machines"`
	MaxSeats      *int             `json:"max_seats"`
	Entitlements  *json.RawMessage `json:"entitlements"`
	LicenseeName  *string          `json:"licensee_name"`
	LicenseeEmail *string          `json:"licensee_email"`
	ExpiresAt     *time.Time       `json:"expires_at"`
}

type CreateResult struct {
	License    *core.License `json:"license"`
	LicenseKey string        `json:"license_key"`
}

type ValidateResult struct {
	Valid   bool          `json:"valid"`
	License *core.License `json:"license"`
}

type ActivateRequest struct {
	Fingerprint string           `json:"fingerprint" validate:"required"`
	Hostname    *string          `json:"hostname"`
	Metadata    *json.RawMessage `json:"metadata"`
}

type DeactivateRequest struct {
	Fingerprint string `json:"fingerprint" validate:"required"`
}

type HeartbeatRequest struct {
	Fingerprint string `json:"fingerprint" validate:"required"`
}
```

**Methods:**
- `Create(ctx, accountID, productID, CreateRequest) (*CreateResult, error)` — WithTenant. Gets product, decrypts private key, generates license key, signs token, creates license. Returns raw key (shown once).
- `List(ctx, accountID, limit, offset) ([]core.License, int, error)` — WithTenant.
- `Get(ctx, accountID, licenseID) (*core.License, error)` — WithTenant.
- `Revoke(ctx, accountID, licenseID) error` — WithTenant. Checks CanRevoke().
- `Suspend(ctx, accountID, licenseID) (*core.License, error)` — WithTenant. Checks CanSuspend().
- `Reinstate(ctx, accountID, licenseID) (*core.License, error)` — WithTenant. Checks CanReinstate().
- `Validate(ctx, licenseKey string) (*ValidateResult, error)` — NO WithTenant (global). HMAC hash key, look up by hash, validate status.
- `Activate(ctx, accountID, licenseID, ActivateRequest) (*core.Machine, error)` — WithTenant. Validates fingerprint, checks existing machine (→ ErrMachineAlreadyActivated), counts machines (→ ErrMachineLimitExceeded), creates machine.
- `Deactivate(ctx, accountID, licenseID, DeactivateRequest) error` — WithTenant.
- `Heartbeat(ctx, accountID, licenseID, HeartbeatRequest) (*core.Machine, error)` — WithTenant.

- [ ] **Step 1: Write keygen_test.go and keygen.go**
- [ ] **Step 2: Run keygen tests**
- [ ] **Step 3: Write service_test.go with mock repos**
- [ ] **Step 4: Implement service.go**
- [ ] **Step 5: Run all tests**

```bash
go test ./internal/licensing/ -v -count=1
```

- [ ] **Step 6: Commit**

```bash
rm -f internal/licensing/.gitkeep internal/machines/.gitkeep
git add internal/licensing/
git commit -m "feat(licensing): license service — create, validate, suspend, revoke, machines, keygen"
```

---

### Task 11: Webhook Service + Delivery

**Files:**
- Create: `internal/webhook/service.go`
- Create: `internal/webhook/deliver.go`
- Create: `internal/webhook/deliver_test.go`
- Delete: `internal/webhook/.gitkeep`

**deliver.go:**
```go
var RetryDelays = []time.Duration{1*time.Second, 5*time.Second, 30*time.Second, 5*time.Minute, 30*time.Minute}
const DeliveryTimeout = 10 * time.Second

func SignPayload(secret string, payload []byte) string // HMAC-SHA256, hex

func DeliverWebhook(ctx context.Context, endpoint core.WebhookEndpoint, eventType core.EventType, data json.RawMessage) error
// Creates envelope {id, event_type, data, timestamp}
// Signs with endpoint.SigningSecret
// POSTs with X-GetLicense-Signature and X-GetLicense-Event-Id headers
// Retries on failure with RetryDelays, 10s timeout per attempt
```

**Service struct:**
```go
type Service struct {
	txManager core.TxManager
	webhooks  core.WebhookRepository
}
```

**Methods:**
- `CreateEndpoint(ctx, accountID, CreateEndpointRequest) (*core.WebhookEndpoint, error)` — WithTenant. Generates 32-byte signing secret.
- `ListEndpoints(ctx, accountID, limit, offset) ([]core.WebhookEndpoint, int, error)` — WithTenant.
- `DeleteEndpoint(ctx, accountID, endpointID) error` — WithTenant.
- `Dispatch(ctx, accountID, eventType, payload json.RawMessage)` — WithTenant. Gets matching endpoints, spawns goroutine per endpoint to deliver. Fire-and-forget.

**Tests:** Test SignPayload produces 64-char hex, test RetryDelays length.

- [ ] **Step 1: Write deliver_test.go and deliver.go**
- [ ] **Step 2: Implement service.go**
- [ ] **Step 3: Run tests**
- [ ] **Step 4: Commit**

```bash
rm -f internal/webhook/.gitkeep
git add internal/webhook/
git commit -m "feat(webhook): webhook service + delivery with HMAC signing and retries"
```

---

## Phase E: HTTP Layer

### Task 12: Server — Fiber App, Config, Error Handler

**Files:**
- Create: `internal/server/app.go`
- Create: `internal/server/config.go`
- Create: `internal/server/deps.go`
- Delete: `internal/server/.gitkeep`

**config.go:**
```go
type Config struct {
	Host, Port, Environment, DatabaseURL string
	MasterKey *crypto.MasterKey
}
func LoadConfig() (*Config, error) // reads env vars, validates master key
func (c *Config) IsDevelopment() bool
func (c *Config) ListenAddr() string
```

**deps.go:**
```go
type Deps struct {
	AuthService    *auth.Service
	ProductService *product.Service
	LicenseService *licensing.Service
	WebhookService *webhook.Service
	APIKeyRepo     core.APIKeyRepository // for auth middleware
	MasterKey      *crypto.MasterKey     // for auth middleware
	Config         *Config
}
```

**app.go:**
```go
func NewApp(deps *Deps) *fiber.App
```
- Custom `ErrorHandler` that handles `*core.AppError`, `*fiber.Error`, and unknown errors
- `StructValidator` using `go-playground/validator`
- Middleware stack: recover, request logger (slog), CORS, security headers (`X-Content-Type-Options`, `X-Frame-Options`, `Cache-Control: no-store`, `X-API-Version: 1`)
- Health endpoint: `GET /health` → `{"status":"ok"}`
- Body limit: 512KB
- Calls `registerRoutes(app, deps)` (stubbed until Task 14)

- [ ] **Step 1: Implement config.go, deps.go, app.go**
- [ ] **Step 2: Verify compilation**

```bash
go get github.com/gofiber/fiber/v3
go get github.com/go-playground/validator/v10
go vet ./internal/server/...
```

- [ ] **Step 3: Commit**

```bash
rm -f internal/server/.gitkeep
git add internal/server/
git commit -m "feat(server): Fiber v3 app with error handler, validation, logging, CORS"
```

---

### Task 13: Server — Auth Middleware

**Files:**
- Create: `internal/server/middleware/auth.go`

**auth.go:**
```go
type AuthenticatedAccount struct {
	AccountID core.AccountID
	UserID    *core.UserID
	Role      *core.UserRole
}

func FromContext(c fiber.Ctx) *AuthenticatedAccount  // read from Fiber locals

func RequireAuth(apiKeyRepo core.APIKeyRepository, masterKey *crypto.MasterKey) fiber.Handler
// Reads Authorization header, strips "Bearer " prefix
// Detects type by prefix:
//   gl_live_ or gl_test_ → HMAC hash with masterKey.HMACKey → apiKeyRepo.GetByHash → AuthenticatedAccount{AccountID}
//   otherwise → crypto.VerifyJWT with masterKey.JWTSigningKey → AuthenticatedAccount{AccountID, UserID, Role}
// Stores in Fiber locals

func RequireRole(required core.UserRole) fiber.Handler
// Checks auth.Role.AtLeast(required). API key auth (nil role) bypasses role checks.
```

- [ ] **Step 1: Implement auth.go**
- [ ] **Step 2: Verify compilation**
- [ ] **Step 3: Commit**

```bash
git add internal/server/middleware/
git commit -m "feat(server): dual-mode auth middleware (API key + JWT)"
```

---

### Task 14: Server — Handlers, Routes, Background Jobs

**Files:**
- Create: `internal/server/handler/helpers.go`
- Create: `internal/server/handler/auth.go`
- Create: `internal/server/handler/products.go`
- Create: `internal/server/handler/licenses.go`
- Create: `internal/server/handler/validate.go`
- Create: `internal/server/handler/apikeys.go`
- Create: `internal/server/handler/webhooks.go`
- Create: `internal/server/routes.go`
- Create: `internal/server/background.go`

**helpers.go:**
```go
func paginationParams(c fiber.Ctx) (limit, offset int) // defaults: limit=20, max=100, offset=0
func parseUUIDParam(c fiber.Ctx, name string) (string, error) // reads c.Params(name)
```

**Handler pattern** — every handler is 5-15 lines:
```go
type ProductHandler struct { svc *product.Service }
func NewProductHandler(svc *product.Service) *ProductHandler

func (h *ProductHandler) Create(c fiber.Ctx) error {
    var req product.CreateRequest
    if err := c.Bind().Body(&req); err != nil { return err }
    auth := middleware.FromContext(c)
    result, err := h.svc.Create(c.Context(), auth.AccountID, req)
    if err != nil { return err }
    return c.Status(fiber.StatusCreated).JSON(result)
}
```

**Handlers to implement:**

`auth.go` — `AuthHandler` with `Signup`, `Login`, `Refresh`, `Logout`, `Me`
`products.go` — `ProductHandler` with `Create`, `List`, `Get`, `Update`, `Delete`
`licenses.go` — `LicenseHandler` with `Create` (under `/products/:id/licenses`), `List`, `Get`, `Revoke` (DELETE), `Suspend`, `Reinstate`, `Activate`, `Deactivate`, `Heartbeat`
`validate.go` — `ValidateHandler` with `Validate`
`apikeys.go` — `APIKeyHandler` with `Create`, `List`, `Delete` (wraps auth service methods)
`webhooks.go` — `WebhookHandler` with `Create`, `List`, `Delete`

**routes.go:**
```go
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

    // Products (authenticated)
    ph := handler.NewProductHandler(deps.ProductService)
    products := v1.Group("/products", authMw)
    products.Post("/", ph.Create)
    products.Get("/", ph.List)
    products.Get("/:id", ph.Get)
    products.Patch("/:id", ph.Update)
    products.Delete("/:id", ph.Delete)

    // License creation under product
    lh := handler.NewLicenseHandler(deps.LicenseService)
    products.Post("/:id/licenses", lh.Create)

    // Licenses (authenticated)
    licenses := v1.Group("/licenses", authMw)
    licenses.Get("/", lh.List)
    licenses.Get("/:id", lh.Get)
    licenses.Delete("/:id", lh.Revoke)
    licenses.Post("/:id/suspend", lh.Suspend)
    licenses.Post("/:id/reinstate", lh.Reinstate)
    licenses.Post("/:id/activate", lh.Activate)
    licenses.Post("/:id/deactivate", lh.Deactivate)
    licenses.Post("/:id/heartbeat", lh.Heartbeat)

    // Validate (public)
    vh := handler.NewValidateHandler(deps.LicenseService)
    v1.Post("/validate", vh.Validate)

    // API Keys (authenticated)
    akh := handler.NewAPIKeyHandler(deps.AuthService)
    apiKeys := v1.Group("/api-keys", authMw)
    apiKeys.Post("/", akh.Create)
    apiKeys.Get("/", akh.List)
    apiKeys.Delete("/:id", akh.Delete)

    // Webhooks (authenticated)
    wh := handler.NewWebhookHandler(deps.WebhookService)
    webhooks := v1.Group("/webhooks", authMw)
    webhooks.Post("/", wh.Create)
    webhooks.Get("/", wh.List)
    webhooks.Delete("/:id", wh.Delete)
}
```

**background.go:**
```go
func StartExpiryLoop(ctx context.Context, licenseRepo core.LicenseRepository)
// goroutine, ticker every 60s, calls licenseRepo.ExpireActive(ctx), logs count
```

- [ ] **Step 1: Implement helpers.go**
- [ ] **Step 2: Implement all handler files**
- [ ] **Step 3: Implement routes.go**
- [ ] **Step 4: Implement background.go**
- [ ] **Step 5: Verify compilation**

```bash
go vet ./...
```

- [ ] **Step 6: Commit**

```bash
git add internal/server/
git commit -m "feat(server): all handlers, route wiring, and license expiry background loop"
```

---

## Phase F: CLI + Integration

### Task 15: CLI — Cobra Commands

**Files:**
- Modify: `cmd/server/main.go` (replace minimal placeholder)

**main.go** — Cobra CLI with two commands:
- `getlicense-server` / `getlicense-server serve` — loads config, creates pool, creates all repos, creates all services, creates Fiber app, starts expiry loop, graceful shutdown on SIGINT/SIGTERM
- `getlicense-server migrate` — reads `DATABASE_URL`, runs goose migrations using embedded `migrations/` FS

```go
//go:embed all:../../migrations
var migrationsFS embed.FS
```

Logging: `slog.NewTextHandler` in development, `slog.NewJSONHandler` in production.

Composition root wires everything:
```go
pool → repos → services → deps → app
```

- [ ] **Step 1: Implement main.go with cobra**
- [ ] **Step 2: Verify build**

```bash
go get github.com/spf13/cobra
go mod tidy
go build ./cmd/server
```

- [ ] **Step 3: Commit**

```bash
git add cmd/server/ go.mod go.sum
git commit -m "feat(cli): cobra commands — serve and migrate with composition root"
```

---

### Task 16: Integration Smoke Test

- [ ] **Step 1: Start Postgres and run migrations**

```bash
make db
sleep 3
source .env
go run ./cmd/server migrate
```

- [ ] **Step 2: Start server and test health endpoint**

```bash
GETLICENSE_ENV=development go run ./cmd/server serve &
sleep 2
curl -s http://localhost:3000/health | jq
```

Expected: `{"status": "ok"}`

- [ ] **Step 3: Test signup → login → create product → create license → validate flow**

```bash
# Signup
curl -s -X POST http://localhost:3000/v1/auth/signup \
  -H "Content-Type: application/json" \
  -d '{"account_name":"Test Corp","email":"test@example.com","password":"password123"}' | jq

# (capture api_key from response, use in subsequent requests)
```

- [ ] **Step 4: Fix any issues discovered**
- [ ] **Step 5: Commit fixes**

```bash
git add -A
git commit -m "fix: integration issues from smoke testing"
```

---

### Task 17: E2E Test Scenarios (Hurl)

**Files:**
- Create: `e2e/scenarios/01_health.hurl`
- Create: `e2e/scenarios/02_auth.hurl`
- Create: `e2e/scenarios/03_products.hurl`
- Create: `e2e/scenarios/04_licenses.hurl`
- Create: `e2e/scenarios/05_validate.hurl`
- Create: `e2e/scenarios/06_machines.hurl`
- Create: `e2e/scenarios/07_webhooks.hurl`
- Create: `e2e/scenarios/08_apikeys.hurl`
- Create: `e2e/scenarios/09_full_journey.hurl`
- Delete: `e2e/.gitkeep` (if it exists)

Scenarios cover: health check, signup/login/refresh/logout/errors, product CRUD, license lifecycle, public validation, machine activation/deactivation/heartbeat, webhook management, API key management, and a full customer journey (signup → product → license → validate → activate → suspend → reinstate → deactivate → revoke → validate fails).

- [ ] **Step 1: Create all hurl scenario files**
- [ ] **Step 2: Run e2e tests**

```bash
make e2e
```

- [ ] **Step 3: Fix any failures**
- [ ] **Step 4: Commit**

```bash
git add e2e/
git commit -m "feat(e2e): 9 hurl test scenarios covering full API surface"
```

---

### Task 18: CLAUDE.md and Cleanup

**Files:**
- Create: `CLAUDE.md`
- Remove stale `.gitkeep` files (any remaining in `internal/distribution/`, `internal/analytics/`)

**CLAUDE.md** content documenting:
- Quick start commands (`make run`, `make e2e`, `make test`)
- Package layout with service/repo pattern explanation
- DB & RLS conventions (NULLIF pattern, WithTenant, global queries)
- Environment variables
- Crypto key derivation (3 HKDF context strings)
- Auth model (API key + JWT dual-mode)
- Handler → Service → Repository data flow
- Testing patterns

- [ ] **Step 1: Create CLAUDE.md**
- [ ] **Step 2: Run full test suite**

```bash
go vet ./...
go test ./... -count=1 -short
```

- [ ] **Step 3: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: CLAUDE.md with project conventions for service/repo pattern"
```

---

## Summary

| Phase | Tasks | What's Built |
|-------|-------|-------------|
| A: Core Interfaces | 1 | Repository interfaces, TxManager interface, UpdateProductParams |
| B: Crypto | 2-4 | Master key, HMAC, AES-GCM, Ed25519, token format, password hashing, API key gen, JWT |
| C: Database | 5-7 | 10 migrations, pool, TxManager impl, all 8 repository implementations |
| D: Services | 8-11 | Auth, Product, Licensing (+ keygen), Webhook (+ delivery) services |
| E: HTTP Layer | 12-14 | Fiber app, auth middleware, all handlers, routes, background jobs |
| F: CLI + Integration | 15-18 | Cobra CLI, smoke test, hurl E2E scenarios, CLAUDE.md |

**Data flow:** Handler → Service → Repository (via TxManager context) → PostgreSQL (with RLS)

**Key pattern:** Services own business logic. Handlers are thin HTTP adapters. Repos implement interfaces from core. Transactions flow through context.
