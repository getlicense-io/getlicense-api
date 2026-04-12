# Tier 2: Production Gaps Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close production gaps — DevSecOps CI/hooks, environment isolation (test/live), webhook dispatch wiring, and OpenAPI spec.

**Architecture:** Environment isolation extends the existing RLS pattern with a second session variable (`app.current_environment`). Webhook dispatch adds fire-and-forget calls after successful service operations. DevSecOps is config-only.

**Tech Stack:** GitHub Actions, golangci-lint, existing Go + Fiber + pgx stack

---

## File Map

### New files
```
.github/workflows/ci.yml                    # Task 1: CI pipeline
.golangci.yml                                # Task 1: linter config
scripts/pre-commit                           # Task 1: pre-commit hook
.dockerignore                                # Task 1: Docker build context filter
migrations/012_environment_isolation.sql     # Task 2: env columns + RLS policy updates
openapi.yaml                                 # Task 5: API spec
```

### Modified files
```
Makefile                                     # Task 1: add hooks target

internal/domain/models.go                    # Task 2: add Environment field to License, Machine, WebhookEndpoint, WebhookEvent
internal/domain/tx.go                        # Task 2: add env param to WithTenant
internal/db/tx.go                            # Task 2: set app.current_environment in WithTenant
internal/db/license_repo.go                  # Task 2: scan + insert environment column
internal/db/machine_repo.go                  # Task 2: scan + insert environment column
internal/db/webhook_repo.go                  # Task 2: scan + insert environment column

internal/server/middleware/auth.go           # Task 3: add Environment to AuthenticatedAccount
internal/auth/service.go                     # Task 3: add env param to WithTenant calls
internal/product/service.go                  # Task 3: add env param to WithTenant calls
internal/licensing/service.go                # Task 3: add env param to WithTenant calls, stamp env on created records
internal/webhook/service.go                  # Task 3: add env param to WithTenant calls, stamp env on created records
internal/server/handler/products.go          # Task 3: pass a.Environment to service
internal/server/handler/licenses.go          # Task 3: pass a.Environment to service
internal/server/handler/auth.go              # Task 3: pass a.Environment to service
internal/server/handler/apikeys.go           # Task 3: pass a.Environment to service
internal/server/handler/webhooks.go          # Task 3: pass a.Environment to service
cmd/server/serve.go                          # Task 3: pass env to service constructors (if needed)
internal/auth/service_test.go                # Task 3: update mock TxManager
internal/product/service_test.go             # Task 3: update mock TxManager
internal/licensing/service_test.go           # Task 3: update mock TxManager

internal/core/enums.go                       # Task 4: add EventTypeLicenseReinstated
internal/licensing/service.go                # Task 4: inject webhookSvc, wire dispatch calls
cmd/server/serve.go                          # Task 4: pass webhookSvc to licensing.NewService
```

---

## Task 1: DevSecOps — CI, Linting, Pre-commit Hook, .dockerignore

**Files:**
- Create: `.github/workflows/ci.yml`
- Create: `.golangci.yml`
- Create: `scripts/pre-commit`
- Create: `.dockerignore`
- Modify: `Makefile`

- [ ] **Step 1: Create GitHub Actions CI workflow**

`.github/workflows/ci.yml`:
```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:

jobs:
  ci:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version-file: go.mod

      - run: go vet ./...

      - uses: golangci/golangci-lint-action@v7

      - run: go test ./... -count=1 -short

      - run: go build ./cmd/server
```

- [ ] **Step 2: Create golangci-lint config**

`.golangci.yml`:
```yaml
linters:
  enable:
    - errcheck
    - govet
    - staticcheck
    - unused
    - ineffassign
    - gosimple

issues:
  exclude-use-default: true
```

- [ ] **Step 3: Create pre-commit hook script**

`scripts/pre-commit`:
```bash
#!/usr/bin/env bash
set -e

# Check formatting on staged Go files.
STAGED_GO_FILES=$(git diff --cached --name-only --diff-filter=ACM -- '*.go')
if [ -n "$STAGED_GO_FILES" ]; then
    UNFORMATTED=$(gofmt -l $STAGED_GO_FILES)
    if [ -n "$UNFORMATTED" ]; then
        echo "Unformatted Go files:"
        echo "$UNFORMATTED"
        echo "Run: gofmt -w <file>"
        exit 1
    fi
fi

# Run vet.
go vet ./...
```

Make it executable:
```bash
chmod +x scripts/pre-commit
```

- [ ] **Step 4: Add hooks target to Makefile**

Add after the `clean` target at the end of `Makefile`:
```makefile

hooks:
	cp scripts/pre-commit .git/hooks/pre-commit
	chmod +x .git/hooks/pre-commit
	@echo "Pre-commit hook installed."
```

Also update the `.PHONY` line at the top to include `hooks release`:
```makefile
.PHONY: build run test test-all lint fmt check db db-reset migrate e2e docker clean hooks release
```

- [ ] **Step 5: Create .dockerignore**

`.dockerignore`:
```
.git
.github
docs/
e2e/
*.md
.golangci.yml
scripts/
```

- [ ] **Step 6: Verify**

```bash
go vet ./...
```

- [ ] **Step 7: Commit**

```bash
git add .github/ .golangci.yml scripts/pre-commit .dockerignore Makefile
git commit -m "feat: DevSecOps — GitHub Actions CI, golangci-lint, pre-commit hook, .dockerignore"
```

---

## Task 2: Environment Isolation — Migration, Domain, TxManager, Repos

**Files:**
- Create: `migrations/012_environment_isolation.sql`
- Modify: `internal/domain/models.go`
- Modify: `internal/domain/tx.go`
- Modify: `internal/db/tx.go`
- Modify: `internal/db/license_repo.go`
- Modify: `internal/db/machine_repo.go`
- Modify: `internal/db/webhook_repo.go`

This task builds the foundation. After this task, the code will NOT compile — all `WithTenant` callers need updating (Task 3).

- [ ] **Step 1: Create the migration**

`migrations/012_environment_isolation.sql`:
```sql
-- +goose Up

-- Add environment column to tenant-scoped tables.
ALTER TABLE licenses ADD COLUMN environment TEXT NOT NULL DEFAULT 'live';
ALTER TABLE machines ADD COLUMN environment TEXT NOT NULL DEFAULT 'live';
ALTER TABLE webhook_endpoints ADD COLUMN environment TEXT NOT NULL DEFAULT 'live';
ALTER TABLE webhook_events ADD COLUMN environment TEXT NOT NULL DEFAULT 'live';

-- Recreate RLS policies to include environment filtering.
-- Pattern: (account_id matches OR no account set) AND (environment matches OR no environment set)

DROP POLICY IF EXISTS tenant_licenses ON licenses;
CREATE POLICY tenant_licenses ON licenses USING (
    (NULLIF(current_setting('app.current_account_id', true), '') IS NULL
     OR account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid)
    AND
    (NULLIF(current_setting('app.current_environment', true), '') IS NULL
     OR environment = current_setting('app.current_environment', true))
);

DROP POLICY IF EXISTS tenant_machines ON machines;
CREATE POLICY tenant_machines ON machines USING (
    (NULLIF(current_setting('app.current_account_id', true), '') IS NULL
     OR account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid)
    AND
    (NULLIF(current_setting('app.current_environment', true), '') IS NULL
     OR environment = current_setting('app.current_environment', true))
);

DROP POLICY IF EXISTS tenant_webhook_endpoints ON webhook_endpoints;
CREATE POLICY tenant_webhook_endpoints ON webhook_endpoints USING (
    (NULLIF(current_setting('app.current_account_id', true), '') IS NULL
     OR account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid)
    AND
    (NULLIF(current_setting('app.current_environment', true), '') IS NULL
     OR environment = current_setting('app.current_environment', true))
);

DROP POLICY IF EXISTS tenant_webhook_events ON webhook_events;
CREATE POLICY tenant_webhook_events ON webhook_events USING (
    (NULLIF(current_setting('app.current_account_id', true), '') IS NULL
     OR account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid)
    AND
    (NULLIF(current_setting('app.current_environment', true), '') IS NULL
     OR environment = current_setting('app.current_environment', true))
);

-- +goose Down

-- Restore original policies (account_id only).
DROP POLICY IF EXISTS tenant_licenses ON licenses;
CREATE POLICY tenant_licenses ON licenses USING (
    NULLIF(current_setting('app.current_account_id', true), '') IS NULL
    OR account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid);

DROP POLICY IF EXISTS tenant_machines ON machines;
CREATE POLICY tenant_machines ON machines USING (
    NULLIF(current_setting('app.current_account_id', true), '') IS NULL
    OR account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid);

DROP POLICY IF EXISTS tenant_webhook_endpoints ON webhook_endpoints;
CREATE POLICY tenant_webhook_endpoints ON webhook_endpoints USING (
    NULLIF(current_setting('app.current_account_id', true), '') IS NULL
    OR account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid);

DROP POLICY IF EXISTS tenant_webhook_events ON webhook_events;
CREATE POLICY tenant_webhook_events ON webhook_events USING (
    NULLIF(current_setting('app.current_account_id', true), '') IS NULL
    OR account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid);

-- Drop environment columns.
ALTER TABLE licenses DROP COLUMN IF EXISTS environment;
ALTER TABLE machines DROP COLUMN IF EXISTS environment;
ALTER TABLE webhook_endpoints DROP COLUMN IF EXISTS environment;
ALTER TABLE webhook_events DROP COLUMN IF EXISTS environment;
```

- [ ] **Step 2: Add Environment field to domain models**

In `internal/domain/models.go`, add `Environment core.Environment` to 4 structs:

**License** (after `UpdatedAt`):
```go
type License struct {
	// ... existing fields ...
	UpdatedAt     time.Time          `json:"updated_at"`
	Environment   core.Environment   `json:"environment"`
}
```

**Machine** (after `CreatedAt`):
```go
type Machine struct {
	// ... existing fields ...
	CreatedAt   time.Time        `json:"created_at"`
	Environment core.Environment `json:"environment"`
}
```

**WebhookEndpoint** (after `CreatedAt`):
```go
type WebhookEndpoint struct {
	// ... existing fields ...
	CreatedAt     time.Time              `json:"created_at"`
	Environment   core.Environment       `json:"environment"`
}
```

**WebhookEvent** (after `CreatedAt`):
```go
type WebhookEvent struct {
	// ... existing fields ...
	CreatedAt       time.Time              `json:"created_at"`
	Environment     core.Environment       `json:"environment"`
}
```

- [ ] **Step 3: Update TxManager interface**

In `internal/domain/tx.go`, change the `WithTenant` signature to accept environment:

```go
type TxManager interface {
	// WithTenant runs fn in a transaction with RLS tenant + environment context set.
	WithTenant(ctx context.Context, accountID core.AccountID, env core.Environment, fn func(ctx context.Context) error) error

	// WithTx runs fn in a plain transaction without tenant context.
	WithTx(ctx context.Context, fn func(ctx context.Context) error) error
}
```

- [ ] **Step 4: Update TxManager implementation**

In `internal/db/tx.go`, update `WithTenant` to set both session variables:

```go
func (m *TxManager) WithTenant(ctx context.Context, accountID core.AccountID, env core.Environment, fn func(context.Context) error) error {
	tx, err := m.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, "SELECT set_config('app.current_account_id', $1, true)", accountID.String())
	if err != nil {
		return fmt.Errorf("setting tenant context: %w", err)
	}

	_, err = tx.Exec(ctx, "SELECT set_config('app.current_environment', $1, true)", string(env))
	if err != nil {
		return fmt.Errorf("setting environment context: %w", err)
	}

	ctx = context.WithValue(ctx, ctxKey{}, tx)
	if err := fn(ctx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
```

- [ ] **Step 5: Update license_repo.go — add environment to columns, scan, create**

In `internal/db/license_repo.go`:

Update `licenseColumns` (add `environment` before `created_at`):
```go
const licenseColumns = `id, account_id, product_id, key_prefix, key_hash, token, license_type, status, max_machines, max_seats, entitlements, licensee_name, licensee_email, expires_at, environment, created_at, updated_at`
```

Update `scanLicense` to scan the new field (add `&envStr` variable and scan between `ExpiresAt` and `CreatedAt`):
```go
func scanLicense(s scannable) (domain.License, error) {
	var l domain.License
	var rawID, rawAccountID, rawProductID uuid.UUID
	var licenseType, status, envStr string
	err := s.Scan(
		&rawID, &rawAccountID, &rawProductID,
		&l.KeyPrefix, &l.KeyHash, &l.Token,
		&licenseType, &status,
		&l.MaxMachines, &l.MaxSeats, &l.Entitlements,
		&l.LicenseeName, &l.LicenseeEmail, &l.ExpiresAt,
		&envStr, &l.CreatedAt, &l.UpdatedAt,
	)
	if err != nil {
		return l, err
	}
	l.ID = core.LicenseID(rawID)
	l.AccountID = core.AccountID(rawAccountID)
	l.ProductID = core.ProductID(rawProductID)
	l.LicenseType = core.LicenseType(licenseType)
	l.Status = core.LicenseStatus(status)
	l.Environment = core.Environment(envStr)
	return l, nil
}
```

Update `Create` — add `string(license.Environment)` to the VALUES (now 17 params):
```go
func (r *LicenseRepo) Create(ctx context.Context, license *domain.License) error {
	q := conn(ctx, r.pool)
	_, err := q.Exec(ctx,
		`INSERT INTO licenses (`+licenseColumns+`)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)`,
		uuid.UUID(license.ID), uuid.UUID(license.AccountID), uuid.UUID(license.ProductID),
		license.KeyPrefix, license.KeyHash, license.Token,
		string(license.LicenseType), string(license.Status),
		license.MaxMachines, license.MaxSeats, license.Entitlements,
		license.LicenseeName, license.LicenseeEmail, license.ExpiresAt,
		string(license.Environment), license.CreatedAt, license.UpdatedAt,
	)
	return err
}
```

- [ ] **Step 6: Update machine_repo.go — add environment to columns, scan, create**

In `internal/db/machine_repo.go`:

Update `machineColumns`:
```go
const machineColumns = `id, account_id, license_id, fingerprint, hostname, metadata, last_seen_at, environment, created_at`
```

Update `scanMachine`:
```go
func scanMachine(s scannable) (domain.Machine, error) {
	var m domain.Machine
	var rawID, rawAccountID, rawLicenseID uuid.UUID
	var envStr string
	err := s.Scan(
		&rawID, &rawAccountID, &rawLicenseID,
		&m.Fingerprint, &m.Hostname, &m.Metadata, &m.LastSeenAt,
		&envStr, &m.CreatedAt,
	)
	if err != nil {
		return m, err
	}
	m.ID = core.MachineID(rawID)
	m.AccountID = core.AccountID(rawAccountID)
	m.LicenseID = core.LicenseID(rawLicenseID)
	m.Environment = core.Environment(envStr)
	return m, nil
}
```

Update `Create` (now 9 params):
```go
func (r *MachineRepo) Create(ctx context.Context, machine *domain.Machine) error {
	q := conn(ctx, r.pool)
	_, err := q.Exec(ctx,
		`INSERT INTO machines (`+machineColumns+`) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		uuid.UUID(machine.ID), uuid.UUID(machine.AccountID), uuid.UUID(machine.LicenseID),
		machine.Fingerprint, machine.Hostname, machine.Metadata, machine.LastSeenAt,
		string(machine.Environment), machine.CreatedAt,
	)
	return err
}
```

- [ ] **Step 7: Update webhook_repo.go — add environment to endpoint columns, scan, create; and event columns/create**

In `internal/db/webhook_repo.go`:

Update `webhookEndpointColumns`:
```go
const webhookEndpointColumns = `id, account_id, url, events, signing_secret, active, environment, created_at`
```

Update `scanWebhookEndpoint`:
```go
func scanWebhookEndpoint(s scannable) (domain.WebhookEndpoint, error) {
	var ep domain.WebhookEndpoint
	var rawID, rawAccountID uuid.UUID
	var rawEvents []string
	var envStr string
	err := s.Scan(
		&rawID, &rawAccountID,
		&ep.URL, &rawEvents, &ep.SigningSecret, &ep.Active,
		&envStr, &ep.CreatedAt,
	)
	if err != nil {
		return ep, err
	}
	ep.ID = core.WebhookEndpointID(rawID)
	ep.AccountID = core.AccountID(rawAccountID)
	ep.Events = make([]core.EventType, len(rawEvents))
	for i, e := range rawEvents {
		ep.Events[i] = core.EventType(e)
	}
	ep.Environment = core.Environment(envStr)
	return ep, nil
}
```

Update `CreateEndpoint` (now 8 params):
```go
func (r *WebhookRepo) CreateEndpoint(ctx context.Context, ep *domain.WebhookEndpoint) error {
	q := conn(ctx, r.pool)
	events := make([]string, len(ep.Events))
	for i, e := range ep.Events {
		events[i] = string(e)
	}
	_, err := q.Exec(ctx,
		`INSERT INTO webhook_endpoints (`+webhookEndpointColumns+`)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		uuid.UUID(ep.ID), uuid.UUID(ep.AccountID),
		ep.URL, events, ep.SigningSecret, ep.Active,
		string(ep.Environment), ep.CreatedAt,
	)
	return err
}
```

Update `CreateEvent` — add `string(event.Environment)` (now 11 params):
```go
func (r *WebhookRepo) CreateEvent(ctx context.Context, event *domain.WebhookEvent) error {
	q := conn(ctx, r.pool)
	_, err := q.Exec(ctx,
		`INSERT INTO webhook_events (id, account_id, endpoint_id, event_type, payload,
		 status, attempts, last_attempted_at, response_status, environment, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		uuid.UUID(event.ID), uuid.UUID(event.AccountID), uuid.UUID(event.EndpointID),
		string(event.EventType), event.Payload,
		string(event.Status), event.Attempts, event.LastAttemptedAt,
		event.ResponseStatus, string(event.Environment), event.CreatedAt,
	)
	return err
}
```

- [ ] **Step 8: Commit (code won't compile yet — callers need updating in Task 3)**

```bash
git add migrations/012_environment_isolation.sql internal/domain/ internal/db/
git commit -m "feat: environment isolation foundation — migration, domain models, TxManager, repos"
```

---

## Task 3: Environment Isolation — Auth Middleware, Services, Handlers, Test Mocks

**Files:**
- Modify: `internal/server/middleware/auth.go`
- Modify: `internal/auth/service.go`
- Modify: `internal/product/service.go`
- Modify: `internal/licensing/service.go`
- Modify: `internal/webhook/service.go`
- Modify: `internal/server/handler/products.go`
- Modify: `internal/server/handler/licenses.go`
- Modify: `internal/server/handler/auth.go`
- Modify: `internal/server/handler/apikeys.go`
- Modify: `internal/server/handler/webhooks.go`
- Modify: `internal/auth/service_test.go`
- Modify: `internal/product/service_test.go`
- Modify: `internal/licensing/service_test.go`

This task updates all `WithTenant` callers to pass environment. The pattern is mechanical:
1. Add `Environment` to auth middleware's `AuthenticatedAccount`
2. Add `env core.Environment` param to every service method that calls `WithTenant`
3. Pass `a.Environment` from every handler to the service
4. Update test mocks

- [ ] **Step 1: Add Environment to AuthenticatedAccount**

In `internal/server/middleware/auth.go`, update the struct and both auth paths:

```go
type AuthenticatedAccount struct {
	AccountID   core.AccountID
	UserID      *core.UserID
	Role        *core.UserRole
	Environment core.Environment
}
```

In the API key auth branch (around line 60), add `Environment`:
```go
c.Locals(localsKeyAuth, &AuthenticatedAccount{
	AccountID:   apiKey.AccountID,
	Environment: apiKey.Environment,
})
```

In the JWT auth branch (around line 72), default to live:
```go
c.Locals(localsKeyAuth, &AuthenticatedAccount{
	AccountID:   claims.AccountID,
	UserID:      &claims.UserID,
	Role:        &claims.Role,
	Environment: core.EnvironmentLive,
})
```

- [ ] **Step 2: Update auth service — add env param to WithTenant calls**

In `internal/auth/service.go`, update every method that calls `WithTenant`:

Every `WithTenant` call changes from:
```go
s.txManager.WithTenant(ctx, accountID, func(ctx context.Context) error {
```
To:
```go
s.txManager.WithTenant(ctx, accountID, env, func(ctx context.Context) error {
```

Methods to update and their environment source:

| Method | Line | Env source |
|--------|------|-----------|
| `Refresh` | 195 | `core.EnvironmentLive` (hardcoded — refresh is JWT/dashboard only, no API key environment) |
| `GetMe` | 244 | Add `env core.Environment` param |
| `CreateAPIKey` | 281 | Add `env core.Environment` param |
| `ListAPIKeys` | 304 | Add `env core.Environment` param |
| `DeleteAPIKey` | 317 | Add `env core.Environment` param |

Example — `GetMe` updated signature:
```go
func (s *Service) GetMe(ctx context.Context, accountID core.AccountID, env core.Environment, userID *core.UserID) (*MeResult, error) {
```

Example — `Refresh` (hardcoded live):
```go
txErr := s.txManager.WithTenant(ctx, stored.AccountID, core.EnvironmentLive, func(ctx context.Context) error {
```

`Signup`, `Login`, `Logout` don't use `WithTenant` — no changes needed. `Signup` uses `WithTx`.

- [ ] **Step 3: Update product service — add env param**

In `internal/product/service.go`, add `env core.Environment` parameter to all 5 methods:

| Method | Line |
|--------|------|
| `Create` | 51 |
| `List` | 107 |
| `Get` | 123 |
| `Update` | 144 |
| `Delete` | 169 |

Pattern for each:
```go
func (s *Service) Create(ctx context.Context, accountID core.AccountID, env core.Environment, req CreateRequest) (*domain.Product, error) {
	// ...
	err := s.txManager.WithTenant(ctx, accountID, env, func(ctx context.Context) error {
```

Products are environment-agnostic (they exist in both environments), but `WithTenant` still needs the env for the session variable.

- [ ] **Step 4: Update licensing service — add env param, stamp environment on records**

In `internal/licensing/service.go`, add `env core.Environment` to methods that call `WithTenant`:

| Method | Line | Notes |
|--------|------|-------|
| `Create` | 80 | Also stamp `env` on license in `buildLicense` |
| `BulkCreate` | 124 | Same |
| `List` | 186 | |
| `Get` | 201 | |
| `Revoke` | 218 | Via `transitionStatus` |
| `Suspend` | 227 | Via `transitionStatus` |
| `Reinstate` | 235 | Via `transitionStatus` |
| `Activate` | 263 | Also stamp `env` on machine |
| `Deactivate` | 331 | |
| `Heartbeat` | 341 | |

`Validate` (line 245) does NOT change — it's a public endpoint with no auth context.

Update `transitionStatus` helper to accept and pass `env`:
```go
func (s *Service) transitionStatus(
	ctx context.Context,
	accountID core.AccountID,
	env core.Environment,
	licenseID core.LicenseID,
	canTransition func(core.LicenseStatus) bool,
	target core.LicenseStatus,
	errMsg string,
) (*domain.License, error) {
	// ...
	err := s.txManager.WithTenant(ctx, accountID, env, func(ctx context.Context) error {
```

Update `buildLicense` to accept and stamp `env`:
```go
func buildLicense(
	req CreateRequest,
	licenseID core.LicenseID,
	prefix, keyHash string,
	now time.Time,
	accountID core.AccountID,
	productID core.ProductID,
	validationTTL int,
	privKey ed25519.PrivateKey,
	env core.Environment,
) (*domain.License, error) {
	// ... at the end, in the license struct:
	license := &domain.License{
		// ... existing fields ...
		Environment:   env,
	}
```

In `Activate`, stamp environment on the machine:
```go
machine := &domain.Machine{
	// ... existing fields ...
	Environment: env,
}
```

- [ ] **Step 5: Update webhook service — add env param, stamp environment on records**

In `internal/webhook/service.go`, add `env core.Environment` to methods:

| Method | Line |
|--------|------|
| `CreateEndpoint` | 33 |
| `ListEndpoints` | 69 |
| `DeleteEndpoint` | 84 |
| `Dispatch` | 92 |

For `CreateEndpoint`, stamp env on the endpoint:
```go
func (s *Service) CreateEndpoint(ctx context.Context, accountID core.AccountID, env core.Environment, req CreateEndpointRequest) (*domain.WebhookEndpoint, error) {
	// ...
	endpoint := &domain.WebhookEndpoint{
		// ... existing fields ...
		Environment:   env,
	}
```

For `Dispatch`, stamp env on the event:
```go
func (s *Service) Dispatch(ctx context.Context, accountID core.AccountID, env core.Environment, eventType core.EventType, payload json.RawMessage) {
	// ...
	s.txManager.WithTenant(ctx, accountID, env, func(ctx context.Context) error {
	// ...
	event := &domain.WebhookEvent{
		// ... existing fields ...
		Environment: env,
	}
```

- [ ] **Step 6: Update all handlers to pass a.Environment**

Each handler gets `a.Environment` from `middleware.FromContext(c)` and passes it to the service.

**products.go** — all 5 handlers. Pattern:
```go
func (h *ProductHandler) Create(c fiber.Ctx) error {
	// ...
	a := middleware.FromContext(c)
	result, err := h.svc.Create(c.Context(), a.AccountID, a.Environment, req)
```

**licenses.go** — all handlers. Pattern:
```go
a := middleware.FromContext(c)
result, err := h.svc.Create(c.Context(), a.AccountID, a.Environment, productID, req)
```

Note: for license Create/BulkCreate, `env` goes after `accountID` and before `productID`.

**auth.go** — `Me` handler:
```go
result, err := h.svc.GetMe(c.Context(), a.AccountID, a.Environment, a.UserID)
```

**apikeys.go** — all 3 handlers. Pattern:
```go
a := middleware.FromContext(c)
result, err := h.svc.CreateAPIKey(c.Context(), a.AccountID, a.Environment, req)
```

**webhooks.go** — all 3 handlers. Pattern:
```go
a := middleware.FromContext(c)
result, err := h.svc.CreateEndpoint(c.Context(), a.AccountID, a.Environment, req)
```

- [ ] **Step 7: Update test mocks**

In all three test files (`auth/service_test.go`, `product/service_test.go`, `licensing/service_test.go`), update the `mockTxManager.WithTenant` signature:

```go
func (m *mockTxManager) WithTenant(_ context.Context, _ core.AccountID, _ core.Environment, fn func(context.Context) error) error {
	return fn(context.Background())
}
```

- [ ] **Step 8: Verify compilation and tests**

```bash
go vet ./...
go test ./... -count=1 -short
```

- [ ] **Step 9: Commit**

```bash
git add internal/ cmd/
git commit -m "feat: environment isolation — auth middleware, services, handlers pass environment through RLS"
```

---

## Task 4: Webhook Dispatch Wiring

**Files:**
- Modify: `internal/core/enums.go`
- Modify: `internal/licensing/service.go`
- Modify: `cmd/server/serve.go`
- Modify: `internal/licensing/service_test.go`

**Depends on:** Task 3 (environment isolation) — `Dispatch` now requires `env` parameter.

- [ ] **Step 1: Add EventTypeLicenseReinstated to core/enums.go**

Add after `EventTypeLicenseRevoked`:
```go
EventTypeLicenseReinstated  EventType = "license.reinstated"
```

- [ ] **Step 2: Inject webhook service into licensing service**

In `internal/licensing/service.go`, add `webhookSvc` field:

```go
type Service struct {
	txManager  domain.TxManager
	licenses   domain.LicenseRepository
	products   domain.ProductRepository
	machines   domain.MachineRepository
	masterKey  *crypto.MasterKey
	webhookSvc *webhook.Service
}
```

Add import for the webhook package:
```go
import (
	// ... existing imports ...
	"github.com/getlicense-io/getlicense-api/internal/webhook"
)
```

Update `NewService`:
```go
func NewService(
	txManager domain.TxManager,
	licenses domain.LicenseRepository,
	products domain.ProductRepository,
	machines domain.MachineRepository,
	masterKey *crypto.MasterKey,
	webhookSvc *webhook.Service,
) *Service {
	return &Service{
		txManager:  txManager,
		licenses:   licenses,
		products:   products,
		machines:   machines,
		masterKey:  masterKey,
		webhookSvc: webhookSvc,
	}
}
```

- [ ] **Step 3: Add dispatch helper**

Add a private helper to avoid repetition:

```go
func (s *Service) dispatchEvent(ctx context.Context, accountID core.AccountID, env core.Environment, eventType core.EventType, payload any) {
	if s.webhookSvc == nil {
		return
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return
	}
	s.webhookSvc.Dispatch(ctx, accountID, env, eventType, data)
}
```

- [ ] **Step 4: Wire dispatch calls in service methods**

Add dispatch calls after each successful operation:

**Create** (after line 121 `return result, nil`):
```go
	// ... after the WithTenant block ...
	if err != nil {
		return nil, err
	}
	s.dispatchEvent(ctx, accountID, env, core.EventTypeLicenseCreated, result.License)
	return result, nil
```

**BulkCreate** (after line 183):
```go
	if err != nil {
		return nil, err
	}
	for _, r := range results.Results {
		s.dispatchEvent(ctx, accountID, env, core.EventTypeLicenseCreated, r.License)
	}
	return results, nil
```

**Suspend** — update to dispatch after getting result:
```go
func (s *Service) Suspend(ctx context.Context, accountID core.AccountID, env core.Environment, licenseID core.LicenseID) (*domain.License, error) {
	result, err := s.transitionStatus(ctx, accountID, env, licenseID,
		func(st core.LicenseStatus) bool { return st.CanSuspend() },
		core.LicenseStatusSuspended,
		"License cannot be suspended from current status",
	)
	if err != nil {
		return nil, err
	}
	s.dispatchEvent(ctx, accountID, env, core.EventTypeLicenseSuspended, result)
	return result, nil
}
```

**Revoke** — change to capture the license before returning:
```go
func (s *Service) Revoke(ctx context.Context, accountID core.AccountID, env core.Environment, licenseID core.LicenseID) error {
	result, err := s.transitionStatus(ctx, accountID, env, licenseID,
		func(st core.LicenseStatus) bool { return st.CanRevoke() },
		core.LicenseStatusRevoked,
		"License cannot be revoked from current status",
	)
	if err != nil {
		return err
	}
	s.dispatchEvent(ctx, accountID, env, core.EventTypeLicenseRevoked, result)
	return nil
}
```

**Reinstate**:
```go
func (s *Service) Reinstate(ctx context.Context, accountID core.AccountID, env core.Environment, licenseID core.LicenseID) (*domain.License, error) {
	result, err := s.transitionStatus(ctx, accountID, env, licenseID,
		func(st core.LicenseStatus) bool { return st.CanReinstate() },
		core.LicenseStatusActive,
		"License cannot be reinstated from current status",
	)
	if err != nil {
		return nil, err
	}
	s.dispatchEvent(ctx, accountID, env, core.EventTypeLicenseReinstated, result)
	return result, nil
}
```

**Activate** (after the WithTenant block):
```go
	if err != nil {
		return nil, err
	}
	s.dispatchEvent(ctx, accountID, env, core.EventTypeMachineActivated, result)
	return result, nil
```

**Deactivate** (after the WithTenant block):
```go
func (s *Service) Deactivate(ctx context.Context, accountID core.AccountID, env core.Environment, licenseID core.LicenseID, req DeactivateRequest) error {
	if err := ValidateFingerprint(req.Fingerprint); err != nil {
		return err
	}

	err := s.txManager.WithTenant(ctx, accountID, env, func(ctx context.Context) error {
		return s.machines.DeleteByFingerprint(ctx, licenseID, req.Fingerprint)
	})
	if err != nil {
		return err
	}
	s.dispatchEvent(ctx, accountID, env, core.EventTypeMachineDeactivated, map[string]string{
		"license_id":  licenseID.String(),
		"fingerprint": req.Fingerprint,
	})
	return nil
}
```

- [ ] **Step 5: Update serve.go**

In `cmd/server/serve.go`, pass `webhookSvc` to licensing:

```go
licenseSvc := licensing.NewService(txManager, licenseRepo, productRepo, machineRepo, cfg.MasterKey, webhookSvc)
```

- [ ] **Step 6: Update licensing test mock**

In `internal/licensing/service_test.go`, update `NewService` call to pass `nil` for webhookSvc:

```go
svc := NewService(txm, licenses, products, machines, mk, nil)
```

- [ ] **Step 7: Verify compilation and tests**

```bash
go vet ./...
go test ./... -count=1 -short
```

- [ ] **Step 8: Commit**

```bash
git add internal/core/ internal/licensing/ cmd/server/
git commit -m "feat: webhook dispatch wiring — 6 events fired from licensing service"
```

---

## Task 5: OpenAPI Spec

**Files:**
- Create: `openapi.yaml`

- [ ] **Step 1: Create the OpenAPI spec**

Create `openapi.yaml` at the repo root with the full API spec. The file covers all endpoints, request/response schemas, error format, authentication, and pagination.

The spec is large (~500 lines of YAML). It must match the Go struct JSON tags exactly. Key design points:
- OpenAPI 3.1.0
- Security scheme: Bearer token
- Error schema: `{"error": {"code": "string", "message": "string", "doc_url": "string"}}`
- Pagination wrapper: `{"data": [...], "pagination": {"limit": N, "offset": N, "total": N}}`
- All endpoints under `/v1/` prefix

Create the full `openapi.yaml` file with:
- **Info**: title "GetLicense API", version "1.0.0"
- **Servers**: `http://localhost:3000` (dev)
- **Security**: BearerAuth (http bearer)
- **Paths**: All 22+ endpoints with request bodies, responses, parameters
- **Components/Schemas**: Account, User, Product, License, Machine, APIKey, WebhookEndpoint, Error, Pagination, all request/response types
- **Tags**: auth, products, licenses, machines, validation, api-keys, webhooks

Note: This is a documentation artifact. Read the handler files, domain models, and request/response types to ensure the spec matches the actual API exactly. Include the `environment` field on License, Machine, and WebhookEndpoint. Include `heartbeat_timeout` on Product. Include the bulk create endpoint.

- [ ] **Step 2: Verify YAML is valid**

```bash
python3 -c "import yaml; yaml.safe_load(open('openapi.yaml'))" && echo "Valid YAML"
```

- [ ] **Step 3: Commit**

```bash
git add openapi.yaml
git commit -m "docs: OpenAPI 3.1 spec — all 22 endpoints documented"
```

---

## Summary

| Task | Feature | Complexity |
|------|---------|-----------|
| 1 | DevSecOps — CI, lint config, pre-commit, .dockerignore | LOW — config files only |
| 2 | Environment isolation — migration, domain, TxManager, repos | MEDIUM — foundation layer |
| 3 | Environment isolation — auth, services, handlers, test mocks | HIGH — cascading signature changes across ~30 call sites |
| 4 | Webhook dispatch wiring — inject webhook service, wire 6 events | MEDIUM — code changes in one service |
| 5 | OpenAPI spec — hand-maintained documentation | MEDIUM — large but straightforward |
