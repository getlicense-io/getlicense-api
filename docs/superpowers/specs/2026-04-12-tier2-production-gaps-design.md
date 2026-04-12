# Tier 2: Production Gaps — Design Spec

## Goal

Close remaining production gaps: environment isolation (test/live), webhook dispatch wiring, DevSecOps (CI + pre-commit), OpenAPI spec, and Docker polish.

## Scope

Five independent features, each shippable on its own:

1. **Environment isolation** — test/live data separation via RLS
2. **Webhook dispatch wiring** — call `Dispatch()` from service methods
3. **GitHub Actions CI** — vet, lint, test, build on push/PR
4. **Pre-commit hook** — gofmt + go vet before push
5. **OpenAPI spec** — hand-maintained openapi.yaml
6. **.dockerignore** — exclude non-build files from Docker context

---

## 1. Environment Isolation (test/live)

### Problem

API keys have an `environment` field (`live` or `test`) but it is never enforced. A test API key can access live data and vice versa.

### Design

**RLS-based filtering** — extend existing RLS policies to also filter by environment. Same pattern as tenant isolation (`app.current_account_id`), new dimension (`app.current_environment`).

#### New column

Add `environment TEXT NOT NULL DEFAULT 'live'` to:
- `licenses`
- `machines`
- `webhook_endpoints`
- `webhook_events`

Products stay environment-agnostic — they exist in both environments. A product's Ed25519 keypair signs both test and live licenses.

#### Migration (012_environment_isolation.sql)

```sql
-- +goose Up
ALTER TABLE licenses ADD COLUMN environment TEXT NOT NULL DEFAULT 'live';
ALTER TABLE machines ADD COLUMN environment TEXT NOT NULL DEFAULT 'live';
ALTER TABLE webhook_endpoints ADD COLUMN environment TEXT NOT NULL DEFAULT 'live';
ALTER TABLE webhook_events ADD COLUMN environment TEXT NOT NULL DEFAULT 'live';

-- Update RLS policies to include environment filtering.
-- Pattern: existing account_id check AND (env setting is null OR environment matches)

-- Drop and recreate each policy for the 4 tables above.
-- Example for licenses:
DROP POLICY IF EXISTS licenses_tenant ON licenses;
CREATE POLICY licenses_tenant ON licenses
  USING (
    (NULLIF(current_setting('app.current_account_id', true), '') IS NULL
     OR account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid)
    AND
    (NULLIF(current_setting('app.current_environment', true), '') IS NULL
     OR environment = current_setting('app.current_environment', true))
  );

-- Same pattern for machines, webhook_endpoints, webhook_events.

-- +goose Down
-- Restore original policies (account_id only).
-- Drop environment columns.
```

#### TxManager change

`WithTenant(ctx, accountID, fn)` currently sets only `app.current_account_id`. Add environment to the context:

```go
func (tm *TxManager) WithTenant(ctx context.Context, accountID core.AccountID, env core.Environment, fn func(ctx context.Context) error) error
```

Inside the transaction, set both:
```go
set_config('app.current_account_id', $1, true)
set_config('app.current_environment', $2, true)
```

This is a signature change on `domain.TxManager` interface. All callers must pass the environment.

#### Auth middleware

Add `Environment core.Environment` to `AuthenticatedAccount`:
```go
type AuthenticatedAccount struct {
    AccountID   core.AccountID
    UserID      *core.UserID
    Role        *core.UserRole
    Environment core.Environment
}
```

- API key auth: populate from `apiKey.Environment`
- JWT auth (dashboard): default to `core.EnvironmentLive`

#### Service layer

All service methods that call `WithTenant` must now pass `auth.Environment`. The handler already has the auth context, so it passes `auth.Environment` to the service, which passes it to `WithTenant`.

Services that create records (licenses, machines, webhook endpoints) stamp `environment` from the auth context.

#### Validation endpoint

`POST /v1/validate` has no auth context. License key lookup is global (by hash). No environment filtering needed — the license key itself is the credential. The response includes the license's environment field so the SDK knows which environment it belongs to.

#### Background jobs

Background loops (license expiry, stale machine cleanup) run without environment context. The `IS NULL` escape hatch in RLS policies allows this — they process all environments.

---

## 2. Webhook Dispatch Wiring

### Problem

`webhook.Service.Dispatch()` exists with full delivery infrastructure (retries, event persistence, HMAC signing) but is never called from any handler or service method.

### Design

#### Inject webhook service into licensing service

```go
type Service struct {
    txManager  domain.TxManager
    licenses   domain.LicenseRepository
    products   domain.ProductRepository
    machines   domain.MachineRepository
    masterKey  *crypto.MasterKey
    webhookSvc *webhook.Service  // new
}
```

Update `NewService` constructor and `serve.go` composition root.

#### New event type

Add `EventTypeLicenseReinstated EventType = "license.reinstated"` to `core/enums.go`. All other event types already exist.

#### Wire 6 events

| Service Method | Event Type | Payload |
|---------------|------------|---------|
| `Create` | `license.created` | License JSON |
| `BulkCreate` | `license.created` | License JSON (one per license) |
| `Suspend` | `license.suspended` | License JSON |
| `Revoke` | `license.revoked` | License JSON |
| `Reinstate` | `license.reinstated` | License JSON |
| `Activate` | `machine.activated` | Machine JSON |
| `Deactivate` | `machine.deactivated` | `{"license_id": "...", "fingerprint": "..."}` |

#### Dispatch pattern

After successful transaction commit, fire-and-forget:
```go
func (s *Service) Suspend(ctx context.Context, accountID core.AccountID, env core.Environment, licenseID core.LicenseID) (*domain.License, error) {
    result, err := s.transitionStatus(...)
    if err != nil {
        return nil, err
    }

    if payload, err := json.Marshal(result); err == nil {
        s.webhookSvc.Dispatch(ctx, accountID, core.EventTypeLicenseSuspended, payload)
    }
    return result, nil
}
```

Dispatch errors are logged internally, never returned to the caller. Marshal errors are silently dropped (all domain structs are JSON-serializable by design).

#### Not wired yet

- `license.validated` — public endpoint, high-volume, no auth context
- `license.expired` — background loop, would need webhook service injected into background; defer to later

---

## 3. GitHub Actions CI

### Workflow (`.github/workflows/ci.yml`)

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

Single job, fast feedback. E2E tests with Postgres deferred to a separate workflow.

### Linting config (`.golangci.yml`)

Enable a focused set of linters:
- `errcheck` — unchecked errors
- `govet` — vet analysis
- `staticcheck` — static analysis
- `unused` — unused code
- `ineffassign` — ineffectual assignments
- `gosimple` — simplifications

No exotic linters. Fast, low false-positive rate.

---

## 4. Pre-commit Hook

### Script (`scripts/pre-commit`)

```bash
#!/usr/bin/env bash
set -e

# Check formatting on staged Go files.
UNFORMATTED=$(gofmt -l $(git diff --cached --name-only --diff-filter=ACM -- '*.go'))
if [ -n "$UNFORMATTED" ]; then
    echo "Unformatted Go files:"
    echo "$UNFORMATTED"
    echo "Run: gofmt -w <file>"
    exit 1
fi

# Run vet.
go vet ./...
```

### Installation

New Makefile target:
```makefile
hooks:
	cp scripts/pre-commit .git/hooks/pre-commit
	chmod +x .git/hooks/pre-commit
```

Zero dependencies beyond Go. Runs in < 2 seconds.

---

## 5. OpenAPI Spec

### File: `openapi.yaml` (repo root)

Hand-maintained OpenAPI 3.1 spec covering all endpoints:

**Paths (~22 endpoints):**
- Auth: signup, login, refresh, logout, me
- Products: CRUD (5)
- Licenses: create, bulk-create, list, get, revoke, suspend, reinstate, activate, deactivate, heartbeat (10)
- Validate: public validation (1)
- API Keys: create, list, delete (3)
- Webhooks: create, list, delete (3)

**Components:**
- Schemas: Account, Product, License, Machine, APIKey, WebhookEndpoint, Error, Pagination, ListResponse
- Security schemes: Bearer token (API key or JWT)
- Common responses: 401, 422, 429, 500

**Design choices:**
- Single file (not split) — manageable at this size
- Request/response schemas match Go struct JSON tags exactly
- Error schema matches the `{"error": {"code": "...", "message": "...", "doc_url": "..."}}` format

---

## 6. Docker Polish

### `.dockerignore`

```
.git
.github
docs/
e2e/
*.md
.golangci.yml
.pre-commit-config.yaml
scripts/
```

Reduces build context size. No changes to existing Dockerfile or docker-compose.yml.

---

## Impact Summary

| Feature | Files Changed | Complexity |
|---------|--------------|------------|
| Environment isolation | Migration, TxManager, auth middleware, all service callers, domain models, repos | HIGH — touches many files |
| Webhook dispatch | licensing/service.go, serve.go | MEDIUM — straightforward wiring |
| GitHub Actions CI | .github/workflows/ci.yml, .golangci.yml | LOW — config only |
| Pre-commit hook | scripts/pre-commit, Makefile | LOW — script + make target |
| OpenAPI spec | openapi.yaml | MEDIUM — documentation |
| .dockerignore | .dockerignore | LOW — one file |

### Recommended order

1. DevSecOps (CI + hook) — foundation, catches issues in everything that follows
2. Environment isolation — most complex, highest value
3. Webhook dispatch wiring — depends on env isolation (needs to pass environment)
4. OpenAPI spec — can be written in parallel, no code deps
5. .dockerignore — trivial, do anytime
