# Tier 1: Production Readiness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the GetLicense API production-ready with rate limiting, webhook event persistence, SSRF protection, bulk license creation, and machine heartbeat expiry.

**Architecture:** Each feature is independent and shippable on its own. Rate limiting uses Fiber's built-in middleware. Webhook delivery moves from a package function to a Service method for repo access. Machine heartbeat expiry adds a background loop alongside the existing license expiry loop.

**Tech Stack:** Fiber v3 limiter middleware, existing service/repository pattern, goose migrations

**Working directory:** `/Users/netf/Projects/getlicense/getlicense-api`

**Note:** Environment isolation and OpenAPI spec are deferred to separate plans — they need their own brainstorm-spec-plan cycle.

---

## File Map

### New files
```
internal/server/middleware/ratelimit.go     # Task 1: rate limit middleware config
internal/webhook/ssrf.go                    # Task 3: URL validation for private IPs
internal/webhook/ssrf_test.go               # Task 3
migrations/011_heartbeat_timeout.sql        # Task 5: add heartbeat_timeout to products
```

### Modified files
```
internal/server/app.go                      # Task 1: add rate limit middleware
internal/server/routes.go                   # Task 1: apply rate limits to route groups
internal/server/deps.go                     # Task 1: pass config to rate limiter

internal/webhook/service.go                 # Task 2: persist events, Task 3: SSRF checks
internal/webhook/deliver.go                 # Task 2: move to Service method, update event status

internal/domain/repositories.go             # Task 4: add BulkCreate to LicenseRepository
internal/domain/models.go                   # Task 5: add HeartbeatTimeout to Product
internal/licensing/service.go               # Task 4: add BulkCreate method
internal/server/handler/licenses.go         # Task 4: add BulkCreate handler
internal/server/routes.go                   # Task 4: add bulk route

internal/db/license_repo.go                 # Task 4: implement BulkCreate
internal/db/machine_repo.go                 # Task 5: add DeactivateStale method
internal/db/product_repo.go                 # Task 5: scan heartbeat_timeout field

internal/server/background.go              # Task 5: add machine heartbeat expiry loop
```

---

## Task 1: Rate Limiting

**Files:**
- Create: `internal/server/middleware/ratelimit.go`
- Modify: `internal/server/routes.go`

Two rate limit tiers per PROJECT.md:
- **Management API** (authenticated routes): 1000 req/min per API key / account
- **Validation endpoint** (public): 10000 req/min per IP (no auth context available)

Uses `github.com/gofiber/fiber/v3/middleware/limiter` with sliding window.

- [ ] **Step 1: Create rate limit middleware config**

`internal/server/middleware/ratelimit.go`:
```go
package middleware

import (
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/limiter"
)

// ManagementRateLimit returns a rate limiter for authenticated management endpoints.
// 1000 requests per minute, keyed by account ID from auth context.
func ManagementRateLimit() fiber.Handler {
	return limiter.New(limiter.Config{
		Max:        1000,
		Expiration: 1 * time.Minute,
		KeyGenerator: func(c fiber.Ctx) string {
			auth := FromContext(c)
			if auth != nil {
				return "mgmt:" + auth.AccountID.String()
			}
			return "mgmt:anonymous"
		},
		LimitReached: rateLimitReached,
	})
}

// ValidationRateLimit returns a rate limiter for the public validation endpoint.
// 10000 requests per minute, keyed by client IP.
func ValidationRateLimit() fiber.Handler {
	return limiter.New(limiter.Config{
		Max:        10000,
		Expiration: 1 * time.Minute,
		KeyGenerator: func(c fiber.Ctx) string {
			return "validate:" + c.IP()
		},
		LimitReached: rateLimitReached,
	})
}

func rateLimitReached(c fiber.Ctx) error {
	return fiber.NewError(fiber.StatusTooManyRequests, "Rate limit exceeded")
}
```

- [ ] **Step 2: Apply rate limits in routes.go**

Modify `internal/server/routes.go` — add rate limit middleware after auth middleware on the management routes, and on the validate route:

```go
func registerRoutes(app *fiber.App, deps *Deps) {
	v1 := app.Group("/v1")
	authMw := middleware.RequireAuth(deps.APIKeyRepo, deps.MasterKey)
	mgmtLimit := middleware.ManagementRateLimit()
	validateLimit := middleware.ValidationRateLimit()

	// Auth (public).
	ah := handler.NewAuthHandler(deps.AuthService)
	v1.Post("/auth/signup", ah.Signup)
	v1.Post("/auth/login", ah.Login)
	v1.Post("/auth/refresh", ah.Refresh)
	v1.Post("/auth/logout", ah.Logout)
	v1.Get("/auth/me", authMw, ah.Me)

	// Products (authenticated + rate limited).
	ph := handler.NewProductHandler(deps.ProductService)
	products := v1.Group("/products", authMw, mgmtLimit)
	// ... (existing routes unchanged)

	// Validate (public + validation rate limit).
	vh := handler.NewValidateHandler(deps.LicenseService)
	v1.Post("/validate", validateLimit, vh.Validate)

	// API Keys (authenticated + rate limited).
	akh := handler.NewAPIKeyHandler(deps.AuthService)
	apiKeys := v1.Group("/api-keys", authMw, mgmtLimit)
	// ...

	// Webhooks (authenticated + rate limited).
	wh := handler.NewWebhookHandler(deps.WebhookService)
	webhooks := v1.Group("/webhooks", authMw, mgmtLimit)
	// ...
}
```

Note: The management rate limiter runs AFTER `authMw` so `FromContext(c)` returns the authenticated account. The Fiber limiter returns 429 which the `errorHandler` in `app.go` converts to the `rate_limit_exceeded` AppError via the existing `fiber.Error` handling path.

- [ ] **Step 3: Verify compilation**

```bash
go vet ./...
```

- [ ] **Step 4: Test manually**

Start server, hit `/v1/validate` rapidly. After 10000 requests in a minute, should get 429.

- [ ] **Step 5: Commit**

```bash
git add internal/server/middleware/ratelimit.go internal/server/routes.go
git commit -m "feat: rate limiting — 1000/min management, 10000/min validation"
```

---

## Task 2: Webhook Event Persistence

**Files:**
- Modify: `internal/webhook/service.go`
- Modify: `internal/webhook/deliver.go`

The `WebhookRepository` already has `CreateEvent` and `UpdateEventStatus` methods (implemented in `db/webhook_repo.go`). The `WebhookEvent` model exists in `domain/models.go`. They're just never called. This task wires them into the delivery pipeline.

Key change: `DeliverWebhook` moves from a package function to a method on `Service`, giving it access to the webhook repository for persisting delivery status.

- [ ] **Step 1: Move DeliverWebhook to Service method and persist events**

Modify `internal/webhook/deliver.go`:
- Remove the standalone `DeliverWebhook` function
- Add `(s *Service) deliver(ctx context.Context, event *domain.WebhookEvent, endpoint domain.WebhookEndpoint, eventType core.EventType, body []byte, sig string)` method that:
  1. Attempts delivery with retries (same logic as current `DeliverWebhook`)
  2. After each attempt, calls `s.webhooks.UpdateEventStatus` with the current attempt count, status (pending/delivered/failed), and response status code

Modify `internal/webhook/service.go` `Dispatch` method:
- Before spawning the goroutine, create a `WebhookEvent` record with `s.webhooks.CreateEvent` (status=pending, attempts=0)
- Pass the event to the goroutine which calls `s.deliver`

```go
// In service.go Dispatch method:
for _, ep := range endpoints {
    // Create event record before spawning goroutine.
    event := &domain.WebhookEvent{
        ID:         core.NewWebhookEventID(),
        AccountID:  accountID,
        EndpointID: ep.ID,
        EventType:  eventType,
        Payload:    payload,
        Status:     core.DeliveryStatusPending,
        Attempts:   0,
        CreatedAt:  time.Now().UTC(),
    }
    // Best-effort persistence — don't block on DB errors.
    if err := s.webhooks.CreateEvent(ctx, event); err != nil {
        slog.Error("webhook: failed to persist event", "error", err)
        continue
    }

    go func() {
        s.deliver(context.Background(), event, ep, eventType, payload)
    }()
}
```

```go
// In deliver.go — new Service method:
func (s *Service) deliver(ctx context.Context, event *domain.WebhookEvent, endpoint domain.WebhookEndpoint, eventType core.EventType, payload json.RawMessage) {
    // Marshal envelope, sign, attempt delivery with retries (same as current DeliverWebhook)
    // After each attempt:
    //   s.webhooks.UpdateEventStatus(ctx, event.ID, status, attempts, &responseStatusCode)
    // On success: status = DeliveryStatusDelivered
    // After all retries exhausted: status = DeliveryStatusFailed
}
```

- [ ] **Step 2: Verify compilation and tests**

```bash
go vet ./...
go test ./internal/webhook/ -v -count=1
```

- [ ] **Step 3: Commit**

```bash
git add internal/webhook/
git commit -m "feat: webhook event persistence — delivery status tracked in DB"
```

---

## Task 3: SSRF Protection

**Files:**
- Create: `internal/webhook/ssrf.go`
- Create: `internal/webhook/ssrf_test.go`
- Modify: `internal/webhook/service.go` (validate URL on endpoint creation)
- Modify: `internal/webhook/deliver.go` (check resolved IP before connecting)

Two protection layers:
1. **Creation-time**: reject obviously private URLs (`http://localhost`, `http://127.0.0.1`, `http://10.x.x.x`, etc.)
2. **Delivery-time**: resolve DNS and check the IP is not in a private range before connecting

Both skip checks when `config.IsDevelopment()` — the service needs the Config.

- [ ] **Step 1: Write SSRF validation tests**

`internal/webhook/ssrf_test.go`:
```go
package webhook

import (
    "testing"

    "github.com/stretchr/testify/assert"
)

func TestValidateWebhookURL_RejectsPrivate(t *testing.T) {
    tests := []struct {
        url     string
        allowed bool
    }{
        {"https://example.com/webhook", true},
        {"https://api.stripe.com/hook", true},
        {"http://localhost/hook", false},
        {"http://127.0.0.1/hook", false},
        {"http://10.0.0.1/hook", false},
        {"http://172.16.0.1/hook", false},
        {"http://192.168.1.1/hook", false},
        {"http://[::1]/hook", false},
        {"http://0.0.0.0/hook", false},
        {"ftp://example.com/hook", false},        // non-HTTP scheme
        {"http://example.com/hook", false},        // HTTP not HTTPS in production
        {"https://169.254.169.254/metadata", false}, // AWS metadata
    }
    for _, tt := range tests {
        t.Run(tt.url, func(t *testing.T) {
            err := ValidateWebhookURL(tt.url, false) // production mode
            if tt.allowed {
                assert.NoError(t, err)
            } else {
                assert.Error(t, err)
            }
        })
    }
}

func TestValidateWebhookURL_DevelopmentAllowsHTTP(t *testing.T) {
    assert.NoError(t, ValidateWebhookURL("http://localhost:3001/hook", true))
    assert.NoError(t, ValidateWebhookURL("http://127.0.0.1:8080/hook", true))
}
```

- [ ] **Step 2: Implement SSRF validation**

`internal/webhook/ssrf.go`:
```go
package webhook

import (
    "fmt"
    "net"
    "net/url"
    "strings"
)

// ValidateWebhookURL checks that a webhook URL is safe to deliver to.
// In production (isDev=false): requires HTTPS, rejects private/loopback IPs.
// In development (isDev=true): allows HTTP and localhost.
func ValidateWebhookURL(rawURL string, isDev bool) error {
    u, err := url.Parse(rawURL)
    if err != nil {
        return fmt.Errorf("invalid URL: %w", err)
    }

    if isDev {
        if u.Scheme != "http" && u.Scheme != "https" {
            return fmt.Errorf("URL scheme must be http or https")
        }
        return nil
    }

    // Production: HTTPS only.
    if u.Scheme != "https" {
        return fmt.Errorf("webhook URL must use HTTPS in production")
    }

    // Check hostname against private ranges.
    hostname := u.Hostname()
    if isPrivateHost(hostname) {
        return fmt.Errorf("webhook URL must not target private or loopback addresses")
    }

    return nil
}

func isPrivateHost(hostname string) bool {
    lower := strings.ToLower(hostname)
    if lower == "localhost" || lower == "" {
        return true
    }

    ip := net.ParseIP(hostname)
    if ip == nil {
        return false // not an IP literal — allow (DNS resolution checked at delivery time)
    }

    return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}
```

- [ ] **Step 3: Wire SSRF check into endpoint creation**

Modify `internal/webhook/service.go` — add Config to Service, validate URL on create:

```go
type Service struct {
    txManager domain.TxManager
    webhooks  domain.WebhookRepository
    isDev     bool // from config.IsDevelopment()
}

func NewService(txManager domain.TxManager, webhooks domain.WebhookRepository, isDev bool) *Service {
    return &Service{txManager: txManager, webhooks: webhooks, isDev: isDev}
}

func (s *Service) CreateEndpoint(...) {
    // Validate URL before persisting.
    if err := ValidateWebhookURL(req.URL, s.isDev); err != nil {
        return nil, core.NewAppError(core.ErrValidationError, err.Error())
    }
    // ... rest unchanged
}
```

Update `cmd/server/serve.go` to pass `cfg.IsDevelopment()` to `webhook.NewService`.

- [ ] **Step 4: Run tests**

```bash
go test ./internal/webhook/ -v -count=1
go vet ./...
```

- [ ] **Step 5: Commit**

```bash
git add internal/webhook/ cmd/server/serve.go
git commit -m "feat: SSRF protection — validate webhook URLs, reject private IPs in production"
```

---

## Task 4: Bulk License Creation

**Files:**
- Modify: `internal/domain/repositories.go` (add `BulkCreate`)
- Modify: `internal/db/license_repo.go` (implement `BulkCreate`)
- Modify: `internal/licensing/service.go` (add `BulkCreate` method)
- Modify: `internal/server/handler/licenses.go` (add `BulkCreate` handler)
- Modify: `internal/server/routes.go` (add route)

Endpoint: `POST /v1/products/:id/licenses/bulk`
Body: `{"licenses": [CreateRequest, ...]}` (max 100 per request)
Response: `{"results": [CreateResult, ...]}` — each with the license + raw key

All licenses in one bulk request share the same product and are created in a single transaction.

- [ ] **Step 1: Add BulkCreate to repository interface**

Add to `domain/repositories.go` `LicenseRepository`:
```go
BulkCreate(ctx context.Context, licenses []*License) error
```

- [ ] **Step 2: Implement BulkCreate in db/license_repo.go**

Use `pgx.Batch` for efficient multi-row insert:
```go
func (r *LicenseRepo) BulkCreate(ctx context.Context, licenses []*domain.License) error {
    q := conn(ctx, r.pool)
    batch := &pgx.Batch{}
    for _, l := range licenses {
        batch.Queue(
            `INSERT INTO licenses (`+licenseColumns+`)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
            uuid.UUID(l.ID), uuid.UUID(l.AccountID), uuid.UUID(l.ProductID),
            l.KeyPrefix, l.KeyHash, l.Token,
            string(l.LicenseType), string(l.Status),
            l.MaxMachines, l.MaxSeats, l.Entitlements,
            l.LicenseeName, l.LicenseeEmail, l.ExpiresAt,
            l.CreatedAt, l.UpdatedAt,
        )
    }
    br := q.SendBatch(ctx, batch)
    defer br.Close()
    for range licenses {
        if _, err := br.Exec(); err != nil {
            return err
        }
    }
    return nil
}
```

Note: `q` might be `pgxpool.Pool` which also supports `SendBatch`. Check the `querier` interface — it doesn't include `SendBatch`. You'll need to type-assert or add `SendBatch` to the interface. The simpler approach: iterate with individual `Exec` calls inside the same transaction (the transaction is already established by `WithTenant`). This is still a single round trip per license but within one transaction, which is correct and simpler.

Actually, the simplest correct implementation: reuse `Create` in a loop inside `BulkCreate`. The transaction boundary ensures atomicity:

```go
func (r *LicenseRepo) BulkCreate(ctx context.Context, licenses []*domain.License) error {
    for _, l := range licenses {
        if err := r.Create(ctx, l); err != nil {
            return err
        }
    }
    return nil
}
```

This works because `Create` uses `conn(ctx, r.pool)` which extracts the transaction from context. All inserts happen in the same transaction.

- [ ] **Step 3: Add BulkCreate to licensing service**

Add to `internal/licensing/service.go`:

```go
type BulkCreateRequest struct {
    Licenses []CreateRequest `json:"licenses" validate:"required,min=1,max=100,dive"`
}

type BulkCreateResult struct {
    Results []CreateResult `json:"results"`
}

func (s *Service) BulkCreate(ctx context.Context, accountID core.AccountID, productID core.ProductID, req BulkCreateRequest) (*BulkCreateResult, error) {
    // Single transaction for all licenses.
    var result *BulkCreateResult

    err := s.txManager.WithTenant(ctx, accountID, func(ctx context.Context) error {
        product, err := s.products.GetByID(ctx, productID)
        if err != nil { return err }
        if product == nil {
            return core.NewAppError(core.ErrProductNotFound, "Product not found")
        }

        privKeyBytes, err := s.masterKey.Decrypt(product.PrivateKeyEnc)
        if err != nil {
            return core.NewAppError(core.ErrInternalError, "Failed to decrypt product private key")
        }

        results := make([]CreateResult, 0, len(req.Licenses))
        for _, lr := range req.Licenses {
            // Generate key, sign token, create license (same logic as single Create)
            // ... build each license and append to results
        }

        result = &BulkCreateResult{Results: results}
        return nil
    })
    if err != nil {
        return nil, err
    }
    return result, nil
}
```

The implementation should reuse the core license-building logic from `Create`. Extract a private `buildLicense` helper that both `Create` and `BulkCreate` call.

- [ ] **Step 4: Add handler and route**

Handler in `internal/server/handler/licenses.go`:
```go
func (h *LicenseHandler) BulkCreate(c fiber.Ctx) error {
    productID, err := core.ParseProductID(c.Params("id"))
    if err != nil {
        return core.NewAppError(core.ErrValidationError, "Invalid product ID")
    }
    var req licensing.BulkCreateRequest
    if err := c.Bind().Body(&req); err != nil { return err }
    auth := middleware.FromContext(c)
    result, err := h.svc.BulkCreate(c.Context(), auth.AccountID, productID, req)
    if err != nil { return err }
    return c.Status(fiber.StatusCreated).JSON(result)
}
```

Route in `internal/server/routes.go`:
```go
products.Post("/:id/licenses/bulk", lh.BulkCreate)
```

- [ ] **Step 5: Run tests and verify**

```bash
go vet ./...
go test ./internal/licensing/ -v -count=1
```

- [ ] **Step 6: Commit**

```bash
git add internal/domain/ internal/db/ internal/licensing/ internal/server/
git commit -m "feat: bulk license creation — POST /v1/products/:id/licenses/bulk (max 100)"
```

---

## Task 5: Machine Heartbeat Expiry

**Files:**
- Create: `migrations/011_heartbeat_timeout.sql`
- Modify: `internal/domain/models.go` (add `HeartbeatTimeout` to Product)
- Modify: `internal/domain/repositories.go` (add `DeactivateStale` to MachineRepository)
- Modify: `internal/db/product_repo.go` (scan new field)
- Modify: `internal/db/machine_repo.go` (implement `DeactivateStale`)
- Modify: `internal/server/background.go` (add stale machine loop)

Machines that stop sending heartbeats should be auto-deactivated after a configurable timeout. The timeout is per-product (on the `products` table), so different products can have different thresholds.

- [ ] **Step 1: Create migration**

`migrations/011_heartbeat_timeout.sql`:
```sql
-- +goose Up
ALTER TABLE products ADD COLUMN heartbeat_timeout INTEGER;

-- +goose Down
ALTER TABLE products DROP COLUMN IF EXISTS heartbeat_timeout;
```

`heartbeat_timeout` is nullable INTEGER (seconds). NULL means no auto-deactivation. Example: `3600` = machines with no heartbeat in the last hour are deactivated.

- [ ] **Step 2: Update Product model**

Add to `internal/domain/models.go` Product struct:
```go
HeartbeatTimeout *int `json:"heartbeat_timeout,omitempty"`
```

Update `internal/domain/models.go` `UpdateProductParams`:
```go
HeartbeatTimeout *int `json:"heartbeat_timeout,omitempty"`
```

- [ ] **Step 3: Update product repo to scan/update the new field**

Modify `internal/db/product_repo.go`:
- Update `productColumns` to include `heartbeat_timeout`
- Update `scanProduct` to scan the new field
- Update `Create` to include the new field in INSERT
- Update `Update` to include `heartbeat_timeout = COALESCE($6, heartbeat_timeout)` in the SET clause

- [ ] **Step 4: Add DeactivateStale to MachineRepository**

Add to `internal/domain/repositories.go`:
```go
type MachineRepository interface {
    // ... existing methods ...
    DeactivateStale(ctx context.Context) (int, error)
}
```

Implement in `internal/db/machine_repo.go`:
```go
func (r *MachineRepo) DeactivateStale(ctx context.Context) (int, error) {
    q := conn(ctx, r.pool)
    tag, err := q.Exec(ctx,
        `DELETE FROM machines m
         USING licenses l, products p
         WHERE m.license_id = l.id
           AND l.product_id = p.id
           AND p.heartbeat_timeout IS NOT NULL
           AND m.last_seen_at IS NOT NULL
           AND m.last_seen_at < NOW() - (p.heartbeat_timeout || ' seconds')::interval`)
    if err != nil {
        return 0, err
    }
    return int(tag.RowsAffected()), nil
}
```

This joins machines → licenses → products to get the per-product timeout, then deletes machines whose `last_seen_at` is older than the timeout.

- [ ] **Step 5: Add stale machine cleanup to background loop**

Modify `internal/server/background.go` — add a second loop or extend the existing one:

```go
func StartBackgroundLoops(ctx context.Context, licenseRepo domain.LicenseRepository, machineRepo domain.MachineRepository) {
    go func() {
        ticker := time.NewTicker(60 * time.Second)
        defer ticker.Stop()

        for {
            select {
            case <-ctx.Done():
                slog.Info("background loops stopped")
                return
            case <-ticker.C:
                // Expire licenses.
                if expired, err := licenseRepo.ExpireActive(ctx); err != nil {
                    slog.Error("license expiry error", "error", err)
                } else if len(expired) > 0 {
                    slog.Info("expired licenses", "count", len(expired))
                }

                // Deactivate stale machines.
                if count, err := machineRepo.DeactivateStale(ctx); err != nil {
                    slog.Error("stale machine cleanup error", "error", err)
                } else if count > 0 {
                    slog.Info("deactivated stale machines", "count", count)
                }
            }
        }
    }()
}
```

Rename `StartExpiryLoop` to `StartBackgroundLoops` and update `cmd/server/serve.go` to pass both repos.

- [ ] **Step 6: Run tests and verify**

```bash
go vet ./...
go test ./... -count=1 -short
```

- [ ] **Step 7: Update hurl E2E tests**

Add a test in `e2e/scenarios/06_machines.hurl` that:
1. Creates a product with `heartbeat_timeout: 1` (1 second)
2. Activates a machine
3. Waits 2 seconds
4. Verifies the machine was deactivated (this requires the background loop to run, which needs the server running — so this is an integration test, not a unit test. Add it to the full journey scenario or test manually.)

- [ ] **Step 8: Commit**

```bash
git add migrations/ internal/domain/ internal/db/ internal/server/ cmd/server/
git commit -m "feat: machine heartbeat expiry — auto-deactivate stale machines per product timeout"
```

---

## Summary

| Task | Feature | What it does |
|------|---------|-------------|
| 1 | Rate limiting | Fiber middleware: 1000/min management, 10000/min validation |
| 2 | Webhook event persistence | Track delivery attempts and status in `webhook_events` table |
| 3 | SSRF protection | Reject private IPs in webhook URLs (configurable for dev) |
| 4 | Bulk license creation | `POST /v1/products/:id/licenses/bulk` — up to 100 per request |
| 5 | Machine heartbeat expiry | Auto-deactivate machines with no heartbeat past product timeout |
