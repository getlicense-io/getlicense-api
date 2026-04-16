# O2 Domain Event Log Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Persist every domain event to `domain_events` with three-ID attribution. Replace the fire-and-forget `EventDispatcher` with synchronous `audit.Writer.Record` inside the mutation tx. Webhook delivery becomes a background consumer polling `domain_events`.

**Architecture:** New `internal/audit/` package owns `Writer`. Services call `writer.Record(ctx, event)` inside their `WithTargetAccount` tx. The existing `domain.EventDispatcher` interface and `licensing.Service.dispatchEvent` helper are retired. The background job gains a webhook-delivery sweep that polls `domain_events` for new rows and fans out to `webhook_endpoints`.

**Tech Stack:** Go, Fiber v3, pgx v5, goose migrations, Postgres 16 with RLS, hurl (e2e).

**Spec:** `docs/superpowers/specs/2026-04-16-o2-domain-events-design.md`

**Conventions:** All established by Release 2. 2-arg `NewAppError`, repo `(nil,nil)` on miss, `scannable`, `conn(ctx,pool)`, interface assertion, metadata nil→`{}`, `testing.Short()` gating, `gofmt -w` pre-commit.

---

## File Map

### New files

```
migrations/024_domain_events.sql                      # Task 3
internal/core/audit.go                                # Task 1 (DomainEventID, ActorKind)
internal/domain/domain_event.go                       # Task 2 (DomainEvent struct + repo interface)
internal/db/domain_event_repo.go                      # Task 4
internal/audit/writer.go                              # Task 5
internal/audit/writer_test.go                         # Task 5
internal/server/handler/events.go                     # Task 8
e2e/scenarios/23_events.hurl                          # Task 11
```

### Modified files

```
internal/core/errors.go                               # Task 1
internal/rbac/permissions.go                          # Task 7
internal/rbac/presets_test.go                         # Task 7
internal/licensing/service.go                         # Task 6 (replace dispatchEvent → audit.Record)
internal/licensing/service_test.go                    # Task 6
internal/domain/tx.go                                 # Task 6 (retire EventDispatcher)
internal/webhook/service.go                           # Task 9 (add webhook delivery from domain_events)
internal/server/background.go                         # Task 9 (add webhook delivery sweep)
internal/server/routes.go                             # Task 8
internal/server/deps.go                               # Task 8
cmd/server/serve.go                                   # Task 8
openapi.yaml                                          # Task 12
CLAUDE.md                                             # Task 12
```

---

## Prerequisites

- [ ] Confirm branch `release-3-observability`, build green, DB at version 23.
- [ ] `make db-reset && make migrate` → migrations through 023 applied.
- [ ] `go build ./... && go test ./...` — green baseline.

---

## Task 1: Core types + error codes

**Files:** Create `internal/core/audit.go`, modify `internal/core/errors.go`

- [ ] Create `internal/core/audit.go` with:
  - `DomainEventID` typed UUID (New/Parse/String/Marshal/Unmarshal — same pattern as all other IDs)
  - `ActorKind` string enum: `identity`, `api_key`, `system`, `public` with `IsValid()` method

- [ ] Add to `errors.go`: `ErrEventNotFound ErrorCode = "event_not_found"` → httpStatusMap 404.

- [ ] `gofmt -w`, `go build ./internal/core/...`, commit: `feat(core): DomainEventID, ActorKind, event error codes`

---

## Task 2: Domain model

**Files:** Create `internal/domain/domain_event.go`

- [ ] Create the file (separate from `models.go` to avoid growing that file further):

```go
type DomainEvent struct {
    ID              core.DomainEventID
    AccountID       core.AccountID
    Environment     core.Environment
    EventType       core.EventType
    ResourceType    string
    ResourceID      *string
    ActingAccountID *core.AccountID
    IdentityID      *core.IdentityID
    ActorLabel      string
    ActorKind       core.ActorKind
    APIKeyID        *core.APIKeyID
    GrantID         *core.GrantID
    RequestID       *string
    IPAddress       *string
    Payload         json.RawMessage
    CreatedAt       time.Time
}

type DomainEventRepository interface {
    Create(ctx context.Context, e *DomainEvent) error
    Get(ctx context.Context, id core.DomainEventID) (*DomainEvent, error)
    List(ctx context.Context, filter DomainEventFilter, cursor core.Cursor, limit int) ([]DomainEvent, bool, error)
}

type DomainEventFilter struct {
    ResourceType string
    ResourceID   string
    EventType    core.EventType
    IdentityID   *core.IdentityID
    GrantID      *core.GrantID
    From         *time.Time
    To           *time.Time
}
```

- [ ] `go build ./internal/domain/...` — clean. Do NOT commit (stays dirty for Task 6).

---

## Task 3: Migration `024_domain_events.sql`

**Files:** Create `migrations/024_domain_events.sql`

- [ ] Create the migration:
  - `CREATE TABLE domain_events` with all columns, CHECK constraint on `actor_kind`, all 4 indexes from spec
  - RLS: account_id + environment (same pattern as licenses — `NULLIF` escape hatch for both)
  - Seed `event:read` onto preset roles (owner/admin/developer/operator)
  - Down block drops table + removes permission

- [ ] Apply via goose directly (Go tree may be broken from Task 2). Verify with `\d domain_events`.
- [ ] Commit: `feat(db): 024 domain_events table with attribution indexes`

---

## Task 4: `DomainEventRepo` pgx implementation

**Files:** Create `internal/db/domain_event_repo.go`

- [ ] Implement `Create`, `Get` (nil/nil on miss), `List` (cursor paginated with all filters from `DomainEventFilter` — build WHERE clauses incrementally like `buildLicenseFilterClause`).
- [ ] `scannable` interface, `conn(ctx,pool)`, interface assertion.
- [ ] Column constant `domainEventColumns` with all 16 fields.
- [ ] `from`/`to` filters: `created_at >= $N` and `created_at <= $N`.
- [ ] Do NOT commit — stays dirty for Task 6.

---

## Task 5: `internal/audit/` package

**Files:** Create `internal/audit/writer.go`, `internal/audit/writer_test.go`

- [ ] `Writer` struct with `repo domain.DomainEventRepository`. Pure — no internal tx.

- [ ] `Record(ctx, event) error` — stamps `ID = NewDomainEventID()`, `CreatedAt = now()`, coerces nil Payload → `{}`, calls `repo.Create`.

- [ ] `EventFromAuth(auth, eventType, resourceType, resourceID, payload) DomainEvent` — helper that extracts attribution from `middleware.AuthContext`:
  ```go
  func EventFromAuth(auth *middleware.AuthContext, eventType core.EventType, resourceType string, resourceID string, payload json.RawMessage) domain.DomainEvent {
      var actorKind core.ActorKind
      var actorLabel string
      if auth.IdentityID != nil {
          actorKind = core.ActorKindIdentity
          actorLabel = auth.Email // or identity label
      } else if auth.APIKeyID != nil {
          actorKind = core.ActorKindAPIKey
          actorLabel = auth.APIKeyLabel // if available
      } else {
          actorKind = core.ActorKindSystem
      }
      // ... build and return DomainEvent
  }
  ```

  **Important:** Check what fields `middleware.AuthContext` actually has. It may not have `Email` or `APIKeyLabel`. If not, `actorLabel` can be empty for now — denormalization is a nice-to-have that can be added later without schema changes.

- [ ] Unit tests with a fake repo: `TestWriter_Record_StampsIDAndCreatedAt`, `TestWriter_Record_CoercesNilPayload`, `TestEventFromAuth_IdentityPath`, `TestEventFromAuth_APIKeyPath`.

- [ ] `go test ./internal/audit/...` — all pass.
- [ ] Do NOT commit — stays dirty for Task 6.

---

## Task 6: Licensing service integration (the big commit)

This is the unified commit that retires `EventDispatcher` and wires `audit.Writer`.

**Files:** Modify `internal/licensing/service.go`, `internal/licensing/service_test.go`, `internal/domain/tx.go`

### Step 6.1: Inject `*audit.Writer` into `licensing.Service`

- [ ] Replace `webhookSvc domain.EventDispatcher` with `audit *audit.Writer` in the struct and `NewService` constructor.

### Step 6.2: Replace every `s.dispatchEvent(...)` call

- [ ] Find all 8+ call sites in `service.go` (Create, BulkCreate, Revoke, Suspend, Reinstate, Activate, Checkin, Deactivate). Replace each with:

```go
s.audit.Record(ctx, audit.EventFromAuth(auth, core.EventTypeLicenseCreated, "license", license.ID.String(), payload))
```

**Challenge:** The current `dispatchEvent` takes `(ctx, accountID, env, eventType, payload)` — no `auth` context. The service methods receive `accountID` and `env` as separate params, not an `AuthContext`. Two options:

**Option A:** Pass `*middleware.AuthContext` through the service layer (add to every method signature). Clean but high blast radius.

**Option B:** Build a minimal `audit.Attribution` struct from the pieces the service already has (accountID, env, grantID from opts) and pass that instead of the full auth context. Keeps the service layer independent of the middleware package.

**Recommendation: Option B.** Define:

```go
// internal/audit/attribution.go
type Attribution struct {
    AccountID       core.AccountID
    Environment     core.Environment
    ActingAccountID *core.AccountID
    IdentityID      *core.IdentityID
    ActorKind       core.ActorKind
    ActorLabel      string
    APIKeyID        *core.APIKeyID
    GrantID         *core.GrantID
    RequestID       *string
    IPAddress       *string
}

func EventFrom(attr Attribution, eventType core.EventType, resourceType, resourceID string, payload json.RawMessage) domain.DomainEvent
```

The handler populates `Attribution` from `AuthContext` and passes it to the service method via a new field on `CreateOptions` or as an additional parameter. The service passes it through to `audit.EventFrom`.

**Simplest integration path:** Add `Attribution audit.Attribution` to `licensing.CreateOptions` (which already carries grant-related context). For methods that don't use `CreateOptions` (Revoke, Suspend, Reinstate, Activate, Checkin, Deactivate), add `attr audit.Attribution` as a new parameter.

### Step 6.3: Delete `dispatchEvent` helper and `EventDispatcher` interface

- [ ] Delete the `dispatchEvent` method from `licensing/service.go`.
- [ ] Delete the `EventDispatcher` interface from `internal/domain/tx.go`.
- [ ] Delete the `webhookSvc` field from the licensing service struct.

### Step 6.4: Update `cmd/server/serve.go`

- [ ] Construct `domainEventRepo := db.NewDomainEventRepo(pool)` and `auditWriter := audit.NewWriter(domainEventRepo)`.
- [ ] Pass `auditWriter` to `licensing.NewService(...)` instead of `webhookSvc`.

### Step 6.5: Update handlers to populate `Attribution`

- [ ] In every license handler that calls a service method, build `audit.Attribution` from the `AuthContext`:

```go
attr := audit.Attribution{
    AccountID:       auth.TargetAccountID,
    Environment:     auth.Environment,
    ActingAccountID: &auth.ActingAccountID,
    IdentityID:      auth.IdentityID,
    APIKeyID:        auth.APIKeyID,
    GrantID:         auth.GrantID,
}
```

Pass it to the service method.

### Step 6.6: Update test mocks

- [ ] Remove `mockWebhookSvc` / `mockEventDispatcher` from `service_test.go`.
- [ ] Add a `fakeAuditWriter` (using a fake `DomainEventRepository`) or inject `audit.NewWriter(fakeRepo)`.
- [ ] Update `NewService(...)` calls in tests to pass the audit writer instead of webhook dispatcher.

### Step 6.7: Build, vet, test

- [ ] `go build ./... && go vet ./... && go test ./...` — all green.

### Step 6.8: Commit

Stage everything: `internal/core/audit.go`, `internal/domain/domain_event.go`, `internal/db/domain_event_repo.go`, `internal/audit/`, `internal/licensing/`, `internal/domain/tx.go`, `cmd/server/serve.go`, `internal/server/handler/licenses.go`.

```
feat(audit): domain event log + retire EventDispatcher

Introduces domain_events table with three-ID attribution. audit.Writer
replaces EventDispatcher — events are now recorded synchronously in the
mutation tx (never lost for successful writes). Every service dispatchEvent
call site switches to audit.Record with Attribution context.

Webhook delivery will become a background consumer in a follow-up task.
```

---

## Task 7: RBAC

**Files:** Modify `internal/rbac/permissions.go`, `internal/rbac/presets_test.go`

- [ ] Add `EventRead = "event:read"`, add to `All()`, update preset test map.
- [ ] `go test ./internal/rbac/...` — pass.
- [ ] Commit: `feat(rbac): event:read permission constant`

---

## Task 8: HTTP handler + routes

**Files:** Create `internal/server/handler/events.go`, modify `routes.go`, `deps.go`, `serve.go`

- [ ] `EventHandler` with `tx domain.TxManager`, `repo domain.DomainEventRepository`.
- [ ] `List` — cursor paginated, all filters from `DomainEventFilter`. RBAC: `event:read`.
- [ ] `Get` — single event by ID. RBAC: `event:read`.
- [ ] Register routes: `GET /v1/events`, `GET /v1/events/:id`.
- [ ] Wire in `serve.go` and `deps.go`.
- [ ] `go build ./...` — clean. `make run` boot smoke.
- [ ] Commit: `feat(http): domain event list/get endpoints`

---

## Task 9: Webhook delivery from domain_events (background consumer)

**Files:** Modify `internal/webhook/service.go`, `internal/server/background.go`, `cmd/server/serve.go`

This is the most architecturally significant task — it changes webhook delivery from in-process synchronous to background poll.

### Step 9.1: Add a high-water-mark mechanism

- [ ] The background job needs to track "last processed domain_event.id" to avoid re-scanning the full table. Simplest approach: an in-memory variable in the background loop (no persistence needed — on restart, re-scan recent events and idempotently skip already-delivered ones via `ON CONFLICT` on `(endpoint_id, domain_event_id)`).

Add a unique index to `webhook_events` on `(endpoint_id, domain_event_id)` to support idempotent delivery. This needs a small migration extension OR can be added as part of O3's migration 025. For O2, use the in-memory watermark and accept that restart re-delivery is possible (webhooks are already idempotent by convention).

### Step 9.2: Add `webhook.Service.DeliverFromEvents` method

```go
func (s *Service) DeliverFromEvents(ctx context.Context, events []domain.DomainEvent) error {
    for _, event := range events {
        endpoints, err := s.endpoints.ListActiveByEventType(ctx, event.AccountID, event.Environment, event.EventType)
        if err != nil { continue }
        for _, ep := range endpoints {
            s.deliverToEndpoint(ctx, ep, event)
        }
    }
    return nil
}
```

The existing `deliverToEndpoint` or equivalent HTTP-dispatch logic is reused.

### Step 9.3: Integrate into background loop

- [ ] In `internal/server/background.go`, add a new sweep after the existing `MarkStaleExpired`/`MarkDeadExpired` calls:

```go
// Webhook delivery from domain_events
newEvents, err := domainEventRepo.ListSince(ctx, lastProcessedID, 100)
if err != nil {
    slog.Error("webhook delivery sweep error", "error", err)
} else if len(newEvents) > 0 {
    webhookSvc.DeliverFromEvents(ctx, newEvents)
    lastProcessedID = newEvents[len(newEvents)-1].ID
}
```

This requires `DomainEventRepository.ListSince(ctx, afterID, limit)` — add it to the repo interface and implement it (no RLS scoping — background job runs unscoped).

### Step 9.4: Update `StartBackgroundLoops` signature

- [ ] Widen to accept `domainEventRepo` and `webhookSvc`:

```go
func StartBackgroundLoops(ctx, licenseRepo, machineRepo, domainEventRepo, webhookSvc)
```

Update the caller in `serve.go`.

### Step 9.5: Commit

```
feat(webhook): background delivery from domain_events

Webhook delivery is now an eventual consumer of the domain_events
stream. The background job polls for new events every 60s and fans
out to matching webhook endpoints. In-process Dispatch is fully
retired.
```

---

## Task 10: DB integration tests

**Files:** Create `internal/db/domain_event_repo_test.go`

- [ ] 6 tests: CreateAndGet, GetNotFound, ListWithFilters (resource_type, event_type, from/to), ListPagination, ListSince (for the background watermark query).
- [ ] `make test-all` — pass.
- [ ] Commit: `test(db): domain_event_repo integration tests`

---

## Task 11: E2E hurl scenario

**Files:** Create `e2e/scenarios/23_events.hurl`

Scenario:
1. Signup, create product, create license (triggers license.created event via audit.Record).
2. `GET /v1/events` → at least 1 event with `event_type == "license.created"`.
3. `GET /v1/events?resource_type=license&resource_id={{license_id}}` → filtered to that license.
4. `GET /v1/events/:id` → single event with full attribution.
5. Suspend the license → `GET /v1/events?event_type=license.suspended` → 1 event.

- [ ] `make e2e` — all pass.
- [ ] Commit: `test(e2e): add 23_events scenario`

---

## Task 12: OpenAPI + CLAUDE.md

**Files:** Modify `openapi.yaml`, `CLAUDE.md`

- [ ] OpenAPI: add `DomainEvent` schema, `DomainEventFilter` query params, `GET /v1/events` and `GET /v1/events/:id` paths. Remove any reference to the retired `EventDispatcher` concept. Update webhook dispatch description to note "eventual delivery from domain_events."

- [ ] CLAUDE.md: Replace the "Webhook Dispatch" section with "Domain Event Log (O2)" describing the new architecture. Add `internal/audit/` to the package layout. Note the background delivery model.

- [ ] Commit: `docs(o2): openapi event paths + CLAUDE.md audit section`

---

## Task 13: Final verification

- [ ] `gofmt -l .` — clean.
- [ ] `go build ./... && go vet ./...` — clean.
- [ ] `make lint` — 0 issues.
- [ ] `make test-all` — all pass.
- [ ] `make e2e` — all pass.
- [ ] Manual curl smoke: create license → `GET /v1/events` → event present with attribution.
- [ ] O2 is DONE. Next: O3.

---

## Self-Review Checklist

- [ ] Every spec section has a covering task.
- [ ] No TBD/TODO placeholders.
- [ ] `EventDispatcher` interface fully retired (Task 6.3).
- [ ] `dispatchEvent` helper fully retired (Task 6.3).
- [ ] Attribution flows from handler → service → audit.Writer → DB.
- [ ] Webhook delivery is eventual (background poll, not in-process).
- [ ] `DomainEventRepository.ListSince` exists for the background watermark.
- [ ] RBAC: `event:read` seeded on preset roles.
- [ ] RLS on domain_events: account_id + environment.
