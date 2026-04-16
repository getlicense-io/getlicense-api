# O2 — Domain Event Log Design

**Release:** 3 (Observability), feature 1 of 4
**Branch:** `release-3-observability`
**Dependencies:** Release 1+2 fully landed (three-ID attribution, policies, customers, entitlements, lease tokens).
**Date:** 2026-04-16

## Goal

Persist every domain event to a `domain_events` table with three-ID request attribution. Replace the existing fire-and-forget `EventDispatcher` with a synchronous `audit.Writer` that records inside the mutation tx. Webhook delivery becomes a background consumer polling `domain_events`.

## Architecture

New `internal/audit/` package owns the `Writer` struct. Services call `writer.Record(ctx, event)` inside their mutation tx — events are never lost for successful writes. The existing `domain.EventDispatcher` interface and its in-process webhook dispatch are retired.

```
Service mutation tx
  └→ audit.Writer.Record(ctx, DomainEvent)  [synchronous, same tx]
       └→ INSERT INTO domain_events

Background job (60s tick)
  └→ Poll domain_events for undelivered events
       └→ Match against webhook_endpoints subscriptions
       └→ Create webhook_events rows + HTTP dispatch
```

## Data Model

### New table `domain_events`

```sql
CREATE TABLE domain_events (
    id                 uuid PRIMARY KEY,
    account_id         uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    environment        text NOT NULL DEFAULT '',

    event_type         text NOT NULL,
    resource_type      text NOT NULL,
    resource_id        text,

    acting_account_id  uuid,
    identity_id        uuid,
    actor_label        text NOT NULL DEFAULT '',
    actor_kind         text NOT NULL DEFAULT 'system'
        CHECK (actor_kind IN ('identity','api_key','system','public')),
    api_key_id         uuid,
    grant_id           uuid,

    request_id         text,
    ip_address         inet,
    payload            jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at         timestamptz NOT NULL DEFAULT now()
);
```

Indexes per FEATURES §O2:
- `(account_id, environment, created_at DESC, id DESC)` — cursor list
- `(account_id, resource_type, resource_id, created_at DESC)` — per-resource
- `(account_id, identity_id, created_at DESC)` — per-actor
- `(account_id, grant_id, created_at DESC)` — per-grant

RLS: account_id + environment (same pattern as licenses/machines).

No environment column in RLS for identity-level events (login, TOTP) — those set `environment = ''` and the RLS `NULLIF(current_setting('app.current_environment', true), '') IS NULL OR environment = ...` escape hatch lets them through.

### Go types

```go
// internal/core/
type DomainEventID uuid.UUID
type ActorKind string
const (
    ActorKindIdentity ActorKind = "identity"
    ActorKindAPIKey   ActorKind = "api_key"
    ActorKindSystem   ActorKind = "system"
    ActorKindPublic   ActorKind = "public"
)

// internal/domain/models.go
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
```

## Service Layer

### `internal/audit/writer.go`

```go
type Writer struct {
    repo domain.DomainEventRepository
}

func (w *Writer) Record(ctx context.Context, event domain.DomainEvent) error {
    event.ID = core.NewDomainEventID()
    event.CreatedAt = time.Now().UTC()
    return w.repo.Create(ctx, &event)
}
```

Pure — no tx management. Called inside the caller's existing `WithTargetAccount` tx.

### Attribution helper

`audit.EventFromAuth(auth *middleware.AuthContext, eventType, resourceType, resourceID, payload)` builds a `DomainEvent` with attribution fields populated from the auth context. Services call this helper, then pass the result to `Writer.Record`.

### Service integration

Every service that currently calls `s.dispatchEvent(ctx, accountID, env, eventType, payload)` or `s.webhookSvc.Dispatch(...)` switches to:

```go
s.audit.Record(ctx, audit.EventFromAuth(auth, core.EventTypeLicenseCreated, "license", license.ID.String(), payload))
```

The `dispatchEvent` helper and `domain.EventDispatcher` interface are deleted.

### Webhook delivery changes

The background job in `internal/server/background.go` gains a third sweep:

1. Query `domain_events` for rows created since the last sweep tick.
2. For each event, match `event_type` against `webhook_endpoints.events` subscriptions for the same `account_id + environment`.
3. For each match, create a `webhook_events` row and dispatch HTTP delivery.
4. Track the high-water mark (last processed `domain_event.id`) to avoid re-scanning.

The existing `webhook.Service.Deliver(ctx, endpoint, event)` stays — it handles the HTTP POST + retry logic. Only the trigger changes: from in-process service call to background poll.

## HTTP Surface

| Verb | Path | Purpose | Permission |
|---|---|---|---|
| GET | `/v1/events` | List events, cursor paginated, filterable | `event:read` |
| GET | `/v1/events/:id` | Single event | `event:read` |

Filters on list: `?resource_type=`, `?resource_id=`, `?event_type=`, `?identity_id=`, `?grant_id=`, `?from=<iso>`, `?to=<iso>`, `?cursor=`, `?limit=`.

No create/update/delete — events are append-only from internal writes.

## RBAC

New permission: `event:read`. All preset roles except `read_only` get it.

## Migration

`024_domain_events.sql`:
1. CREATE TABLE domain_events with all columns, indexes, RLS.
2. Seed `event:read` onto preset roles.

## Event Types

Existing event types from Release 1+2 carry over: `license.created`, `license.suspended`, `license.revoked`, `license.reinstated`, `machine.activated`, `machine.deactivated`, `machine.checked_in`. O2 also adds attribution for auth events if desired — but for v1, we only persist events that services already fire. No new event types in O2 itself.

## Testing

- Unit: `audit.Writer.Record` persists correctly; `EventFromAuth` populates all fields.
- Integration: domain_events round-trip; cursor pagination; filter combinations.
- E2E: create a license → `GET /v1/events?resource_type=license` returns the `license.created` event with correct attribution.

## Out of Scope

- Retention policy (30-day auto-delete) — deferred, manual cleanup for now.
- Request log (O6) — separate feature, deferred.
- Event streaming / webhooks from events — that's O3.
