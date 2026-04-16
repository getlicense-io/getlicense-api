# O3 — Webhook Delivery Log Design

**Release:** 3 (Observability), feature 2 of 4
**Branch:** `release-3-observability`
**Dependencies:** O2 Domain Event Log (domain_events table + webhook delivery restructure).
**Date:** 2026-04-16

## Goal

Surface existing webhook delivery rows via list/get/redeliver endpoints, now FK'd to `domain_events`. Vendors can see delivery failures, inspect response bodies, and manually redeliver failed webhooks.

## Architecture

No new package. `webhook.Service` grows `ListDeliveries`, `GetDelivery`, `Redeliver` methods. The existing `webhook_events` table gains new columns for response details and the `domain_event_id` FK.

## Data Model

### `webhook_events` changes (migration `025_webhook_delivery_log.sql`)

```sql
ALTER TABLE webhook_events
    ADD COLUMN domain_event_id        uuid REFERENCES domain_events(id),
    ADD COLUMN response_body          text,
    ADD COLUMN response_body_truncated boolean NOT NULL DEFAULT false,
    ADD COLUMN response_headers       jsonb,
    ADD COLUMN next_retry_at          timestamptz;
```

`domain_event_id` is nullable — existing rows predate O2.

Index for the nested list under endpoints:
```sql
CREATE INDEX webhook_events_endpoint_created
    ON webhook_events (endpoint_id, created_at DESC, id DESC);
```

### Go type extension

`domain.WebhookEvent` gains:
```go
DomainEventID         *core.DomainEventID
ResponseBody          *string
ResponseBodyTruncated bool
ResponseHeaders       json.RawMessage
NextRetryAt           *time.Time
```

## HTTP Surface

Nested under webhook endpoints (Option B from brainstorm):

| Verb | Path | Purpose | Permission |
|---|---|---|---|
| GET | `/v1/webhooks/:id/deliveries` | List deliveries for an endpoint, cursor paginated | `webhook:read` |
| GET | `/v1/webhooks/:id/deliveries/:delivery_id` | Single delivery detail | `webhook:read` |
| POST | `/v1/webhooks/:id/deliveries/:delivery_id/redeliver` | Re-dispatch from the domain event | `webhook:write` |

Filters on list: `?event_type=`, `?status=`, `?cursor=`, `?limit=`.

### Redeliver mechanics

1. Load the `webhook_event` row by ID.
2. Load the linked `domain_event` by `domain_event_id`. If null (pre-O2 delivery), return 422 "delivery predates event log; cannot redeliver."
3. Create a NEW `webhook_event` row with `attempts=0`, same `endpoint_id` + `domain_event_id` + `event_type`.
4. Dispatch HTTP delivery immediately (synchronous, not background).
5. Return the new delivery row.

### Response body truncation

The webhook dispatch HTTP client truncates `response_body` to 2 KiB at write time and sets `response_body_truncated = true` if the original exceeded 2 KiB. This keeps the DB lean while giving ops enough to diagnose "why did my endpoint return 500."

## RBAC

No new permissions. Reuses `webhook:read` and `webhook:write` from Release 1.

## Migration

`025_webhook_delivery_log.sql`:
1. ALTER TABLE webhook_events — add 4 columns + index.
2. No role seed needed (existing permissions cover it).

## Testing

- Integration: delivery round-trip with domain_event FK; redeliver creates new row.
- E2E: create webhook endpoint → create license (triggers domain event → webhook delivery) → `GET /v1/webhooks/:id/deliveries` returns the delivery → redeliver → new delivery row.

## Out of Scope

- Webhook delivery retry queue redesign (current retry logic stays).
- Delivery filtering by date range (use cursor pagination).
- Bulk redeliver.
