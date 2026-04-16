# O3 Webhook Delivery Log Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Surface webhook delivery history via `GET /v1/webhooks/:id/deliveries`, extend `webhook_events` with response details + `domain_event_id` FK, and add a redeliver endpoint.

**Architecture:** No new packages. `webhook.Service` grows list/get/redeliver methods. Migration extends existing `webhook_events` table. Endpoints nested under `/v1/webhooks/:id/deliveries` per brainstorm Option B.

**Tech Stack:** Go, Fiber v3, pgx v5, goose, hurl.

**Spec:** `docs/superpowers/specs/2026-04-16-o3-webhook-delivery-log-design.md`

---

## Task 1: Migration `025_webhook_delivery_log.sql`

- [ ] ALTER TABLE webhook_events:
  - ADD `domain_event_id uuid REFERENCES domain_events(id)` (nullable)
  - ADD `response_body text`
  - ADD `response_body_truncated boolean NOT NULL DEFAULT false`
  - ADD `response_headers jsonb`
  - ADD `next_retry_at timestamptz`
  - ADD INDEX `webhook_events_endpoint_created ON webhook_events (endpoint_id, created_at DESC, id DESC)`
  - ADD UNIQUE INDEX `webhook_events_endpoint_domain_event ON webhook_events (endpoint_id, domain_event_id)` for idempotent delivery
- [ ] Down block drops columns + indexes
- [ ] Apply via goose, verify. Commit: `feat(db): 025 webhook delivery log columns`

## Task 2: Domain model + repo extensions

- [ ] Extend `domain.WebhookEvent` in `models.go` with: `DomainEventID *core.DomainEventID`, `ResponseBody *string`, `ResponseBodyTruncated bool`, `ResponseHeaders json.RawMessage`, `NextRetryAt *time.Time`
- [ ] Add to `WebhookEventRepository` interface: `ListByEndpoint(ctx, endpointID, filter, cursor, limit)`, `GetByID(ctx, id)`, `CreateDelivery(ctx, *WebhookEvent)` (for redeliver)
- [ ] Add `WebhookDeliveryFilter struct { EventType, Status }`
- [ ] Update `internal/db/webhook_repo.go`: extend `scanWebhookEvent` + column constants, implement new methods
- [ ] Update existing webhook delivery code to populate the new response fields (truncate body to 2 KiB, capture headers)
- [ ] Build clean. Commit: `feat(webhook): delivery list/get/redeliver repo methods + response capture`

## Task 3: Webhook service + handler

- [ ] Add `ListDeliveries`, `GetDelivery`, `Redeliver` methods to `webhook.Service`
- [ ] Redeliver: load webhook_event → load domain_event → create new delivery row → dispatch
- [ ] Create handler methods in `internal/server/handler/webhooks.go` (or a new `deliveries.go`):
  - `GET /v1/webhooks/:id/deliveries` — cursor paginated, `?event_type=&status=`. Permission: `webhook:read`
  - `GET /v1/webhooks/:id/deliveries/:delivery_id` — Permission: `webhook:read`
  - `POST /v1/webhooks/:id/deliveries/:delivery_id/redeliver` — Permission: `webhook:write`
- [ ] Register routes in `routes.go`
- [ ] Build + test. Commit: `feat(http): webhook delivery list/get/redeliver endpoints`

## Task 4: E2E + OpenAPI + CLAUDE.md

- [ ] Add to `e2e/scenarios/07_webhooks.hurl` (or new `24_webhook_deliveries.hurl`): create webhook endpoint → create license (triggers delivery) → list deliveries → get single → redeliver → verify new delivery row
- [ ] OpenAPI: add delivery paths + updated WebhookEvent schema
- [ ] CLAUDE.md: brief note under the O2 section about delivery log surface
- [ ] `make e2e` — all pass
- [ ] Commit: `test(e2e): webhook delivery scenario + docs`

## Task 5: Final verification

- [ ] `gofmt -l .`, `go build ./...`, `go vet ./...`, `make lint`, `make test-all`, `make e2e`
- [ ] O3 DONE
