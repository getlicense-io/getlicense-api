# O4 Metrics Snapshot Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Single `GET /v1/metrics?from=&to=` returning KPI counts (licenses, machines, customers, grants) + daily event buckets from domain_events.

**Architecture:** New `internal/analytics/` package (fills reserved empty dir). Pure read service — no writes, no new tables. Direct pool queries for aggregate counts. One migration for partial indexes.

**Spec:** `docs/superpowers/specs/2026-04-16-o4-metrics-snapshot-design.md`

---

## Task 1: Migration `026_metrics_indexes.sql`

- [ ] Add partial indexes for cheap status counts:
  ```sql
  CREATE INDEX IF NOT EXISTS idx_licenses_env_status ON licenses (account_id, environment, status);
  CREATE INDEX IF NOT EXISTS idx_machines_env_status ON machines (account_id, environment, status);
  ```
- [ ] Apply, commit: `feat(db): 026 metrics partial indexes`

## Task 2: Analytics service

- [ ] Create `internal/analytics/service.go` with `Service` struct (takes `*pgxpool.Pool` + `domain.TxManager`)
- [ ] `Snapshot(ctx, accountID, env, from, to) (*Snapshot, error)` — runs inside `WithTargetAccount` for RLS:
  - License counts: `SELECT status, COUNT(*) FROM licenses GROUP BY status`
  - Machine counts: `SELECT status, COUNT(*) FROM machines GROUP BY status`
  - Customer count: `SELECT COUNT(*) FROM customers` (account-scoped, run without env filter via separate query or `NULLIF` env)
  - Grant stats: active grants + licenses-via-grants count
  - Daily buckets: `SELECT date_trunc('day', created_at)::date, COUNT(*) FROM domain_events WHERE created_at BETWEEN $1 AND $2 GROUP BY 1 ORDER BY 1`
- [ ] Parallel queries 1-4 via `errgroup`, then query 5
- [ ] Types: `Snapshot`, `LicenseStats`, `MachineStats`, `CustomerStats`, `GrantStats`, `DailyBucket`
- [ ] Unit test with mock pool or integration test
- [ ] Commit: `feat(analytics): metrics snapshot service`

## Task 3: HTTP handler + routes

- [ ] Create `internal/server/handler/metrics.go`:
  - `MetricsHandler` with `svc *analytics.Service`
  - `Snapshot` method — GET /v1/metrics, parses `from`/`to` (default 30 days), permission: `event:read`
- [ ] Register route, wire deps
- [ ] Commit: `feat(http): GET /v1/metrics endpoint`

## Task 4: E2E + docs + verification

- [ ] E2E: `25_metrics.hurl` — signup, create product+license, `GET /v1/metrics` → assert license counts > 0, events_by_day present
- [ ] OpenAPI: add `Snapshot` schema + `/v1/metrics` path
- [ ] CLAUDE.md: add analytics package + brief section
- [ ] Full verification gates
- [ ] Commit: `test(e2e): metrics scenario + docs`
