# O4 — Metrics Snapshot Design

**Release:** 3 (Observability), feature 3 of 4
**Branch:** `release-3-observability`
**Dependencies:** O2 Domain Event Log (reads domain_events for time series).
**Date:** 2026-04-16

## Goal

Single `GET /v1/metrics` endpoint returning KPI counts + daily event buckets, scoped to the current target account and environment. Dashboard's first data surface.

## Architecture

New `internal/analytics/` package (fills the reserved empty dir). Pure read service — no writes, no new tables. Reads existing state tables (`licenses`, `machines`, `customers`, `grants`) for counts and `domain_events` for time series.

## Data Model

No new tables. Migration `026_metrics_indexes.sql` adds partial indexes to keep count queries cheap:

```sql
CREATE INDEX idx_licenses_env_status
    ON licenses (account_id, environment, status);
CREATE INDEX idx_machines_env_status
    ON machines (account_id, environment, status);
```

(These may already exist from prior migrations — check before creating. Use `IF NOT EXISTS`.)

## Service Layer

```go
// internal/analytics/service.go
type Service struct {
    db *pgxpool.Pool  // direct pool access for read-only aggregate queries
}

type Snapshot struct {
    Licenses  LicenseStats   `json:"licenses"`
    Machines  MachineStats   `json:"machines"`
    Customers CustomerStats  `json:"customers"`
    Grants    GrantStats     `json:"grants"`
    Events    []DailyBucket  `json:"events_by_day"`
}

type LicenseStats struct {
    Active    int `json:"active"`
    Suspended int `json:"suspended"`
    Revoked   int `json:"revoked"`
    Expired   int `json:"expired"`
    Inactive  int `json:"inactive"`
    Total     int `json:"total"`
}

type MachineStats struct {
    Active int `json:"active"`
    Stale  int `json:"stale"`
    Dead   int `json:"dead"`
    Total  int `json:"total"`
}

type CustomerStats struct {
    Total int `json:"total"`
}

type GrantStats struct {
    ActiveGrants       int `json:"active_grants"`
    LicensesViaGrants  int `json:"licenses_via_grants"`
}

type DailyBucket struct {
    Date  string `json:"date"`  // "2026-04-15"
    Count int    `json:"count"`
}

func (s *Service) Snapshot(ctx context.Context, from, to time.Time) (*Snapshot, error)
```

### Queries

All run inside a `WithTargetAccount` tx so RLS scopes by account + environment:

1. **License stats:** `SELECT status, COUNT(*) FROM licenses GROUP BY status`
2. **Machine stats:** `SELECT status, COUNT(*) FROM machines GROUP BY status`
3. **Customer stats:** `SELECT COUNT(*) FROM customers` (account-scoped, env-agnostic — run without env RLS)
4. **Grant stats:** `SELECT COUNT(*) FROM grants WHERE grantor_account_id = current_account AND status = 'active'` + `SELECT COUNT(*) FROM licenses WHERE grant_id IS NOT NULL`
5. **Daily buckets:** `SELECT date_trunc('day', created_at)::date AS date, COUNT(*) FROM domain_events WHERE created_at BETWEEN $from AND $to GROUP BY 1 ORDER BY 1`

Queries 1-4 run in parallel via `errgroup`. Query 5 runs after (depends on the same tx context).

### Environment scoping

Metrics are always env-scoped (per FEATURES: "no 'all envs' mode"). The RLS session variable `app.current_environment` handles this automatically. Customers are account-scoped (env-agnostic) — the customer count query skips the environment filter.

## HTTP Surface

| Verb | Path | Purpose | Permission |
|---|---|---|---|
| GET | `/v1/metrics?from=<iso>&to=<iso>` | KPI snapshot | `event:read` |

Default range: last 30 days if `from`/`to` omitted. Max range: 365 days. Returns one `Snapshot` object.

## RBAC

Reuses `event:read` from O2. No new permissions.

## Testing

- Unit: mock pool, verify parallel query fan-out and aggregation.
- Integration: seed licenses/machines/events, verify counts match.
- E2E: `GET /v1/metrics` after seeding some data → verify non-zero counts and daily buckets.

## Out of Scope

- Caching / materialized views — premature until query latency is measured.
- Per-product breakdown — defer to dashboard iteration.
- Export / CSV — defer.
- "All environments" aggregate — explicitly rejected per FEATURES.
