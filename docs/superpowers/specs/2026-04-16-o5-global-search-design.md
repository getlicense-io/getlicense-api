# O5 — Global Search Design

**Release:** 3 (Observability), feature 4 of 4
**Branch:** `release-3-observability`
**Dependencies:** None (independent of O2/O3/O4). Uses existing tables + indexes.
**Date:** 2026-04-16

## Goal

`GET /v1/search?q=<query>` — simple DSL for prefix-match search across licenses, machines, customers, and products. Parallel sub-queries, whitelisted fields per type, no full-text search.

## Architecture

New `internal/search/` package. Handwritten DSL parser (~100 LoC). Sub-queries run in parallel via `errgroup`, limit 10 per type. Reads existing tables via existing repo interfaces — no new tables, no new indexes (existing btree indexes on name/slug/email/fingerprint/key_prefix support `LIKE 'prefix%'`).

## DSL Syntax

```
q=type:license key:GETL-ABCD
q=type:customer email:john@
q=john@example.com                    (bare word → primary field per type)
q=type:machine fingerprint:abc123
```

### Whitelisted fields

| Type | Fields | Primary (bare word) |
|---|---|---|
| `license` | `key:`, `email:` (customer join), `customer_id:`, `status:` | `key:` |
| `machine` | `fingerprint:`, `hostname:`, `license_id:` | `fingerprint:` |
| `customer` | `email:`, `name:` | `email:` |
| `product` | `slug:`, `name:` | `slug:` |

### Parser rules

- Tokens are whitespace-separated.
- `field:value` sets a filter on a specific field.
- `type:X` restricts search to type X only. If omitted, all types are searched.
- `types=license,machine` query param restricts which types to search (alternative to `type:` in the DSL).
- Bare words (no `:`) route to each type's primary field.
- All string matches are case-insensitive prefix: `WHERE LOWER(field) LIKE LOWER(value) || '%'`.
- `status:active` is exact match (not prefix).
- `customer_id:` and `license_id:` are exact UUID match.

### Parser output

```go
type ParsedQuery struct {
    Types   []string           // empty = all types
    Filters map[string]string  // field → value
    Bare    string             // bare word (no field prefix)
}
```

## Service Layer

```go
// internal/search/service.go
type Service struct {
    licenses  domain.LicenseRepository
    machines  domain.MachineRepository
    customers domain.CustomerRepository
    products  domain.ProductRepository
}

type Result struct {
    Licenses  []domain.License  `json:"licenses,omitempty"`
    Machines  []domain.Machine  `json:"machines,omitempty"`
    Customers []domain.Customer `json:"customers,omitempty"`
    Products  []domain.Product  `json:"products,omitempty"`
}

func (s *Service) Search(ctx context.Context, query string, types []string, limit int) (*Result, error)
```

### Execution

1. Parse the DSL into `ParsedQuery`.
2. Determine which types to search (explicit `type:` or `types=` param, or all).
3. For each type, build a filter from the parsed query and call the corresponding repo's `List` method with the filter. Limit per type = 10.
4. Run all sub-queries in parallel via `errgroup`.
5. Collect results into `Result`.

### Repo integration

Each sub-query uses existing repo `List` methods with their existing filter shapes:
- **Licenses:** `LicenseListFilters{Q: bareWord, Status: statusFilter, CustomerID: customerIDFilter}` — the existing `?q=` search on licenses already does prefix match on key_prefix + customer name/email.
- **Machines:** Need a new `MachineListFilters` or a simple query method. Simplest: add `Search(ctx, filters, limit) ([]Machine, error)` to `MachineRepository`.
- **Customers:** `CustomerListFilter{Email: emailPrefix}` — existing.
- **Products:** Need a simple prefix search. Add `Search(ctx, query, limit) ([]Product, error)` to `ProductRepository` or use the existing list with a name/slug filter.

For types that don't have a search-friendly list method, add a minimal one. Keep it simple — the search service delegates to repos, never writes raw SQL.

## HTTP Surface

| Verb | Path | Purpose | Permission |
|---|---|---|---|
| GET | `/v1/search?q=<query>&types=license,machine,customer,product` | Global search | auth required (RLS scopes) |

No dedicated RBAC permission — any authenticated caller can search within their tenant. RLS handles scoping.

## Error Handling

- Empty query → 422 `validation_error`
- Unknown `type:X` → 422 `validation_error` listing valid types
- Unknown field `foo:bar` → 422 `validation_error` listing valid fields for the type
- No results → 200 with empty arrays (not 404)

## Testing

- Unit: DSL parser tests — bare words, field:value, type: filter, multiple tokens, edge cases (empty, whitespace-only, unknown field).
- Unit: Service search with mock repos — parallel fan-out, per-type limit, type filtering.
- E2E: seed data, search by key prefix, by customer email, by product slug → verify correct results.

## Out of Scope

- Full-text search (Elasticsearch/pg_trgm) — premature.
- Grant-scoped search (`/v1/grants/:id/search`) — deferred per brainstorm Q2.
- Search result ranking/scoring — all results are equal; sorted by created_at DESC.
- Pagination on search results — limit 10 per type is the cap. Use dedicated list endpoints for more.
- Fuzzy matching — prefix only.
