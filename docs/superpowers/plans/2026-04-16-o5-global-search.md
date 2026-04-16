# O5 Global Search Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `GET /v1/search?q=<query>&types=license,machine,customer,product` — simple DSL for prefix-match search across resource types with parallel sub-queries.

**Architecture:** New `internal/search/` package. Handwritten DSL parser (~100 LoC). Sub-queries run in parallel via `errgroup`, limit 10 per type. Uses existing repos — no new tables, no new indexes.

**Spec:** `docs/superpowers/specs/2026-04-16-o5-global-search-design.md`

---

## Task 1: DSL parser

- [ ] Create `internal/search/parser.go`:
  ```go
  type ParsedQuery struct {
      Types   []string
      Filters map[string]string
      Bare    string
  }
  func Parse(q string) (*ParsedQuery, error)
  ```
- [ ] Tokenize on whitespace. `type:X` sets Types. `field:value` sets Filters. Bare word sets Bare.
- [ ] Validate against whitelist per type:
  - license: key, email, customer_id, status
  - machine: fingerprint, hostname, license_id
  - customer: email, name
  - product: slug, name
- [ ] Unknown type → error. Unknown field for the type → error.

- [ ] Create `internal/search/parser_test.go` — table-driven tests:
  - Bare word: `john@` → Bare="john@", all types
  - Field: `type:license key:GETL` → Types=[license], Filters={key: GETL}
  - Multi-token: `type:customer email:john name:doe` → both filters
  - Unknown type → error
  - Unknown field → error
  - Empty → error

- [ ] `go test ./internal/search/...` — pass
- [ ] Commit: `feat(search): DSL parser with whitelisted fields`

## Task 2: Search service

- [ ] Create `internal/search/service.go`:
  ```go
  type Service struct {
      licenses  domain.LicenseRepository
      machines  domain.MachineRepository
      customers domain.CustomerRepository
      products  domain.ProductRepository
      tx        domain.TxManager
  }

  type Result struct {
      Licenses  []domain.License  `json:"licenses,omitempty"`
      Machines  []domain.Machine  `json:"machines,omitempty"`
      Customers []domain.Customer `json:"customers,omitempty"`
      Products  []domain.Product  `json:"products,omitempty"`
  }

  func (s *Service) Search(ctx, accountID, env, query string, types []string, limit int) (*Result, error)
  ```
- [ ] Parse query via `Parse(query)`
- [ ] For each active type, build a sub-query function. Run all in parallel via `errgroup`.
- [ ] Each sub-query uses existing repo `List` methods with filter params:
  - License: existing `LicenseListFilters{Q: bareOrKey, Status: statusFilter}`
  - Customer: existing `CustomerListFilter{Email: emailPrefix}`
  - Product: may need a new `ProductListFilter{NameOrSlug: prefix}` or a search method
  - Machine: may need a new search method — check existing `MachineRepository` methods
- [ ] For repos that don't support the needed filter, add a minimal `Search(ctx, query, limit)` method
- [ ] Limit per type = 10 (or the `limit` param, whichever is smaller)
- [ ] Commit: `feat(search): parallel sub-query service`

## Task 3: HTTP handler + routes

- [ ] Create `internal/server/handler/search.go`:
  - `SearchHandler` with `svc *search.Service`
  - `Search` method — GET /v1/search, parses `q` and `types` params
  - Permission: auth required (any role — RLS scopes results)
  - Returns `search.Result`
- [ ] Register route: `v1.Get("/search", authMw, mgmtLimit, sh.Search)`
- [ ] Wire in deps
- [ ] Commit: `feat(http): GET /v1/search endpoint`

## Task 4: E2E + docs + verification

- [ ] E2E: `26_search.hurl` — seed product + customer + license, search by key prefix, by customer email, by product slug → verify correct results in each type bucket
- [ ] OpenAPI: add SearchResult schema + `/v1/search` path with `q` and `types` params
- [ ] CLAUDE.md: add search package + section
- [ ] Full verification
- [ ] Commit: `test(e2e): search scenario + docs`
