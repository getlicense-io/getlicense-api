# Comprehensive Code Review Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Prove the GetLicense API fully implements `api/openapi.yaml`, fix high-confidence defects, and leave a clear record of any remaining product or contract questions.

**Architecture:** Use a spec-led review from OpenAPI route contract to Fiber routes, handlers, services, repositories, migrations, and tests. Each pass produces a concrete artifact or code/test change before moving to the next pass.

**Tech Stack:** Go 1.26, Fiber v3, pgx, PostgreSQL 17, sqlc v1.29.0, goose migrations, Hurl e2e tests, golangci-lint.

---

### Task 1: Create the Review Workspace Artifacts

**Files:**
- Read: `docs/plans/2026-04-24-comprehensive-code-review-design.md`
- Create: `docs/plans/2026-04-24-comprehensive-code-review-findings.md`
- Create: `docs/plans/2026-04-24-openapi-route-matrix.md`

**Step 1: Create the findings log**

Create `docs/plans/2026-04-24-comprehensive-code-review-findings.md`:

```markdown
# Comprehensive Code Review Findings

## Summary

- Status: in progress
- Review started: 2026-04-24
- Contract source: `api/openapi.yaml`
- Runtime route source: `internal/server/routes.go`

## Findings

No findings recorded yet.

## Open Questions

No open questions recorded yet.

## Verification Log

No verification commands run yet.
```

**Step 2: Create the initial route matrix**

Create `docs/plans/2026-04-24-openapi-route-matrix.md`:

```markdown
# OpenAPI Route Matrix

| Status | Method | Path | Operation ID | Route Handler | Auth | Tests | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
```

**Step 3: Commit**

Run:

```bash
git add docs/plans/2026-04-24-comprehensive-code-review-design.md docs/plans/2026-04-24-comprehensive-code-review.md docs/plans/2026-04-24-comprehensive-code-review-findings.md docs/plans/2026-04-24-openapi-route-matrix.md
git commit -m "docs: plan comprehensive code review"
```

Expected: commit succeeds with only review planning artifacts.

---

### Task 2: Build the OpenAPI Operation Inventory

**Files:**
- Read: `api/openapi.yaml`
- Modify: `docs/plans/2026-04-24-openapi-route-matrix.md`

**Step 1: Extract operation inventory**

Run:

```bash
rg -n "^  /|operationId:|tags:" api/openapi.yaml
```

Expected: every `/v1/...` path and operationId is visible.

**Step 2: Fill matrix rows from OpenAPI**

For every operation in `api/openapi.yaml`, add a row:

```markdown
| unchecked | POST | `/v1/auth/signup` | `signup` | TBD | public | TBD | TBD |
```

Use one row per HTTP method, not one row per path.

**Step 3: Commit**

Run:

```bash
git add docs/plans/2026-04-24-openapi-route-matrix.md
git commit -m "docs: inventory openapi operations"
```

Expected: route matrix contains all OpenAPI operations.

---

### Task 3: Compare OpenAPI Routes to Fiber Routes

**Files:**
- Read: `internal/server/routes.go`
- Modify: `docs/plans/2026-04-24-openapi-route-matrix.md`
- Modify: `docs/plans/2026-04-24-comprehensive-code-review-findings.md`

**Step 1: Extract runtime routes**

Run:

```bash
rg -n "v1\\.|\\.Group\\(|\\.Get\\(|\\.Post\\(|\\.Patch\\(|\\.Put\\(|\\.Delete\\(" internal/server/routes.go
```

Expected: every public route registration under `/v1` is visible.

**Step 2: Match each OpenAPI row**

For each matrix row, fill:

- `Route Handler`: exact handler such as `LicenseHandler.Create`
- `Auth`: `public`, `authMw`, `authMw+ResolveGrant`, or equivalent
- `Status`: `matched`, `missing-route`, `missing-spec`, or `needs-review`

**Step 3: Record route drift findings**

If OpenAPI has a missing runtime route or runtime has a missing OpenAPI route, record it in findings:

```markdown
### F-001: Missing OpenAPI coverage for runtime route

- Severity: High
- Evidence: `internal/server/routes.go:<line>`
- Contract impact: route exists but clients cannot discover it from OpenAPI
- Fix plan: add path operation to `api/openapi.yaml` and e2e coverage
```

**Step 4: Commit**

Run:

```bash
git add docs/plans/2026-04-24-openapi-route-matrix.md docs/plans/2026-04-24-comprehensive-code-review-findings.md
git commit -m "docs: map openapi operations to routes"
```

Expected: route matrix identifies all route/spec mismatches.

---

### Task 4: Review Handler Contract Conformance

**Files:**
- Read: `internal/server/handler/*.go`
- Read: `api/openapi.yaml`
- Modify: `docs/plans/2026-04-24-openapi-route-matrix.md`
- Modify: `docs/plans/2026-04-24-comprehensive-code-review-findings.md`
- Test: `e2e/scenarios/*.hurl`

**Step 1: Review request parsing**

For each handler method in the matrix, verify:

- path params are parsed with typed ID helpers or equivalent validation
- query params match documented defaults and bounds
- request body struct matches OpenAPI required/optional fields
- body binding failures map to expected API error shape

**Step 2: Review response status and shape**

Verify success status codes match OpenAPI:

- `201` for create operations
- `200` for reads, updates, lifecycle actions with response bodies
- `204` only when OpenAPI documents no response body

Verify response structs do not include secrets, raw hashes, private keys, or internal-only attribution fields unless explicitly documented.

**Step 3: Review auth and RBAC**

Verify each handler calls the intended permission:

- management routes use `authz(c, rbac.<Permission>)`
- public routes skip auth only when OpenAPI marks them public
- grant-scoped routes preserve `ActingAccountID` and use `TargetAccountID` for tenant data

**Step 4: Add findings or tests**

For every mismatch, either fix it immediately if the intended behavior is obvious or record a finding if contract intent is unclear.

Add or update Hurl tests for route-level contract issues.

**Step 5: Run focused tests**

Run the relevant test target:

```bash
go test ./internal/server/... -count=1
```

Expected: pass.

**Step 6: Commit**

Run:

```bash
git add api/openapi.yaml internal/server/handler e2e/scenarios docs/plans/2026-04-24-openapi-route-matrix.md docs/plans/2026-04-24-comprehensive-code-review-findings.md
git commit -m "fix: align handler contracts with openapi"
```

Expected: commit includes only reviewed handler/spec/test changes. If no code changes were needed, commit only documentation updates.

---

### Task 5: Review Service-Level Business Invariants

**Files:**
- Read: `internal/*/service.go`
- Read: `internal/*/service_test.go`
- Read: `CLAUDE.md`
- Modify: service files only for confirmed defects
- Test: relevant `internal/*/*_test.go`
- Modify: `docs/plans/2026-04-24-comprehensive-code-review-findings.md`

**Step 1: Review critical service invariants**

Check these areas against `CLAUDE.md`:

- `internal/licensing`: policy resolution, validation TTL, license status transitions, machine activation, checkout/checkin, customer requirement, entitlement resolution
- `internal/grant`: capabilities, constraints, grantor/grantee state transitions, sharing v2 rules
- `internal/customer`: email normalization, first-write-wins, grant-created attribution
- `internal/invitation`: token lookup, accept flows, revoke/resend permissions
- `internal/policy`: effective value resolution, default policy constraints, delete/force behavior
- `internal/entitlement`: code validation, attach/detach behavior, effective resolution
- `internal/webhook`: SSRF protection, delivery, retry, redelivery
- `internal/auth` and `internal/identity`: JWT/API key/TOTP flows and environment selection
- `internal/search`, `internal/analytics`, `internal/audit`: tenant scoping and output shape

**Step 2: Add focused tests before fixes**

For each confirmed bug, write the failing unit test first in the closest existing test file.

Example:

```go
func TestServiceBehaviorSpecificInvariant(t *testing.T) {
    // Arrange the smallest state that proves the bug.
    // Act through the service.
    // Assert the documented behavior.
}
```

**Step 3: Run failing test**

Run:

```bash
go test ./internal/<package> -count=1 -run TestSpecificName
```

Expected: fail before the implementation fix.

**Step 4: Fix minimally**

Change only the service code needed to make the test pass.

**Step 5: Run package tests**

Run:

```bash
go test ./internal/<package> -count=1
```

Expected: pass.

**Step 6: Commit per package**

Run:

```bash
git add internal/<package> docs/plans/2026-04-24-comprehensive-code-review-findings.md
git commit -m "fix: address <package> review findings"
```

Expected: each commit is scoped to one package or one invariant family.

---

### Task 6: Review Repository, RLS, Pagination, and sqlc Conventions

**Files:**
- Read: `internal/db/*.go`
- Read: `internal/db/sqlc/queries/*.sql`
- Read: `migrations/*.sql`
- Modify: repository, query, migration, or generated files only for confirmed defects
- Test: `internal/db/*_test.go`
- Modify: `docs/plans/2026-04-24-comprehensive-code-review-findings.md`

**Step 1: Verify sqlc generation freshness**

Run:

```bash
make sqlc-verify
```

Expected: pass with no generated diff.

**Step 2: Review query conventions**

For each query file, check:

- explicit column lists
- no accidental `SELECT *`
- all `sqlc.narg` values have explicit casts
- paginated tuple cursors cast both timestamp and UUID
- named `sqlc.arg` where generated names would be ambiguous

**Step 3: Review repo adapter conventions**

Check:

- `Get*` methods use explicit `pgx.ErrNoRows` branches
- row conversion helpers are shared
- nullable IDs and pointers use helpers from `internal/db/helpers.go`
- `sliceHasMore` and cursor helpers are used consistently
- unique constraint classification is only used where user-visible

**Step 4: Review RLS migrations**

Verify tenant-scoped tables use both account and environment RLS where required:

```sql
NULLIF(current_setting('app.current_account_id', true), '') IS NULL
NULLIF(current_setting('app.current_environment', true), '') IS NULL
```

Products, customers, memberships, roles, grants, and account-level metadata should follow their intended scope rather than blindly using environment filters.

**Step 5: Add integration tests before fixes**

For repository or RLS bugs, add failing tests in the closest `internal/db/*_test.go`.

**Step 6: Regenerate sqlc if queries change**

Run:

```bash
make sqlc
```

Expected: generated files update only when query files changed.

**Step 7: Run database tests**

Run:

```bash
make test-all
```

Expected: pass.

**Step 8: Commit**

Run:

```bash
git add internal/db migrations sqlc.yaml docs/plans/2026-04-24-comprehensive-code-review-findings.md
git commit -m "fix: address repository review findings"
```

Expected: commit includes query, generated, repository, migration, and test changes together when relevant.

---

### Task 7: Review e2e Coverage Against the Contract

**Files:**
- Read: `e2e/scenarios/*.hurl`
- Read: `docs/plans/2026-04-24-openapi-route-matrix.md`
- Modify: `e2e/scenarios/*.hurl`
- Modify: `docs/plans/2026-04-24-openapi-route-matrix.md`
- Modify: `docs/plans/2026-04-24-comprehensive-code-review-findings.md`

**Step 1: Map e2e coverage**

For each route matrix row, set `Tests` to the scenario file that exercises it, for example:

```markdown
`e2e/scenarios/04_licenses.hurl`
```

If no e2e exists, mark `unit-only`, `integration-only`, or `missing`.

**Step 2: Add missing high-value e2e tests**

Prioritize e2e gaps for:

- auth and account switching
- environment isolation
- grant-scoped license and customer behavior
- invitations and sharing v2 privacy scrubbing
- public validation and validation TTL
- pagination on list endpoints
- webhook delivery logs and redelivery
- search and metrics scoping

**Step 3: Run e2e**

Run:

```bash
make e2e
```

Expected: all Hurl scenarios pass.

**Step 4: Commit**

Run:

```bash
git add e2e/scenarios docs/plans/2026-04-24-openapi-route-matrix.md docs/plans/2026-04-24-comprehensive-code-review-findings.md
git commit -m "test: expand api contract e2e coverage"
```

Expected: e2e additions are grouped by contract area.

---

### Task 8: Run Full Quality Gate and Fix Regressions

**Files:**
- Modify only files required by failures
- Modify: `docs/plans/2026-04-24-comprehensive-code-review-findings.md`

**Step 1: Run unit tests**

Run:

```bash
make test
```

Expected: pass.

**Step 2: Run integration tests**

Run:

```bash
make test-all
```

Expected: pass.

**Step 3: Run e2e tests**

Run:

```bash
make e2e
```

Expected: pass.

**Step 4: Run lint**

Run:

```bash
make lint
```

Expected: pass.

**Step 5: Run vet and sqlc verification**

Run:

```bash
make check
```

Expected: pass.

**Step 6: Fix failures with smallest failing test first**

For any failure:

1. Record it in the findings log.
2. Identify the smallest failing test or command.
3. Fix the root cause.
4. Re-run the failing command.
5. Re-run the full quality gate section that failed.

**Step 7: Commit fixes**

Run:

```bash
git add .
git commit -m "fix: resolve comprehensive review regressions"
```

Expected: commit contains only verified fixes.

---

### Task 9: Final Review Report

**Files:**
- Modify: `docs/plans/2026-04-24-comprehensive-code-review-findings.md`
- Modify: `docs/plans/2026-04-24-openapi-route-matrix.md`

**Step 1: Finalize the route matrix**

Every row should have:

- `matched` or an explicit unresolved status
- handler mapping
- auth classification
- test coverage
- notes for any deliberate deviations

**Step 2: Finalize findings**

Move fixed items to a `Resolved Findings` section with commit hashes when available.

Any unresolved item must include:

- severity
- affected route or package
- evidence
- user-visible impact
- recommended next action

**Step 3: Record verification results**

Add exact command outcomes:

```markdown
## Verification Log

- `make test`: PASS
- `make test-all`: PASS
- `make e2e`: PASS
- `make lint`: PASS
- `make check`: PASS
```

If a command cannot be run, record the reason and residual risk.

**Step 4: Commit final report**

Run:

```bash
git add docs/plans/2026-04-24-comprehensive-code-review-findings.md docs/plans/2026-04-24-openapi-route-matrix.md
git commit -m "docs: finalize comprehensive review report"
```

Expected: final report clearly states whether OpenAPI implementation is complete and which risks remain.
