# L3 Entitlements Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Introduce a first-class entitlements registry with stable `code` values. Entitlements attach to policies (inherited by every license minted from that policy) and optionally per-license (add-only). The effective set is the sorted union, embedded in the gl2 lease token and returned in the validate response.

**Architecture:** New `internal/entitlement/` package owns registry CRUD + code validation. Three new tables: `entitlements` (registry), `policy_entitlements` (join), `license_entitlements` (join). `EntitlementRepository.ResolveEffective` runs a single UNION query at lease-issuance time. `licensing.Service.Activate/Checkin` call it and populate `LeaseTokenPayload.Entitlements`. `licensing.Service.Validate` adds an `Entitlements []string` field to `ValidateResult`. Grant constraint `AllowedEntitlementCodes` is enforced on license-level attach paths.

**Tech Stack:** Go, Fiber v3, pgx v5, goose migrations, Postgres 16 with RLS, hurl (e2e).

**Spec:** `docs/superpowers/specs/2026-04-15-l3-entitlements-design.md`

**Conventions:** All established by L1/L2/L4. 2-arg `NewAppError`, repo `(nil,nil)` on miss, `scannable` interface, `conn(ctx,pool)`, compile-time interface assertion, metadata nil→`{}` coercion, `testing.Short()` gating for integration tests, `gofmt -w` pre-commit.

---

## File Map

### New files

```
migrations/023_entitlements.sql                       # Task 3
internal/core/entitlement.go                          # Task 1
internal/entitlement/service.go                       # Task 5
internal/entitlement/service_test.go                  # Task 6
internal/entitlement/code.go                          # Task 5
internal/entitlement/code_test.go                     # Task 5
internal/db/entitlement_repo.go                       # Task 4
internal/db/entitlement_repo_test.go                  # Task 12
internal/server/handler/entitlements.go               # Task 10
e2e/scenarios/22_entitlements.hurl                    # Task 13
```

### Modified files

```
internal/core/errors.go                               # Task 1
internal/domain/models.go                             # Task 2
internal/domain/repositories.go                       # Task 2
internal/rbac/permissions.go                          # Task 9
internal/rbac/presets_test.go                         # Task 9
internal/licensing/service.go                         # Task 7
internal/licensing/service_test.go                    # Task 7
internal/licensing/lease.go                           # Task 7
internal/server/handler/policies.go                   # Task 10
internal/server/handler/licenses.go                   # Task 10
internal/grant/service.go                             # Task 8
internal/grant/service_test.go                        # Task 8
internal/server/handler/grants.go                     # Task 8
internal/server/routes.go                             # Task 11
internal/server/deps.go                               # Task 11
cmd/server/serve.go                                   # Task 11
openapi.yaml                                          # Task 14
CLAUDE.md                                             # Task 14
```

---

## Prerequisites

- [ ] **Step 0.1:** Confirm branch `release-2-license-model`, L1+L4+L2 landed, build green.
- [ ] **Step 0.2:** `make db-reset && make migrate` — DB at version 22.
- [ ] **Step 0.3:** `go build ./... && go test ./...` — green baseline.

---

## Task 1: Core types + error codes

**Files:** Create `internal/core/entitlement.go`, modify `internal/core/errors.go`

- [ ] Create `internal/core/entitlement.go` with `EntitlementID` typed UUID (same pattern as `PolicyID`, `CustomerID` — `NewEntitlementID`, `ParseEntitlementID`, `String`, `MarshalText`, `UnmarshalText`).

- [ ] Add error codes to `internal/core/errors.go`:

```go
ErrEntitlementNotFound    ErrorCode = "entitlement_not_found"
ErrEntitlementInvalidCode ErrorCode = "entitlement_invalid_code"
ErrEntitlementDuplicateCode ErrorCode = "entitlement_duplicate_code"
ErrEntitlementInUse       ErrorCode = "entitlement_in_use"
ErrEntitlementCodeImmutable ErrorCode = "entitlement_code_immutable"
ErrGrantEntitlementNotAllowed ErrorCode = "grant_entitlement_not_allowed"
```

httpStatusMap entries: `not_found→404`, `invalid_code→422`, `duplicate_code→409`, `in_use→409`, `code_immutable→422`, `grant_entitlement_not_allowed→403`.

- [ ] `gofmt -w internal/core/errors.go internal/core/entitlement.go`
- [ ] `go build ./internal/core/...` — clean.
- [ ] Commit: `feat(core): EntitlementID and entitlement error codes`

---

## Task 2: Domain models

**Files:** Modify `internal/domain/models.go`, `internal/domain/repositories.go`

- [ ] Add `Entitlement` struct to `models.go`:

```go
type Entitlement struct {
    ID        core.EntitlementID `json:"id"`
    AccountID core.AccountID     `json:"account_id"`
    Code      string             `json:"code"`
    Name      string             `json:"name"`
    Metadata  json.RawMessage    `json:"metadata,omitempty"`
    CreatedAt time.Time          `json:"created_at"`
    UpdatedAt time.Time          `json:"updated_at"`
}
```

- [ ] Add `EntitlementRepository` interface to `repositories.go`:

```go
type EntitlementRepository interface {
    Create(ctx context.Context, e *Entitlement) error
    Get(ctx context.Context, id core.EntitlementID) (*Entitlement, error)
    GetByCodes(ctx context.Context, accountID core.AccountID, codes []string) ([]Entitlement, error)
    List(ctx context.Context, accountID core.AccountID, codePrefix string, cursor core.Cursor, limit int) ([]Entitlement, bool, error)
    Update(ctx context.Context, e *Entitlement) error
    Delete(ctx context.Context, id core.EntitlementID) error

    AttachToPolicy(ctx context.Context, policyID core.PolicyID, entitlementIDs []core.EntitlementID) error
    DetachFromPolicy(ctx context.Context, policyID core.PolicyID, entitlementIDs []core.EntitlementID) error
    ReplacePolicyAttachments(ctx context.Context, policyID core.PolicyID, entitlementIDs []core.EntitlementID) error
    ListPolicyCodes(ctx context.Context, policyID core.PolicyID) ([]string, error)

    AttachToLicense(ctx context.Context, licenseID core.LicenseID, entitlementIDs []core.EntitlementID) error
    DetachFromLicense(ctx context.Context, licenseID core.LicenseID, entitlementIDs []core.EntitlementID) error
    ReplaceLicenseAttachments(ctx context.Context, licenseID core.LicenseID, entitlementIDs []core.EntitlementID) error
    ListLicenseCodes(ctx context.Context, licenseID core.LicenseID) ([]string, error)

    ResolveEffective(ctx context.Context, licenseID core.LicenseID) ([]string, error)
}
```

- [ ] `go build ./internal/core/... ./internal/domain/...` — clean. `go build ./...` may fail if other packages reference the new interface. Do NOT commit — stays dirty for Task 7.

---

## Task 3: Migration `023_entitlements.sql`

**Files:** Create `migrations/023_entitlements.sql`

- [ ] Create the file with three tables (`entitlements`, `policy_entitlements`, `license_entitlements`), unique indexes, FK constraints (ON DELETE RESTRICT for entitlement_id, ON DELETE CASCADE for policy_id/license_id), RLS policies, and permission seed.

Key SQL per spec:
- `entitlements` table: `id, account_id, code, name, metadata, created_at, updated_at`. Unique index on `(account_id, lower(code))`. RLS on account_id only (env-agnostic). No env column.
- `policy_entitlements`: composite PK `(policy_id, entitlement_id)`, `created_at`. RLS via EXISTS subquery on parent policy's account_id.
- `license_entitlements`: same shape as policy_entitlements but keyed on `license_id`.
- Role seed: `UPDATE roles SET permissions = array_cat(permissions, ARRAY['entitlement:read','entitlement:write','entitlement:delete'])` for owner/admin/developer; `entitlement:read` only for operator.
- Down block restores symmetrically.

- [ ] Apply via goose directly (Go tree may be broken from Task 2):

```bash
DATABASE_URL=postgres://getlicense:getlicense@localhost:5432/getlicense?sslmode=disable \
  goose -dir migrations postgres \
  "postgres://getlicense:getlicense@localhost:5432/getlicense?sslmode=disable" up
```

- [ ] Verify: `\d entitlements`, `\d policy_entitlements`, `\d license_entitlements`.
- [ ] Commit: `feat(db): 023 entitlements tables, join tables, RBAC seed`

---

## Task 4: `EntitlementRepo` pgx implementation

**Files:** Create `internal/db/entitlement_repo.go`

- [ ] Implement all 17 methods from the interface. Follow L1/L4/L2 patterns:
  - `scannable` for scanner, `conn(ctx, pool)` for tx-aware connections
  - `var _ domain.EntitlementRepository = (*EntitlementRepo)(nil)`
  - `Get` returns `(nil, nil)` on miss
  - `Update` uses `RETURNING` + scan
  - `Delete` returns error on zero rows
  - Metadata nil → `{}` coercion on Create/Update

- [ ] `ResolveEffective` — the one-query UNION per spec:

```sql
SELECT DISTINCT e.code FROM entitlements e
WHERE e.id IN (
    SELECT pe.entitlement_id FROM policy_entitlements pe
    JOIN licenses l ON l.policy_id = pe.policy_id
    WHERE l.id = $1
    UNION
    SELECT le.entitlement_id FROM license_entitlements le
    WHERE le.license_id = $1
)
ORDER BY e.code ASC
```

- [ ] `AttachToPolicy` / `AttachToLicense` — `INSERT INTO ... ON CONFLICT DO NOTHING` for idempotency.
- [ ] `DetachFromPolicy` / `DetachFromLicense` — `DELETE ... WHERE policy_id = $1 AND entitlement_id = ANY($2)`.
- [ ] `ReplacePolicyAttachments` / `ReplaceLicenseAttachments` — inside a single statement or two: `DELETE WHERE policy_id = $1`, then `INSERT ... ON CONFLICT DO NOTHING` for each ID. All within the caller's ambient tx.
- [ ] `GetByCodes` — `WHERE account_id = $1 AND lower(code) = ANY($2)` returning matched rows.
- [ ] `ListPolicyCodes` / `ListLicenseCodes` — `SELECT e.code FROM entitlements e JOIN (policy|license)_entitlements ... ORDER BY e.code ASC`.

- [ ] Do NOT commit — stays dirty for Task 7's unified commit.

---

## Task 5: `internal/entitlement/` package (Service + code validation)

**Files:** Create `internal/entitlement/service.go`, `code.go`, `code_test.go`

- [ ] `code.go`: `ValidateCode(code string) error` — regex `^[A-Z][A-Z0-9_]{0,63}$`. Returns `ErrEntitlementInvalidCode` on mismatch.

- [ ] `code_test.go`: table-driven tests for valid codes (`OFFLINE_SUPPORT`, `A`, `A_B_C_1`), invalid codes (lowercase, leading digit, too long, empty, unicode, whitespace).

- [ ] `service.go`: `Service` struct with `repo domain.EntitlementRepository`. Pure — no internal tx (same pattern as `customer.Service`, `policy.Service`). Methods:

  - `Create(ctx, accountID, req CreateRequest) (*domain.Entitlement, error)` — validates code format, checks for duplicate via repo.GetByCodes, creates.
  - `Get(ctx, id) (*domain.Entitlement, error)` — translates nil → ErrEntitlementNotFound.
  - `List(ctx, accountID, codePrefix, cursor, limit) ([]Entitlement, bool, error)`
  - `Update(ctx, id, req UpdateRequest) (*domain.Entitlement, error)` — rejects code changes with ErrEntitlementCodeImmutable. Updates name/metadata only.
  - `Delete(ctx, id) error` — checks for in-use via a count query or FK error translation.
  - `ResolveCodeToIDs(ctx, accountID, codes []string) ([]core.EntitlementID, error)` — looks up codes → IDs, returns error if any code is unknown.
  - `AttachToPolicy(ctx, policyID, codes []string, accountID) error` — resolves codes → IDs, calls repo.AttachToPolicy.
  - `DetachFromPolicy(ctx, policyID, code string, accountID) error`
  - `ReplacePolicyAttachments(ctx, policyID, codes []string, accountID) error`
  - `AttachToLicense(ctx, licenseID, codes []string, accountID) error`
  - `DetachFromLicense(ctx, licenseID, code string, accountID) error`
  - `ReplaceLicenseAttachments(ctx, licenseID, codes []string, accountID) error`
  - `ListPolicyCodes(ctx, policyID) ([]string, error)`
  - `ListLicenseCodes(ctx, licenseID) ([]string, error)`
  - `ResolveEffective(ctx, licenseID) ([]string, error)` — delegates to repo.ResolveEffective.
  - `ThreeSetResponse(ctx, licenseID, policyID) (EntitlementSets, error)` — calls ListPolicyCodes + ListLicenseCodes, computes effective as sorted union.

  ```go
  type EntitlementSets struct {
      Policy    []string `json:"policy"`
      License   []string `json:"license"`
      Effective []string `json:"effective"`
  }
  ```

- [ ] `go build ./internal/entitlement/...` and `go test ./internal/entitlement/...` — clean.
- [ ] Do NOT commit — stays dirty for Task 7's unified commit (or commit if the entitlement package builds independently and has no dep on the dirty domain/db layer... actually it depends on `domain.EntitlementRepository` which IS dirty). So: do NOT commit.

---

## Task 6: Service unit tests

**Files:** Create `internal/entitlement/service_test.go`

- [ ] Build a `fakeEntitlementRepo` implementing the full interface (17 methods). Use in-memory maps. Match the L4 `fakeCustomerRepo` pattern.

- [ ] Tests:
  - `TestCreate_HappyPath` — creates, verifies round-trip.
  - `TestCreate_InvalidCode` — lowercase → ErrEntitlementInvalidCode.
  - `TestCreate_DuplicateCode` — same code twice → error.
  - `TestGet_NotFound` → ErrEntitlementNotFound.
  - `TestUpdate_CodeImmutable` — attempt to change code → ErrEntitlementCodeImmutable.
  - `TestUpdate_NameOnly` — name changes, code stays.
  - `TestDelete_InUse` — attach to a policy, try delete → ErrEntitlementInUse.
  - `TestDelete_Success` — not attached, deletes.
  - `TestAttachToPolicy_UnknownCode` — unknown code → ErrEntitlementNotFound.
  - `TestAttachToPolicy_Idempotent` — attach same code twice, no error.
  - `TestResolveEffective_Union` — attach A to policy, B to license, effective = [A, B] sorted.
  - `TestThreeSetResponse` — verifies policy/license/effective shape.

- [ ] `go test ./internal/entitlement/...` — all pass.
- [ ] Do NOT commit — stays dirty.

---

## Task 7: Licensing integration (the big commit)

**Files:** Modify `internal/licensing/service.go`, `internal/licensing/lease.go`, `internal/licensing/service_test.go`

This is the unified commit that lands Tasks 2, 4, 5, 6, and 7 together.

### Step 7.1: Inject `entitlement.Service` into `licensing.Service`

- [ ] Add `entitlements *entitlement.Service` field. Update `NewService` signature.

### Step 7.2: Update `BuildLeaseClaimsInput` and `BuildLeaseClaims`

- [ ] Open `internal/licensing/lease.go`. Add `Entitlements []string` to `BuildLeaseClaimsInput`. In `BuildLeaseClaims`, use `in.Entitlements` instead of the hardcoded `[]string{}`:

```go
ent := in.Entitlements
if ent == nil {
    ent = []string{}
}
return crypto.LeaseTokenPayload{
    // ...
    Entitlements: ent,
    // ...
}
```

### Step 7.3: Populate entitlements in Activate + Checkin

- [ ] In `Activate`, after the machine UpsertActivation and before `BuildLeaseClaims`, resolve:

```go
entCodes, err := s.entitlements.ResolveEffective(ctx, l.ID)
if err != nil {
    return err
}
```

Pass `entCodes` as `Entitlements` in the `BuildLeaseClaimsInput`.

- [ ] Same for `Checkin`.

### Step 7.4: Add entitlements to `ValidateResult`

- [ ] Add `Entitlements []string` to `ValidateResult`:

```go
type ValidateResult struct {
    Valid        bool            `json:"valid"`
    License      *domain.License `json:"license"`
    Entitlements []string        `json:"entitlements"`
}
```

- [ ] In `Validate`, after loading the license and policy, resolve entitlements:

```go
entCodes, err := s.entitlements.ResolveEffective(ctx, license.ID)
if err != nil {
    return nil, err
}
return &ValidateResult{Valid: true, License: license, Entitlements: entCodes}, nil
```

### Step 7.5: Accept inline entitlements on license create

- [ ] Add `Entitlements []string` to `CreateRequest` (optional, for inline attach at creation time).

- [ ] In `Create`, after the license INSERT, if `req.Entitlements` is non-empty, resolve codes → IDs and attach:

```go
if len(req.Entitlements) > 0 {
    if err := s.entitlements.AttachToLicense(ctx, license.ID, req.Entitlements, accountID); err != nil {
        return err
    }
}
```

### Step 7.6: Add `AllowedEntitlementCodes` to `CreateOptions`

- [ ] Add `AllowedEntitlementCodes []string` to `CreateOptions`.

- [ ] In `Create`, after inline attach, if `opts.AllowedEntitlementCodes` is non-empty, check every requested code is in the allowlist:

```go
if len(opts.AllowedEntitlementCodes) > 0 && len(req.Entitlements) > 0 {
    for _, code := range req.Entitlements {
        if !slices.Contains(opts.AllowedEntitlementCodes, code) {
            return core.NewAppError(core.ErrGrantEntitlementNotAllowed, "entitlement code not allowed by grant: "+code)
        }
    }
}
```

### Step 7.7: Update `cmd/server/serve.go`

- [ ] Construct `entitlementRepo := db.NewEntitlementRepo(pool)` and `entitlementSvc := entitlement.NewService(entitlementRepo)`.
- [ ] Pass `entitlementSvc` to `licensing.NewService(...)`.

### Step 7.8: Update tests

- [ ] Update `mockEntitlementService` or inject a stub. Since `licensing.Service` depends on `*entitlement.Service` (not an interface), you need a real `entitlement.Service` backed by a fake repo in the test harness.
- [ ] Add tests:
  - `TestActivate_LeaseTokenContainsEntitlements` — attach entitlements to policy, activate, verify `LeaseClaims.Entitlements` contains the codes.
  - `TestValidate_ReturnsEntitlements` — attach entitlements, validate, verify response.
  - `TestCreate_InlineEntitlements` — create license with `Entitlements: ["CODE_A"]`, verify attached.

### Step 7.9: Build, vet, test, commit

- [ ] `go build ./... && go vet ./... && go test ./...` — all green.
- [ ] Stage everything: `internal/core/entitlement.go`, `internal/domain/`, `internal/db/entitlement_repo.go`, `internal/entitlement/`, `internal/licensing/`, `cmd/server/serve.go`.
- [ ] Commit:

```
feat(licensing): entitlement registry + lease token population + validate response

Three new tables (entitlements, policy_entitlements, license_entitlements)
with code-based attach/detach. Effective set = policy ∪ license (add-only).
Lease token Entitlements field now populated from ResolveEffective on
Activate and Checkin. ValidateResult gains Entitlements array.
CreateRequest accepts optional inline entitlements at license creation.
Grant AllowedEntitlementCodes placeholder wired into CreateOptions.
```

---

## Task 8: Grant `AllowedEntitlementCodes` enforcement

**Files:** Modify `internal/grant/service.go`, `internal/grant/service_test.go`, `internal/server/handler/grants.go`

- [ ] In the grant-scoped license create handler (`internal/server/handler/grants.go`), populate `opts.AllowedEntitlementCodes` from the decoded grant constraints.

- [ ] Add tests:
  - `TestCreateLicense_AllowedEntitlementCodes_Allowed` — codes in allowlist, success.
  - `TestCreateLicense_AllowedEntitlementCodes_NotAllowed` — code not in allowlist → 403.
  - `TestCreateLicense_AllowedEntitlementCodes_Empty_AllowsAll` — empty slice, all codes allowed.

- [ ] `go test ./internal/grant/... ./internal/licensing/...` — pass.
- [ ] Commit: `feat(grant): enforce AllowedEntitlementCodes on license create`

---

## Task 9: RBAC constants

**Files:** Modify `internal/rbac/permissions.go`, `internal/rbac/presets_test.go`

- [ ] Add `EntitlementRead`, `EntitlementWrite`, `EntitlementDelete` constants.
- [ ] Add to `All()`.
- [ ] Update `presetSeedPermissions` test map: owner/admin/developer get all three, operator gets read only.
- [ ] `go test ./internal/rbac/...` — pass.
- [ ] Commit: `feat(rbac): entitlement permission constants`

---

## Task 10: HTTP handlers

**Files:** Create `internal/server/handler/entitlements.go`, modify `policies.go`, `licenses.go`

### Entitlement registry CRUD (`entitlements.go`)

- [ ] `EntitlementHandler` struct with `tx domain.TxManager`, `svc *entitlement.Service`.
- [ ] Methods: `List`, `Create`, `Get`, `Update`, `Delete`.
- [ ] RBAC: `entitlement:read`, `entitlement:write`, `entitlement:delete`.
- [ ] List accepts `?code_prefix=` filter.

### Policy entitlement attach/detach (`policies.go` or `entitlements.go`)

- [ ] `ListPolicyEntitlements(c) error` — `GET /v1/policies/:id/entitlements` → calls `svc.ListPolicyCodes`, returns `[]string`.
- [ ] `AttachPolicyEntitlements(c) error` — `POST /v1/policies/:id/entitlements` body `{codes: [...]}`. Permission: `policy:write`.
- [ ] `ReplacePolicyEntitlements(c) error` — `PUT /v1/policies/:id/entitlements` body `{codes: [...]}`. Permission: `policy:write`.
- [ ] `DetachPolicyEntitlement(c) error` — `DELETE /v1/policies/:id/entitlements/:code`. Permission: `policy:write`.

### License entitlement surface (`licenses.go` or `entitlements.go`)

- [ ] `ListLicenseEntitlements(c) error` — `GET /v1/licenses/:id/entitlements` → three-set response `{policy: [...], license: [...], effective: [...]}`.
- [ ] `AttachLicenseEntitlements(c) error` — `POST /v1/licenses/:id/entitlements` body `{codes: [...]}`. Permission: `license:update`.
- [ ] `ReplaceLicenseEntitlements(c) error` — `PUT /v1/licenses/:id/entitlements` body `{codes: [...]}`. Permission: `license:update`.
- [ ] `DetachLicenseEntitlement(c) error` — `DELETE /v1/licenses/:id/entitlements/:code`. Permission: `license:update`.

- [ ] `go build ./...` — clean.
- [ ] Commit: `feat(http): entitlement registry CRUD + policy/license attach handlers`

---

## Task 11: Routes + deps wiring

**Files:** Modify `internal/server/routes.go`, `internal/server/deps.go`, `cmd/server/serve.go`

- [ ] Construct `entitlementHandler` in serve.go or routes.go (match the existing pattern).
- [ ] Register routes:

```
/v1/entitlements               GET, POST
/v1/entitlements/:id           GET, PATCH, DELETE
/v1/policies/:id/entitlements  GET, POST, PUT
/v1/policies/:id/entitlements/:code  DELETE
/v1/licenses/:id/entitlements  GET, POST, PUT
/v1/licenses/:id/entitlements/:code  DELETE
```

- [ ] `go build ./...` — clean.
- [ ] `make run` boot smoke — server starts, /health returns 200.
- [ ] Commit: `feat(server): register entitlement routes`

---

## Task 12: DB integration tests

**Files:** Create `internal/db/entitlement_repo_test.go`

- [ ] 10 tests:
  1. `TestEntitlementRepo_CreateAndGet`
  2. `TestEntitlementRepo_GetByCodes_CaseInsensitive`
  3. `TestEntitlementRepo_UniqueCodePerAccount`
  4. `TestEntitlementRepo_AttachToPolicy_Idempotent`
  5. `TestEntitlementRepo_ReplacePolicyAttachments`
  6. `TestEntitlementRepo_AttachToLicense`
  7. `TestEntitlementRepo_ResolveEffective_Union`
  8. `TestEntitlementRepo_DeleteBlockedByFK`
  9. `TestEntitlementRepo_ListPolicyCodes_Sorted`
  10. `TestEntitlementRepo_List_Pagination`

- [ ] `make test-all` — all pass.
- [ ] Commit: `test(db): entitlement_repo integration tests`

---

## Task 13: E2E hurl scenarios

**Files:** Create `e2e/scenarios/22_entitlements.hurl`

Scenario covering:
1. Signup, create product.
2. Create entitlements `OFFLINE_SUPPORT`, `PRIORITY_MAIL`.
3. Attach `OFFLINE_SUPPORT` to the default policy.
4. Create a license → `GET /v1/licenses/:id/entitlements` shows `{policy: [OFFLINE_SUPPORT], license: [], effective: [OFFLINE_SUPPORT]}`.
5. Attach `PRIORITY_MAIL` to the license.
6. `GET /v1/licenses/:id/entitlements` → effective = `[OFFLINE_SUPPORT, PRIORITY_MAIL]`.
7. Activate machine → lease token `$.lease_claims.ent` contains both codes sorted.
8. PUT license entitlements to `[]` → effective reverts to `[OFFLINE_SUPPORT]`.
9. DELETE `OFFLINE_SUPPORT` → 409 `entitlement_in_use`.
10. Detach from policy → DELETE `OFFLINE_SUPPORT` succeeds (204).
11. Validate → `$.entitlements` matches effective set.
12. Invalid code format → 422 `entitlement_invalid_code`.

- [ ] `make e2e` — all scenarios pass.
- [ ] Commit: `test(e2e): add 22_entitlements scenario`

---

## Task 14: OpenAPI + CLAUDE.md

**Files:** Modify `openapi.yaml`, `CLAUDE.md`

- [ ] OpenAPI: add `Entitlement` schema, entitlement paths (6 CRUD + 8 attach/detach/replace), `EntitlementSets` response schema. Update `CreateLicenseRequest` with optional `entitlements` array. Update `ValidateResult` with `entitlements` array. Update `LeaseClaims.ent` description.

- [ ] CLAUDE.md: add `internal/entitlement/` to package layout. Add "Entitlements (L3)" section covering: code format, registry CRUD, policy/license attach (add-only union), effective = sorted union, lease token population, validate response, grant `AllowedEntitlementCodes`, attach permissions (license:update / policy:write, NOT entitlement:write).

- [ ] Commit: `docs(l3): openapi entitlement paths + CLAUDE.md entitlements section`

---

## Task 15: Final verification

- [ ] `gofmt -l .` — clean (fix drift if needed).
- [ ] `go build ./... && go vet ./...` — clean.
- [ ] `make lint` — 0 issues.
- [ ] `make test-all` — all packages pass.
- [ ] `make e2e` — all scenarios pass.
- [ ] Manual curl smoke: signup → create entitlement → attach to policy → create license → activate → verify lease token carries entitlement codes → validate → verify entitlements in response.
- [ ] `git log --oneline main..HEAD` — verify ~55-60 commits total for Release 2.
- [ ] L3 is DONE. Release 2 License Model Reshape is complete.

---

## Self-Review Checklist

- [ ] Every section in `2026-04-15-l3-entitlements-design.md` has a covering task.
- [ ] No TBD / TODO / "add appropriate X" placeholders.
- [ ] Code format regex `^[A-Z][A-Z0-9_]{0,63}$` used consistently.
- [ ] `Entitlements` field on `LeaseTokenPayload` is populated (not hardcoded `[]string{}`).
- [ ] `ValidateResult.Entitlements` is populated.
- [ ] Three-set response shape `{policy, license, effective}` matches spec.
- [ ] Attach permissions: `license:update` for license attach, `policy:write` for policy attach, `entitlement:write` only for registry CRUD.
- [ ] Grant `AllowedEntitlementCodes` enforcement on inline attach at license create.
- [ ] Code immutability enforced in Update.
- [ ] Delete blocked by FK (ON DELETE RESTRICT on entitlement_id in join tables).
- [ ] POST attach is idempotent (ON CONFLICT DO NOTHING).
- [ ] PUT replace deletes missing + inserts new atomically.
- [ ] Union is sorted alphabetically for deterministic lease tokens.
