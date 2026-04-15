# L4 — Customers Design

**Release:** 2 (License Model Reshape), feature 2 of 4
**Branch:** `release-2-license-model`
**Dependencies:** L1 Policies (this spec runs after L1 lands in the worktree). F4 Grants (already in Release 1).
**Next:** L2 Checkout, then L3 Entitlements.
**Date:** 2026-04-15

## Goal

Introduce a first-class `customers` table representing the end-users of a vendor's licensed software. Every license references a customer by FK. Customers are account-scoped (not environment-scoped), never called "users", and never have a login in v1. Drop the ad-hoc `licensee_email` / `licensee_name` columns on `licenses`.

## Non-Goals

- Customer self-login or customer-facing portal. See FEATURES.md §6 — this is explicit v2.
- Multi-seat licenses (one customer per license in v1). `max_seats` scaffold exists on the policy from L1 but activation still assumes one seat.
- Customer import / CSV upload.
- Customer-level entitlements. Entitlements attach to policies and licenses (L3), not customers.
- Additional contact fields beyond `email` / `name`. Phones, billing addresses, company, tax ID, etc. go in `metadata` jsonb until use-case demand emerges.
- Backwards compatibility with existing dev data — hard cutover, same as L1. `make db-reset` is already required for this branch by the time L4's migration runs.

## Naming Discipline

Three distinct concepts, three distinct names, no collisions:

| Concept | Table | Has login? | Role |
|---|---|---|---|
| Identity | `identities` | yes | human who accesses the vendor dashboard |
| Customer | `customers` | **no** (v1) | end-user of the licensed software, owns licenses |
| Membership | `account_memberships` | n/a | join between identity and account |

The word "user" appears nowhere in this spec, in the migration, in the Go types, in the API shape, or in the OpenAPI doc. The word "reseller" appears nowhere either — delegated license creation is a **grant** from a **grantor account** to a **grantee account**, and grant-scoped endpoints are the vocabulary used throughout.

## Architecture

New package `internal/customer/` owns customer CRUD and upsert-by-email. `licensing.Service.Create` is extended to accept either `customer_id` or an inline `customer: {email, name?}` and upserts inside the license-create transaction. `grant.Service` grows two new grant capabilities (`CUSTOMER_CREATE`, `CUSTOMER_READ`) so that grant-scoped license creation enforces whether a grantee is allowed to touch customer records.

```
HTTP  → handler/customer_handler.go
          ↓
        customer.Service  (CRUD + upsert-by-email)
          ↓
        CustomerRepository  (pgx)
          ↓
        Postgres

licensing.Service.Create(ctx, req):
  tx {
    customerID := customer.Service.UpsertForLicense(ctx, req.Customer | req.CustomerID, createdBy)
    license.Insert(ctx, req, customerID)
    grant capability check: CUSTOMER_CREATE if acting ≠ target and inline customer
  }
```

## Data Model

### New table `customers`

```sql
CREATE TABLE customers (
    id                    uuid PRIMARY KEY,
    account_id            uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    email                 text NOT NULL,
    name                  text,
    metadata              jsonb NOT NULL DEFAULT '{}'::jsonb,

    -- Attribution: which account created the customer record.
    -- NULL = created by the owning account directly.
    -- Non-NULL = created by a grantee acting under a grant on account_id.
    created_by_account_id uuid REFERENCES accounts(id) ON DELETE SET NULL,

    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX customers_account_email_ci
    ON customers (account_id, lower(email));

CREATE INDEX customers_account_created
    ON customers (account_id, created_at DESC, id DESC);

CREATE INDEX customers_account_created_by
    ON customers (account_id, created_by_account_id);

ALTER TABLE customers ENABLE ROW LEVEL SECURITY;
ALTER TABLE customers FORCE ROW LEVEL SECURITY;

CREATE POLICY customers_tenant ON customers
USING (
  NULLIF(current_setting('app.current_account_id', true), '') IS NULL
  OR account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid
);
```

Account-scoped, **not** environment-scoped. A single customer row is shared across live/test/custom envs. License-level environment filtering is unchanged; customer queries never touch `app.current_environment`.

`created_by_account_id` rules:

- Direct path (`acting_account_id == target_account_id`): column is **NULL**.
- Grant-scoped path (`acting_account_id != target_account_id`, only possible via grant routing middleware): column is set to **`acting_account_id`** (the grantee).
- On `ON DELETE SET NULL` for the FK: if a grantee account is later deleted, the attribution simply becomes NULL, preserving the vendor's customer history.

### Changed `licenses`

```sql
ALTER TABLE licenses
    ADD COLUMN customer_id uuid REFERENCES customers(id),  -- NOT NULL set after cutover
    DROP COLUMN licensee_email,
    DROP COLUMN licensee_name;

ALTER TABLE licenses ALTER COLUMN customer_id SET NOT NULL;

CREATE INDEX licenses_customer ON licenses (customer_id);
```

### Go types

```go
// internal/core/customer.go
type CustomerID uuid.UUID  // plus NewCustomerID, String, Marshal/Unmarshal helpers

// internal/domain/models.go
type Customer struct {
    ID                 core.CustomerID `json:"id"`
    AccountID          core.AccountID  `json:"account_id"`
    Email              string          `json:"email"`
    Name               *string         `json:"name,omitempty"`
    Metadata           json.RawMessage `json:"metadata,omitempty"`
    CreatedByAccountID *core.AccountID `json:"created_by_account_id,omitempty"`
    CreatedAt          time.Time       `json:"created_at"`
    UpdatedAt          time.Time       `json:"updated_at"`
}

// License struct gains:
//   CustomerID core.CustomerID `json:"customer_id"`
// and loses LicenseeEmail, LicenseeName.
```

### Forward compatibility with the v2 customer portal

L4 does **not** add a `customers.identity_id` column. That column is the v2 portal's job — see FEATURES.md §6. Adding it later is a zero-risk forward-only migration (`ADD COLUMN identity_id uuid NULL REFERENCES identities(id)`). L4 is therefore forward-compatible with the portal without baking in any portal-specific surface area today.

## Creation Semantics

`POST /v1/licenses` body must contain **exactly one** of:

- `customer_id: uuid` — attach to existing customer. 404 `customer.not_found` if the customer does not exist in the target account.
- `customer: {email, name?, metadata?}` — upsert keyed on `(target_account_id, lower(email))`.

Errors:

| Condition | HTTP | Code |
|---|---|---|
| Both `customer_id` and `customer` provided | 422 | `customer.ambiguous` |
| Neither provided | 422 | `customer.required` |
| Invalid email format | 422 | `customer.invalid_email` |
| `customer_id` points to a customer in a different account | 404 | `customer.not_found` (don't leak existence) |

### Upsert semantics on existing customer

When the inline `customer.email` already exists in the target account, the service attaches the license to the existing customer row and **does not mutate** `name` or `metadata` on that row. Rationale: license creation should never silently overwrite existing customer fields from a one-line license-create call. Vendors who want to update a customer use `PATCH /v1/customers/:id` explicitly.

### Upsert implementation

A single `INSERT ... ON CONFLICT (account_id, lower(email)) DO UPDATE SET updated_at = now() RETURNING id` inside the license-create transaction. The `DO UPDATE SET updated_at = now()` is a no-op-ish touch that makes `RETURNING id` work on both insert and conflict paths without a second round-trip. `name` and `metadata` are deliberately NOT in the UPDATE clause.

### Attribution on upsert

- If the customer row is **inserted**, `created_by_account_id` is set from the request context: NULL on direct path, acting account on grant-scoped path.
- If the customer row **already exists**, `created_by_account_id` is not changed. First-write-wins for attribution.

## Delete and Reassignment

### Delete

`DELETE /v1/customers/:id`:
- 409 `customer.in_use` if any license references the customer. No cascade, no soft-delete.
- Vendors bulk-delete licenses first, then the customer. This is the exact same blocking pattern as Release 1's FK-referenced entities.

### Reassignment

`PATCH /v1/licenses/:id` accepts a new `customer_id` field:
- The new customer must exist in the license's **target account** (not acting account — important for grant-scoped PATCH).
- Returns 422 `customer.account_mismatch` if the target customer is in a different account.
- Does not change `created_by_account_id` on either customer.

No dedicated "reassign" endpoint — reusing PATCH keeps the surface small and matches how other license mutations work.

## HTTP Surface

### Vendor endpoints

| Verb | Path | Purpose | Permission |
|------|------|---------|------------|
| GET  | `/v1/customers` | List. Filters: `?email=&created_by_account_id=` + cursor pagination | `customer:read` |
| GET  | `/v1/customers/:id` | Read single | `customer:read` |
| POST | `/v1/customers` | Create a customer directly (no license required) | `customer:write` |
| PATCH | `/v1/customers/:id` | Partial update (`name`, `metadata`) | `customer:write` |
| DELETE | `/v1/customers/:id` | Block if in use | `customer:delete` |
| GET  | `/v1/customers/:id/licenses` | Licenses owned by this customer | `customer:read` + `license:read` |

### Grant-scoped lens

`GET /v1/grants/:id/customers` — served by existing grant routing middleware, which sets `target_account_id = grant.grantor_account_id`. The handler then filters rows additionally by `created_by_account_id = auth.acting_account_id` so a grantee only sees the customers it created under this grant. Other grantees' customers and the vendor's own customers are invisible on this endpoint.

When a grantee hits `GET /v1/customers/:id` directly for a customer they did not create, the service returns **404** `customer.not_found` — not 403 — to avoid leaking existence.

## RBAC

New permissions in `internal/rbac/`:

```go
const (
    CustomerRead   = "customer:read"
    CustomerWrite  = "customer:write"
    CustomerDelete = "customer:delete"
)
```

Migration seeds preset roles:

- `owner`, `admin`, `developer`: read + write + delete
- `operator`: read only

## Grants

Two new grant capabilities in `domain.GrantCapability`:

```go
GrantCapCustomerCreate GrantCapability = "CUSTOMER_CREATE"
GrantCapCustomerRead   GrantCapability = "CUSTOMER_READ"
```

Added to `allGrantCapabilities` in `internal/domain/models.go`.

Enforcement:

- `grant.Service.CreateLicense` (the grant-scoped license creation path):
  - If the request body has inline `customer: {...}` and the email does not already exist in the grantor account: requires `CUSTOMER_CREATE`. Missing → `grant.capability_missing`.
  - If the request body has `customer_id` or the inline email already exists (pure attach): requires `CUSTOMER_READ` to verify the customer exists in the grantor account.
- `GET /v1/grants/:id/customers` requires `CUSTOMER_READ`.

## Error Codes

| Code | HTTP | Meaning |
|---|---|---|
| `customer.not_found` | 404 | Customer does not exist in the target account (or the grantee is not allowed to see it) |
| `customer.ambiguous` | 422 | Both `customer_id` and `customer` provided on license create |
| `customer.required` | 422 | Neither `customer_id` nor `customer` provided on license create |
| `customer.invalid_email` | 422 | Email fails format validation |
| `customer.in_use` | 409 | Delete refused because licenses reference the customer |
| `customer.account_mismatch` | 422 | License reassignment to a customer in a different account |
| `grant.capability_missing` | 403 | Grant lacks `CUSTOMER_CREATE` or `CUSTOMER_READ` |

## Testing

### Unit (no DB)

- `internal/customer/service_test.go` — email normalization (lowercase + trim), RFC-ish format validation matching existing `licensee_email` regex from Release 1.
- Upsert decision table: `(acting, target, customer_exists) → (action, created_by_account_id set?)`.
- Grant capability check decision table.

### Integration (real DB)

- Upsert idempotency: creating two licenses with the same inline `customer: {email}` under the same account produces exactly one customer row, and both licenses reference it.
- Name not overwritten: upserting an existing customer with a new `name` value leaves the stored `name` unchanged.
- Delete blocked when a license references the customer; succeeds after the license is deleted.
- PATCH reassignment updates `customer_id`, leaves other license fields unchanged, and validates the new customer is in the target account.
- Grant-scoped path: grantee creates license with inline customer → row inserted with `created_by_account_id = grantee_account_id` in the grantor's tenant.
- Direct path on the same email: inserted row has `created_by_account_id IS NULL`.
- Grant-scoped list: `GET /v1/grants/:id/customers` returns only rows where `created_by_account_id = acting` AND row lives in grantor's account.
- Direct fetch on unauthorized customer returns 404 `customer.not_found`, not 403.

### E2E (hurl)

New `e2e/scenarios/customers.hurl`:
- Signup, create product, create customer directly.
- Create a license with `customer_id` → license attached.
- Create a second license with inline `customer: {email: <same>}` → same customer row reused; `GET /v1/customers/:id/licenses` returns two.
- DELETE customer fails with 409 `customer.in_use`.
- DELETE both licenses, DELETE customer succeeds (204).
- PATCH a license to reassign to a different customer; verify.

Extended `e2e/scenarios/grants.hurl`:
- Grantor issues grant with `CUSTOMER_CREATE` + `CUSTOMER_READ` + `LICENSE_CREATE` + `LICENSE_READ`.
- Grantee creates a license under the grant with inline customer.
- Grantor sees the customer in `GET /v1/customers` with `created_by_account_id` populated.
- Grantee sees the customer in `GET /v1/grants/:id/customers` but gets 404 on `GET /v1/customers/:id` directly.
- Grantee tries license create without `CUSTOMER_CREATE` capability → 403 `grant.capability_missing`.

## Migration

`021_customers.sql` (goose, up-only, hard cutover):

1. `CREATE TABLE customers` with columns, indexes, unique index on `(account_id, lower(email))`, RLS policies.
2. `ALTER TABLE licenses`: ADD `customer_id uuid REFERENCES customers(id)`, DROP `licensee_email`, DROP `licensee_name`.
3. `ALTER TABLE licenses ALTER COLUMN customer_id SET NOT NULL`.
4. `CREATE INDEX licenses_customer ON licenses (customer_id)`.
5. Seed `customer:read`, `customer:write`, `customer:delete` into preset roles.
6. Extend `allGrantCapabilities` at the Go layer (no SQL for this — grant capabilities are a Go enum allow-listed in `IsValidGrantCapability`). No migration needed for capabilities.

No down migration. Same as L1. `make db-reset` has already been run for the branch by L1's migration.

## File Layout

New:

- `migrations/021_customers.sql`
- `internal/core/customer.go`
- `internal/domain/models.go` — `Customer` struct + `License.CustomerID` field
- `internal/domain/repositories.go` — `CustomerRepository` interface
- `internal/db/customer_repo.go` — pgx implementation
- `internal/customer/service.go`
- `internal/customer/service_test.go`
- `internal/server/handler/customer_handler.go`
- `e2e/scenarios/customers.hurl`

Modified (non-exhaustive):

- `internal/licensing/service.go` — Create upserts customer, drops LicenseeEmail/Name fields from request DTO, adds PATCH reassignment path
- `internal/grant/service.go` — `CUSTOMER_CREATE` / `CUSTOMER_READ` capability checks on CreateLicense path, plus wiring for `GET /v1/grants/:id/customers`
- `internal/domain/models.go` — extend `allGrantCapabilities` with the two new capabilities
- `internal/rbac/permissions.go` — new `Customer*` constants
- `internal/server/app.go` — register customer handler + routes
- `openapi.yaml` — new customer paths, updated license schemas
- `CLAUDE.md` — customer package in the layout section, grants capability section updated
- `e2e/scenarios/grants.hurl` — extended for new capabilities and attribution assertions

## Implementation Risks

- **Upsert race on parallel license-creates.** Two concurrent license creates with the same new email could both hit an empty customers table and both try to insert. `INSERT ... ON CONFLICT (account_id, lower(email)) DO UPDATE SET updated_at = now() RETURNING id` is atomic and gives each call the same `id`. Must run inside the license-create tx.
- **Grant-scoped list filter bug.** `GET /v1/grants/:id/customers` needs BOTH filters: `account_id = grantor` (enforced by RLS via `target_account_id`) AND `created_by_account_id = acting`. Getting only one wrong leaks customer data across grantees of the same vendor. Integration tests cover this.
- **PATCH reassignment and RLS.** Grant-scoped PATCH runs under `target_account_id = grantor`, so the new customer is checked against the grantor's account via RLS. But the query must explicitly verify the new customer's `account_id = target` as a belt-and-braces check — RLS plus an explicit check is the Release 1 pattern.
- **Dropping `licensee_email` breaks any code that still reads it.** Mitigation: delete the column in the migration first so the compiler finds every reference. Same trick as L1 uses for `license.max_machines`.
- **Email normalization consistency.** Every path that compares emails must `lower(trim(email))` before comparison. The unique index uses `lower(email)` (not `lower(trim(email))`), so trimming must happen in the service layer before the DB sees the string. Unit tests cover empty whitespace, mixed case, and Unicode edge cases.

## Open Questions

None at spec-write time. If the implementation surfaces one, stop and resolve before proceeding.
