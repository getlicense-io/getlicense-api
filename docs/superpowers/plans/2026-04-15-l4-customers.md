# L4 Customers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Introduce a first-class `customers` table that owns end-user records, reshape `licenses` to FK to a customer (dropping `licensee_name`/`licensee_email`), and activate grant-scoped customer capabilities so a grantee can create licenses under a grantor's tenant while preserving the grantor's customer relationship.

**Architecture:** New `internal/customer/` package owns CRUD + upsert-by-email. `licensing.Service.Create` accepts either `customer_id` or an inline `{email, name}` and upserts inside the license-create transaction. Grant-scoped license creation upserts into the **grantor's** customer table with `created_by_account_id` set to the **grantee's** acting account. Delete is blocked when the customer has licenses (no cascade, no soft-delete). Customers are **account-scoped, not environment-scoped** — one customer row is shared across live/test/custom envs. No `identity_id` column in v1 — the portal is explicit v2.

**Tech Stack:** Go, Fiber v3, pgx v5, goose migrations, Postgres 16 with RLS, hurl (e2e).

**Spec:** `docs/superpowers/specs/2026-04-15-l4-customers-design.md` — consult when a step references a decision by name.

**Error code convention:** Underscore — `customer_not_found`, not `customer.not_found`. Matches Release 1 / L1.

**Naming discipline:** The word `user` must not appear anywhere in new code, migration SQL, or handler docs. The word `reseller` must not appear either — delegated license creation is a **grant** from a **grantor account** to a **grantee account**.

**Dependencies:** L1 Policies (fully landed). F4 Grants from Release 1. Hard cutover continues — `make db-reset` is already required for this branch.

---

## File Map

### New files

```
migrations/021_customers.sql                          # Task 3
internal/core/customer.go                             # Task 1 (CustomerID)
internal/customer/service.go                          # Task 5
internal/customer/service_test.go                     # Task 5
internal/customer/email.go                            # Task 5 (normalization + validation)
internal/customer/email_test.go                       # Task 5
internal/db/customer_repo.go                          # Task 4
internal/db/customer_repo_test.go                     # Task 12 (integration)
internal/server/handler/customers.go                  # Task 9
e2e/scenarios/20_customers.hurl                       # Task 13
```

### Modified files

```
internal/core/errors.go                               # Task 1 (new error codes)
internal/domain/models.go                             # Task 2 (Customer struct, License loses LicenseeName/Email)
internal/domain/repositories.go                       # Task 4 (CustomerRepository interface)
internal/rbac/permissions.go                          # Task 8 (customer_read/write/delete constants)
internal/rbac/presets_test.go                         # Task 8 (preset mapping test)
internal/licensing/service.go                         # Task 6 (Create + Update customer path, drop Licensee* fields)
internal/licensing/service_test.go                    # Task 6
internal/db/license_repo.go                           # Task 6 (licenseColumns reshape, search filter update, scan reshape)
internal/grant/service.go                             # Task 7 (CUSTOMER_CREATE / CUSTOMER_READ capabilities, grant-scoped attribution plumbing)
internal/grant/service_test.go                        # Task 7
internal/server/handler/grants.go                     # Task 7 (grant-scoped customer list)
internal/server/handler/licenses.go                   # Task 6 (reshape CreateRequest wire DTO)
internal/server/routes.go                             # Task 10 (register customer routes)
internal/server/deps.go                               # Task 10 (wire customer service)
cmd/server/serve.go                                   # Task 10 (construct customerRepo + customerSvc)
e2e/scenarios/04_licenses.hurl                        # Task 13 (use inline customer instead of licensee_*)
e2e/scenarios/05_validate.hurl                        # Task 13
e2e/scenarios/06_machines.hurl                        # Task 13
e2e/scenarios/09_full_journey.hurl                    # Task 13
e2e/scenarios/10_bulk_licenses.hurl                   # Task 13
e2e/scenarios/11_environment_isolation.hurl           # Task 13
e2e/scenarios/14_jwt_environment_switching.hurl       # Task 13
e2e/scenarios/15_environments.hurl                    # Task 13
e2e/scenarios/18_grants.hurl                          # Task 13 (grant CUSTOMER_CREATE path)
openapi.yaml                                          # Task 14
CLAUDE.md                                             # Task 14
```

### Files that must NOT change (guardrails)
- `internal/core/ids.go` — existing ID types untouched; add `CustomerID` in `internal/core/customer.go` instead
- `migrations/020_policies.sql` — L1 migration frozen, do not amend
- `internal/policy/` — L1 package frozen
- `internal/domain/models.go`'s `Policy` / `LicenseOverrides` / `Grant` — L1/Release 1 territory; only the `License` struct changes

---

## Prerequisites

- [ ] **Step 0.1: Confirm you are on the `release-2-license-model` worktree**

```bash
pwd
git branch --show-current
git log --oneline -1
```
Expected working dir `.../worktrees/release-2-license-model`, branch `release-2-license-model`, HEAD commit is the latest L1 commit (`32f7d98` gofmt cleanup or later).

- [ ] **Step 0.2: Reset dev DB** (continuing hard cutover per spec §Cutover Strategy)

```bash
make db-reset
```

- [ ] **Step 0.3: Verify green baseline**

```bash
go build ./... && go vet ./... && go test ./... | tail
```
Expected: every package builds, vets, and tests cleanly. If any package fails here, stop and report — that's a pre-existing L1 regression, not an L4 issue.

---

## Task 1: Core types + error codes

**Files:**
- Create: `internal/core/customer.go`
- Modify: `internal/core/errors.go`

### Step 1.1: Write `internal/core/customer.go`

- [ ] Create the file:

```go
package core

import "github.com/google/uuid"

// CustomerID is a typed UUID v7 for customers.
type CustomerID uuid.UUID

// NewCustomerID generates a new CustomerID using UUID v7.
func NewCustomerID() CustomerID {
	id, err := uuid.NewV7()
	if err != nil {
		panic("core: failed to generate CustomerID: " + err.Error())
	}
	return CustomerID(id)
}

// ParseCustomerID parses a UUID string into a CustomerID.
func ParseCustomerID(s string) (CustomerID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return CustomerID{}, err
	}
	return CustomerID(id), nil
}

// String returns the string representation of the CustomerID.
func (id CustomerID) String() string { return uuid.UUID(id).String() }

// MarshalText implements encoding.TextMarshaler (used by JSON).
func (id CustomerID) MarshalText() ([]byte, error) { return uuid.UUID(id).MarshalText() }

// UnmarshalText implements encoding.TextUnmarshaler (used by JSON).
func (id *CustomerID) UnmarshalText(data []byte) error {
	var u uuid.UUID
	if err := u.UnmarshalText(data); err != nil {
		return err
	}
	*id = CustomerID(u)
	return nil
}
```

### Step 1.2: Add error codes to `internal/core/errors.go`

- [ ] Add these constants alongside existing error codes (alphabetical placement within the notfound/conflict/validation groups is fine):

```go
// Customer errors (L4)
ErrCustomerNotFound        ErrorCode = "customer_not_found"
ErrCustomerAmbiguous       ErrorCode = "customer_ambiguous"
ErrCustomerRequired        ErrorCode = "customer_required"
ErrCustomerInvalidEmail    ErrorCode = "customer_invalid_email"
ErrCustomerInUse           ErrorCode = "customer_in_use"
ErrCustomerAccountMismatch ErrorCode = "customer_account_mismatch"
ErrGrantCapabilityMissing  ErrorCode = "grant_capability_missing"
```

- [ ] Add matching `httpStatusMap` entries:

```go
ErrCustomerNotFound:        404,
ErrCustomerAmbiguous:       422,
ErrCustomerRequired:        422,
ErrCustomerInvalidEmail:    422,
ErrCustomerInUse:           409,
ErrCustomerAccountMismatch: 422,
ErrGrantCapabilityMissing:  403,
```

Note: `ErrGrantCapabilityMissing` may already exist in Release 1 — grep first. If it exists, skip it.

### Step 1.3: Build the core package

- [ ] Run:

```bash
go build ./internal/core/...
```
Expected: clean.

### Step 1.4: Commit

- [ ] Stage and commit:

```bash
git add internal/core/customer.go internal/core/errors.go
git commit -m "feat(core): CustomerID and customer error codes"
```

---

## Task 2: Domain model reshape

**Files:**
- Modify: `internal/domain/models.go`

### Step 2.1: Add the `Customer` struct

- [ ] Open `internal/domain/models.go`. Add this struct near other top-level resources (place it alphabetically or near `Account` — placement is stylistic):

```go
// Customer represents an end-user of the vendor's licensed software.
// Account-scoped, environment-agnostic. Never called "users".
// No login in v1 — the portal is explicit v2 (see FEATURES.md §6).
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
```

### Step 2.2: Update the `License` struct

- [ ] Find `License`. Add the new field:

```go
CustomerID core.CustomerID `json:"customer_id"`
```

Place it after `PolicyID`.

- [ ] Remove these fields from `License`:

```go
// DELETE: LicenseeName  *string `json:"licensee_name,omitempty"`
// DELETE: LicenseeEmail *string `json:"licensee_email,omitempty"`
```

### Step 2.3: Build — expect failures in licensing / db / handler / tests

- [ ] Run:

```bash
go build ./... 2>&1 | head -30
```

Expected: errors in `internal/licensing/service.go`, `internal/db/license_repo.go`, `internal/server/handler/licenses.go`, `internal/licensing/service_test.go`, `internal/domain/models_test.go`, `internal/grant/service.go` (for the licensee_email_pattern line which references `LicenseeEmail` via grant constraints — but that reference is on `GrantConstraints`, not `License`, so it might be fine. Verify.)

**This is expected.** Task 6 rewrites all of it. Do NOT commit Task 2's change yet — it goes in the unified Task 6 commit to keep main buildable. The working tree stays dirty.

---

## Task 3: Migration `021_customers.sql`

**Files:**
- Create: `migrations/021_customers.sql`

### Step 3.1: Verify L1 migration numbering and role schema

- [ ] Run:

```bash
ls migrations/ | tail -5
```
Expected: `020_policies.sql` is the highest. `021_customers.sql` is the next in sequence.

- [ ] Check how `016_memberships_and_roles.sql` stores permissions:

```bash
grep -n "permissions" migrations/016_memberships_and_roles.sql | head
```
Expected: `permissions TEXT[]` on the `roles` table. There is NO separate `role_permissions` table. Your seed block will `UPDATE roles SET permissions = array_cat(...)`.

### Step 3.2: Write the migration

- [ ] Create `migrations/021_customers.sql`:

```sql
-- +goose Up
-- +goose StatementBegin

CREATE TABLE customers (
    id                    uuid PRIMARY KEY,
    account_id            uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    email                 text NOT NULL,
    name                  text,
    metadata              jsonb NOT NULL DEFAULT '{}'::jsonb,

    -- Attribution: which account created this customer record.
    -- NULL = created by the owning account directly.
    -- Non-NULL = created by a grantee account acting under a grant on account_id.
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

-- Licenses: add customer_id NOT NULL FK, drop licensee_name / licensee_email.
ALTER TABLE licenses
    ADD COLUMN customer_id uuid REFERENCES customers(id),
    DROP COLUMN IF EXISTS licensee_name,
    DROP COLUMN IF EXISTS licensee_email;

-- Hard cutover: dev DB is wiped. No backfill. Set NOT NULL immediately.
ALTER TABLE licenses ALTER COLUMN customer_id SET NOT NULL;

CREATE INDEX licenses_customer ON licenses (customer_id);

-- Seed new RBAC permissions onto preset roles.
UPDATE roles
SET permissions = array_cat(permissions, ARRAY['customer:read','customer:write','customer:delete']),
    updated_at  = now()
WHERE account_id IS NULL AND slug IN ('owner','admin','developer');

UPDATE roles
SET permissions = array_cat(permissions, ARRAY['customer:read']),
    updated_at  = now()
WHERE account_id IS NULL AND slug = 'operator';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- Restore licensee columns for a clean rollback.
ALTER TABLE licenses
    ADD COLUMN IF NOT EXISTS licensee_name  text,
    ADD COLUMN IF NOT EXISTS licensee_email text;

ALTER TABLE licenses
    DROP COLUMN IF EXISTS customer_id;

DROP TABLE IF EXISTS customers;

UPDATE roles
SET permissions = (
    SELECT array_agg(p)
    FROM unnest(permissions) p
    WHERE p NOT IN ('customer:read','customer:write','customer:delete')
),
    updated_at  = now()
WHERE account_id IS NULL AND slug IN ('owner','admin','developer','operator');

-- +goose StatementEnd
```

### Step 3.3: Apply the migration

- [ ] Because Task 2 has made the Go tree red, you can't use `make run` (it builds the server first). Apply migrations via `goose` directly:

```bash
GOOSE_DRIVER=postgres GOOSE_DBSTRING="postgres://postgres:postgres@localhost:5432/getlicense?sslmode=disable" \
  goose -dir migrations up
```

Adapt the connection string to whatever Release 1 uses (check `docker/docker-compose.yml` or `make run` output). Expected: `020_policies.sql` was already applied in L1 so goose applies only 021.

Verify manually:

```bash
docker compose -f docker/docker-compose.yml exec -T postgres \
  psql -U postgres getlicense -c '\d customers' | head -20
```
Expected: the `customers` table exists with the 8 columns plus RLS.

### Step 3.4: Commit

- [ ] Stage and commit:

```bash
git add migrations/021_customers.sql
git commit -m "feat(db): 021 customers table, license FK reshape, RBAC seed"
```

---

## Task 4: CustomerRepository interface + pgx impl

**Files:**
- Modify: `internal/domain/repositories.go`
- Create: `internal/db/customer_repo.go`

### Step 4.1: Add the `CustomerRepository` interface

- [ ] Open `internal/domain/repositories.go`. Add near other repo interfaces:

```go
// CustomerRepository persists end-user customer records. Account-scoped,
// environment-agnostic. Email comparisons are case-insensitive via a
// unique (account_id, lower(email)) index.
type CustomerRepository interface {
	Create(ctx context.Context, c *Customer) error
	Get(ctx context.Context, id core.CustomerID) (*Customer, error)
	GetByEmail(ctx context.Context, accountID core.AccountID, email string) (*Customer, error)
	List(ctx context.Context, accountID core.AccountID, filter CustomerListFilter, cursor core.Cursor, limit int) ([]Customer, bool, error)
	Update(ctx context.Context, c *Customer) error
	Delete(ctx context.Context, id core.CustomerID) error
	CountReferencingLicenses(ctx context.Context, id core.CustomerID) (int, error)

	// UpsertByEmail inserts a new customer row or returns the existing one
	// keyed on (account_id, lower(email)). On insert, createdByAccountID
	// is written to customers.created_by_account_id (may be nil). On
	// conflict, existing row is returned UNCHANGED — name and metadata
	// from the request are ignored (first-write-wins per spec §Upsert semantics).
	UpsertByEmail(ctx context.Context, accountID core.AccountID, email string, name *string, metadata json.RawMessage, createdByAccountID *core.AccountID) (*Customer, bool, error)
}

// CustomerListFilter is the narrow filter surface for customer list queries.
type CustomerListFilter struct {
	Email              string           // case-insensitive prefix match; empty = no filter
	CreatedByAccountID *core.AccountID  // nil = no filter
}
```

### Step 4.2: Write `internal/db/customer_repo.go` — header, columns, scanner

- [ ] Create the file:

```go
package db

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const customerColumns = `
	id, account_id, email, name, metadata, created_by_account_id, created_at, updated_at
`

type CustomerRepo struct {
	pool *pgxpool.Pool
}

func NewCustomerRepo(pool *pgxpool.Pool) *CustomerRepo { return &CustomerRepo{pool: pool} }

var _ domain.CustomerRepository = (*CustomerRepo)(nil)

func scanCustomer(s scannable) (*domain.Customer, error) {
	c := &domain.Customer{}
	err := s.Scan(
		&c.ID, &c.AccountID, &c.Email, &c.Name, &c.Metadata,
		&c.CreatedByAccountID, &c.CreatedAt, &c.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return c, nil
}
```

### Step 4.3: Implement `Create`, `Get`, `GetByEmail`

- [ ] Append:

```go
func (r *CustomerRepo) Create(ctx context.Context, c *domain.Customer) error {
	// Normalize metadata nil → '{}' (policy_repo had the same latent bug — fixed pre-emptively here).
	if len(c.Metadata) == 0 {
		c.Metadata = json.RawMessage("{}")
	}
	q := `INSERT INTO customers (
		id, account_id, email, name, metadata, created_by_account_id, created_at, updated_at
	) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	_, err := conn(ctx, r.pool).Exec(ctx, q,
		c.ID, c.AccountID, c.Email, c.Name, c.Metadata,
		c.CreatedByAccountID, c.CreatedAt, c.UpdatedAt,
	)
	return err
}

func (r *CustomerRepo) Get(ctx context.Context, id core.CustomerID) (*domain.Customer, error) {
	q := `SELECT ` + customerColumns + ` FROM customers WHERE id = $1`
	row := conn(ctx, r.pool).QueryRow(ctx, q, id)
	c, err := scanCustomer(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return c, err
}

func (r *CustomerRepo) GetByEmail(ctx context.Context, accountID core.AccountID, email string) (*domain.Customer, error) {
	q := `SELECT ` + customerColumns + `
	      FROM customers
	      WHERE account_id = $1 AND lower(email) = lower($2)`
	row := conn(ctx, r.pool).QueryRow(ctx, q, accountID, email)
	c, err := scanCustomer(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return c, err
}
```

### Step 4.4: Implement `List`

- [ ] Append:

```go
func (r *CustomerRepo) List(ctx context.Context, accountID core.AccountID, filter domain.CustomerListFilter, cursor core.Cursor, limit int) ([]domain.Customer, bool, error) {
	// Build WHERE clauses incrementally.
	args := []any{accountID}
	where := "account_id = $1"
	next := 2
	if filter.Email != "" {
		where += " AND lower(email) LIKE lower($" + itoa(next) + ") || '%'"
		args = append(args, filter.Email)
		next++
	}
	if filter.CreatedByAccountID != nil {
		where += " AND created_by_account_id = $" + itoa(next)
		args = append(args, *filter.CreatedByAccountID)
		next++
	}
	var q string
	if cursor.IsZero() {
		q = `SELECT ` + customerColumns + ` FROM customers WHERE ` + where +
			` ORDER BY created_at DESC, id DESC LIMIT $` + itoa(next)
		args = append(args, limit+1)
	} else {
		q = `SELECT ` + customerColumns + ` FROM customers WHERE ` + where +
			` AND (created_at, id) < ($` + itoa(next) + `, $` + itoa(next+1) + `)` +
			` ORDER BY created_at DESC, id DESC LIMIT $` + itoa(next+2)
		args = append(args, cursor.CreatedAt, cursor.ID, limit+1)
	}
	rows, err := conn(ctx, r.pool).Query(ctx, q, args...)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	var out []domain.Customer
	for rows.Next() {
		c, err := scanCustomer(rows)
		if err != nil {
			return nil, false, err
		}
		out = append(out, *c)
	}
	hasMore := len(out) > limit
	if hasMore {
		out = out[:limit]
	}
	return out, hasMore, nil
}
```

`itoa` is `strconv.Itoa` — add `"strconv"` to imports and rename in the code (or just use `strconv.Itoa` directly).

### Step 4.5: Implement `Update`, `Delete`, `CountReferencingLicenses`, `UpsertByEmail`

- [ ] Append:

```go
func (r *CustomerRepo) Update(ctx context.Context, c *domain.Customer) error {
	if len(c.Metadata) == 0 {
		c.Metadata = json.RawMessage("{}")
	}
	q := `UPDATE customers SET
		name       = $2,
		metadata   = $3,
		updated_at = now()
	WHERE id = $1
	RETURNING ` + customerColumns
	row := conn(ctx, r.pool).QueryRow(ctx, q, c.ID, c.Name, c.Metadata)
	got, err := scanCustomer(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return core.NewAppError(core.ErrCustomerNotFound, "customer not found")
	}
	if err != nil {
		return err
	}
	*c = *got
	return nil
}

func (r *CustomerRepo) Delete(ctx context.Context, id core.CustomerID) error {
	tag, err := conn(ctx, r.pool).Exec(ctx, `DELETE FROM customers WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return core.NewAppError(core.ErrCustomerNotFound, "customer not found")
	}
	return nil
}

func (r *CustomerRepo) CountReferencingLicenses(ctx context.Context, id core.CustomerID) (int, error) {
	var n int
	err := conn(ctx, r.pool).QueryRow(ctx,
		`SELECT count(*) FROM licenses WHERE customer_id = $1`, id).Scan(&n)
	return n, err
}

func (r *CustomerRepo) UpsertByEmail(
	ctx context.Context,
	accountID core.AccountID,
	email string,
	name *string,
	metadata json.RawMessage,
	createdByAccountID *core.AccountID,
) (*domain.Customer, bool, error) {
	if len(metadata) == 0 {
		metadata = json.RawMessage("{}")
	}
	// Try fetch first — cheaper than INSERT+ON CONFLICT when the customer already exists.
	existing, err := r.GetByEmail(ctx, accountID, email)
	if err != nil {
		return nil, false, err
	}
	if existing != nil {
		return existing, false, nil
	}
	c := &domain.Customer{
		ID:                 core.NewCustomerID(),
		AccountID:          accountID,
		Email:              email,
		Name:               name,
		Metadata:           metadata,
		CreatedByAccountID: createdByAccountID,
		CreatedAt:          timeNow(),
		UpdatedAt:          timeNow(),
	}
	// Use ON CONFLICT to handle race: two concurrent license creates with
	// the same new email. The conflict target is the unique index on
	// (account_id, lower(email)). On conflict, re-fetch and return existing.
	q := `INSERT INTO customers (
		id, account_id, email, name, metadata, created_by_account_id, created_at, updated_at
	) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	ON CONFLICT (account_id, lower(email)) DO NOTHING
	RETURNING ` + customerColumns
	row := conn(ctx, r.pool).QueryRow(ctx, q,
		c.ID, c.AccountID, c.Email, c.Name, c.Metadata,
		c.CreatedByAccountID, c.CreatedAt, c.UpdatedAt,
	)
	inserted, scanErr := scanCustomer(row)
	if errors.Is(scanErr, pgx.ErrNoRows) {
		// Conflict — another concurrent tx inserted first. Re-fetch.
		existing, err := r.GetByEmail(ctx, accountID, email)
		if err != nil {
			return nil, false, err
		}
		if existing == nil {
			return nil, false, errors.New("customer_repo: upsert conflict without matching row")
		}
		return existing, false, nil
	}
	if scanErr != nil {
		return nil, false, scanErr
	}
	return inserted, true, nil
}

// timeNow is a package-level shim so tests can stub it if needed.
// For now it's just time.Now().UTC().
var timeNow = func() time.Time { return time.Now().UTC() }
```

Add `"time"` to the import list if not already there.

### Step 4.6: Build

- [ ] Run:

```bash
go build ./internal/domain/... ./internal/core/... 2>&1
```
Expected: clean.

- [ ] Run:

```bash
go build ./internal/db/... 2>&1
```
Expected: clean (customer_repo.go compiles in isolation). NOTE: `license_repo.go` and `license_repo_test.go` are still red from Task 2's `License` struct reshape — that's expected. This build command only targets files in the package, so if the package is broken overall by license_repo's references to `LicenseeName`/`LicenseeEmail`, this build will fail. If so, skip to the verification gate at the end of Task 6.

### Step 4.7: No commit yet

- [ ] Don't commit. Task 2 + Task 4 ship together in the big Task 6 commit.

---

## Task 5: `internal/customer/` package

**Files:**
- Create: `internal/customer/service.go`
- Create: `internal/customer/service_test.go`
- Create: `internal/customer/email.go`
- Create: `internal/customer/email_test.go`

### Step 5.1: Write the failing email test

- [ ] Create `internal/customer/email_test.go`:

```go
package customer_test

import (
	"testing"

	"github.com/getlicense-io/getlicense-api/internal/customer"
)

func TestNormalizeEmail(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"Alice@Example.COM", "alice@example.com"},
		{"  bob@example.org  ", "bob@example.org"},
		{"carol@example.com", "carol@example.com"},
	}
	for _, c := range cases {
		got, err := customer.NormalizeEmail(c.in)
		if err != nil {
			t.Errorf("NormalizeEmail(%q) error = %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("NormalizeEmail(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNormalizeEmail_Invalid(t *testing.T) {
	cases := []string{
		"",
		"   ",
		"not-an-email",
		"@example.com",
		"foo@",
		"foo bar@example.com",
	}
	for _, in := range cases {
		if _, err := customer.NormalizeEmail(in); err == nil {
			t.Errorf("NormalizeEmail(%q) unexpectedly succeeded", in)
		}
	}
}
```

### Step 5.2: Run the test — expect compile failure

- [ ] Run:

```bash
go test ./internal/customer/... 2>&1 | head
```
Expected: undefined `customer.NormalizeEmail`.

### Step 5.3: Implement `email.go`

- [ ] Create `internal/customer/email.go`:

```go
package customer

import (
	"regexp"
	"strings"

	"github.com/getlicense-io/getlicense-api/internal/core"
)

// Conservative RFC-ish email regex used across the codebase. Matches
// the existing Release 1 pattern in auth/signup validation. It does NOT
// validate full RFC 5321 — it catches common format errors.
var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

// NormalizeEmail returns the trimmed, lowercased form of email. Returns
// ErrCustomerInvalidEmail if the input does not match the email regex.
// Callers must use the returned value for any DB comparison — the unique
// index on customers(account_id, lower(email)) expects lowercased input.
func NormalizeEmail(email string) (string, error) {
	trimmed := strings.TrimSpace(email)
	lowered := strings.ToLower(trimmed)
	if lowered == "" || !emailRegex.MatchString(lowered) {
		return "", core.NewAppError(core.ErrCustomerInvalidEmail, "invalid email format")
	}
	return lowered, nil
}
```

### Step 5.4: Run the email test — expect PASS

- [ ] Run:

```bash
go test ./internal/customer/...
```
Expected: all TestNormalizeEmail* pass.

### Step 5.5: Write `service.go`

- [ ] Create `internal/customer/service.go`:

```go
// Package customer owns the customer registry — end-user records
// referenced by licenses. Customers are account-scoped and have no
// login in v1. The portal is explicit v2 (see FEATURES.md §6).
//
// Service methods are pure business logic — they do NOT open their
// own transactions. Callers (HTTP handlers OR other services like
// licensing.Service.Create) are responsible for tx discipline. This
// mirrors the policy.Service pattern so callers can compose
// customer operations into wider transactions without nested-tx issues.
package customer

import (
	"context"
	"encoding/json"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

type Service struct {
	repo domain.CustomerRepository
}

func NewService(repo domain.CustomerRepository) *Service {
	return &Service{repo: repo}
}

// CreateRequest is the public create shape.
type CreateRequest struct {
	Email    string          `json:"email"`
	Name     *string         `json:"name,omitempty"`
	Metadata json.RawMessage `json:"metadata,omitempty"`
}

// UpdateRequest is the partial update shape. Omitted fields unchanged.
type UpdateRequest struct {
	Name     *string          `json:"name,omitempty"`
	Metadata *json.RawMessage `json:"metadata,omitempty"`
}

// UpsertRequest is used internally by licensing.Service.Create when
// the caller passes inline customer details.
type UpsertRequest struct {
	Email              string
	Name               *string
	Metadata           json.RawMessage
	CreatedByAccountID *core.AccountID
}

// Create inserts a new customer. Email is normalized and validated
// before the insert. Duplicate email within the account is surfaced
// as the DB unique-violation error; the caller (typically a handler)
// should return 409 in that case.
func (s *Service) Create(ctx context.Context, accountID core.AccountID, req CreateRequest) (*domain.Customer, error) {
	email, err := NormalizeEmail(req.Email)
	if err != nil {
		return nil, err
	}
	c := &domain.Customer{
		ID:        core.NewCustomerID(),
		AccountID: accountID,
		Email:     email,
		Name:      req.Name,
		Metadata:  req.Metadata,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := s.repo.Create(ctx, c); err != nil {
		return nil, err
	}
	return c, nil
}

// Get fetches a customer by ID; translates repo nil to ErrCustomerNotFound.
func (s *Service) Get(ctx context.Context, id core.CustomerID) (*domain.Customer, error) {
	c, err := s.repo.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if c == nil {
		return nil, core.NewAppError(core.ErrCustomerNotFound, "customer not found")
	}
	return c, nil
}

// List returns a paginated customer list for the account.
func (s *Service) List(ctx context.Context, accountID core.AccountID, filter domain.CustomerListFilter, cursor core.Cursor, limit int) ([]domain.Customer, bool, error) {
	return s.repo.List(ctx, accountID, filter, cursor, limit)
}

// Update mutates name and/or metadata. Email is immutable post-create.
func (s *Service) Update(ctx context.Context, id core.CustomerID, req UpdateRequest) (*domain.Customer, error) {
	c, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if req.Name != nil {
		c.Name = req.Name
	}
	if req.Metadata != nil {
		c.Metadata = *req.Metadata
	}
	c.UpdatedAt = time.Now().UTC()
	if err := s.repo.Update(ctx, c); err != nil {
		return nil, err
	}
	return c, nil
}

// Delete refuses to remove a customer that has licenses.
func (s *Service) Delete(ctx context.Context, id core.CustomerID) error {
	if _, err := s.Get(ctx, id); err != nil {
		return err
	}
	n, err := s.repo.CountReferencingLicenses(ctx, id)
	if err != nil {
		return err
	}
	if n > 0 {
		return core.NewAppError(core.ErrCustomerInUse, "customer is referenced by licenses")
	}
	return s.repo.Delete(ctx, id)
}

// UpsertForLicense is called by licensing.Service.Create with inline
// customer details. Returns the existing or newly inserted customer.
// Attribution: CreatedByAccountID is set to the grantee account on
// inserts only; first-write-wins on conflicts.
func (s *Service) UpsertForLicense(ctx context.Context, accountID core.AccountID, req UpsertRequest) (*domain.Customer, error) {
	email, err := NormalizeEmail(req.Email)
	if err != nil {
		return nil, err
	}
	c, _, err := s.repo.UpsertByEmail(ctx, accountID, email, req.Name, req.Metadata, req.CreatedByAccountID)
	return c, err
}
```

### Step 5.6: Write the service tests with a fake repo

- [ ] Create `internal/customer/service_test.go`:

```go
package customer_test

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/customer"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

type fakeRepo struct {
	mu       sync.Mutex
	byID     map[core.CustomerID]*domain.Customer
	byEmail  map[string]core.CustomerID // key: accountID|lower(email)
	refCount map[core.CustomerID]int
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{
		byID:     map[core.CustomerID]*domain.Customer{},
		byEmail:  map[string]core.CustomerID{},
		refCount: map[core.CustomerID]int{},
	}
}

func emailKey(a core.AccountID, e string) string { return a.String() + "|" + e }

func (r *fakeRepo) Create(_ context.Context, c *domain.Customer) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	k := emailKey(c.AccountID, c.Email)
	if _, exists := r.byEmail[k]; exists {
		return errors.New("unique violation")
	}
	r.byID[c.ID] = c
	r.byEmail[k] = c.ID
	return nil
}
func (r *fakeRepo) Get(_ context.Context, id core.CustomerID) (*domain.Customer, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.byID[id]
	if !ok {
		return nil, nil
	}
	return c, nil
}
func (r *fakeRepo) GetByEmail(_ context.Context, accountID core.AccountID, email string) (*domain.Customer, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id, ok := r.byEmail[emailKey(accountID, email)]
	if !ok {
		return nil, nil
	}
	return r.byID[id], nil
}
func (r *fakeRepo) List(context.Context, core.AccountID, domain.CustomerListFilter, core.Cursor, int) ([]domain.Customer, bool, error) {
	return nil, false, nil
}
func (r *fakeRepo) Update(_ context.Context, c *domain.Customer) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.byID[c.ID]; !ok {
		return core.NewAppError(core.ErrCustomerNotFound, "not found")
	}
	r.byID[c.ID] = c
	return nil
}
func (r *fakeRepo) Delete(_ context.Context, id core.CustomerID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.byID[id]
	if !ok {
		return core.NewAppError(core.ErrCustomerNotFound, "not found")
	}
	delete(r.byID, id)
	delete(r.byEmail, emailKey(c.AccountID, c.Email))
	return nil
}
func (r *fakeRepo) CountReferencingLicenses(_ context.Context, id core.CustomerID) (int, error) {
	return r.refCount[id], nil
}
func (r *fakeRepo) UpsertByEmail(_ context.Context, accountID core.AccountID, email string, name *string, metadata json.RawMessage, createdByAccountID *core.AccountID) (*domain.Customer, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if id, ok := r.byEmail[emailKey(accountID, email)]; ok {
		return r.byID[id], false, nil
	}
	c := &domain.Customer{
		ID:                 core.NewCustomerID(),
		AccountID:          accountID,
		Email:              email,
		Name:               name,
		Metadata:           metadata,
		CreatedByAccountID: createdByAccountID,
	}
	r.byID[c.ID] = c
	r.byEmail[emailKey(accountID, email)] = c.ID
	return c, true, nil
}

func TestService_Create(t *testing.T) {
	repo := newFakeRepo()
	svc := customer.NewService(repo)
	c, err := svc.Create(context.Background(), core.NewAccountID(), customer.CreateRequest{
		Email: "Alice@Example.COM",
	})
	if err != nil {
		t.Fatal(err)
	}
	if c.Email != "alice@example.com" {
		t.Errorf("email not normalized: got %q", c.Email)
	}
}

func TestService_Create_InvalidEmail(t *testing.T) {
	svc := customer.NewService(newFakeRepo())
	_, err := svc.Create(context.Background(), core.NewAccountID(), customer.CreateRequest{Email: "not-an-email"})
	var appErr *core.AppError
	if !errors.As(err, &appErr) || appErr.Code != core.ErrCustomerInvalidEmail {
		t.Errorf("want customer_invalid_email, got %v", err)
	}
}

func TestService_GetNotFound(t *testing.T) {
	svc := customer.NewService(newFakeRepo())
	_, err := svc.Get(context.Background(), core.NewCustomerID())
	var appErr *core.AppError
	if !errors.As(err, &appErr) || appErr.Code != core.ErrCustomerNotFound {
		t.Errorf("want customer_not_found, got %v", err)
	}
}

func TestService_DeleteInUse(t *testing.T) {
	repo := newFakeRepo()
	svc := customer.NewService(repo)
	c, _ := svc.Create(context.Background(), core.NewAccountID(), customer.CreateRequest{Email: "user@example.com"})
	repo.refCount[c.ID] = 3
	err := svc.Delete(context.Background(), c.ID)
	var appErr *core.AppError
	if !errors.As(err, &appErr) || appErr.Code != core.ErrCustomerInUse {
		t.Errorf("want customer_in_use, got %v", err)
	}
}

func TestService_DeleteSuccess(t *testing.T) {
	repo := newFakeRepo()
	svc := customer.NewService(repo)
	c, _ := svc.Create(context.Background(), core.NewAccountID(), customer.CreateRequest{Email: "user@example.com"})
	if err := svc.Delete(context.Background(), c.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Get(context.Background(), c.ID); err == nil {
		t.Error("customer should be deleted")
	}
}

func TestService_UpsertForLicense_NewThenReuse(t *testing.T) {
	repo := newFakeRepo()
	svc := customer.NewService(repo)
	acc := core.NewAccountID()
	c1, err := svc.UpsertForLicense(context.Background(), acc, customer.UpsertRequest{Email: "bob@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	c2, err := svc.UpsertForLicense(context.Background(), acc, customer.UpsertRequest{Email: "BOB@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if c1.ID != c2.ID {
		t.Errorf("case-insensitive upsert should return same row: %v vs %v", c1.ID, c2.ID)
	}
}

func TestService_UpsertForLicense_DoesNotMutateExistingName(t *testing.T) {
	repo := newFakeRepo()
	svc := customer.NewService(repo)
	acc := core.NewAccountID()
	firstName := "Original"
	_, err := svc.UpsertForLicense(context.Background(), acc, customer.UpsertRequest{Email: "a@b.com", Name: &firstName})
	if err != nil {
		t.Fatal(err)
	}
	secondName := "Updated"
	c2, err := svc.UpsertForLicense(context.Background(), acc, customer.UpsertRequest{Email: "a@b.com", Name: &secondName})
	if err != nil {
		t.Fatal(err)
	}
	if c2.Name == nil || *c2.Name != "Original" {
		t.Errorf("existing customer name should not be overwritten: got %v", c2.Name)
	}
}

func TestService_UpsertForLicense_AttributionOnInsert(t *testing.T) {
	repo := newFakeRepo()
	svc := customer.NewService(repo)
	grantor := core.NewAccountID()
	grantee := core.NewAccountID()
	c, err := svc.UpsertForLicense(context.Background(), grantor, customer.UpsertRequest{
		Email:              "end@user.com",
		CreatedByAccountID: &grantee,
	})
	if err != nil {
		t.Fatal(err)
	}
	if c.CreatedByAccountID == nil || *c.CreatedByAccountID != grantee {
		t.Errorf("attribution not set: got %v, want %v", c.CreatedByAccountID, grantee)
	}
}
```

### Step 5.7: Run tests

- [ ] Run:

```bash
go test ./internal/customer/...
```
Expected: all tests pass.

### Step 5.8: No commit yet

- [ ] Keep going. The package compiles and tests pass in isolation, but the domain/licensing/db tree is still red from Task 2. Commit happens at Task 6 end.

---

## Task 6: Licensing service customer integration (the big commit)

This is Batch 4's counterpart for L4 — the commit that lands Tasks 2, 4, 5, and the licensing rewrite all together.

**Files:**
- Modify: `internal/licensing/service.go`
- Modify: `internal/licensing/service_test.go`
- Modify: `internal/db/license_repo.go`
- Modify: `internal/server/handler/licenses.go`
- Modify: `internal/domain/models_test.go` (if it exists and references LicenseeName/Email)
- Modify: `internal/grant/service.go` (licensee_email_pattern constraint — decide whether to keep or retire)

### Step 6.1: Decide what to do with `GrantConstraints.LicenseeEmailPattern`

- [ ] Grep for all references:

```bash
grep -rn "LicenseeEmailPattern\|licensee_email_pattern" internal/ e2e/ 2>/dev/null
```

The field was added in Release 1. Its enforcement was in `grant.Service.validateCreateLicenseConstraints` (or similar) checking `req.LicenseeEmail` against a regex. After L4, `req.LicenseeEmail` no longer exists — the customer is in a separate field.

**Decision for L4:** rename and rewire. The constraint still makes sense — a grantee should only be allowed to create licenses for customers matching a pattern. The new check runs against `customer.Email` after resolution (explicit `customer_id` → fetch customer → check; inline `customer.email` → normalize → check).

1. Rename `GrantConstraints.LicenseeEmailPattern` → `CustomerEmailPattern` with JSON tag `customer_email_pattern`.
2. Update the enforcement code in `grant.Service` to accept a customer email string and match against the pattern. The resolution of "which email to check" happens in licensing.Service.Create (which already has the customer before committing).

If time-pressed: you can also DELETE the constraint field entirely and have Task 7 reintroduce a `CustomerEmailPattern` if desired. But clean rename is cleaner.

### Step 6.2: Rewrite `licensing.CreateRequest`

- [ ] Open `internal/licensing/service.go`. Locate `CreateRequest` struct. Delete `LicenseeName` and `LicenseeEmail`. Add:

```go
// CustomerID attaches the license to an existing customer. Mutually
// exclusive with Customer — exactly one must be provided.
CustomerID *core.CustomerID `json:"customer_id,omitempty"`

// Customer creates or upserts a customer row in the target account
// keyed on (account_id, lower(email)). Mutually exclusive with CustomerID.
Customer *CustomerInlineRequest `json:"customer,omitempty"`
```

And define `CustomerInlineRequest` in the same file:

```go
// CustomerInlineRequest is the shape used when a license is created
// with an inline customer rather than a pre-existing customer_id.
type CustomerInlineRequest struct {
	Email    string          `json:"email"`
	Name     *string         `json:"name,omitempty"`
	Metadata json.RawMessage `json:"metadata,omitempty"`
}
```

### Step 6.3: Rewrite `licensing.UpdateRequest`

- [ ] Locate `UpdateRequest`. Delete `LicenseeName` and `LicenseeEmail` fields. Add:

```go
// CustomerID reassigns the license to a different customer in the same account.
CustomerID *core.CustomerID `json:"customer_id,omitempty"`
```

(`Overrides` and `ExpiresAt` stay unchanged.)

### Step 6.4: Inject `customer.Service` into `licensing.Service`

- [ ] Locate the `Service` struct in `internal/licensing/service.go`. Add a field:

```go
customers *customer.Service
```

- [ ] Update `NewService` to take the customer service as a new parameter. Add import `"github.com/getlicense-io/getlicense-api/internal/customer"`.

```go
func NewService(
	txManager domain.TxManager,
	licenses domain.LicenseRepository,
	products domain.ProductRepository,
	machines domain.MachineRepository,
	policies domain.PolicyRepository,
	customers *customer.Service,
	masterKey *crypto.MasterKey,
	webhookSvc domain.EventDispatcher,
) *Service {
	return &Service{
		txManager:  txManager,
		licenses:   licenses,
		products:   products,
		machines:   machines,
		policies:   policies,
		customers:  customers,
		masterKey:  masterKey,
		webhookSvc: webhookSvc,
	}
}
```

### Step 6.5: Rewrite `Create` to resolve customer

- [ ] Find the `Create` method. Inside the `WithTargetAccount` callback, after policy resolution and BEFORE building the license, add:

```go
// Resolve customer: exactly one of req.CustomerID or req.Customer.
var customerID core.CustomerID
switch {
case req.CustomerID != nil && req.Customer != nil:
	return core.NewAppError(core.ErrCustomerAmbiguous, "provide exactly one of customer_id or customer")
case req.CustomerID == nil && req.Customer == nil:
	return core.NewAppError(core.ErrCustomerRequired, "customer_id or customer is required")
case req.CustomerID != nil:
	// Existing customer path — verify it exists in the target account (RLS-scoped).
	c, err := s.customers.Get(ctx, *req.CustomerID)
	if err != nil {
		return err
	}
	if c.AccountID != accountID {
		// RLS should have already filtered, but belt-and-braces.
		return core.NewAppError(core.ErrCustomerNotFound, "customer not found")
	}
	customerID = c.ID
case req.Customer != nil:
	// Inline upsert path.
	var createdBy *core.AccountID
	if opts.GrantID != nil && opts.CreatedByAccountID != accountID {
		cb := opts.CreatedByAccountID
		createdBy = &cb
	}
	c, err := s.customers.UpsertForLicense(ctx, accountID, customer.UpsertRequest{
		Email:              req.Customer.Email,
		Name:               req.Customer.Name,
		Metadata:           req.Customer.Metadata,
		CreatedByAccountID: createdBy,
	})
	if err != nil {
		return err
	}
	customerID = c.ID
}
```

- [ ] In the license struct-build section (search for `&domain.License{`), delete the lines:

```go
// DELETE: LicenseeName:  req.LicenseeName,
// DELETE: LicenseeEmail: req.LicenseeEmail,
```

Add:

```go
CustomerID: customerID,
```

### Step 6.6: Rewrite `Update` for reassignment

- [ ] Find the `Update` method. Delete the `LicenseeName` / `LicenseeEmail` branches. Add a customer-reassignment branch:

```go
if req.CustomerID != nil {
	// Verify the new customer belongs to the license's target account.
	c, err := s.customers.Get(ctx, *req.CustomerID)
	if err != nil {
		return err
	}
	if c.AccountID != accountID {
		return core.NewAppError(core.ErrCustomerAccountMismatch, "customer belongs to a different account")
	}
	l.CustomerID = c.ID
}
```

### Step 6.7: Fix `license_repo.go`

- [ ] Open `internal/db/license_repo.go`. Update `licenseColumns`:

```go
const licenseColumns = `id, account_id, product_id, policy_id, overrides, key_prefix, key_hash, token, status, customer_id, expires_at, first_activated_at, environment, created_at, updated_at, grant_id, created_by_account_id, created_by_identity_id`
```

The change: `licensee_name, licensee_email` → `customer_id`. Position between `status` and `expires_at`.

- [ ] Update `licenseColumnsAliased` (line ~433) symmetrically with `l.` prefixes.

- [ ] Update `scanLicense` to read `&l.CustomerID` where it previously read `&l.LicenseeName, &l.LicenseeEmail`.

- [ ] Update `Create` INSERT statement — both the column list and the `VALUES ($1..$N)` placeholder count. The INSERT goes from 20 columns to 19 columns (2 dropped, 1 added). Renumber the placeholders if needed.

- [ ] Update `Update` — the method currently sets `licensee_name = $4, licensee_email = $5`. Change to `customer_id = $4` and drop the second one. Renumber subsequent placeholders.

- [ ] Update `buildLicenseFilterClause` (line ~34) — the search filter currently joins `licensee_name` and `licensee_email` into a `LOWER(...) LIKE LOWER(...)` OR clause. Change it to join `customers.email` and `customers.name` via a subquery OR a JOIN:

```go
// Search now matches key_prefix OR (via LEFT JOIN customers) name/email.
// Simplest form: subquery EXISTS to avoid touching the main query's JOIN shape.
clauses = append(clauses, fmt.Sprintf(
    "(LOWER(key_prefix) LIKE LOWER($%d) OR EXISTS (SELECT 1 FROM customers c WHERE c.id = licenses.customer_id AND (LOWER(COALESCE(c.name, '')) LIKE LOWER($%d) OR LOWER(c.email) LIKE LOWER($%d))))",
    next, next, next))
```

(One bind argument reused across three placeholders — match the existing helper's pattern. If the helper uses distinct placeholders per occurrence, replicate.)

### Step 6.8: Rewrite license service tests

- [ ] Open `internal/licensing/service_test.go`. Delete every test that asserts on `LicenseeName` / `LicenseeEmail` OR update them to go through the customer path.

- [ ] Find the mock license repo used in tests. Update its `licenseColumns`-equivalent to match the new shape. Many mocks just store the whole struct in a map so no SQL reshape is needed.

- [ ] Add a `customerSvc *customer.Service` field to the test harness construction. Use a fake customer repo — copy the Batch 2 `fakeRepo` pattern but for customer.

- [ ] Update search-by-licensee tests (there's an existing test that searches for licenses by `licensee_name` / `licensee_email`) to:
  1. Create a customer first.
  2. Create a license referencing that customer.
  3. Search by a substring of the customer's email / name.
  4. Assert the license is returned.

- [ ] Add new test coverage:

```go
func TestCreate_WithCustomerID(t *testing.T) { /* ... */ }
func TestCreate_WithInlineCustomer(t *testing.T) { /* upsert happy path */ }
func TestCreate_BothCustomerAndCustomerID_Returns422(t *testing.T) { /* ambiguous */ }
func TestCreate_NeitherCustomerNorCustomerID_Returns422(t *testing.T) { /* required */ }
func TestCreate_InlineWithSameEmailReusesCustomer(t *testing.T) { /* two creates, one customer row */ }
func TestCreate_GrantScopedInline_SetsCreatedByAccountID(t *testing.T) { /* attribution */ }
func TestUpdate_ReassignCustomer(t *testing.T) { /* happy path */ }
func TestUpdate_ReassignCustomer_AccountMismatch_Returns422(t *testing.T) { /* customer from another account */ }
```

Use the test harness's existing `seedDefaultPolicy` helper for policy resolution. Each test seeds exactly what it needs.

### Step 6.9: Fix `licenses.go` handler DTO

- [ ] Open `internal/server/handler/licenses.go`. If the handler binds to `licensing.CreateRequest` directly, nothing changes — the new fields come through via the service layer. If there's a separate wire DTO, update it to mirror the new shape.

- [ ] Search for any assertion on `licensee_name` / `licensee_email` in responses — delete or rewrite them to read `customer_id` instead.

### Step 6.10: Fix `internal/grant/service.go`

- [ ] Rename `GrantConstraints.LicenseeEmailPattern` → `CustomerEmailPattern` (JSON tag `customer_email_pattern`). Grep one more time to ensure no other callers.

- [ ] Update the enforcement point. Currently it checks `req.LicenseeEmail` against the pattern. Now it must check whichever email will become the customer's email. Options:

- **Option A (simplest):** move the check to `licensing.Service.Create` after the customer is resolved. Add a new field to `CreateOptions` like `CustomerEmailPattern string` (or carry a whole `*GrantConstraints`). Licensing checks the pattern against the resolved customer's email post-Upsert.

- **Option B:** keep the check in `grant.Service` but change its signature so callers pass in the resolved email string.

Recommendation: **Option A**. The `CreateOptions` struct already has grant-related fields (`GrantID`, `AllowedPolicyIDs`). Add `CustomerEmailPattern string` alongside, and check it in `licensing.Service.Create` after resolving the customer.

### Step 6.11: Unified commit

- [ ] Stage EVERYTHING touched since Task 2:

```bash
git add internal/core/ internal/customer/ internal/db/customer_repo.go \
  internal/db/license_repo.go internal/domain/models.go internal/domain/repositories.go \
  internal/licensing/ internal/server/handler/licenses.go \
  internal/grant/service.go
```

- [ ] Build + vet + test:

```bash
go build ./... && go vet ./... && go test ./... 2>&1 | tail -20
```
Expected: every package builds and tests cleanly.

- [ ] Commit:

```bash
git commit -m "$(cat <<'EOF'
feat(licensing): customer-aware Create/Update; drop licensee_name/email

Introduces domain.Customer + internal/customer package with CRUD and
upsert-by-email. licenses.customer_id replaces licensee_name/licensee_email.
licensing.Service.Create requires exactly one of customer_id or inline
customer {email, name, metadata}; inline path upserts in the same tx.

Grant-scoped license creation writes customer_id into the grantor's
tenant with created_by_account_id = acting account (grantee). First-
write-wins for name/metadata on upsert conflicts.

GrantConstraints.LicenseeEmailPattern renamed to CustomerEmailPattern
and now checks against the resolved customer email after upsert.

Includes domain/repo/migration changes held back from Tasks 2-5 per
the plan's unified-commit strategy.
EOF
)"
```

---

## Task 7: Grant capabilities `CUSTOMER_CREATE` / `CUSTOMER_READ`

**Files:**
- Modify: `internal/domain/models.go`
- Modify: `internal/grant/service.go`
- Modify: `internal/grant/service_test.go`
- Modify: `internal/server/handler/grants.go`

### Step 7.1: Add the new capabilities

- [ ] Open `internal/domain/models.go`. Find the `GrantCapability` enum block. Add:

```go
GrantCapCustomerCreate GrantCapability = "CUSTOMER_CREATE"
GrantCapCustomerRead   GrantCapability = "CUSTOMER_READ"
```

- [ ] Add them to `allGrantCapabilities`:

```go
GrantCapCustomerCreate: {},
GrantCapCustomerRead:   {},
```

### Step 7.2: Enforce `CUSTOMER_CREATE` in grant-scoped license create

- [ ] Open `internal/grant/service.go`. Find the function that validates grant constraints on a license create (likely `CheckLicenseCreateConstraints` or similar from Batch 5).

- [ ] Add a parameter or branch that the caller uses to signal whether an inline customer is being created (vs. attaching to an existing `customer_id`):

```go
// CheckLicenseCreateConstraints gains an `inlineCustomer bool` parameter
// that is true when the license create carries a `customer: {...}` block
// that would INSERT a new customer row. Callers set this to false when
// the request uses `customer_id` alone.
func (s *Service) CheckLicenseCreateConstraints(
	ctx context.Context,
	grant *domain.Grant,
	req *licensing.CreateRequest,
	inlineCustomer bool,
) error {
	// ... existing capability + constraint checks
	if inlineCustomer {
		if !hasCapability(grant.Capabilities, domain.GrantCapCustomerCreate) {
			return core.NewAppError(core.ErrGrantCapabilityMissing, "grant lacks CUSTOMER_CREATE")
		}
	} else {
		// Attaching to an existing customer requires CUSTOMER_READ.
		if !hasCapability(grant.Capabilities, domain.GrantCapCustomerRead) {
			return core.NewAppError(core.ErrGrantCapabilityMissing, "grant lacks CUSTOMER_READ")
		}
	}
	// ... existing AllowedPolicyIDs check, CustomerEmailPattern check, etc.
}
```

Adapt the signature to match Batch 5's actual function. The point is: inline customer path → `CUSTOMER_CREATE`, `customer_id` attach path → `CUSTOMER_READ`.

- [ ] Update the caller site (probably `internal/server/handler/grants.go`'s grant-scoped license create handler) to pass `inlineCustomer = (req.Customer != nil)`.

### Step 7.3: Add a grant-scoped customer list endpoint

- [ ] In `internal/server/handler/grants.go`, add a handler for `GET /v1/grants/:id/customers`:

```go
// ListCustomers returns customers created under this grant's scope.
// The caller must be the grantee (acting account). The response
// filters by: customers.account_id = grantor (enforced by RLS via
// ResolveGrant middleware which sets target_account_id) AND
// customers.created_by_account_id = acting account (applied here).
func (h *GrantHandler) ListCustomers(c fiber.Ctx) error {
	auth, err := authz(c, rbac.CustomerRead)
	if err != nil {
		return err
	}
	if !hasCapability(auth.Grant.Capabilities, domain.GrantCapCustomerRead) {
		return core.NewAppError(core.ErrGrantCapabilityMissing, "grant lacks CUSTOMER_READ")
	}
	cursor, limit, err := cursorParams(c)
	if err != nil {
		return err
	}
	acting := auth.ActingAccountID
	filter := domain.CustomerListFilter{CreatedByAccountID: &acting}
	var page core.Page[domain.Customer]
	err = h.tx.WithTargetAccount(c.Context(), auth.TargetAccountID, auth.Environment, func(ctx context.Context) error {
		items, hasMore, err := h.customerSvc.List(ctx, auth.TargetAccountID, filter, cursor, limit)
		if err != nil {
			return err
		}
		page = pageFromCursor(items, hasMore, func(cu domain.Customer) core.Cursor {
			return core.Cursor{CreatedAt: cu.CreatedAt, ID: cu.ID.String()}
		})
		return nil
	})
	if err != nil {
		return err
	}
	return c.JSON(page)
}
```

Adapt handler struct fields (`h.tx`, `h.customerSvc`) to match the existing `GrantHandler` shape — inject as needed.

### Step 7.4: Add grant unit tests

- [ ] Add to `internal/grant/service_test.go`:

```go
func TestCheckLicenseCreate_InlineCustomer_RequiresCustomerCreate(t *testing.T) {
	grant := &domain.Grant{Capabilities: []domain.GrantCapability{domain.GrantCapLicenseCreate}}
	svc := newTestGrantService(t)
	err := svc.CheckLicenseCreateConstraints(context.Background(), grant, &licensing.CreateRequest{Customer: &licensing.CustomerInlineRequest{Email: "a@b.com"}}, true)
	var appErr *core.AppError
	if !errors.As(err, &appErr) || appErr.Code != core.ErrGrantCapabilityMissing {
		t.Errorf("want grant_capability_missing, got %v", err)
	}
}

func TestCheckLicenseCreate_ExistingCustomer_RequiresCustomerRead(t *testing.T) {
	grant := &domain.Grant{Capabilities: []domain.GrantCapability{domain.GrantCapLicenseCreate}}
	svc := newTestGrantService(t)
	cid := core.NewCustomerID()
	err := svc.CheckLicenseCreateConstraints(context.Background(), grant, &licensing.CreateRequest{CustomerID: &cid}, false)
	var appErr *core.AppError
	if !errors.As(err, &appErr) || appErr.Code != core.ErrGrantCapabilityMissing {
		t.Errorf("want grant_capability_missing, got %v", err)
	}
}

func TestCheckLicenseCreate_WithCustomerCreate_Allows(t *testing.T) {
	grant := &domain.Grant{Capabilities: []domain.GrantCapability{domain.GrantCapLicenseCreate, domain.GrantCapCustomerCreate}}
	svc := newTestGrantService(t)
	err := svc.CheckLicenseCreateConstraints(context.Background(), grant, &licensing.CreateRequest{Customer: &licensing.CustomerInlineRequest{Email: "a@b.com"}}, true)
	if err != nil {
		t.Errorf("should allow, got %v", err)
	}
}
```

### Step 7.5: Build, test, commit

- [ ] Run:

```bash
go build ./... && go test ./internal/grant/...
```
Expected: clean.

- [ ] Commit:

```bash
git add internal/domain/models.go internal/grant/ internal/server/handler/grants.go
git commit -m "feat(grant): CUSTOMER_CREATE/READ capabilities + grant-scoped customer list"
```

---

## Task 8: RBAC constants + preset wiring

**Files:**
- Modify: `internal/rbac/permissions.go`
- Modify: `internal/rbac/presets_test.go`

### Step 8.1: Add permission constants

- [ ] Open `internal/rbac/permissions.go`. Add:

```go
CustomerRead   = "customer:read"
CustomerWrite  = "customer:write"
CustomerDelete = "customer:delete"
```

- [ ] Add to the `All()` function if one exists.

### Step 8.2: Update preset test

- [ ] Open `internal/rbac/presets_test.go`. Find `presetSeedPermissions` (the test's parallel-truth map against the migration seed). Add the three new permissions to:
  - `owner`: all three
  - `admin`: all three
  - `developer`: all three
  - `operator`: `customer:read` only
  - `read_only`: none (or wherever Release 1's fifth preset is)

### Step 8.3: Build, test, commit

- [ ] Run:

```bash
go test ./internal/rbac/...
```
Expected: clean.

- [ ] Commit:

```bash
git add internal/rbac/
git commit -m "feat(rbac): customer permission constants + preset mapping"
```

---

## Task 9: HTTP handler for customers

**Files:**
- Create: `internal/server/handler/customers.go`

### Step 9.1: Write the handler skeleton

- [ ] Create the file:

```go
package handler

import (
	"context"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/customer"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/getlicense-io/getlicense-api/internal/rbac"
	"github.com/gofiber/fiber/v3"
)

// CustomerHandler serves /v1/customers.
// Tx discipline lives here, not in customer.Service — matches PolicyHandler.
type CustomerHandler struct {
	tx  domain.TxManager
	svc *customer.Service
}

func NewCustomerHandler(tx domain.TxManager, svc *customer.Service) *CustomerHandler {
	return &CustomerHandler{tx: tx, svc: svc}
}

// List returns a page of customers. Filters: ?email= (prefix, case-insensitive),
// ?created_by_account_id= (exact match, uuid).
func (h *CustomerHandler) List(c fiber.Ctx) error {
	auth, err := authz(c, rbac.CustomerRead)
	if err != nil {
		return err
	}
	cursor, limit, err := cursorParams(c)
	if err != nil {
		return err
	}
	filter := domain.CustomerListFilter{
		Email: c.Query("email"),
	}
	if s := c.Query("created_by_account_id"); s != "" {
		id, perr := core.ParseAccountID(s)
		if perr != nil {
			return core.NewAppError(core.ErrValidationError, "invalid created_by_account_id")
		}
		filter.CreatedByAccountID = &id
	}
	var page core.Page[domain.Customer]
	err = h.tx.WithTargetAccount(c.Context(), auth.TargetAccountID, auth.Environment, func(ctx context.Context) error {
		items, hasMore, err := h.svc.List(ctx, auth.TargetAccountID, filter, cursor, limit)
		if err != nil {
			return err
		}
		page = pageFromCursor(items, hasMore, func(cu domain.Customer) core.Cursor {
			return core.Cursor{CreatedAt: cu.CreatedAt, ID: cu.ID.String()}
		})
		return nil
	})
	if err != nil {
		return err
	}
	return c.JSON(page)
}

// Create inserts a new customer. Email normalization happens inside the service.
func (h *CustomerHandler) Create(c fiber.Ctx) error {
	auth, err := authz(c, rbac.CustomerWrite)
	if err != nil {
		return err
	}
	var req customer.CreateRequest
	if err := c.Bind().Body(&req); err != nil {
		return err
	}
	var created *domain.Customer
	err = h.tx.WithTargetAccount(c.Context(), auth.TargetAccountID, auth.Environment, func(ctx context.Context) error {
		var err error
		created, err = h.svc.Create(ctx, auth.TargetAccountID, req)
		return err
	})
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(created)
}

// Get fetches a single customer by ID. Returns 404 if not found OR if
// the customer is not visible under the current RLS context (avoids
// leaking existence across accounts).
func (h *CustomerHandler) Get(c fiber.Ctx) error {
	auth, err := authz(c, rbac.CustomerRead)
	if err != nil {
		return err
	}
	id, err := core.ParseCustomerID(c.Params("id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "invalid customer id")
	}
	var got *domain.Customer
	err = h.tx.WithTargetAccount(c.Context(), auth.TargetAccountID, auth.Environment, func(ctx context.Context) error {
		var err error
		got, err = h.svc.Get(ctx, id)
		return err
	})
	if err != nil {
		return err
	}
	return c.JSON(got)
}

// Update applies a partial change (name, metadata).
func (h *CustomerHandler) Update(c fiber.Ctx) error {
	auth, err := authz(c, rbac.CustomerWrite)
	if err != nil {
		return err
	}
	id, err := core.ParseCustomerID(c.Params("id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "invalid customer id")
	}
	var req customer.UpdateRequest
	if err := c.Bind().Body(&req); err != nil {
		return err
	}
	var updated *domain.Customer
	err = h.tx.WithTargetAccount(c.Context(), auth.TargetAccountID, auth.Environment, func(ctx context.Context) error {
		var err error
		updated, err = h.svc.Update(ctx, id, req)
		return err
	})
	if err != nil {
		return err
	}
	return c.JSON(updated)
}

// Delete refuses customers that have licenses referencing them.
func (h *CustomerHandler) Delete(c fiber.Ctx) error {
	auth, err := authz(c, rbac.CustomerDelete)
	if err != nil {
		return err
	}
	id, err := core.ParseCustomerID(c.Params("id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "invalid customer id")
	}
	err = h.tx.WithTargetAccount(c.Context(), auth.TargetAccountID, auth.Environment, func(ctx context.Context) error {
		return h.svc.Delete(ctx, id)
	})
	if err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// ListLicenses returns all licenses owned by this customer.
// Delegates to licensing service.
func (h *CustomerHandler) ListLicenses(c fiber.Ctx) error {
	// This endpoint is /v1/customers/:id/licenses.
	// licensing.Service needs a ListByCustomer method — add it as part of Task 9
	// if it doesn't already exist, or delegate to a filtered List query.
	// For now, placeholder that returns 501 if the licensing service
	// method is missing.
	return core.NewAppError(core.ErrValidationError, "unimplemented — wire to licensing.Service.ListByCustomer")
}
```

Note the `ListLicenses` endpoint is a stub because it requires a new `licensing.Service.ListByCustomer` method. Implement it as a minimal wrapper OR defer — see Step 9.2.

### Step 9.2: Implement `licensing.Service.ListByCustomer`

- [ ] Open `internal/licensing/service.go`. Add:

```go
// ListByCustomer returns all licenses for a given customer, paginated.
func (s *Service) ListByCustomer(
	ctx context.Context,
	accountID core.AccountID,
	env core.Environment,
	customerID core.CustomerID,
	cursor core.Cursor,
	limit int,
) ([]domain.License, bool, error) {
	var out []domain.License
	var hasMore bool
	err := s.txManager.WithTargetAccount(ctx, accountID, env, func(ctx context.Context) error {
		filters := domain.LicenseListFilters{CustomerID: &customerID}
		var err error
		out, hasMore, err = s.licenses.List(ctx, cursor, limit, filters)
		return err
	})
	return out, hasMore, err
}
```

- [ ] Add `CustomerID *core.CustomerID` to `domain.LicenseListFilters` in `internal/domain/models.go` or wherever that struct lives. Update `buildLicenseFilterClause` in `internal/db/license_repo.go` to emit a `customer_id = $N` clause when set.

- [ ] Update `CustomerHandler.ListLicenses` to call `h.licenseSvc.ListByCustomer(...)`. Inject `*licensing.Service` into `CustomerHandler` if not already present.

### Step 9.3: Build

- [ ] Run:

```bash
go build ./...
```
Expected: clean.

### Step 9.4: Commit

- [ ] Commit:

```bash
git add internal/server/handler/customers.go internal/licensing/service.go internal/domain/ internal/db/license_repo.go
git commit -m "feat(http): customer handler + licensing.Service.ListByCustomer"
```

---

## Task 10: Routes + deps wiring

**Files:**
- Modify: `internal/server/deps.go`
- Modify: `internal/server/routes.go`
- Modify: `cmd/server/serve.go`

### Step 10.1: Wire into `cmd/server/serve.go`

- [ ] Open `cmd/server/serve.go`. Find the block where Batch 6 constructed `policyRepo`, `policySvc`, and the handlers. Add:

```go
customerRepo := db.NewCustomerRepo(pool)
customerSvc  := customer.NewService(customerRepo)
```

Place it next to the policy service construction.

- [ ] Update the `licensing.NewService(...)` call to include `customerSvc`:

```go
licenseSvc := licensing.NewService(txManager, licenseRepo, productRepo, machineRepo, policyRepo, customerSvc, cfg.MasterKey, webhookSvc)
```

- [ ] Construct the handler:

```go
customerHandler := handler.NewCustomerHandler(txManager, customerSvc)
```

- [ ] Populate `deps.CustomerService = customerSvc` and `deps.CustomerHandler = customerHandler` (whichever field shape `Deps` uses — see Step 10.2).

### Step 10.2: Update `internal/server/deps.go`

- [ ] Add to the `Deps` struct:

```go
CustomerService *customer.Service
CustomerHandler *handler.CustomerHandler  // if handlers live in Deps; otherwise skip
```

Add `import "github.com/getlicense-io/getlicense-api/internal/customer"`.

### Step 10.3: Register routes in `internal/server/routes.go`

- [ ] Find the existing route-register block. Add customer routes alongside other tenant-scoped routes:

```go
// Customers
customers := v1.Group("/customers", authMw, mgmtLimit)
customers.Get("/",      customerHandler.List)
customers.Post("/",     customerHandler.Create)
customers.Get("/:id",   customerHandler.Get)
customers.Patch("/:id", customerHandler.Update)
customers.Delete("/:id", customerHandler.Delete)
customers.Get("/:id/licenses", customerHandler.ListLicenses)
```

Match the exact group syntax Release 1 uses — check how `policies` was added in Batch 6 for reference.

- [ ] Add the grant-scoped customer list under the existing grant-scoped route group:

```go
grantScoped := v1.Group("/grants/:id", authMw, mgmtLimit, resolveGrantMw)
// ... existing routes
grantScoped.Get("/customers", grantHandler.ListCustomers)
```

### Step 10.4: Build + smoke

- [ ] Run:

```bash
go build ./... && go vet ./...
```
Expected: clean.

- [ ] Run:

```bash
make run
```

In another terminal:

```bash
curl -sw 'HTTP=%{http_code}\n' http://localhost:3000/health
```
Expected: `{"status":"ok"}HTTP=200`.

Kill the server.

### Step 10.5: Commit

- [ ] Commit:

```bash
git add cmd/server/serve.go internal/server/deps.go internal/server/routes.go
git commit -m "feat(server): wire customer service and register customer routes"
```

---

## Task 11: Fix existing tests that build the mock license repo

Release 1's mock license repos in `internal/environment/service_test.go`, `internal/product/service_test.go`, and possibly others have a fake `LicenseRepository` that was already updated in L1 to include `Update`. Now L4's `LicenseListFilters.CustomerID` and `LicenseeName`/`Email` removal means those fakes may need tweaking.

### Step 11.1: Scan for mock license repos

- [ ] Run:

```bash
grep -rln "mockLicenseRepo\|fakeLicenseRepo\|type.*LicenseRepository struct" internal/ 2>/dev/null
```

### Step 11.2: Update each mock

- [ ] For each mock: remove any `LicenseeName` / `LicenseeEmail` references in seed data, add `CustomerID` to any seed-license helpers. If a mock pre-dates the L4 fields, it's probably already correct by virtue of never populating them.

- [ ] Run the full test suite:

```bash
go test ./...
```
Expected: all green.

### Step 11.3: Commit (if changes were made)

- [ ] If any mock needed updating, commit:

```bash
git add internal/
git commit -m "test: update mock license repos for L4 customer_id field"
```

Otherwise skip this task's commit.

---

## Task 12: DB integration tests for `customer_repo`

**Files:**
- Create: `internal/db/customer_repo_test.go`

### Step 12.1: Write the integration test file

- [ ] Use the same `testing.Short()` gating that Batch 7 established for `policy_repo_test.go`. Read it first:

```bash
head -60 internal/db/policy_repo_test.go
```

- [ ] Create `internal/db/customer_repo_test.go` with these tests (tests roughly parallel to Batch 7's policy tests):

1. `TestCustomerRepo_CreateAndGet` — create, get by ID, assert round-trip.
2. `TestCustomerRepo_GetByEmail_CaseInsensitive` — create with `Alice@Example.com`, query with `alice@example.com`, assert match.
3. `TestCustomerRepo_GetByEmail_NotFound` — returns `(nil, nil)`.
4. `TestCustomerRepo_UniqueEmailPerAccount` — insert two with same email → second errors with unique violation (pg SQLSTATE `23505`).
5. `TestCustomerRepo_UpsertByEmail_Idempotent` — upsert same email twice, assert same ID, second call returns `inserted=false`.
6. `TestCustomerRepo_UpsertByEmail_DifferentAccountsDistinct` — two accounts, same email, two distinct rows.
7. `TestCustomerRepo_Update` — update name, verify updated_at bumps and name persists, metadata untouched if not provided.
8. `TestCustomerRepo_Delete_Success` — create, delete, verify not found.
9. `TestCustomerRepo_CountReferencingLicenses` — create customer, insert two licenses referencing it, assert count == 2.
10. `TestCustomerRepo_List_Pagination` — create 7 customers, list with limit=3, verify cursor flow returns all seven across 3 pages.
11. `TestCustomerRepo_List_EmailFilter` — seed multiple emails, filter by prefix, verify only matching rows return.

Each test uses the same rollback-only tx harness as `policy_repo_test.go` — copy the helper or put a shared helper in `testhelpers_test.go`.

### Step 12.2: Run and commit

- [ ] Run:

```bash
make test-all
```
Expected: unit + integration all pass.

- [ ] Commit:

```bash
git add internal/db/customer_repo_test.go
git commit -m "test(db): customer_repo integration tests"
```

---

## Task 13: E2E hurl scenarios

Ten existing scenarios reference `licensee_email` / `licensee_name` in license creation request bodies. They all currently pass (Batch 8 kept them working by leaving those fields alone). Now L4 drops those fields entirely and the scenarios break.

**Files:**
- Modify: `e2e/scenarios/04_licenses.hurl`
- Modify: `e2e/scenarios/05_validate.hurl`
- Modify: `e2e/scenarios/06_machines.hurl`
- Modify: `e2e/scenarios/09_full_journey.hurl`
- Modify: `e2e/scenarios/10_bulk_licenses.hurl`
- Modify: `e2e/scenarios/11_environment_isolation.hurl`
- Modify: `e2e/scenarios/14_jwt_environment_switching.hurl`
- Modify: `e2e/scenarios/15_environments.hurl`
- Modify: `e2e/scenarios/18_grants.hurl`
- Create: `e2e/scenarios/20_customers.hurl`

### Step 13.1: Grep existing licensee references

- [ ] Run:

```bash
grep -rn "licensee_email\|licensee_name" e2e/scenarios/
```

### Step 13.2: Replace each POST body

- [ ] For each scenario: replace every `"licensee_email": "foo@bar.com"` (and optional `"licensee_name"`) with:

```json
"customer": {
  "email": "foo@bar.com",
  "name": "Foo Bar"
}
```

Leave the email value identical so any downstream assertion on the email still works — just under the customer.email JSON path.

- [ ] If any scenario asserted `$.license.licensee_email` or `$.license.licensee_name`, rewrite the assertion to instead:
  - Fetch `$.license.customer_id` (capture it)
  - Follow up with `GET /v1/customers/{{customer_id}}`
  - Assert `$.email` / `$.name` on that response

OR if the assertion was just a round-trip smoke check, drop it — the `20_customers.hurl` scenario covers the explicit case.

### Step 13.3: Write `20_customers.hurl`

- [ ] Create `e2e/scenarios/20_customers.hurl`. Structure (mirror `19_policies.hurl` style):

1. Signup + capture API key.
2. `POST /v1/customers` with `{"email":"alice@example.com","name":"Alice"}` → 201. Capture `customer_id`.
3. `GET /v1/customers/{{customer_id}}` → 200, assert email + name.
4. `GET /v1/customers` → 200, assert `$.data[0].id == {{customer_id}}` and `$.data[0].created_by_account_id == null` (direct create path).
5. `GET /v1/customers?email=alic` → 200, prefix match works.
6. Create a product → capture `product_id`.
7. Create a license using `customer_id` → 201, assert `$.license.customer_id == {{customer_id}}`.
8. Create a second license using inline customer `{"email":"alice@example.com","name":"Different"}` → 201, assert `$.license.customer_id == {{customer_id}}` (same customer reused, first-write-wins on name).
9. `GET /v1/customers/{{customer_id}}/licenses` → 200, assert 2 licenses returned.
10. `DELETE /v1/customers/{{customer_id}}` → 409, error code `customer_in_use`.
11. Revoke one license, then try DELETE again → still 409 (revoked still references it).
12. Actually delete both licenses (admin-hard-delete if the service supports it; otherwise skip to step 13).
13. Create a THIRD customer `{"email":"bob@example.com"}`, then DELETE it → 204.
14. PATCH a license to reassign to a different customer:
    - Create customer `carol@example.com` → capture `carol_id`.
    - `PATCH /v1/licenses/{{first_license_id}}` body `{"customer_id":"{{carol_id}}"}` → 200, assert `$.customer_id == {{carol_id}}`.
15. Attempt to create a customer with a malformed email → 422 `customer_invalid_email`.
16. Attempt to create a license with BOTH customer_id AND inline customer → 422 `customer_ambiguous`.
17. Attempt to create a license with NEITHER → 422 `customer_required`.

### Step 13.4: Write a grant scenario extension

- [ ] Extend `e2e/scenarios/18_grants.hurl` (or add a new 21_grants_customers.hurl):

1. Two signups: `GrantorCo` and `GranteeCo`.
2. Grantor creates a product.
3. Grantor issues a grant to grantee with capabilities `LICENSE_CREATE`, `LICENSE_READ`, `CUSTOMER_CREATE`, `CUSTOMER_READ`.
4. Grantee accepts the grant.
5. Grantee calls `POST /v1/grants/:id/licenses` with inline customer `dave@example.com`. Expect 201.
6. Grantor calls `GET /v1/customers` — sees Dave with `created_by_account_id == grantee_account_id`.
7. Grantee calls `GET /v1/grants/:id/customers` — sees only Dave (no other customers).
8. Grantee calls `GET /v1/customers/{{dave_id}}` directly — expects 404 (no leakage).
9. Grantor revokes `CUSTOMER_CREATE` from the grant; grantee attempts to create another license with a new inline customer — expects 403 `grant_capability_missing`.
10. Grantee creates a license with `customer_id = dave_id` (attach path) — expects 201 (CUSTOMER_READ is sufficient).

### Step 13.5: Run e2e

- [ ] Run:

```bash
make e2e
```
Expected: every scenario passes. If any existing scenario fails, check whether it's the license-type (L1) or licensee (L4) cleanup that's still incomplete.

### Step 13.6: Commit

- [ ] Commit:

```bash
git add e2e/scenarios/
git commit -m "test(e2e): fix L4 hurl scenarios; add 20_customers; extend 18_grants"
```

---

## Task 14: OpenAPI + CLAUDE.md updates

**Files:**
- Modify: `openapi.yaml`
- Modify: `CLAUDE.md`

### Step 14.1: Update `openapi.yaml` schemas

- [ ] Remove `licensee_name` / `licensee_email` from the `License` schema and `CreateLicenseRequest`.

- [ ] Add `customer_id` (required) to the `License` schema.

- [ ] Add these schemas under `components.schemas`:

```yaml
Customer:
  type: object
  required: [id, account_id, email, created_at, updated_at]
  properties:
    id: {type: string, format: uuid}
    account_id: {type: string, format: uuid}
    email: {type: string, format: email}
    name: {type: string, nullable: true}
    metadata: {type: object, nullable: true}
    created_by_account_id:
      type: string
      format: uuid
      nullable: true
      description: Non-null when created via a grant by a grantee account.
    created_at: {type: string, format: date-time}
    updated_at: {type: string, format: date-time}

CustomerInlineRequest:
  type: object
  required: [email]
  properties:
    email: {type: string, format: email}
    name: {type: string}
    metadata: {type: object}

CreateCustomerRequest:
  type: object
  required: [email]
  properties:
    email: {type: string, format: email}
    name: {type: string}
    metadata: {type: object}

UpdateCustomerRequest:
  type: object
  properties:
    name: {type: string}
    metadata: {type: object}
```

- [ ] Update `CreateLicenseRequest`: add `customer_id` (uuid) and `customer` (CustomerInlineRequest) as mutually-exclusive fields. Add a description explaining the exactly-one-of rule.

- [ ] Update `UpdateLicenseRequest`: add `customer_id` for reassignment.

### Step 14.2: Add new paths

- [ ] Add under `paths:`:

```yaml
/v1/customers:
  get: { operationId: listCustomers, ... }
  post: { operationId: createCustomer, ... }

/v1/customers/{id}:
  get: { operationId: getCustomer, ... }
  patch: { operationId: updateCustomer, ... }
  delete: { operationId: deleteCustomer, ... }

/v1/customers/{id}/licenses:
  get: { operationId: listCustomerLicenses, ... }

/v1/grants/{grant_id}/customers:
  get: { operationId: listGrantCustomers, ... }
```

Expand each to match existing OpenAPI style (parameters, responses, error envelopes).

### Step 14.3: Update `CLAUDE.md`

- [ ] Add `internal/customer/` to the package layout tree.

- [ ] Add a new section **Customers (L4)** after the Policies section:

```markdown
## Customers (L4)

Every license references a first-class customer via `customer_id` FK.
Customers are account-scoped (shared across environments) and have no
login in v1 — the customer portal is explicit v2 (FEATURES.md §6).

- **Naming discipline:** the word `user` never appears in code referring
  to customers. `Identity` = logs in, `Customer` = license owner, `Membership`
  = join between identity and account.
- **Creation:** `POST /v1/licenses` accepts exactly one of `customer_id`
  (attach existing) or `customer: {email, name}` (inline upsert). Email is
  normalized and matched case-insensitively via the unique
  `customers(account_id, lower(email))` index.
- **First-write-wins for name/metadata.** License creation never mutates
  an existing customer's name or metadata. Use `PATCH /v1/customers/:id`
  to update those explicitly.
- **Grant-scoped creation** upserts into the grantor's tenant and writes
  `customers.created_by_account_id = acting account (grantee)`. Requires
  `CUSTOMER_CREATE` capability on the grant. Attaching to an existing
  customer via `customer_id` requires `CUSTOMER_READ`.
- **Grant-scoped visibility:** `GET /v1/grants/:id/customers` returns only
  customers where `created_by_account_id = acting account`. A grantee
  hitting `GET /v1/customers/:id` directly for a customer they did not
  create returns 404 (not 403 — no existence leak).
- **Delete** is blocked with 409 `customer_in_use` when the customer
  has licenses; no cascade, no soft-delete. Reassign licenses via
  `PATCH /v1/licenses/:id` body `{customer_id: ...}` first.

See `docs/superpowers/specs/2026-04-15-l4-customers-design.md` for the
full design and `docs/superpowers/plans/2026-04-15-l4-customers.md` for
the implementation plan.
```

- [ ] Update the RBAC section to mention the three new `customer:*` permissions.

### Step 14.4: Commit

- [ ] Commit:

```bash
git add openapi.yaml CLAUDE.md
git commit -m "docs(l4): openapi customer paths + CLAUDE.md customers section"
```

---

## Task 15: Final verification

### Step 15.1: Full format + lint

- [ ] Run:

```bash
gofmt -l . | head && make lint 2>&1 | tail -5
```
Expected: `gofmt -l .` prints nothing. `make lint` reports `0 issues`.

If gofmt drifted, run `gofmt -w .` and commit as a separate style commit.

### Step 15.2: Full test-all

- [ ] Run:

```bash
make test-all
```
Expected: every package (unit + integration) passes.

### Step 15.3: Full e2e

- [ ] Run:

```bash
make e2e
```
Expected: every scenario passes, including new 20_customers and extended 18_grants.

### Step 15.4: Manual curl smoke

- [ ] Start the server (`make run` in one terminal). In another:

```bash
B=http://localhost:3000
TOKEN=$(curl -s -X POST $B/v1/auth/signup -H 'content-type: application/json' \
  -d '{"email":"l4-smoke@example.com","password":"hunter22hunter22","account_name":"l4-smoke"}' \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')

# Create customer
CID=$(curl -s -X POST $B/v1/customers -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{"email":"alice@example.com","name":"Alice"}' | python3 -c 'import sys,json; print(json.load(sys.stdin)["id"])')
echo "customer: $CID"

# Create product + license with inline same email
PID=$(curl -s -X POST $B/v1/products -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' -d '{"name":"Smoke","slug":"smoke"}' \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["id"])')

LICRESP=$(curl -s -X POST $B/v1/products/$PID/licenses -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{"customer":{"email":"alice@example.com","name":"Different"}}')
LIC_CID=$(echo "$LICRESP" | python3 -c 'import sys,json; print(json.load(sys.stdin)["license"]["customer_id"])')
echo "license.customer_id: $LIC_CID"

# Assert license.customer_id == customer id
[ "$LIC_CID" = "$CID" ] && echo "REUSE OK" || echo "FAIL: new customer row created"

# Delete customer — expect 409
curl -sw 'HTTP=%{http_code}\n' -X DELETE $B/v1/customers/$CID -H "authorization: Bearer $TOKEN"
```
Expected: reuse confirmed, delete returns 409 with `customer_in_use`.

### Step 15.5: Review git log

- [ ] Run:

```bash
git log --oneline main..HEAD | head -20
```
Expected: ~10-12 new L4 commits on top of the L1 commits.

### Step 15.6: L4 complete

- [ ] Update task tracker. L4 is done. Next plan: L2 Checkout. The spec is at `docs/superpowers/specs/2026-04-15-l2-checkout-design.md`.

---

## Self-Review Checklist

- [ ] Every section in `2026-04-15-l4-customers-design.md` has a covering task.
- [ ] No TBD / TODO / "add appropriate X" placeholders.
- [ ] Struct field names consistent: `CustomerID`, not `customerId` or `CustomerId`.
- [ ] Error codes underscore: `customer_not_found`, not `customer.not_found`.
- [ ] The word `user` does not appear anywhere outside the naming-discipline note.
- [ ] The word `reseller` does not appear anywhere outside the naming-discipline note.
- [ ] Tx discipline: `customer.Service` has no internal tx management — handlers/other services open txs and call the pure service methods. Mirrors policy.Service.
- [ ] Hard cutover: no backfill logic in the migration; `make db-reset` covered in prerequisites.
- [ ] Big unified commit at Task 6 bundles domain/repo/service/migration references held back from Tasks 2/4/5.
- [ ] Grant capability check discriminates between inline-customer (`CUSTOMER_CREATE`) and attach-by-id (`CUSTOMER_READ`).
- [ ] Grant-scoped customer list filters by BOTH target_account_id (RLS) AND created_by_account_id (handler) — the common data-leak trap is covered.
