# L1 — Policies Design

**Release:** 2 (License Model Reshape), feature 1 of 4
**Branch:** `release-2-license-model`
**Dependencies:** Release 1 (Foundations) fully landed.
**Next:** L4 Customers, then L2 Checkout, then L3 Entitlements (Option B order).
**Date:** 2026-04-15

## Goal

Extract all license lifecycle configuration into a first-class `policies` table. Every license references a policy by FK. Licenses carry a small `overrides` struct for per-license exceptions. Effective values are resolved lazily via a pure function, so policy updates roll out instantly to all referencing licenses (cascade, not copy).

This is the biggest functional gap in the system today: license config is re-entered per license, bulk updates are impossible, and there is no single home for checkout config, component matching, or entitlement inheritance.

## Non-Goals

- Entitlements on policies — separate spec (L3).
- Lease token embedding of `policy_id` — separate spec (L2).
- Component matching logic — the column scaffold exists, the behavior is L5 (Release 4).
- Multi-seat activation — `max_seats` column exists but activation still assumes one seat per license.
- Backwards compatibility with existing dev data — hard cutover, `make db-reset` before first run on this branch.

## Cutover Strategy

Hard cutover. The migration drops columns (`licenses.max_machines`, `licenses.license_type`, `licenses.entitlements`, `products.validation_ttl`, `products.grace_period`, `products.heartbeat_timeout`) without backfill. `make db-reset` is required when switching to this branch for the first time. e2e already drops its own DB so e2e is unaffected. No production data exists today.

## Architecture

New package `internal/policy/` owns policy CRUD and pure-function effective-value resolution. `licensing.Service` reads from `internal/policy/` to resolve effective values on validate/activate/checkin. `product.Service.Create` is extended to auto-create a "Default" policy inside the same transaction so new products are never policy-less.

```
HTTP  → handler/policy_handler.go
          ↓
        policy.Service  (CRUD, set-default, force-delete reassignment)
          ↓                 ↑ (pure) policy.Resolve(p, overrides) → Effective
        PolicyRepository    ↑
          ↓                 ↑
        Postgres  ←  licensing.Service reads policy + overrides,
                      calls Resolve, makes enforcement decisions
                      against the Effective struct only.
```

All validation and activation logic reads `Effective` values, never raw policy or override fields directly. This is the invariant that makes cascade work.

## Data Model

### New table `policies`

```sql
CREATE TABLE policies (
    id                          uuid PRIMARY KEY,
    account_id                  uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    product_id                  uuid NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    name                        text NOT NULL,
    is_default                  boolean NOT NULL DEFAULT false,

    -- Lifecycle
    duration_seconds            integer,                              -- NULL = perpetual
    expiration_strategy         text NOT NULL DEFAULT 'REVOKE_ACCESS'
        CHECK (expiration_strategy IN ('MAINTAIN_ACCESS','RESTRICT_ACCESS','REVOKE_ACCESS')),
    expiration_basis            text NOT NULL DEFAULT 'FROM_CREATION'
        CHECK (expiration_basis IN ('FROM_CREATION','FROM_FIRST_ACTIVATION')),

    -- Machine constraints
    max_machines                integer,                              -- NULL = unlimited
    max_seats                   integer,                              -- NULL = unlimited; scaffold for multi-seat
    floating                    boolean NOT NULL DEFAULT false,
    strict                      boolean NOT NULL DEFAULT false,

    -- Checkout (leases; see L2)
    require_checkout            boolean NOT NULL DEFAULT false,
    checkout_interval_sec       integer NOT NULL DEFAULT 86400,        -- 1 day
    max_checkout_duration_sec   integer NOT NULL DEFAULT 604800,       -- 7 days

    -- Component matching (see L5 in Release 4; ignored until then)
    component_matching_strategy text NOT NULL DEFAULT 'MATCH_ANY'
        CHECK (component_matching_strategy IN ('MATCH_ANY','MATCH_TWO','MATCH_ALL')),

    metadata                    jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at                  timestamptz NOT NULL DEFAULT now(),
    updated_at                  timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX policies_default_per_product
    ON policies (product_id) WHERE is_default = true;

CREATE INDEX policies_account_product_created
    ON policies (account_id, product_id, created_at DESC, id DESC);

ALTER TABLE policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE policies FORCE ROW LEVEL SECURITY;

CREATE POLICY policies_tenant ON policies
USING (
  NULLIF(current_setting('app.current_account_id', true), '') IS NULL
  OR account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid
);
```

Note: policies are **account-scoped, not environment-scoped**. A policy exists for all environments under the account. This matches products (which are also env-agnostic). Environment filtering happens on licenses, not on policies.

### Changed `licenses`

```sql
ALTER TABLE licenses
    ADD COLUMN policy_id uuid REFERENCES policies(id),  -- NOT NULL added after seed
    ADD COLUMN overrides jsonb NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN first_activated_at timestamptz,
    DROP COLUMN max_machines,
    DROP COLUMN license_type,
    DROP COLUMN entitlements;

-- After hard cutover wipe, policy_id is NOT NULL:
ALTER TABLE licenses ALTER COLUMN policy_id SET NOT NULL;

CREATE INDEX licenses_policy ON licenses (policy_id);
```

`expires_at` stays as a first-class column (not in overrides). It is the materialized expiration moment, computed at creation (or first-activation) from `policy.duration_seconds`. Policy duration changes affect NEW licenses only.

### Changed `products`

```sql
ALTER TABLE products
    DROP COLUMN validation_ttl,
    DROP COLUMN grace_period,
    DROP COLUMN heartbeat_timeout;
```

These were the ad-hoc per-product policy surface; they now live on `policies`.

### Go types

```go
// internal/domain/models.go

type Policy struct {
    ID                        core.PolicyID              `json:"id"`
    AccountID                 core.AccountID             `json:"account_id"`
    ProductID                 core.ProductID             `json:"product_id"`
    Name                      string                     `json:"name"`
    IsDefault                 bool                       `json:"is_default"`

    DurationSeconds           *int                       `json:"duration_seconds,omitempty"`
    ExpirationStrategy        core.ExpirationStrategy    `json:"expiration_strategy"`
    ExpirationBasis           core.ExpirationBasis       `json:"expiration_basis"`

    MaxMachines               *int                       `json:"max_machines,omitempty"`
    MaxSeats                  *int                       `json:"max_seats,omitempty"`
    Floating                  bool                       `json:"floating"`
    Strict                    bool                       `json:"strict"`

    RequireCheckout           bool                       `json:"require_checkout"`
    CheckoutIntervalSec       int                        `json:"checkout_interval_sec"`
    MaxCheckoutDuration       int                        `json:"max_checkout_duration_sec"`

    ComponentMatchingStrategy core.ComponentMatchingStrategy `json:"component_matching_strategy"`

    Metadata                  json.RawMessage            `json:"metadata,omitempty"`
    CreatedAt                 time.Time                  `json:"created_at"`
    UpdatedAt                 time.Time                  `json:"updated_at"`
}

type LicenseOverrides struct {
    MaxMachines         *int `json:"max_machines,omitempty"`
    MaxSeats            *int `json:"max_seats,omitempty"`
    CheckoutIntervalSec *int `json:"checkout_interval_sec,omitempty"`
    MaxCheckoutDuration *int `json:"max_checkout_duration_sec,omitempty"`
}

// License struct gains:
//   PolicyID           core.PolicyID         `json:"policy_id"`
//   Overrides          LicenseOverrides      `json:"overrides"`
//   FirstActivatedAt   *time.Time            `json:"first_activated_at,omitempty"`
// and loses MaxMachines, LicenseType, Entitlements.
```

New `core` enums in `internal/core/`:

```go
type ExpirationStrategy string
const (
    ExpirationStrategyMaintainAccess ExpirationStrategy = "MAINTAIN_ACCESS"
    ExpirationStrategyRestrictAccess ExpirationStrategy = "RESTRICT_ACCESS"
    ExpirationStrategyRevokeAccess   ExpirationStrategy = "REVOKE_ACCESS"
)

type ExpirationBasis string
const (
    ExpirationBasisFromCreation        ExpirationBasis = "FROM_CREATION"
    ExpirationBasisFromFirstActivation ExpirationBasis = "FROM_FIRST_ACTIVATION"
)

type ComponentMatchingStrategy string
const (
    ComponentMatchingAny ComponentMatchingStrategy = "MATCH_ANY"
    ComponentMatchingTwo ComponentMatchingStrategy = "MATCH_TWO"
    ComponentMatchingAll ComponentMatchingStrategy = "MATCH_ALL"
)

type PolicyID uuid.UUID  // plus the usual NewPolicyID/String/UnmarshalJSON helpers
```

## Effective-Value Resolution

`internal/policy/resolve.go`:

```go
type Effective struct {
    MaxMachines         *int
    MaxSeats            *int
    Floating            bool
    Strict              bool
    DurationSeconds     *int
    ExpirationStrategy  core.ExpirationStrategy
    ExpirationBasis     core.ExpirationBasis
    RequireCheckout     bool
    CheckoutIntervalSec int
    MaxCheckoutDuration int
}

func Resolve(p *domain.Policy, o domain.LicenseOverrides) Effective {
    eff := Effective{
        MaxMachines:         p.MaxMachines,
        MaxSeats:            p.MaxSeats,
        Floating:            p.Floating,
        Strict:              p.Strict,
        DurationSeconds:     p.DurationSeconds,
        ExpirationStrategy:  p.ExpirationStrategy,
        ExpirationBasis:     p.ExpirationBasis,
        RequireCheckout:     p.RequireCheckout,
        CheckoutIntervalSec: p.CheckoutIntervalSec,
        MaxCheckoutDuration: p.MaxCheckoutDuration,
    }
    if o.MaxMachines != nil         { eff.MaxMachines = o.MaxMachines }
    if o.MaxSeats != nil             { eff.MaxSeats = o.MaxSeats }
    if o.CheckoutIntervalSec != nil  { eff.CheckoutIntervalSec = *o.CheckoutIntervalSec }
    if o.MaxCheckoutDuration != nil  { eff.MaxCheckoutDuration = *o.MaxCheckoutDuration }
    return eff
}
```

Only quantitative fields are overridable. Behavioral flags (`Floating`, `Strict`, `ExpirationStrategy`, `ExpirationBasis`, `RequireCheckout`) are policy-only. Vendors who need different behavior clone the policy.

All enforcement paths (machine count check, lease TTL, expiration check, strict-mode refusal) must read `Effective`, never raw fields. This invariant is enforced by code review and by the fact that `licensing.Service` imports `internal/policy` for the resolver.

## Expiration Semantics

`expires_at` is a first-class `licenses` column, not an override. It is computed once:

- **FROM_CREATION**: `expires_at = created_at + duration_seconds` at license create time. `first_activated_at` is stamped on first activation but does not affect `expires_at`.
- **FROM_FIRST_ACTIVATION**: `expires_at` is NULL until the first machine activation. At that moment, `licensing.Service.Activate` sets `expires_at = now + duration_seconds` AND `first_activated_at = now`, in the same transaction. Subsequent activations do not re-trigger.
- **`duration_seconds IS NULL`** → perpetual regardless of basis; `expires_at` stays NULL.

Policy duration changes affect NEW licenses only. Vendors who want to extend existing licenses PATCH the license's `expires_at` directly. This is a deliberate divergence from the FEATURES.md cascade-everything philosophy: expiration is an instant fact, not a runtime-evaluated limit, and cascading it either breaks indexing or requires bulk SQL sweeps on every policy update.

### Past-expires-at behavior by strategy

All three strategies check `license.expires_at < now()` in the same code path but branch on `Effective.ExpirationStrategy`:

| Strategy           | License status after expires_at | Validate response               | Checkin/Activate | Background job transitions status? |
|--------------------|---------------------------------|---------------------------------|------------------|------------------------------------|
| `REVOKE_ACCESS` (default) | `expired`                 | `valid:false code:license.expired` | rejected      | **yes** |
| `RESTRICT_ACCESS`  | stays `active`                  | `valid:false code:license.expired` | rejected      | no |
| `MAINTAIN_ACCESS`  | stays `active`                  | `valid:true`                      | succeed       | no |

The background job `expire_licenses` scans only licenses whose policy has `expiration_strategy=REVOKE_ACCESS` AND `status=active` AND `expires_at < now()`, and transitions them to `expired`. It runs on the existing job scheduler in `internal/server/` next to the webhook delivery job.

`MAINTAIN_ACCESS` is the "perpetual with support expiry" model — software keeps running forever, dashboards show "support ended on X" as informational.

## Default Policy Mechanics

- On `product.Service.Create`, a "Default" policy is inserted in the same transaction with `is_default=true`, `max_machines=NULL`, `floating=false`, `strict=false`, `require_checkout=false`, `duration_seconds=NULL`, `expiration_strategy=REVOKE_ACCESS`, `expiration_basis=FROM_CREATION`. New products are never policy-less.
- A unique partial index (`WHERE is_default=true`) on `policies(product_id)` enforces at most one default per product.
- `POST /v1/policies/:id/set-default` promotes a non-default policy; inside a single transaction it clears the old default's flag and sets the new one. Refuses if the target policy belongs to a different product.
- `DELETE /v1/policies/:id` refuses the default policy with `code=policy.is_default`. You must promote another policy first.
- `POST /v1/licenses` with `policy_id` omitted uses the product's current default. Explicit `policy_id` takes precedence.

## HTTP Surface

### Policy endpoints

| Verb | Path | Purpose | Permission |
|------|------|---------|------------|
| GET  | `/v1/products/:id/policies` | List (cursor paginated) | `policy:read` |
| POST | `/v1/products/:id/policies` | Create | `policy:write` |
| GET  | `/v1/policies/:id` | Read | `policy:read` |
| PATCH | `/v1/policies/:id` | Partial update | `policy:write` |
| DELETE | `/v1/policies/:id` | Delete; `?force=true` reassigns referencing licenses to the product's default in the same tx | `policy:delete` |
| POST | `/v1/policies/:id/set-default` | Promote to default | `policy:write` |

### License endpoint changes

- `POST /v1/licenses` — `policy_id` optional; falls back to product default. `overrides` optional on create. Response body includes `policy_id`, `overrides`, and a resolved `effective` object (for dashboard convenience).
- `PATCH /v1/licenses/:id` — accepts a new `overrides` field. Merge semantics: absent key → leave alone; explicit `null` value → clear (revert to policy); explicit value → set. `expires_at` remains a first-class editable field.
- `POST /v1/licenses/:id/freeze` — computes `Effective` now, writes overrides so every currently-effective value is an explicit override. After freeze, the license is immune to future policy changes until those overrides are cleared.
- `POST /v1/licenses/:id/attach-policy` — body `{policy_id: uuid, clear_overrides: bool}`. Refuses if the target policy belongs to a different product (`policy.product_mismatch`).

### Grant enforcement

`grant.Service.CreateLicense` (the grant-scoped license creation path) gains a check:

```go
if len(constraints.AllowedPolicyIDs) > 0 {
    if !slices.Contains(constraints.AllowedPolicyIDs, effectivePolicyID.String()) {
        return nil, core.NewAppError("grant.policy_not_allowed", 403, ...)
    }
}
```

where `effectivePolicyID` is the request's `policy_id` or the product's default if unspecified. The `AllowedPolicyIDs` field already exists on `GrantConstraints` (added in Release 1 as scaffolding); this spec activates it.

## RBAC

New permission constants in `internal/rbac/`:

```go
const (
    PolicyRead   = "policy:read"
    PolicyWrite  = "policy:write"
    PolicyDelete = "policy:delete"
)
```

Migration `020_policies.sql` seeds these onto preset roles:
- `owner`, `admin`, `developer`: read + write + delete
- `operator`: read only

## Error Codes

New typed error codes (flat string, `core.AppError`):

- `policy.not_found` (404)
- `policy.invalid_duration` (422) — non-positive duration
- `policy.invalid_strategy` (422) — unknown expiration_strategy value
- `policy.is_default` (409) — cannot delete the default policy
- `policy.in_use` (409) — delete refused because licenses reference the policy; suggest `?force=true`
- `policy.product_mismatch` (422) — attach-policy or set-default for a policy in a different product
- `license.override_invalid` (422) — override field has a non-sensical value (e.g. negative max_machines)
- `grant.policy_not_allowed` (403) — grant constraint violation

## Testing

### Unit (no DB)

- `internal/policy/resolve_test.go` — table-driven `Resolve(policy, overrides) → Effective`. Covers every overridable field, nil cascading, override precedence, behavioral flags NOT cascaded.
- `internal/policy/expiration_test.go` — past-expires-at with each of the three strategies, asserts validate return values and whether checkin/activate succeeds.
- `internal/licensing/service_test.go` — extended with mock policy repo, asserts enforcement uses `Effective` values.

### Integration (real DB)

- Policy CRUD round-trips.
- `is_default` unique-per-product enforced by the partial index.
- Force-delete reassigns referencing licenses to the product's default atomically.
- `POST /v1/licenses` without `policy_id` uses the default; with `policy_id` uses the explicit value.
- `POST /v1/licenses/:id/freeze` snapshots effective values into `overrides`.
- Grant `allowed_policy_ids` enforcement on grant-scoped license creation.
- `set-default` promotion is atomic (old default cleared, new default set, within one tx).

### E2E (hurl)

- New `e2e/scenarios/policies.hurl`:
  - Product create → default policy auto-present.
  - Create a second policy, attach a new license to it.
  - Promote the second to default; old default loses flag.
  - `DELETE` old default fails with `policy.in_use`.
  - `DELETE ?force=true` succeeds, referencing licenses moved to new default.
- Extended `e2e/scenarios/licenses.hurl`:
  - License with `overrides.max_machines=5` caps activations at 5 even though the policy allows 10.
  - License with `overrides.max_machines=null` (clear) reverts to the policy value.

## Migration

`020_policies.sql` (goose, up-only, hard cutover):

1. `CREATE TABLE policies` with columns, constraints, indexes, RLS policies.
2. `ALTER TABLE licenses`: ADD `policy_id`, `overrides`, `first_activated_at`; DROP `max_machines`, `license_type`, `entitlements`.
3. `ALTER TABLE products`: DROP `validation_ttl`, `grace_period`, `heartbeat_timeout`.
4. `ALTER TABLE licenses ALTER COLUMN policy_id SET NOT NULL`.
5. `INSERT INTO role_permissions` for `policy:read`, `policy:write`, `policy:delete` on preset roles.

A single down migration is not provided; Release 2 is forward-only like Release 1.

`make db-reset` before first run on this branch. Documented in the implementation plan.

## File Layout

New files:

- `migrations/020_policies.sql`
- `internal/core/policy.go` — `PolicyID`, enum types
- `internal/domain/models.go` — `Policy`, `LicenseOverrides` structs; `License` changes
- `internal/domain/repositories.go` — `PolicyRepository` interface
- `internal/db/policy_repo.go` — pgx implementation
- `internal/policy/service.go` — CRUD, set-default, force-delete, freeze, attach-policy
- `internal/policy/resolve.go` — pure Resolve function
- `internal/policy/resolve_test.go`
- `internal/policy/expiration_test.go`
- `internal/policy/service_test.go`
- `internal/server/handler/policy_handler.go`
- `e2e/scenarios/policies.hurl`

Modified files (non-exhaustive):

- `internal/product/service.go` — auto-create default policy in `Create` tx
- `internal/licensing/service.go` — Create reads/requires policy, Activate/Checkin/Validate read via `policy.Resolve`, first-activation expiration stamping
- `internal/licensing/keygen.go` — remove references to dropped fields
- `internal/grant/service.go` — activate `AllowedPolicyIDs` constraint check
- `internal/server/app.go` — register policy handler + routes
- `internal/server/jobs.go` (or wherever jobs live) — `expire_licenses` job
- `internal/rbac/permissions.go` — add `Policy*` constants
- `openapi.yaml` — new policy paths and license response shape changes
- `CLAUDE.md` — policy package in the layout section

## Implementation Risks

- **`licensing.Service` refactor surface.** Every raw-field read (`license.MaxMachines`, `product.HeartbeatTimeout`, etc.) must be rewritten to go through `policy.Resolve`. This is mechanical but touches many lines. Mitigation: delete the raw fields in the migration first so the compiler finds every remaining reference.
- **Default policy race on product create.** If the auto-create insert and the product insert are not in the same transaction, a concurrent license create could see the product but not its default. Mitigation: both inserts happen inside `product.Service.Create`'s existing `WithTargetAccount` tx.
- **Force-delete reassignment correctness.** `DELETE ?force=true` must reassign within the same tx as the delete, otherwise a concurrent `licensing.Service.Create` could attach to the deleted policy. Mitigation: `SELECT ... FOR UPDATE` the target policy, update referencing licenses, then delete.
- **Override JSON drift.** `LicenseOverrides` is stored as jsonb. A typo or stale client could write unknown keys that silently never apply. Mitigation: service-layer strict unmarshal via `json.Decoder.DisallowUnknownFields()`, not raw jsonb pass-through.

## Open Questions

None at spec-write time. If the implementation surfaces one, stop and resolve before proceeding.
