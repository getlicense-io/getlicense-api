# L3 — Entitlements Design

**Release:** 2 (License Model Reshape), feature 4 of 4 (last)
**Branch:** `release-2-license-model`
**Dependencies:** L1 Policies (attaches to policies), L2 Checkout (populates the `entitlements: []` slot in the lease token), L4 Customers (no direct dependency; L4 ships before L3 in the Option B order so the license-create surface is already customer-aware).
**Date:** 2026-04-15

## Goal

Introduce a first-class `entitlements` registry with stable `code` values that vendors attach to policies (inherited by every license minted from that policy) and optionally add per-license. The effective entitlement set is the union of policy-attached and license-attached codes. SDKs read `license.HasEntitlement("OFFLINE_SUPPORT")` from the cached lease token — no network call.

This closes the fourth and final L-feature of Release 2 and leaves the license-model reshape complete.

## Non-Goals

- Removing entitlements at the license level. A license can **add** to its policy's set, not remove from it. For "revoke one feature on this license" vendors clone the policy or move the license.
- Per-customer entitlements. Entitlements attach to policies and licenses, never to customers. The v2 portal concept (FEATURES.md §6) may revisit this if demand emerges.
- Time-bounded entitlements (entitlement X expires before the license does). Out of scope. Vendors use license `expires_at` or separate licenses.
- Entitlement quantity / usage counters. A binary "has it or doesn't." Usage metering is a separate feature category.
- Auto-creation of unknown codes at attach time. Attach by code rejects unknown codes with 404 — no silent typo-creates-new-entitlement footgun.
- Renaming a code. Codes are immutable. Delete + recreate if needed.

## Architecture

```
HTTP  → handler/entitlement_handler.go
          ↓
        entitlement.Service   (registry CRUD)
          ↓
        EntitlementRepository (pgx)
          ↓
        Postgres

licensing.Service.Activate / Checkin:
  tx {
    codes := entitlement.Resolve(ctx, policyID, licenseID)  // UNION query
    lease := crypto.IssueLeaseToken(key, claims{..., Entitlements: codes})
  }

licensing.Service.Validate:
  returns { valid, code, license: {...}, entitlements: codes }

grant.Service.CreateLicense / AttachEntitlements:
  if constraints.AllowedEntitlementCodes != nil:
    requested ⊆ allowed, else grant.entitlement_not_allowed
```

New package `internal/entitlement/`. `licensing.Service` gains a small helper `resolveEntitlementCodes` that runs the UNION query during lease issuance and validate. `grant.Service` activates the existing `AllowedEntitlementCodes` scaffolding.

## Data Model

### New table `entitlements` — the registry

```sql
CREATE TABLE entitlements (
    id          uuid PRIMARY KEY,
    account_id  uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    code        text NOT NULL,
    name        text NOT NULL,
    metadata    jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX entitlements_account_code_ci
    ON entitlements (account_id, lower(code));

CREATE INDEX entitlements_account_created
    ON entitlements (account_id, created_at DESC, id DESC);

ALTER TABLE entitlements ENABLE ROW LEVEL SECURITY;
ALTER TABLE entitlements FORCE ROW LEVEL SECURITY;

CREATE POLICY entitlements_tenant ON entitlements
USING (
  NULLIF(current_setting('app.current_account_id', true), '') IS NULL
  OR account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid
);
```

- Account-scoped, **not** environment-scoped — the same code means the same thing in live and test.
- `code` format: `^[A-Z][A-Z0-9_]{0,63}$` enforced at the service layer (regex in Go) because Postgres CHECK constraints with regex are awkward. Uniqueness is on `lower(code)` so callers can't create both `PRO_MODE` and `pro_mode`.
- `metadata` is free-form jsonb. Convention (documented in CLAUDE.md, not enforced): `{"label": "Pro mode", "description": "Unlocks everything"}`. Dashboards render these when present.

### `policy_entitlements` — policy attachments

```sql
CREATE TABLE policy_entitlements (
    policy_id       uuid NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    entitlement_id  uuid NOT NULL REFERENCES entitlements(id) ON DELETE RESTRICT,
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (policy_id, entitlement_id)
);

CREATE INDEX policy_entitlements_entitlement
    ON policy_entitlements (entitlement_id);

ALTER TABLE policy_entitlements ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_entitlements FORCE ROW LEVEL SECURITY;

CREATE POLICY policy_entitlements_tenant ON policy_entitlements
USING (
  NULLIF(current_setting('app.current_account_id', true), '') IS NULL
  OR EXISTS (
    SELECT 1 FROM policies p
    WHERE p.id = policy_entitlements.policy_id
      AND p.account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid
  )
);
```

`ON DELETE RESTRICT` on `entitlement_id` is the "entitlement.in_use" check at the DB level: if any policy still references the entitlement, the registry-level DELETE fails.

### `license_entitlements` — per-license additions

```sql
CREATE TABLE license_entitlements (
    license_id      uuid NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
    entitlement_id  uuid NOT NULL REFERENCES entitlements(id) ON DELETE RESTRICT,
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (license_id, entitlement_id)
);

CREATE INDEX license_entitlements_entitlement
    ON license_entitlements (entitlement_id);

ALTER TABLE license_entitlements ENABLE ROW LEVEL SECURITY;
ALTER TABLE license_entitlements FORCE ROW LEVEL SECURITY;

CREATE POLICY license_entitlements_tenant ON license_entitlements
USING (
  NULLIF(current_setting('app.current_account_id', true), '') IS NULL
  OR EXISTS (
    SELECT 1 FROM licenses l
    WHERE l.id = license_entitlements.license_id
      AND l.account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid
  )
);
```

No `source` column. The table itself tells you where the attachment came from: rows in `policy_entitlements` are policy-sourced, rows in `license_entitlements` are license-sourced. FEATURES.md's reference to a `Source` field was a modeling vestige.

### Go types

```go
// internal/core/entitlement.go
type EntitlementID uuid.UUID  // plus NewEntitlementID, String, Marshal/Unmarshal

// internal/domain/models.go
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

No Go model for the join tables — repositories operate in terms of code slices:

```go
type EntitlementRepository interface {
    // Registry CRUD
    Create(ctx, e *Entitlement) error
    Get(ctx, id core.EntitlementID) (*Entitlement, error)
    GetByCode(ctx, accountID core.AccountID, code string) (*Entitlement, error)
    ListByAccount(ctx, accountID core.AccountID, cursor *core.Cursor, limit int) ([]Entitlement, bool, error)
    Update(ctx, e *Entitlement) error
    Delete(ctx, id core.EntitlementID) error

    // Attachments
    AttachToPolicy(ctx, policyID core.PolicyID, entitlementIDs []core.EntitlementID) error
    DetachFromPolicy(ctx, policyID core.PolicyID, entitlementIDs []core.EntitlementID) error
    ReplacePolicyAttachments(ctx, policyID core.PolicyID, entitlementIDs []core.EntitlementID) error
    ListPolicyCodes(ctx, policyID core.PolicyID) ([]string, error)

    AttachToLicense(ctx, licenseID core.LicenseID, entitlementIDs []core.EntitlementID) error
    DetachFromLicense(ctx, licenseID core.LicenseID, entitlementIDs []core.EntitlementID) error
    ReplaceLicenseAttachments(ctx, licenseID core.LicenseID, entitlementIDs []core.EntitlementID) error
    ListLicenseCodes(ctx, licenseID core.LicenseID) ([]string, error)

    // Used by lease issuance & validate
    ResolveEffective(ctx, licenseID core.LicenseID) ([]string, error)
}
```

`ResolveEffective` runs the one-query UNION described below and returns the sorted, deduped `[]string`.

## Effective Resolution

Effective entitlement set for a license = (codes attached to its policy) ∪ (codes attached to the license).

One query, returns a deterministic ordering so lease tokens byte-compare identically across re-issuances with the same attachments:

```sql
SELECT DISTINCT e.code
FROM entitlements e
WHERE e.id IN (
    SELECT pe.entitlement_id FROM policy_entitlements pe
    JOIN licenses l ON l.policy_id = pe.policy_id
    WHERE l.id = $1
    UNION
    SELECT le.entitlement_id FROM license_entitlements le
    WHERE le.license_id = $1
)
ORDER BY e.code ASC;
```

Called from:

- `licensing.Service.Activate` — to embed in the lease token.
- `licensing.Service.Checkin` — to embed in the refreshed lease token (catches newly-attached entitlements at the next checkin).
- `licensing.Service.Validate` — to return in the validate response.

## Attach and Bulk-Replace Semantics

### Attach-by-code — the only public vocabulary

Public APIs accept codes, not IDs. Internal service calls translate codes → IDs via `GetByCode` in a single `WHERE lower(code) IN (...)` query inside the same transaction as the attach:

1. Validate code format (regex) up front; reject before DB round-trip.
2. `SELECT id, code FROM entitlements WHERE account_id = $1 AND lower(code) = ANY($2)`.
3. If the returned row count < request count, the missing codes are unknown → 422 `entitlement.not_found` with a list of the unknown codes in the error details.
4. Otherwise insert join rows with `ON CONFLICT DO NOTHING` for idempotency.

**Idempotent:** attaching a code that is already attached is a no-op 200.

### Incremental vs replace

Two shapes on each attachment surface:

- `POST /v1/policies/:id/entitlements {codes: [...]}` — add. Idempotent.
- `PUT /v1/policies/:id/entitlements {codes: [...]}` — replace. Deletes any existing attachments not in the list, inserts any missing ones. Done inside one tx.

Same for licenses. The PUT shape is what the vendor dashboard uses ("here's the current checkbox state"); the POST shape is what CLI tools and integrations use ("add OFFLINE_SUPPORT"). Both paths share the code → ID translation.

### Single-code detach

- `DELETE /v1/policies/:id/entitlements/:code` — remove one attachment. Idempotent (204 even if not attached).
- `DELETE /v1/licenses/:id/entitlements/:code` — same for licenses.

## Grant Enforcement

`GrantConstraints.AllowedEntitlementCodes` (existing Release 1 scaffolding) activates in L3.

Enforcement points:

- `POST /v1/grants/:id/licenses` with inline `entitlements: [...]` — each requested code must be a member of `AllowedEntitlementCodes`.
- `POST /v1/grants/:id/licenses/:lid/entitlements` (grant-scoped attach) — same check.
- `PUT /v1/grants/:id/licenses/:lid/entitlements` — same check for the replacement set.

Mismatch → 403 `grant.entitlement_not_allowed` with the offending codes in error details.

**Not enforced at the policy level.** Grants don't let grantees create or modify policies in v1 (no `POLICY_WRITE` capability), so `AllowedEntitlementCodes` only gates the license-level attach paths. If/when policy-writing grants land, the check extends to `POST /v1/policies/:id/entitlements` too.

## HTTP Surface

### Registry

| Verb | Path | Purpose | Permission |
|------|------|---------|------------|
| GET  | `/v1/entitlements` | List (cursor paginated, `?code_prefix=` filter) | `entitlement:read` |
| POST | `/v1/entitlements` | Create | `entitlement:write` |
| GET  | `/v1/entitlements/:id` | Read | `entitlement:read` |
| PATCH | `/v1/entitlements/:id` | Partial update (`name`, `metadata`). `code` immutable. | `entitlement:write` |
| DELETE | `/v1/entitlements/:id` | Block if in use (409 `entitlement.in_use`) | `entitlement:delete` |

### Policy attachments

| Verb | Path | Purpose | Permission |
|------|------|---------|------------|
| GET  | `/v1/policies/:id/entitlements` | List codes attached to the policy | `policy:read` |
| POST | `/v1/policies/:id/entitlements` | Idempotent add of codes | `policy:write` |
| PUT  | `/v1/policies/:id/entitlements` | Replace the whole set | `policy:write` |
| DELETE | `/v1/policies/:id/entitlements/:code` | Detach one | `policy:write` |

### License attachments

| Verb | Path | Purpose | Permission |
|------|------|---------|------------|
| GET  | `/v1/licenses/:id/entitlements` | Three-set response: `policy`, `license`, `effective` | `license:read` |
| POST | `/v1/licenses/:id/entitlements` | Idempotent add of codes | `license:update` |
| PUT  | `/v1/licenses/:id/entitlements` | Replace the license-only set | `license:update` |
| DELETE | `/v1/licenses/:id/entitlements/:code` | Detach one from the license-only set | `license:update` |

The three-set response:

```json
{
  "policy":    ["OFFLINE_SUPPORT"],
  "license":   ["PRIORITY_MAIL"],
  "effective": ["OFFLINE_SUPPORT", "PRIORITY_MAIL"]
}
```

Dashboards render all three without needing multiple calls. `effective` is always the sorted union of the first two.

### License create extension

`POST /v1/licenses` body gains an optional `entitlements: [codes]` field. On create, the service looks up codes → IDs, inserts `license_entitlements` rows inside the same tx as the license insert, and — for the grant-scoped path — enforces `AllowedEntitlementCodes`.

### Validate response extension

`POST /v1/validate` response gains:

```json
{
  "valid": true,
  "code": "license.valid",
  "license": { ... },
  "entitlements": ["OFFLINE_SUPPORT", "PRIORITY_MAIL"]
}
```

Sorted, deduped effective set. Same query as lease issuance.

### Attach permission rules

- Attaching entitlements to a **license** requires `license:update`, not `entitlement:write`. You're mutating the license, not the registry.
- Attaching to a **policy** requires `policy:write`, same reason.
- `entitlement:write` governs **only** registry CRUD (create/update/delete of the entitlement rows).

This keeps permissions semantically clean: `operator` role can manage license-level attachments via `license:update` without being able to invent new entitlements.

## RBAC

New permission constants in `internal/rbac/`:

```go
const (
    EntitlementRead   = "entitlement:read"
    EntitlementWrite  = "entitlement:write"
    EntitlementDelete = "entitlement:delete"
)
```

Preset role seeding (migration `023_entitlements.sql`):

- `owner`, `admin`, `developer`: read + write + delete
- `operator`: read only

## Lease Token Embedding

L2 already shipped `LeaseClaims.Entitlements []string` as an empty array. L3 populates it:

- `licensing.Service.Activate` calls `entitlementRepo.ResolveEffective(ctx, licenseID)` inside the lease-issuance tx.
- Same for `Checkin`. A client that has never re-checked-in sees the old entitlements; the next checkin picks up any new ones. For `require_checkout=false` policies, newly-attached entitlements are visible only after the next checkin (which may be never) — document this in CLAUDE.md under the "Gotchas" section.
- Result is sorted and deduped; lease token byte-representation is deterministic given the same attachments.

## Error Codes

| Code | HTTP | Meaning |
|---|---|---|
| `entitlement.not_found` | 404 / 422 | Unknown code on attach, or direct GET on unknown ID |
| `entitlement.invalid_code` | 422 | Code fails `^[A-Z][A-Z0-9_]{0,63}$` regex |
| `entitlement.duplicate_code` | 409 | Create request with an existing code in the account |
| `entitlement.in_use` | 409 | Delete blocked because a policy or license references it |
| `entitlement.code_immutable` | 422 | PATCH attempted to change `code` |
| `grant.entitlement_not_allowed` | 403 | Grant constraint violation |

## Testing

### Unit (no DB)

- `internal/entitlement/code_test.go` — regex validation cases: happy path, lowercase, leading digit, too long, empty, unicode, whitespace.
- `internal/entitlement/resolve_test.go` — against a mocked repo, verifies sorted-deduped union.
- `internal/licensing/service_test.go` extension — lease-issuance path calls `ResolveEffective` once per issuance and the result flows into `LeaseClaims.Entitlements`.
- `internal/grant/service_test.go` extension — `AllowedEntitlementCodes` check, mismatched codes in error details.

### Integration (real DB)

- Registry CRUD round-trips.
- Unique `(account_id, lower(code))` enforced — both `PRO_MODE` and `pro_mode` collide.
- `entitlements.delete` blocked when referenced from a policy OR from a license.
- Policy and license attach are idempotent on re-POST.
- PUT replace correctly removes codes not in the new list, inserts missing ones, leaves overlapping ones alone.
- Effective resolution: license with policy-only attachments, license-only attachments, both, neither; returns correct sorted union in every case.
- Inline attach on `POST /v1/licenses`: unknown code → 422 `entitlement.not_found`, known codes → rows inserted atomically with the license.
- Grant `AllowedEntitlementCodes` enforcement: grantee create with disallowed code → 403, with allowed codes → success.
- Lease token from activate contains the right entitlements; after `PUT /v1/licenses/:id/entitlements` and a fresh checkin, the new token contains the updated list.

### E2E (hurl)

New `e2e/scenarios/entitlements.hurl`:

- Create two entitlements `OFFLINE_SUPPORT`, `PRIORITY_MAIL`.
- Attach `OFFLINE_SUPPORT` to a policy.
- Create a license under that policy → `GET /v1/licenses/:id/entitlements` shows `policy:[OFFLINE_SUPPORT]`, `license:[]`, `effective:[OFFLINE_SUPPORT]`.
- Attach `PRIORITY_MAIL` to the license → effective becomes `[OFFLINE_SUPPORT, PRIORITY_MAIL]`.
- Activate a machine → lease token claims carry both codes in alphabetical order.
- PUT license entitlements to `[]` → effective reverts to `[OFFLINE_SUPPORT]` (policy still attaches it).
- DELETE `OFFLINE_SUPPORT` → 409 `entitlement.in_use`.
- Detach from policy first, then delete → 204.
- Validate endpoint returns the `entitlements` array matching the effective set.

Extended `e2e/scenarios/grants.hurl`:

- Issue a grant with `AllowedEntitlementCodes: ["PRIORITY_MAIL"]`.
- Grantee creates a license with `entitlements: ["PRIORITY_MAIL"]` → success.
- Grantee tries `entitlements: ["OFFLINE_SUPPORT"]` → 403 `grant.entitlement_not_allowed`.

## Migration

`023_entitlements.sql` (goose, up-only, hard cutover):

1. `CREATE TABLE entitlements` with unique index, RLS.
2. `CREATE TABLE policy_entitlements` with FKs (ON DELETE RESTRICT for entitlement_id, ON DELETE CASCADE for policy_id), PK, RLS.
3. `CREATE TABLE license_entitlements` — same shape as policy_entitlements.
4. Seed `entitlement:read`, `entitlement:write`, `entitlement:delete` into preset roles.

No new grant capabilities — `AllowedEntitlementCodes` is a constraint field that already exists; the spec only activates the enforcement check in `grant.Service`.

No down migration. Same forward-only pattern as L1/L2/L4.

## File Layout

New:

- `migrations/023_entitlements.sql`
- `internal/core/entitlement.go` — `EntitlementID`
- `internal/domain/models.go` — `Entitlement` struct
- `internal/domain/repositories.go` — `EntitlementRepository` interface
- `internal/db/entitlement_repo.go` — pgx implementation
- `internal/entitlement/service.go` — CRUD + attach/detach/replace + code→ID translation
- `internal/entitlement/code.go` — regex + format validation
- `internal/entitlement/service_test.go`
- `internal/entitlement/resolve_test.go`
- `internal/server/handler/entitlement_handler.go`
- `e2e/scenarios/entitlements.hurl`

Modified:

- `internal/licensing/service.go` — `Activate`/`Checkin` call `ResolveEffective`, populate `LeaseClaims.Entitlements`; `Create` handles inline `entitlements: []`; `Validate` response includes `entitlements`
- `internal/grant/service.go` — `AllowedEntitlementCodes` check on grant-scoped create and attach paths
- `internal/rbac/permissions.go`
- `internal/server/app.go` — register entitlement handler + routes (registry, policy-attached, license-attached)
- `openapi.yaml` — all new paths + extended response shapes
- `CLAUDE.md` — entitlement package in the layout section; gotcha about entitlement changes not taking effect on `require_checkout=false` machines until next checkin

## Implementation Risks

- **Lease token size.** Each entitlement code is up to 64 bytes. A policy with 50 entitlements produces a ~3KB `entitlements` claim, plus JWT base64 overhead. Mitigation: no hard limit in v1; document a soft recommendation of ≤50 codes per license. If a vendor hits practical limits, revisit with a shortened-code scheme in v2.
- **`ON DELETE RESTRICT` vs `entitlement.in_use` service-level check.** The DB-level RESTRICT is the safety net; the service-level check returns a clean typed error before the DB complains. Both layers matter — race conditions where the service check passes but a concurrent attach happens before the DELETE are caught by the FK constraint, which the service translates to `entitlement.in_use` via the existing pg-error-to-AppError bridge in Release 1.
- **Stale entitlements in offline lease tokens.** When `require_checkout=false`, a machine may hold a lease for years. Detaching an entitlement on the server is not visible to that machine until license rotation or explicit re-activation. Documented as a known limitation; vendors who need immediate revocation should use `require_checkout=true` with a short `checkout_interval_sec`.
- **Grant constraint on PUT replace.** The PUT path must check every code in the requested set, not only codes being added. Otherwise a grantee could PUT with an allowed subset, then POST-add a disallowed code (caught) — but if PUT is the only check point in a grant flow, missing the constraint check means a gap. Both POST and PUT call the same `validateAllowedEntitlements` helper in `grant.Service`.
- **Race between entitlement delete and license create with inline attach.** A concurrent `DELETE /v1/entitlements/:id` and `POST /v1/licenses { entitlements: [that-code] }` could both see a live entitlement at check time but race each other on commit. The FK constraint catches it: whichever commits second fails. The service translates the FK error to `entitlement.not_found` (the delete committed first) or `entitlement.in_use` (the create committed first) depending on which side lost.

## Out of Scope

- Per-customer entitlements.
- Time-bounded entitlements (`expires_at` per attachment).
- Usage-counter entitlements ("quota of 100 uses per month").
- Entitlement hierarchy / implication (`PRO_MODE` implies `OFFLINE_SUPPORT`).
- Code aliases (rename support without breaking existing tokens).
- Automatic propagation of policy-entitlement changes to existing `require_checkout=false` machines.

## Open Questions

None at spec-write time. If the implementation surfaces one, stop and resolve before proceeding.
