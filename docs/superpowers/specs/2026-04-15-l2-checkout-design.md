# L2 — Checkout Design

**Release:** 2 (License Model Reshape), feature 3 of 4
**Branch:** `release-2-license-model`
**Dependencies:** L1 Policies (owns `checkout_interval_sec`, `max_checkout_duration_sec`, `require_checkout`). L4 Customers (license-create path already requires customer_id by the time L2 lands).
**Next:** L3 Entitlements.
**Date:** 2026-04-15

## Goal

Replace heartbeat-based machine liveness with cryptographically signed lease tokens. Every machine activation issues a short-lived lease. Clients must check in before the lease expires or the machine transitions through `stale` → `dead` and stops counting against the license's machine cap. Heartbeat as a distinct mechanism ceases to exist.

The point is a single mental model for liveness: every machine has a lease, vendors who want loose enforcement set a long `checkout_interval_sec`, and the lease token IS the validation token, signed with the same Ed25519 key the SDK already trusts for license token verification.

## Non-Goals

- Component matching (L5, Release 4). The lease token does not include a `components_hash` field in L2; that gets added when L5 lands.
- Entitlement embedding beyond an empty `entitlements: []` array (L3, next in the sequence). L2 reserves the slot so L3 does not reshape the token.
- SDK implementation. L2 produces the server-side lease issuance + verification surface and a test vector for the SDK; the SDK update is a separate effort in `getlicense-go`.
- Backwards compatibility with existing machines in the dev DB. Hard cutover continues — `make db-reset` is already required for this branch by L1.
- Clock-skew handling in the SDK. Server issues leases with standard `iat`/`exp` JWT claims and the SDK's local clock is its own problem.
- Billing / quota / rate limiting on checkin volume. The checkin endpoint is called frequently by design; rate limiting is a Release 4+ concern per FEATURES.md appendix.

## Architecture

```
Activate  ─┐
Checkin   ─┼→ licensing.Service ──→ policy.Resolve(p, overrides) → Effective
Deactivate─┘         │                       │
                     ↓                       ↓
                MachineRepo      crypto.IssueLeaseToken(productKey, claims)
                     ↓                       │
                Postgres                     ↓
                                    returned to client
```

`licensing.Service` grows three methods: `Activate`, `Checkin`, `Deactivate`. All three share a common `issueLease` helper that reads the effective policy, computes `lease_expires_at`, writes the machine row, signs the token, and returns it. `internal/crypto/token.go` gains `IssueLeaseToken` / `VerifyLeaseToken` (JWT-Ed25519, same verification path as license tokens).

A background job `expire_leases` runs next to Release 1's webhook delivery job and sweeps machines through `active → stale → dead`.

## Data Model

### `machines` changes (migration `022_license_checkout.sql`)

```sql
ALTER TABLE machines
    DROP COLUMN last_seen_at,
    ADD COLUMN lease_issued_at   timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN lease_expires_at  timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN last_checkin_at   timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN status            text NOT NULL DEFAULT 'active'
        CHECK (status IN ('active','stale','dead'));

CREATE INDEX machines_lease_expires
    ON machines (lease_expires_at) WHERE status != 'dead';
CREATE INDEX machines_license_status
    ON machines (license_id, status);
```

Hard cutover: the dev DB is wiped by L1; L2 starts from an empty `machines` table. No backfill of old heartbeat data.

### `policies` extension

```sql
ALTER TABLE policies
    ADD COLUMN checkout_grace_sec integer NOT NULL DEFAULT 86400;
```

L1 added `checkout_interval_sec`, `max_checkout_duration_sec`, `require_checkout`. L2 adds the grace window — the time between `lease_expires_at` and the `dead` transition. Default: 1 day (86400 seconds). Setting to 0 means "immediate death on expiry." Vendors who want lenient liveness set a longer interval.

### Go types

```go
// internal/core/machine.go
type MachineStatus string
const (
    MachineStatusActive MachineStatus = "active"
    MachineStatusStale  MachineStatus = "stale"
    MachineStatusDead   MachineStatus = "dead"
)

// internal/domain/models.go — Machine struct gains:
//   LeaseIssuedAt  time.Time
//   LeaseExpiresAt time.Time
//   LastCheckinAt  time.Time
//   Status         core.MachineStatus
// and loses LastSeenAt.
```

`Policy` and the `policy.Effective` struct both gain `CheckoutGraceSec int`.

## Machine Status State Machine

| From    | To      | Trigger                                                                          |
|---------|---------|----------------------------------------------------------------------------------|
| (none)  | active  | `POST /v1/licenses/:id/machines` (activate) with a new fingerprint               |
| dead    | active  | Activate again with the same fingerprint — resurrects the row (same `machine.id`) |
| active  | active  | `POST /v1/licenses/:id/machines/:fingerprint/checkin` renews the lease          |
| active  | stale   | Background job: `lease_expires_at < now AND status='active'`                     |
| stale   | active  | Checkin succeeds within grace window; `last_checkin_at` updates                  |
| stale   | dead    | Background job: `lease_expires_at + policy.checkout_grace_sec < now AND status='stale'` |
| *       | (gone)  | `DELETE /v1/licenses/:id/machines/:fingerprint` — hard delete                    |

**Counting for `max_machines` enforcement:**

```sql
SELECT count(*) FROM machines
WHERE license_id = $1 AND environment = $2 AND status != 'dead';
```

`active` and `stale` count. `dead` does not. This lets a customer's machines lapse without permanently consuming seats.

**Resurrection rule:**

When `POST /v1/licenses/:id/machines` is called with a fingerprint that already has a `dead` row in the DB, the service performs an UPSERT:
- Reuse the existing `machine.id` and audit history.
- Reset `lease_issued_at`, `lease_expires_at`, `last_checkin_at`.
- Transition status back to `active`.
- Hostname / metadata from the new activation request overwrite the old values.

When the fingerprint has an `active` or `stale` row, the service treats it as a checkin (idempotent activate) rather than erroring.

## Lease Token Format

JWT-Ed25519 signed with the product's existing private key. Verification uses the existing `internal/crypto/token.go` path that already handles license tokens.

```json
{
  "iss": "getlicense",
  "sub": "<license_id>",
  "aud": "<product_id>",
  "iat": 1712345678,
  "exp": 1712349278,
  "jti": "<16-byte-random-hex>",

  "license": {
    "id":         "<license_id>",
    "status":     "active",
    "expires_at": 1735689600,
    "policy_id":  "<policy_id>"
  },
  "machine": {
    "id":          "<machine_id>",
    "fingerprint": "<fp>"
  },
  "lease": {
    "issued_at":        1712345678,
    "expires_at":       1712349278,
    "requires_checkin": true,
    "grace_sec":        86400
  },
  "entitlements": []
}
```

### Claim rules

- `exp` always equals `lease.expires_at`. Standard JWT validators reject expired leases automatically.
- `jti` is a 16-byte random hex per issuance. Server does not track issued `jti`s; the field is reserved for SDK-side replay detection if it becomes necessary.
- `license.expires_at` is the Unix timestamp of `licenses.expires_at`, or 0 for perpetual licenses.
- `lease.grace_sec` mirrors the effective `checkout_grace_sec` so offline clients can compute "am I within the grace window" without hitting the server.
- `entitlements` is always present, defaulted to an empty array in L2. L3 populates it without reshaping the token.

### `require_checkout=false` case

When `Effective.RequireCheckout` is false:

- `lease.requires_checkin` set to `false`.
- `lease.expires_at` set to `license.expires_at` if the license is time-bound; otherwise to `9999-01-01T00:00:00Z` (perpetual).
- `lease.grace_sec` set to 0.
- Machines covered by such a policy never transition to `stale` or `dead` — the background job's WHERE clause explicitly filters by `policy.require_checkout = true` when resolving policies via the license join.

The SDK sees `requires_checkin=false` and skips its background check-in loop entirely. Vendors who want soft enforcement set a long `checkout_interval_sec` (e.g. 30 days) with `require_checkout=true` instead.

### Signing

`internal/crypto/token.go` gains:

```go
type LeaseClaims struct {
    // standard JWT
    Iss string `json:"iss"`
    Sub string `json:"sub"`
    Aud string `json:"aud"`
    Iat int64  `json:"iat"`
    Exp int64  `json:"exp"`
    Jti string `json:"jti"`
    // custom
    License      LeaseLicenseClaim      `json:"license"`
    Machine      LeaseMachineClaim      `json:"machine"`
    Lease        LeaseClaim             `json:"lease"`
    Entitlements []string               `json:"entitlements"`
}

func IssueLeaseToken(priv ed25519.PrivateKey, claims LeaseClaims) (string, error)
func VerifyLeaseToken(pub ed25519.PublicKey, token string) (*LeaseClaims, error)
```

The existing Ed25519-JWT helpers are reused. No new key material. The product's private key is decrypted from `products.private_key_enc` once per activate/checkin call inside the service, matching the existing license-token issuance pattern.

## Service Layer

### `licensing.Service.Activate`

```go
func (s *Service) Activate(ctx context.Context, req ActivateRequest) (*ActivateResult, error)

type ActivateRequest struct {
    LicenseID   core.LicenseID
    Fingerprint string
    Hostname    *string
    Metadata    json.RawMessage
}

type ActivateResult struct {
    Machine    *domain.Machine
    LeaseToken string
    LeaseClaims crypto.LeaseClaims
}
```

Flow (inside `WithTargetAccount` tx):

1. Fetch license + policy via repo (single join).
2. Resolve effective values: `eff := policy.Resolve(policy, license.Overrides)`.
3. Evaluate license state: check `license.Status`, check past-expires-at with `eff.ExpirationStrategy` (reuses the same `evaluateLicense` helper that validate calls). Reject on revoked/restricted/suspended.
4. Locate existing machine row by fingerprint (for resurrection/idempotent-activate path). `SELECT FOR UPDATE` to avoid races.
5. Enforce machine cap: `SELECT count(*) FROM machines WHERE license_id = ? AND environment = ? AND status != 'dead'`. If adding this machine would exceed `eff.MaxMachines` (when set), reject with `license.max_machines_exceeded`. Counting excludes the current fingerprint so an idempotent re-activate does not double-count.
6. Stamp `first_activated_at` on the license if unset and `policy.ExpirationBasis == FROM_FIRST_ACTIVATION`. Compute and write `licenses.expires_at = now + policy.duration_seconds` in the same tx.
7. UPSERT machine row: new insert, or resurrection of dead row, or status-reset on active/stale.
8. Compute `lease_expires_at`:
   - `require_checkout=true`: `now + min(checkout_interval_sec, max_checkout_duration_sec)`.
   - `require_checkout=false`: `license.expires_at` (or far-future).
9. Call `crypto.IssueLeaseToken` with the populated claims struct.
10. Dispatch `machine.activated` domain event (existing bus) with payload including `machine.id`, `fingerprint`, `lease.expires_at`.
11. Return machine + lease token + claims.

### `licensing.Service.Checkin`

```go
func (s *Service) Checkin(ctx context.Context, licenseID core.LicenseID, fingerprint string) (*CheckinResult, error)

type CheckinResult struct {
    Machine     *domain.Machine
    LeaseToken  string
    LeaseClaims crypto.LeaseClaims
}
```

Flow:

1. Fetch license + policy + machine (by fingerprint + license_id, `SELECT FOR UPDATE`).
2. If machine is `dead`, reject with `machine.dead` (client should call activate to resurrect). Rationale: checkin is "extend my existing lease," activate is "start or restart." Keeping them distinct keeps the semantics clean.
3. If license is revoked/restricted/expired per `eff.ExpirationStrategy`, reject.
4. Update machine row: `last_checkin_at = now`, status → `active`, new `lease_issued_at`, new `lease_expires_at`.
5. Issue fresh lease token.
6. Dispatch `machine.checkin` domain event.
7. Return.

No machine-cap recheck on checkin — an existing machine is already counted.

### `licensing.Service.Deactivate`

```go
func (s *Service) Deactivate(ctx context.Context, licenseID core.LicenseID, fingerprint string) error
```

Hard-deletes the machine row. Dispatches `machine.deactivated`. Returns 404 if no such fingerprint under the license. No lease returned.

### Validate (unchanged surface)

`POST /v1/validate` continues to accept either `{key: <license_key>}` or `{token: <license_token>}` and return `{valid: bool, code: string, license: {...}}`. No machine context, no lease issuance. The internal `evaluateLicense` function is shared with activate/checkin for consistent expiration-strategy behavior:

| Strategy | Past expires_at | Validate response |
|---|---|---|
| REVOKE_ACCESS | status transitions to `expired` (background job) | `{valid: false, code: "license.expired"}` |
| RESTRICT_ACCESS | status stays `active` | `{valid: false, code: "license.expired"}` |
| MAINTAIN_ACCESS | status stays `active` | `{valid: true, code: "license.valid"}` |

## HTTP Surface

| Verb | Path | Purpose | Auth |
|------|------|---------|------|
| POST | `/v1/licenses/:id/machines` | Activate (or resurrect dead, or idempotent re-activate). Response body includes `machine`, `lease_token`, `lease_claims`. | API key OR license key OR JWT with `license:activate` |
| POST | `/v1/licenses/:id/machines/:fingerprint/checkin` | Renew lease. Response: `machine`, `lease_token`, `lease_claims`. | API key OR license key OR JWT with `license:activate` |
| DELETE | `/v1/licenses/:id/machines/:fingerprint` | Hard-delete machine row. | API key OR license key OR JWT with `license:deactivate` |
| GET | `/v1/licenses/:id/machines` | List machines for a license (cursor paginated, response includes lease fields + status). | `machine:read` |
| GET | `/v1/machines/:id` | Read single machine by ID. | `machine:read` |
| POST | `/v1/validate` | License-only check, unchanged surface. | license key OR API key |

### URL encoding

The `:fingerprint` path parameter is URL-encoded by the client. Server validates with `^[A-Za-z0-9+/=_\-]{1,512}$` and returns 400 `machine.invalid_fingerprint` otherwise. Fingerprints with slashes are not supported via this URL shape — the SDK must hash them first (which it already does, SHA-256 hex is the existing convention).

### Checkin authentication

The checkin endpoint is the hot-path call. It accepts three auth modes:

- **License key** in `Authorization: License <key>` — the common SDK path. No vendor dashboard credential required.
- **Product API key** in `Authorization: Bearer <api_key>` — for backend-to-backend integrations.
- **JWT with `license:activate` permission** — for staff-driven operations via the dashboard.

The license-key auth path validates the key and loads `AuthContext` with the license's target account and environment; it's a pre-existing Release 1 code path used by `/v1/validate`, extended to cover the checkin endpoint.

## Background Job: `expire_leases`

Runs on the same scheduler as webhook delivery (Release 1 job infrastructure in `internal/server/`).

- Interval: every 60 seconds. Cheap — both queries hit the partial index.
- Query 1 (active → stale):
  ```sql
  UPDATE machines m
  SET status = 'stale'
  FROM licenses l JOIN policies p ON p.id = l.policy_id
  WHERE m.license_id = l.id
    AND m.status = 'active'
    AND p.require_checkout = true
    AND m.lease_expires_at < now();
  ```
- Query 2 (stale → dead):
  ```sql
  UPDATE machines m
  SET status = 'dead'
  FROM licenses l JOIN policies p ON p.id = l.policy_id
  WHERE m.license_id = l.id
    AND m.status = 'stale'
    AND p.require_checkout = true
    AND m.lease_expires_at + make_interval(secs => p.checkout_grace_sec) < now();
  ```
- Both queries bypass RLS — the job runs without an account context, matching the existing `expire_licenses` pattern.
- Dispatches `machine.stale` and `machine.dead` domain events for each transitioned row. Event payload carries `machine_id`, `license_id`, `fingerprint`, `lease_expires_at`.

## Error Codes

| Code | HTTP | Meaning |
|---|---|---|
| `license.max_machines_exceeded` | 409 | Machine count at the license's effective cap |
| `license.revoked` | 409 | License in revoked status |
| `license.suspended` | 409 | License in suspended status |
| `license.expired` | 409 | License past expires_at (REVOKE or RESTRICT strategy) |
| `machine.not_found` | 404 | Unknown fingerprint on checkin/deactivate |
| `machine.dead` | 409 | Checkin attempted on dead machine — caller should activate to resurrect |
| `machine.invalid_fingerprint` | 400 | Fingerprint fails format validation |
| `lease.sign_failed` | 500 | Internal error signing the lease token |

## RBAC / Permission constants

No new permissions. Existing `license:activate`, `license:deactivate`, `machine:read` cover the endpoints. The permission constant `rbac.LicenseActivate` already exists in Release 1 for the activation path; checkin reuses it.

## Testing

### Unit (no DB)

- `internal/licensing/lease_test.go` — `computeLeaseExpiresAt(eff, license, now)` pure function, covers `require_checkout=true`/`false`, capped by `max_checkout_duration`, perpetual license.
- `internal/crypto/token_test.go` — `IssueLeaseToken` round-trips through `VerifyLeaseToken`. Tampered signature fails. Expired `exp` fails. Test vector written to `testdata/lease_token_vector.json` for SDK reuse.
- `internal/licensing/service_test.go` — activate/checkin/deactivate against mocked repos, covering resurrection of dead rows, idempotent re-activate, max-machines cap excludes the current fingerprint.

### Integration (real DB)

- Activate creates a row; checkin renews the lease; deactivate hard-deletes.
- Resurrection: force a machine to `dead` status via DB, call activate, assert `machine.id` unchanged and status `active`.
- Max-machines cap enforcement against real `count(... WHERE status != 'dead')`.
- Background job `expire_leases` transitions active → stale → dead in two ticks (by manipulating `lease_expires_at` in the DB).
- `require_checkout=false` policy: activated machine gets `lease.expires_at = license.expires_at`, never transitions to stale.
- L1 expiration strategies: past-expires-at with MAINTAIN_ACCESS still issues leases; REVOKE_ACCESS rejects; RESTRICT_ACCESS rejects.

### E2E (hurl)

Extended `e2e/scenarios/licenses.hurl` (or new `e2e/scenarios/leases.hurl`):

- Activate a machine → response has lease token + `lease.expires_at`.
- Checkin → new lease token with advanced `lease.expires_at`.
- Deactivate → 204, `GET /v1/licenses/:id/machines` no longer returns the fingerprint.
- Activate past `max_machines` cap → 409 `license.max_machines_exceeded`.
- Activate with a policy `require_checkout=false` → response has `lease.requires_checkin=false` and `lease.expires_at == license.expires_at`.
- Validate endpoint still returns `{valid: true}` for a healthy license, `{valid: false, code: "license.expired"}` past expiry under REVOKE_ACCESS.

### Test vector for SDK

`testdata/lease_token_vector.json` contains a signed lease token plus the product public key (hex) and the expected decoded claims. The SDK team in `getlicense-go` uses this to validate their verifier implementation without standing up a server. Committed as part of L2.

## File Layout

New:

- `migrations/022_license_checkout.sql`
- `internal/crypto/lease_token.go` — `IssueLeaseToken`, `VerifyLeaseToken`, `LeaseClaims`
- `internal/crypto/lease_token_test.go`
- `internal/licensing/lease.go` — `computeLeaseExpiresAt`, `buildLeaseClaims`
- `internal/licensing/lease_test.go`
- `internal/server/jobs/expire_leases.go` (or wherever Release 1 put the job scaffolding)
- `testdata/lease_token_vector.json`

Modified:

- `internal/core/machine.go` — `MachineStatus` enum
- `internal/domain/models.go` — `Machine` gains lease fields + status, loses `LastSeenAt`; `Policy` gains `CheckoutGraceSec`
- `internal/domain/repositories.go` — `MachineRepository` gains `UpsertForActivation`, `RenewLease`, `MarkStale`, `MarkDead`, `CountAliveByLicense`
- `internal/db/machine_repo.go` — implementations
- `internal/db/policy_repo.go` — include `checkout_grace_sec`
- `internal/policy/resolve.go` — `Effective.CheckoutGraceSec` plumbing
- `internal/licensing/service.go` — Activate / Checkin / Deactivate rewrites; `evaluateLicense` shared helper
- `internal/licensing/service_test.go`
- `internal/server/handler/license_handler.go` — activate/checkin/deactivate handlers, response shape
- `internal/server/app.go` — register checkin route, wire expire_leases job
- `openapi.yaml` — updated machine shape, new checkin endpoint, lease-token response fields
- `CLAUDE.md` — "Heartbeat" → "Leases" mentions, new checkin endpoint in the data flow example if present

## Risks

- **License-key auth on checkin.** Checkin is the highest-volume endpoint and accepts license-key auth. A leaked license key lets any holder check in, extending leases indefinitely. Mitigation: checkin does not change ownership or config, only advances `lease_expires_at` — a leaked key's worst case is "the legitimate licensee and an attacker share the lease," which is already the worst case of a leaked key in any license system. Document this explicitly in CLAUDE.md and ship.
- **Expire_leases job and replication lag.** The job runs every 60 seconds but could be slow on a large `machines` table. Mitigation: the partial index `machines_lease_expires WHERE status != 'dead'` keeps both queries O(expired rows). Add a per-batch `LIMIT 10000` to cap worst-case runtime.
- **Resurrection race with cap enforcement.** Concurrent activate calls with different fingerprints could both see "at cap, but current fingerprint is the resurrection target, so excluded from count" and both commit. Mitigation: `SELECT FOR UPDATE` on the license row at the start of activate, serializing activations per license. Release 1 already uses this pattern for license suspend/revoke.
- **Clock skew on `require_checkout=false` perpetual leases.** `9999-01-01` as a far-future expiry works on most JWT libraries but some (notably some Go libs) may reject values past `2262` due to `int64` nanosecond overflow in `time.Time`. Mitigation: use `time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC).Unix()` for JWT claims (seconds-since-epoch), which stays inside int64 range. Unit test the edge case.
- **Checkin endpoint path shape.** Putting `:fingerprint` in the URL means fingerprints can't contain slashes. SDK's existing behavior (hash the fingerprint to SHA-256 hex) sidesteps this. Documented constraint.
- **Dropping `machines.last_seen_at`.** Any code or dashboard query still reading this field breaks at compile time (Go) or migration time (SQL). The migration drops it unconditionally to force the compile error. Same trap-detection pattern as L1.

## Out of Scope

- Component matching (`lease.components_hash` — L5, Release 4).
- Entitlement payload beyond empty array (L3, next in sequence).
- Rate limiting / abuse on checkin.
- SDK lease-verifier implementation — shipped via `getlicense-go` separately, using the test vector from this spec.
- Retroactive lease revocation via a blocklist. Leases are short-lived enough that revocation happens naturally when `require_checkout=true`; for the `require_checkout=false` case, a compromised lease lasts until license expiration and is handled by revoking the license.

## Open Questions

None at spec-write time. If the implementation surfaces one, stop and resolve before proceeding.
