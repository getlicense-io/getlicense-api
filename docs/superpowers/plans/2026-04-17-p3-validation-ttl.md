# P3 — Validation TTL for Offline-First SDK Cache

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a signed, policy-level (+ license-override) **validation staleness tolerance** (`validation_ttl_sec`) so runtime SDKs can trust a cached `gl1` license token for N seconds before re-checking the server. Without it, every `Validate()` hits the server — defeating the offline-first design.

**Architecture:** Three-layer cascade (same shape as `max_machines`): `license.overrides.validation_ttl_sec ?? policy.validation_ttl_sec ?? GETLICENSE_DEFAULT_VALIDATION_TTL_SEC` (default 3600). The resolved TTL is embedded as the `ttl` claim in every minted `gl1` token so the SDK can trust it. The `gl1` token is **re-minted on every `/v1/validate` call** so policy updates cascade to existing licenses without re-issuing the stored license key. The stored `licenses.token` column is never updated by this feature — only Validate returns a fresh token.

**Tech Stack:** Go 1.22+, Postgres, goose migrations, Ed25519, pgx v5, Fiber v3, hurl e2e.

**Spec source:** SDK developer feedback (P3 pause note) — see original issue title `spec: add policy.validation_ttl_sec + license.overrides.validation_ttl_sec + token ttl claim for offline-first SDK cache`.

**Design notes (from advisor):**
1. **Re-mint-on-validate is a scope extension** beyond the SDK dev's literal spec. It is the only design that satisfies both the "server authoritative, signed TTL" intent and the CLAUDE.md cascade invariant. If we freeze TTL at license creation, an in-flight policy update never reaches existing licenses (bad), or requires an unsigned mirror (defeats signing). Ed25519 sign is microseconds — cost is negligible.
2. **Keep `policy.Resolve` two-arg.** Add `ValidationTTLSec *int` to `Effective` (nil when neither policy nor override set it). `licensing.Service` holds `defaultValidationTTLSec int` and applies the default right before signing. This avoids touching 5 call sites + 6 tests.
3. **The stored `licenses.token` is never updated** by this feature. `GET /v1/licenses/:id`, list endpoints, and the create response all continue to return the original token (with TTL-at-creation). Only `POST /v1/validate` returns a re-minted token with current effective TTL. Document this asymmetry explicitly in `CLAUDE.md`.
4. **`gl2` lease tokens are unaffected.** This feature is `gl1`-only; lease tokens have their own expiry semantics via policy `max_checkout_duration_sec` / `checkout_grace_sec`.
5. **Backwards compat:** `TokenPayload.TTL` uses `json:"ttl"` (no `omitempty`) so new servers always emit it. Old tokens (no `ttl` field) unmarshal to `TTL=0`, which new SDKs can treat as "server didn't signal TTL, fall back to per-call validation" — matches current behavior.
6. **Bounds:** 60 ≤ TTL ≤ 2592000 (30 days). Enforce at:
   - Policy CRUD (POST/PATCH `/v1/policies`)
   - License create (POST `/v1/licenses`, inline `overrides.validation_ttl_sec`)
   - License update (PATCH `/v1/licenses/:id`, body `overrides.validation_ttl_sec`)
   - Config load (`GETLICENSE_DEFAULT_VALIDATION_TTL_SEC`)
   - Postgres CHECK constraint (defense-in-depth)

---

## File Structure

**Create:**
- `migrations/027_validation_ttl.sql` — add nullable column + CHECK constraint to `policies`.
- `e2e/scenarios/22_validation_ttl.hurl` — e2e TTL cascade scenario.

**Modify:**
- `internal/core/errors.go` — add `ErrPolicyInvalidTTL`.
- `internal/domain/models.go` — add `ValidationTTLSec` to `Policy` and `LicenseOverrides`.
- `internal/db/policy_repo.go` — include column in scan/insert/update.
- `internal/policy/resolve.go` — merge override → policy → nil into `Effective.ValidationTTLSec`.
- `internal/policy/resolve_test.go` — add resolution tests.
- `internal/policy/service.go` — validate bounds in Create/Update.
- `internal/policy/service_test.go` — add bounds tests.
- `internal/crypto/token.go` — add `TTL int` to `TokenPayload`.
- `internal/crypto/token_test.go` — add TTL roundtrip + backwards-compat test.
- `internal/licensing/service.go` — add `defaultValidationTTLSec` field, override validation, re-mint in Validate, `ValidationTTLSec` on `ValidateResult`.
- `internal/licensing/service_test.go` — constructor signature, new tests.
- `internal/server/config.go` — parse `GETLICENSE_DEFAULT_VALIDATION_TTL_SEC`.
- `cmd/server/serve.go` — pass config value to `licensing.NewService`.
- `openapi.yaml` — extend `Policy`, `LicenseOverrides`, `ValidateResult`; add `LicenseTokenClaims`.
- `CLAUDE.md` — document the cascade + re-mint asymmetry (under "Policies & Effective Values (L1)" section, new subsection "Validation TTL (P3)").

---

## Task 1: Add migration for `policies.validation_ttl_sec`

**Files:**
- Create: `migrations/027_validation_ttl.sql`

- [ ] **Step 1: Write the migration**

Create `migrations/027_validation_ttl.sql`:

```sql
-- +goose Up

-- P3: validation staleness tolerance. Signed policy-level knob that tells
-- runtime SDKs how long they can trust a cached gl1 token before
-- re-checking the server. Null means "inherit server default" (env var
-- GETLICENSE_DEFAULT_VALIDATION_TTL_SEC, default 3600). Bounds enforced
-- at the DB for defense-in-depth; the service layer validates the same
-- range and returns a typed policy_invalid_ttl error for API callers.
ALTER TABLE policies
    ADD COLUMN validation_ttl_sec INTEGER,
    ADD CONSTRAINT policies_validation_ttl_sec_range
        CHECK (validation_ttl_sec IS NULL
               OR (validation_ttl_sec >= 60 AND validation_ttl_sec <= 2592000));

-- +goose Down
ALTER TABLE policies
    DROP CONSTRAINT IF EXISTS policies_validation_ttl_sec_range,
    DROP COLUMN IF EXISTS validation_ttl_sec;
```

- [ ] **Step 2: Apply migration and verify**

Run: `make run` (in a second shell; watch for migration log lines). Expect no errors. Alternatively: `psql $DATABASE_URL -c "\d policies"` and confirm `validation_ttl_sec` column exists with the check constraint.

- [ ] **Step 3: Commit**

```bash
git add migrations/027_validation_ttl.sql
git commit -m "feat(p3): migration 027 — policies.validation_ttl_sec column"
```

---

## Task 2: Add `ErrPolicyInvalidTTL` error code

**Files:**
- Modify: `internal/core/errors.go`

- [ ] **Step 1: Add the error code**

Insert into the `const` block alongside the other `ErrPolicy*` codes (keep alphabetical order):

```go
ErrPolicyInvalidTTL        ErrorCode = "policy_invalid_ttl"
```

And into the status-code map alongside the other `ErrPolicy*` entries:

```go
ErrPolicyInvalidTTL:       422,
```

- [ ] **Step 2: Build and confirm**

Run: `go build ./...`
Expected: PASS (no compilation errors).

- [ ] **Step 3: Commit**

```bash
git add internal/core/errors.go
git commit -m "feat(p3): add ErrPolicyInvalidTTL error code"
```

---

## Task 3: Add `ValidationTTLSec` to domain `Policy` and `LicenseOverrides`

**Files:**
- Modify: `internal/domain/models.go`

- [ ] **Step 1: Extend Policy struct**

In `internal/domain/models.go`, inside the `Policy` struct, add the new field in the "Lifecycle" group (next to `DurationSeconds`):

```go
	// Runtime SDK staleness tolerance. Null = inherit server default.
	ValidationTTLSec *int `json:"validation_ttl_sec,omitempty"`
```

- [ ] **Step 2: Extend LicenseOverrides struct**

In the same file, inside `LicenseOverrides`, add:

```go
	ValidationTTLSec       *int `json:"validation_ttl_sec,omitempty"`
```

- [ ] **Step 3: Build**

Run: `go build ./...`
Expected: PASS (domain changes are additive; callers don't reference the new field yet).

- [ ] **Step 4: Commit**

```bash
git add internal/domain/models.go
git commit -m "feat(p3): add ValidationTTLSec to Policy and LicenseOverrides"
```

---

## Task 4: Wire `validation_ttl_sec` through `PolicyRepo`

**Files:**
- Modify: `internal/db/policy_repo.go`

- [ ] **Step 1: Extend `policyColumns`**

Append `, validation_ttl_sec` at the end of the `policyColumns` constant so it reads:

```go
const policyColumns = `
	id, account_id, product_id, name, is_default,
	duration_seconds, expiration_strategy, expiration_basis,
	max_machines, max_seats, floating, strict,
	require_checkout, checkout_interval_sec, max_checkout_duration_sec, checkout_grace_sec,
	component_matching_strategy, metadata, created_at, updated_at,
	validation_ttl_sec
`
```

- [ ] **Step 2: Extend `scanPolicy`**

Append `&p.ValidationTTLSec` to the `s.Scan(...)` argument list so it matches the new column order:

```go
err := s.Scan(
	&p.ID, &p.AccountID, &p.ProductID, &p.Name, &p.IsDefault,
	&p.DurationSeconds, &p.ExpirationStrategy, &p.ExpirationBasis,
	&p.MaxMachines, &p.MaxSeats, &p.Floating, &p.Strict,
	&p.RequireCheckout, &p.CheckoutIntervalSec, &p.MaxCheckoutDurationSec, &p.CheckoutGraceSec,
	&p.ComponentMatchingStrategy, &p.Metadata, &p.CreatedAt, &p.UpdatedAt,
	&p.ValidationTTLSec,
)
```

- [ ] **Step 3: Extend `Create` INSERT**

Rewrite the `Create` method's SQL + Exec to include `validation_ttl_sec` as the 21st column/param:

```go
func (r *PolicyRepo) Create(ctx context.Context, p *domain.Policy) error {
	q := `INSERT INTO policies (
		id, account_id, product_id, name, is_default,
		duration_seconds, expiration_strategy, expiration_basis,
		max_machines, max_seats, floating, strict,
		require_checkout, checkout_interval_sec, max_checkout_duration_sec, checkout_grace_sec,
		component_matching_strategy, metadata, created_at, updated_at,
		validation_ttl_sec
	) VALUES (
		$1, $2, $3, $4, $5,
		$6, $7, $8,
		$9, $10, $11, $12,
		$13, $14, $15, $16,
		$17, $18, $19, $20,
		$21
	)`
	if len(p.Metadata) == 0 {
		p.Metadata = []byte("{}")
	}
	_, err := conn(ctx, r.pool).Exec(ctx, q,
		p.ID, p.AccountID, p.ProductID, p.Name, p.IsDefault,
		p.DurationSeconds, p.ExpirationStrategy, p.ExpirationBasis,
		p.MaxMachines, p.MaxSeats, p.Floating, p.Strict,
		p.RequireCheckout, p.CheckoutIntervalSec, p.MaxCheckoutDurationSec, p.CheckoutGraceSec,
		p.ComponentMatchingStrategy, p.Metadata, p.CreatedAt, p.UpdatedAt,
		p.ValidationTTLSec,
	)
	return err
}
```

- [ ] **Step 4: Extend `Update` UPDATE**

In `PolicyRepo.Update`, add `validation_ttl_sec = $16` to the SET list, include `p.ValidationTTLSec` in the `QueryRow` args, and keep `RETURNING policyColumns` (scanPolicy already scans the new column). Full method:

```go
func (r *PolicyRepo) Update(ctx context.Context, p *domain.Policy) error {
	q := `UPDATE policies SET
		name = $2,
		duration_seconds = $3,
		expiration_strategy = $4,
		expiration_basis = $5,
		max_machines = $6,
		max_seats = $7,
		floating = $8,
		strict = $9,
		require_checkout = $10,
		checkout_interval_sec = $11,
		max_checkout_duration_sec = $12,
		checkout_grace_sec = $13,
		component_matching_strategy = $14,
		metadata = $15,
		validation_ttl_sec = $16,
		updated_at = NOW()
	WHERE id = $1
	RETURNING ` + policyColumns
	if len(p.Metadata) == 0 {
		p.Metadata = []byte("{}")
	}
	row := conn(ctx, r.pool).QueryRow(ctx, q,
		p.ID, p.Name, p.DurationSeconds, p.ExpirationStrategy, p.ExpirationBasis,
		p.MaxMachines, p.MaxSeats, p.Floating, p.Strict,
		p.RequireCheckout, p.CheckoutIntervalSec, p.MaxCheckoutDurationSec, p.CheckoutGraceSec,
		p.ComponentMatchingStrategy, p.Metadata, p.ValidationTTLSec,
	)
	result, err := scanPolicy(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return core.NewAppError(core.ErrPolicyNotFound, "policy not found")
		}
		return err
	}
	*p = *result
	return nil
}
```

- [ ] **Step 5: Run policy-repo tests**

Run: `make test-all` (or at minimum `go test ./internal/db/... -run TestPolicyRepo`).
Expected: PASS. Existing tests insert policies with `ValidationTTLSec == nil`, which round-trips correctly since the column is nullable.

- [ ] **Step 6: Commit**

```bash
git add internal/db/policy_repo.go
git commit -m "feat(p3): wire validation_ttl_sec through PolicyRepo"
```

---

## Task 5: Resolve effective `ValidationTTLSec` in `policy.Resolve`

**Files:**
- Modify: `internal/policy/resolve.go`
- Modify: `internal/policy/resolve_test.go`

- [ ] **Step 1: Add tests for resolution**

Append to `internal/policy/resolve_test.go`:

```go
func TestResolve_ValidationTTL_InheritedFromPolicy(t *testing.T) {
	p := &domain.Policy{
		CheckoutIntervalSec:    3600,
		MaxCheckoutDurationSec: 7200,
		ValidationTTLSec:       intPtr(600),
	}
	eff := policy.Resolve(p, domain.LicenseOverrides{})
	if eff.ValidationTTLSec == nil || *eff.ValidationTTLSec != 600 {
		t.Errorf("ValidationTTLSec = %v, want 600 (inherit)", eff.ValidationTTLSec)
	}
}

func TestResolve_ValidationTTL_OverrideWins(t *testing.T) {
	p := &domain.Policy{
		CheckoutIntervalSec:    3600,
		MaxCheckoutDurationSec: 7200,
		ValidationTTLSec:       intPtr(600),
	}
	o := domain.LicenseOverrides{ValidationTTLSec: intPtr(120)}
	eff := policy.Resolve(p, o)
	if eff.ValidationTTLSec == nil || *eff.ValidationTTLSec != 120 {
		t.Errorf("ValidationTTLSec = %v, want 120 (override)", eff.ValidationTTLSec)
	}
}

func TestResolve_ValidationTTL_NilWhenUnset(t *testing.T) {
	p := &domain.Policy{CheckoutIntervalSec: 3600, MaxCheckoutDurationSec: 7200}
	eff := policy.Resolve(p, domain.LicenseOverrides{})
	if eff.ValidationTTLSec != nil {
		t.Errorf("ValidationTTLSec = %v, want nil (caller applies server default)", *eff.ValidationTTLSec)
	}
}
```

- [ ] **Step 2: Run the new tests — verify they fail**

Run: `go test ./internal/policy/... -run TestResolve_ValidationTTL`
Expected: FAIL (`Effective.ValidationTTLSec` does not yet exist).

- [ ] **Step 3: Extend `Effective` and `Resolve`**

Edit `internal/policy/resolve.go`:

```go
type Effective struct {
	MaxMachines            *int
	MaxSeats               *int
	Floating               bool
	Strict                 bool
	DurationSeconds        *int
	ExpirationStrategy     core.ExpirationStrategy
	ExpirationBasis        core.ExpirationBasis
	RequireCheckout        bool
	CheckoutIntervalSec    int
	MaxCheckoutDurationSec int
	CheckoutGraceSec       int
	// Nil when neither policy nor override set it; the licensing layer
	// applies the server default (GETLICENSE_DEFAULT_VALIDATION_TTL_SEC)
	// before signing tokens. Keeping it *int here lets callers that don't
	// sign tokens (e.g. freeze snapshots) observe the "unset" state.
	ValidationTTLSec *int
}

func Resolve(p *domain.Policy, o domain.LicenseOverrides) Effective {
	eff := Effective{
		MaxMachines:            p.MaxMachines,
		MaxSeats:               p.MaxSeats,
		Floating:               p.Floating,
		Strict:                 p.Strict,
		DurationSeconds:        p.DurationSeconds,
		ExpirationStrategy:     p.ExpirationStrategy,
		ExpirationBasis:        p.ExpirationBasis,
		RequireCheckout:        p.RequireCheckout,
		CheckoutIntervalSec:    p.CheckoutIntervalSec,
		MaxCheckoutDurationSec: p.MaxCheckoutDurationSec,
		CheckoutGraceSec:       p.CheckoutGraceSec,
		ValidationTTLSec:       p.ValidationTTLSec,
	}
	if o.MaxMachines != nil {
		eff.MaxMachines = o.MaxMachines
	}
	if o.MaxSeats != nil {
		eff.MaxSeats = o.MaxSeats
	}
	if o.CheckoutIntervalSec != nil {
		eff.CheckoutIntervalSec = *o.CheckoutIntervalSec
	}
	if o.MaxCheckoutDurationSec != nil {
		eff.MaxCheckoutDurationSec = *o.MaxCheckoutDurationSec
	}
	if o.ValidationTTLSec != nil {
		eff.ValidationTTLSec = o.ValidationTTLSec
	}
	return eff
}
```

- [ ] **Step 4: Re-run all policy tests**

Run: `go test ./internal/policy/... -v`
Expected: PASS including the three new `TestResolve_ValidationTTL_*` tests.

- [ ] **Step 5: Commit**

```bash
git add internal/policy/resolve.go internal/policy/resolve_test.go
git commit -m "feat(p3): resolve effective validation_ttl_sec"
```

---

## Task 6: Validate bounds in `policy.Service` Create/Update

**Files:**
- Modify: `internal/policy/service.go`
- Modify: `internal/policy/service_test.go`

- [ ] **Step 1: Write the failing tests**

Append to `internal/policy/service_test.go`:

```go
func TestService_CreateRejectsTTLBelowMin(t *testing.T) {
	repo := newFakeRepo()
	svc := policy.NewService(repo)
	tooSmall := 59
	_, err := svc.Create(context.Background(), core.NewAccountID(), core.NewProductID(), policy.CreateRequest{
		Name:             "bad",
		ValidationTTLSec: &tooSmall,
	}, false)
	var appErr *core.AppError
	if !errors.As(err, &appErr) || appErr.Code != core.ErrPolicyInvalidTTL {
		t.Errorf("want policy_invalid_ttl, got %v", err)
	}
}

func TestService_CreateRejectsTTLAboveMax(t *testing.T) {
	repo := newFakeRepo()
	svc := policy.NewService(repo)
	tooBig := 2_592_001
	_, err := svc.Create(context.Background(), core.NewAccountID(), core.NewProductID(), policy.CreateRequest{
		Name:             "bad",
		ValidationTTLSec: &tooBig,
	}, false)
	var appErr *core.AppError
	if !errors.As(err, &appErr) || appErr.Code != core.ErrPolicyInvalidTTL {
		t.Errorf("want policy_invalid_ttl, got %v", err)
	}
}

func TestService_CreateAcceptsTTLAtBounds(t *testing.T) {
	repo := newFakeRepo()
	svc := policy.NewService(repo)
	lo, hi := 60, 2_592_000
	if _, err := svc.Create(context.Background(), core.NewAccountID(), core.NewProductID(), policy.CreateRequest{
		Name:             "lo",
		ValidationTTLSec: &lo,
	}, false); err != nil {
		t.Errorf("min bound (60) rejected: %v", err)
	}
	if _, err := svc.Create(context.Background(), core.NewAccountID(), core.NewProductID(), policy.CreateRequest{
		Name:             "hi",
		ValidationTTLSec: &hi,
	}, false); err != nil {
		t.Errorf("max bound (2592000) rejected: %v", err)
	}
}

func TestService_UpdateRejectsTTLBelowMin(t *testing.T) {
	repo := newFakeRepo()
	svc := policy.NewService(repo)
	p, _ := svc.Create(context.Background(), core.NewAccountID(), core.NewProductID(), policy.CreateRequest{Name: "ok"}, false)
	bad := 30
	ttlPtrPtr := &bad
	_, err := svc.Update(context.Background(), p.ID, policy.UpdateRequest{
		ValidationTTLSec: &ttlPtrPtr,
	})
	var appErr *core.AppError
	if !errors.As(err, &appErr) || appErr.Code != core.ErrPolicyInvalidTTL {
		t.Errorf("want policy_invalid_ttl, got %v", err)
	}
}
```

- [ ] **Step 2: Run — expect fails**

Run: `go test ./internal/policy/... -run TestService_.*TTL.* -v`
Expected: FAIL (field + validation not present yet).

- [ ] **Step 3: Extend `CreateRequest`, `UpdateRequest`, and service logic**

Edit `internal/policy/service.go`:

Add to `CreateRequest` (next to `MaxSeats`):

```go
	ValidationTTLSec *int `json:"validation_ttl_sec,omitempty"`
```

Add to `UpdateRequest` (same position):

```go
	ValidationTTLSec **int `json:"validation_ttl_sec,omitempty"`
```

(`**int` mirrors `MaxMachines`/`DurationSeconds` — outer nil = "not provided", inner nil = "explicitly clear to nil / inherit default".)

Extend `validateCreate` — append before the `return nil`:

```go
	if req.ValidationTTLSec != nil {
		if *req.ValidationTTLSec < 60 || *req.ValidationTTLSec > 2_592_000 {
			return core.NewAppError(core.ErrPolicyInvalidTTL, "validation_ttl_sec must be between 60 and 2592000")
		}
	}
```

Extend `Create` (between the existing field assignments, inside the `&domain.Policy{...}` literal) — add:

```go
		ValidationTTLSec:          req.ValidationTTLSec,
```

Extend `Update` — after the `req.MaxSeats` block, add:

```go
	if req.ValidationTTLSec != nil {
		if *req.ValidationTTLSec != nil {
			v := **req.ValidationTTLSec
			if v < 60 || v > 2_592_000 {
				return nil, core.NewAppError(core.ErrPolicyInvalidTTL, "validation_ttl_sec must be between 60 and 2592000")
			}
		}
		p.ValidationTTLSec = *req.ValidationTTLSec
	}
```

- [ ] **Step 4: Re-run tests**

Run: `go test ./internal/policy/... -v`
Expected: PASS — including the four new `TestService_.*TTL.*` cases and existing tests.

- [ ] **Step 5: Commit**

```bash
git add internal/policy/service.go internal/policy/service_test.go
git commit -m "feat(p3): validate validation_ttl_sec bounds in policy service"
```

---

## Task 7: Add `TTL` claim to `crypto.TokenPayload`

**Files:**
- Modify: `internal/crypto/token.go`
- Modify: `internal/crypto/token_test.go`

- [ ] **Step 1: Write the failing tests**

Append to `internal/crypto/token_test.go`:

```go
func TestSignVerifyToken_TTLRoundtrip(t *testing.T) {
	pub, priv, err := GenerateEd25519Keypair()
	if err != nil {
		t.Fatal(err)
	}

	payload := makeTestPayload()
	payload.TTL = 3600

	token, err := SignToken(payload, priv)
	if err != nil {
		t.Fatalf("SignToken error: %v", err)
	}

	got, err := VerifyToken(token, pub)
	if err != nil {
		t.Fatalf("VerifyToken error: %v", err)
	}
	if got.TTL != 3600 {
		t.Errorf("TTL: got %d, want 3600", got.TTL)
	}
}

// Old tokens minted before P3 have no "ttl" claim. They must still
// verify cleanly against the current decoder. Unmarshal gives TTL=0,
// which SDKs treat as "server didn't signal TTL, fall back to per-call
// validation" — matches pre-P3 behaviour.
func TestVerifyToken_BackwardsCompatMissingTTL(t *testing.T) {
	pub, priv, err := GenerateEd25519Keypair()
	if err != nil {
		t.Fatal(err)
	}

	// Hand-build an old-shape payload (no TTL field) to simulate a token
	// minted by a pre-P3 server. We marshal a minimal anonymous struct
	// that matches the pre-P3 TokenPayload JSON shape.
	legacy := struct {
		V      int    `json:"v"`
		PID    string `json:"pid"`
		LID    string `json:"lid"`
		Status string `json:"status"`
		IAT    int64  `json:"iat"`
	}{
		V: 1, PID: "prod-1", LID: "lic-1", Status: "active", IAT: 1700000000,
	}
	jsonBytes, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(jsonBytes)
	sig := Ed25519Sign(priv, []byte(payloadB64))
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	legacyToken := "gl1." + payloadB64 + "." + sigB64

	got, err := VerifyToken(legacyToken, pub)
	if err != nil {
		t.Fatalf("VerifyToken legacy: %v", err)
	}
	if got.TTL != 0 {
		t.Errorf("legacy token TTL = %d, want 0", got.TTL)
	}
	if got.ProductID != "prod-1" {
		t.Errorf("legacy token ProductID = %q, want prod-1", got.ProductID)
	}
}
```

Add the needed imports at the top of the test file (keep alphabetical):

```go
import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)
```

- [ ] **Step 2: Run — expect fails**

Run: `go test ./internal/crypto/... -run TestSignVerifyToken_TTLRoundtrip -v`
Expected: FAIL (`payload.TTL` undefined).

- [ ] **Step 3: Extend `TokenPayload`**

Edit `internal/crypto/token.go` — add `TTL` to the struct:

```go
type TokenPayload struct {
	Version   int                `json:"v"`
	ProductID string             `json:"pid"`
	LicenseID string             `json:"lid"`
	Status    core.LicenseStatus `json:"status"`
	IssuedAt  int64              `json:"iat"`
	ExpiresAt *int64             `json:"exp,omitempty"`
	// Validation staleness tolerance in seconds. P3 — always populated by
	// new servers. Legacy tokens with no `ttl` field unmarshal to 0;
	// clients treat 0 as "no TTL signal, fall back to per-call validation".
	TTL int `json:"ttl"`
}
```

- [ ] **Step 4: Re-run all crypto tests**

Run: `go test ./internal/crypto/... -v`
Expected: PASS (all roundtrip tests, plus the two new ones). The existing `TestSignVerifyToken_Roundtrip` continues to pass because `TTL` is zero in its payload, which roundtrips cleanly.

- [ ] **Step 5: Commit**

```bash
git add internal/crypto/token.go internal/crypto/token_test.go
git commit -m "feat(p3): add TTL claim to gl1 TokenPayload"
```

---

## Task 8: Parse `GETLICENSE_DEFAULT_VALIDATION_TTL_SEC` in server config

**Files:**
- Modify: `internal/server/config.go`

- [ ] **Step 1: Extend `Config` struct**

Add near the existing fields (keep grouping logical — place next to `MasterKey`):

```go
	DefaultValidationTTLSec int // P3 — server default for effective validation_ttl_sec; env var GETLICENSE_DEFAULT_VALIDATION_TTL_SEC
```

- [ ] **Step 2: Parse + validate the env var in `LoadConfig`**

Insert after the `masterKeyHex` / `mk` block and before the `publicBaseURL` block:

```go
	defaultTTL := 3600
	if raw := os.Getenv("GETLICENSE_DEFAULT_VALIDATION_TTL_SEC"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil {
			return nil, fmt.Errorf("server: GETLICENSE_DEFAULT_VALIDATION_TTL_SEC must be an integer: %w", err)
		}
		if n < 60 || n > 2_592_000 {
			return nil, fmt.Errorf("server: GETLICENSE_DEFAULT_VALIDATION_TTL_SEC must be between 60 and 2592000 (got %d)", n)
		}
		defaultTTL = n
	}
```

Add `"strconv"` to the import list.

Populate the returned `&Config{...}` literal with:

```go
		DefaultValidationTTLSec: defaultTTL,
```

- [ ] **Step 3: Build**

Run: `go build ./...`
Expected: PASS (no compile errors — downstream callers will be updated in the next task).

- [ ] **Step 4: Commit**

```bash
git add internal/server/config.go
git commit -m "feat(p3): parse GETLICENSE_DEFAULT_VALIDATION_TTL_SEC env var"
```

---

## Task 9: Wire default TTL into `licensing.Service` + validate override bounds

**Files:**
- Modify: `internal/licensing/service.go`
- Modify: `internal/licensing/service_test.go`

- [ ] **Step 1: Extend service struct + constructor**

In `internal/licensing/service.go`, add `defaultValidationTTLSec int` to the `Service` struct (next to `masterKey`):

```go
type Service struct {
	txManager               domain.TxManager
	licenses                domain.LicenseRepository
	products                domain.ProductRepository
	machines                domain.MachineRepository
	policies                domain.PolicyRepository
	customers               *customer.Service
	entitlements            *entitlement.Service
	masterKey               *crypto.MasterKey
	audit                   *audit.Writer
	defaultValidationTTLSec int
}
```

Extend `NewService`:

```go
func NewService(
	txManager domain.TxManager,
	licenses domain.LicenseRepository,
	products domain.ProductRepository,
	machines domain.MachineRepository,
	policies domain.PolicyRepository,
	customers *customer.Service,
	entitlements *entitlement.Service,
	masterKey *crypto.MasterKey,
	auditWriter *audit.Writer,
	defaultValidationTTLSec int,
) *Service {
	return &Service{
		txManager:               txManager,
		licenses:                licenses,
		products:                products,
		machines:                machines,
		policies:                policies,
		customers:               customers,
		entitlements:            entitlements,
		masterKey:               masterKey,
		audit:                   auditWriter,
		defaultValidationTTLSec: defaultValidationTTLSec,
	}
}
```

- [ ] **Step 2: Add override-bounds validator**

Inside the same file, add near the other package-scope helpers (e.g. next to `ValidateFingerprint`):

```go
// validateOverrideTTL enforces the same 60..2_592_000 bound the policy
// service applies to policies, so override-only writes can't bypass the
// rule. Returns nil when ValidationTTLSec is nil (inherit).
func validateOverrideTTL(o domain.LicenseOverrides) error {
	if o.ValidationTTLSec == nil {
		return nil
	}
	v := *o.ValidationTTLSec
	if v < 60 || v > 2_592_000 {
		return core.NewAppError(core.ErrPolicyInvalidTTL, "overrides.validation_ttl_sec must be between 60 and 2592000")
	}
	return nil
}
```

Call it at the top of the `Create` method — right after the existing `PolicyID` / `Overrides` parsing but before the DB tx. Find the early-return block that validates the customer inputs (`req.CustomerID != nil && req.Customer != nil` etc.) and append after it:

```go
	if err := validateOverrideTTL(req.Overrides); err != nil {
		return nil, err
	}
```

Call it inside `Update`, at the top of the tx closure (right after `l == nil` check, before `if req.Overrides != nil { l.Overrides = *req.Overrides }`):

```go
			if req.Overrides != nil {
				if err := validateOverrideTTL(*req.Overrides); err != nil {
					return err
				}
			}
```

(Keep the existing `if req.Overrides != nil { l.Overrides = *req.Overrides }` block immediately after.)

- [ ] **Step 3: Update test helper that constructs the service**

In `internal/licensing/service_test.go`, find the sole `NewService(...)` call (currently on line ~790) and add `3600` as the final arg:

```go
	svc := NewService(&mockTxManager{}, licenses, products, machines, policies, customerSvc, entitlementSvc, mk, nil, 3600)
```

- [ ] **Step 4: Add override-bounds tests**

Append to `internal/licensing/service_test.go`. Fixture pattern mirrors existing `TestCreate_*` tests using `newTestEnv`, `createTestProduct`, and `seedDefaultPolicy`:

```go
func TestCreate_RejectsOverrideTTLBelowMin(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	too := 10
	_, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		Customer:  inlineCustomer("user@example.com"),
		Overrides: domain.LicenseOverrides{ValidationTTLSec: &too},
	}, CreateOptions{CreatedByAccountID: testAccountID})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrPolicyInvalidTTL, appErr.Code)
}

func TestCreate_RejectsOverrideTTLAboveMax(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	tooBig := 2_592_001
	_, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		Customer:  inlineCustomer("user@example.com"),
		Overrides: domain.LicenseOverrides{ValidationTTLSec: &tooBig},
	}, CreateOptions{CreatedByAccountID: testAccountID})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrPolicyInvalidTTL, appErr.Code)
}

func TestUpdate_RejectsOverrideTTLBelowMin(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)
	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		Customer: inlineCustomer("user@example.com"),
	}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	too := 30
	_, err = env.svc.Update(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, UpdateRequest{
		Overrides: &domain.LicenseOverrides{ValidationTTLSec: &too},
	})
	require.Error(t, err)
	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrPolicyInvalidTTL, appErr.Code)
}
```

- [ ] **Step 5: Update `cmd/server/serve.go` caller in the same commit**

`licensing.NewService` now takes `defaultValidationTTLSec int` as the final arg. Update the call in `cmd/server/serve.go`:

```go
	licenseSvc := licensing.NewService(
		txManager, licenseRepo, productRepo, machineRepo, policyRepo,
		customerSvc, entitlementSvc, cfg.MasterKey, auditWriter,
		cfg.DefaultValidationTTLSec,
	)
```

Keeping this in the same commit as the signature change is important — skipping it leaves the tree unbuildable across several intermediate commits (breaks `git bisect`).

- [ ] **Step 6: Full build + tests**

Run: `go build ./...` then `go test ./internal/licensing/... -v` then `go test ./cmd/... -v` (if any tests there).
Expected: PASS everywhere. Existing tests compile with the new constructor arg; new override-bounds tests pass.

- [ ] **Step 7: Commit**

```bash
git add internal/licensing/service.go internal/licensing/service_test.go cmd/server/serve.go
git commit -m "feat(p3): wire default validation TTL + validate override bounds"
```

---

## Task 10: Populate `payload.TTL` at license creation

**Files:**
- Modify: `internal/licensing/service.go`

- [ ] **Step 1: Add a small helper**

Just above `buildLicense` (near the end of the file), add:

```go
// effectiveValidationTTL returns the per-license effective TTL seconds:
// override > policy > server default. Never returns zero — the server
// default is applied when neither policy nor override set the field.
func (s *Service) effectiveValidationTTL(eff policy.Effective) int {
	if eff.ValidationTTLSec != nil {
		return *eff.ValidationTTLSec
	}
	return s.defaultValidationTTLSec
}
```

- [ ] **Step 2: Thread TTL through `buildLicense`**

`buildLicense` is a package-level function — the simplest change is to make it a method on `*Service`, OR pass `defaultValidationTTLSec int` as an explicit parameter. Prefer the method conversion for clarity (mirrors other `Service.*` helpers in the file).

Change the signature:

```go
func (s *Service) buildLicense(
	req CreateRequest,
	p *domain.Policy,
	customerID core.CustomerID,
	licenseID core.LicenseID,
	prefix, keyHash string,
	now time.Time,
	accountID core.AccountID,
	productID core.ProductID,
	privKey ed25519.PrivateKey,
	env core.Environment,
) (*domain.License, error) {
```

Update both callers — `Create` (around line 251) and `BulkCreate` (around line 517). Both call `buildLicense(...)` — change to `s.buildLicense(...)`. Use `grep -n "buildLicense(" internal/licensing/service.go` to locate them.

Inside the body, right after `eff := policy.Resolve(p, req.Overrides)`:

```go
	ttl := s.effectiveValidationTTL(eff)
```

Populate `payload.TTL`:

```go
	payload := crypto.TokenPayload{
		Version:   1,
		ProductID: productID.String(),
		LicenseID: licenseID.String(),
		Status:    core.LicenseStatusActive,
		IssuedAt:  now.Unix(),
		TTL:       ttl,
	}
	if expiresAt != nil {
		ts := expiresAt.Unix()
		payload.ExpiresAt = &ts
	}
```

- [ ] **Step 3: Build**

Run: `go build ./...`
Expected: PASS.

- [ ] **Step 4: Run licensing tests**

Run: `go test ./internal/licensing/... -v`
Expected: PASS. Existing `Create` tests don't assert on the token's TTL claim, so they keep working; the next task adds dedicated assertions.

- [ ] **Step 5: Commit**

```bash
git add internal/licensing/service.go
git commit -m "feat(p3): populate TTL claim when minting license tokens"
```

---

## Task 11: Re-mint token + return mirror TTL in `Validate`

**Files:**
- Modify: `internal/licensing/service.go`
- Modify: `internal/licensing/service_test.go`

- [ ] **Step 1: Extend `ValidateResult`**

Edit the struct:

```go
type ValidateResult struct {
	Valid             bool            `json:"valid"`
	License           *domain.License `json:"license"`
	Entitlements      []string        `json:"entitlements"`
	// Mirror of the token's `ttl` claim. Exposed so callers can decode
	// the response without verifying the token (debug / proxy use cases).
	// Authoritative for SDK caching decisions only after token verification.
	ValidationTTLSec  int             `json:"validation_ttl_sec"`
}
```

- [ ] **Step 2: Re-mint token in `Validate`**

Replace the tail of `Validate` (after entitlement resolution) with the re-mint logic. Full updated method:

```go
func (s *Service) Validate(ctx context.Context, licenseKey string) (*ValidateResult, error) {
	keyHash := s.masterKey.HMAC(licenseKey)

	license, err := s.licenses.GetByKeyHash(ctx, keyHash)
	if err != nil {
		return nil, err
	}
	if license == nil {
		return nil, core.NewAppError(core.ErrInvalidLicenseKey, "Invalid license key")
	}

	switch license.Status {
	case core.LicenseStatusRevoked:
		return nil, core.NewAppError(core.ErrLicenseRevoked, "License has been revoked")
	case core.LicenseStatusSuspended:
		return nil, core.NewAppError(core.ErrLicenseSuspended, "License is suspended")
	case core.LicenseStatusInactive:
		return nil, core.NewAppError(core.ErrLicenseInactive, "License is inactive")
	case core.LicenseStatusExpired:
		return nil, core.NewAppError(core.ErrLicenseExpired, "License has expired")
	}

	p, err := s.policies.Get(ctx, license.PolicyID)
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, core.NewAppError(core.ErrPolicyNotFound, "policy not found")
	}
	eff := policy.Resolve(p, license.Overrides)
	if dec := policy.EvaluateExpiration(eff, license.ExpiresAt); !dec.Valid {
		return nil, core.NewAppError(dec.Code, "License has expired")
	}

	entCodes, err := s.entitlements.ResolveEffective(ctx, license.ID)
	if err != nil {
		return nil, err
	}

	// Re-mint the gl1 token with the current effective TTL so policy
	// updates cascade to existing licenses (the stored licenses.token
	// column is never updated by this path — only /v1/validate returns
	// a re-minted token). See CLAUDE.md § Validation TTL (P3).
	ttl := s.effectiveValidationTTL(eff)
	privKey, err := s.decryptProductPrivateKey(ctx, license.ProductID)
	if err != nil {
		return nil, err
	}
	payload := crypto.TokenPayload{
		Version:   1,
		ProductID: license.ProductID.String(),
		LicenseID: license.ID.String(),
		Status:    license.Status,
		IssuedAt:  time.Now().UTC().Unix(),
		TTL:       ttl,
	}
	if license.ExpiresAt != nil {
		ts := license.ExpiresAt.Unix()
		payload.ExpiresAt = &ts
	}
	fresh, err := crypto.SignToken(payload, privKey)
	if err != nil {
		return nil, core.NewAppError(core.ErrInternalError, "Failed to sign license token")
	}

	// Shallow-copy the license so swapping .Token doesn't mutate
	// anything a future caching layer might hold. The repo returns a
	// fresh struct per call today, but this keeps the intent explicit.
	licenseOut := *license
	licenseOut.Token = fresh

	return &ValidateResult{
		Valid:            true,
		License:          &licenseOut,
		Entitlements:     entCodes,
		ValidationTTLSec: ttl,
	}, nil
}
```

(`s.decryptProductPrivateKey` already exists in the file — used by Activate / Checkin to sign gl2 lease tokens and signature-matches this call site exactly.)

- [ ] **Step 3: Add a service-level cascade test**

Append to `internal/licensing/service_test.go` near the existing `TestValidate_*` group. The test proves three properties in one flow: policy TTL propagates, re-mint updates the returned token, and policy updates cascade to the same license on re-validate.

```go
func TestValidate_ReMintsTokenWithCurrentEffectiveTTL(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	initialTTL := 600
	policy := seedDefaultPolicy(t, env.policies, testAccountID, product.ID, func(p *domain.Policy) {
		p.ValidationTTLSec = &initialTTL
	})

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		Customer: inlineCustomer("user@example.com"),
	}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	// Decode the public key once so we can verify the re-minted token.
	privBytes, err := env.mk.Decrypt(createdTestProductPrivateKeyEnc(t, env, product.ID))
	require.NoError(t, err)
	priv := ed25519.PrivateKey(privBytes)
	pub := priv.Public().(ed25519.PublicKey)

	// 1. Initial validate — mirror + signed claim both report 600.
	result, err := env.svc.Validate(context.Background(), created.LicenseKey)
	require.NoError(t, err)
	assert.Equal(t, 600, result.ValidationTTLSec)
	claims, err := crypto.VerifyToken(result.License.Token, pub)
	require.NoError(t, err)
	assert.Equal(t, 600, claims.TTL)

	// 2. Bump policy TTL. The stored licenses.token is unchanged; only
	// Validate returns a freshly-minted token with the new value.
	newTTL := 900
	policy.ValidationTTLSec = &newTTL
	require.NoError(t, env.policies.Update(context.Background(), policy))

	result, err = env.svc.Validate(context.Background(), created.LicenseKey)
	require.NoError(t, err)
	assert.Equal(t, 900, result.ValidationTTLSec)
	claims, err = crypto.VerifyToken(result.License.Token, pub)
	require.NoError(t, err)
	assert.Equal(t, 900, claims.TTL)
}

// createdTestProductPrivateKeyEnc returns the encrypted private key bytes
// stored on the seeded product so we can round-trip through mk.Decrypt.
// Inlined here rather than hoisted globally because only this test needs it.
func createdTestProductPrivateKeyEnc(t *testing.T, env *testEnv, id core.ProductID) []byte {
	t.Helper()
	p, ok := env.products.byID[id]
	require.True(t, ok, "product not seeded")
	return p.PrivateKeyEnc
}
```

If `createTestProduct` uses a different fixture name for the product's encrypted key, adjust the helper accordingly — inspect the existing helper to confirm. Add `ed25519` import if not already present:

```go
import (
	"crypto/ed25519"
	// ... existing imports
)
```

Add `"github.com/getlicense-io/getlicense-api/internal/crypto"` to the test imports if it is not yet referenced by the file (it is by other tests — verify with `grep`).

- [ ] **Step 4: Run tests**

Run: `go test ./internal/licensing/... -v`
Expected: PASS including the new re-mint cascade test.

- [ ] **Step 5: Commit**

```bash
git add internal/licensing/service.go internal/licensing/service_test.go
git commit -m "feat(p3): re-mint gl1 token on validate to cascade TTL updates"
```

---

## Task 12: Update OpenAPI spec

**Files:**
- Modify: `openapi.yaml`

- [ ] **Step 1: Extend `Policy` schema**

Inside `components.schemas.Policy.properties`, add after `metadata` (before `created_at`):

```yaml
        validation_ttl_sec:
          type: integer
          nullable: true
          minimum: 60
          maximum: 2592000
          description: |
            Runtime SDK staleness tolerance (seconds). Tells the SDK how long
            it may trust a cached gl1 token before re-checking the server.
            Null inherits the server default (GETLICENSE_DEFAULT_VALIDATION_TTL_SEC,
            default 3600). Cascades to licenses via the effective-value rule.
```

- [ ] **Step 2: Extend `LicenseOverrides` schema**

Inside `components.schemas.LicenseOverrides.properties`, add after `max_checkout_duration_sec`:

```yaml
        validation_ttl_sec:
          type: integer
          nullable: true
          minimum: 60
          maximum: 2592000
          description: |
            Per-license override of policy.validation_ttl_sec. Null inherits
            from policy. Same bounds as the policy field.
```

- [ ] **Step 3: Extend `ValidateResult` schema**

Inside `components.schemas.ValidateResult.properties`, add:

```yaml
        validation_ttl_sec:
          type: integer
          minimum: 60
          maximum: 2592000
          description: |
            Effective validation TTL seconds for this license. Mirrors the
            `ttl` claim in the returned token (license.token). Exposed here
            for debugging and for callers that decode the response body
            without verifying the token — authoritative SDK caching should
            verify the token and read the signed `ttl` claim instead.
```

And add `validation_ttl_sec` to the `ValidateResult.required` list so it becomes:

```yaml
      required: [valid, license, validation_ttl_sec]
```

- [ ] **Step 4: Add `LicenseTokenClaims` schema**

Inside `components.schemas` (near the existing token-shaped schemas, alphabetical), insert:

```yaml
    LicenseTokenClaims:
      type: object
      description: |
        Claim set of the gl1 license token. The wire form is
        `gl1.<base64url(json)>.<base64url(ed25519sig)>`. The signature
        covers the base64url-encoded payload string, not the raw JSON.
        Clients must decode using the product's Ed25519 public key before
        trusting any field. This schema is documentation-only — the token
        is returned as a plain string on License.token and ValidateResult.license.token.
      required: [v, pid, lid, status, iat, ttl]
      properties:
        v:
          type: integer
          description: Payload version. Currently always 1.
        pid:
          type: string
          format: uuid
          description: Product ID.
        lid:
          type: string
          format: uuid
          description: License ID.
        status:
          $ref: "#/components/schemas/LicenseStatus"
        iat:
          type: integer
          description: Issued-at Unix timestamp (seconds).
        exp:
          type: integer
          nullable: true
          description: Expires-at Unix timestamp (seconds). Null = perpetual.
        ttl:
          type: integer
          description: |
            Validation staleness tolerance (seconds). SDK may trust a cached
            copy of this token for this many seconds before re-checking the
            server. 0 on legacy tokens minted by pre-P3 servers — clients
            should treat 0 as "no TTL signal, fall back to per-call validation".
```

- [ ] **Step 5: Syntax-check the OpenAPI**

Run: `npx @redocly/cli lint openapi.yaml` (or the project's preferred linter — check the Makefile / CI for the canonical invocation).
Expected: PASS (no new lint errors introduced). If the repo has no OpenAPI linter wired up, at minimum run `yamllint openapi.yaml` or `python -c "import yaml; yaml.safe_load(open('openapi.yaml'))"`.

- [ ] **Step 6: Commit**

```bash
git add openapi.yaml
git commit -m "docs(openapi): add validation_ttl_sec + LicenseTokenClaims schema"
```

---

## Task 13: Document cascade + re-mint asymmetry in CLAUDE.md

**Files:**
- Modify: `CLAUDE.md` (project — `getlicense-api/CLAUDE.md`)

- [ ] **Step 1: Add a new subsection**

Under the existing "Policies & Effective Values (L1)" section, after the "Design spec" / "Implementation plan" bullet pair for L1, insert a new top-level subsection **before** the "Customers (L4)" section:

```markdown
## Validation TTL (P3)

Runtime SDKs need a signed, server-authoritative hint for how long a cached `gl1` license token may be trusted before re-checking. `policy.validation_ttl_sec` + `license.overrides.validation_ttl_sec` cascade to an effective value via the standard policy.Resolve merge; the default comes from `GETLICENSE_DEFAULT_VALIDATION_TTL_SEC` (default 3600, bounds 60..2592000).

- **Signed claim, not response mirror.** The effective TTL is embedded as the `ttl` claim in the `gl1` token so a MITM can't extend or reduce the value.
- **Token re-minting on `POST /v1/validate`.** `/v1/validate` re-signs the license token with the current effective TTL and returns it in `license.token` on the response. Every other endpoint (`GET /v1/licenses/:id`, list, create) returns the stored `licenses.token` from the DB (with TTL-at-creation). The stored column is never updated by this feature — only Validate returns a fresh token. This is the only design that makes policy TTL updates cascade to existing licenses without re-issuing license keys.
- **`gl2` lease tokens are unaffected.** P3 is `gl1`-only; lease tokens have independent expiry via `max_checkout_duration_sec` / `checkout_grace_sec`.
- **Bounds.** 60 ≤ TTL ≤ 2592000 enforced at policy CRUD, license override writes (POST/PATCH), Postgres CHECK constraint on the policy column, and config load.
- **Backwards compat.** Legacy (pre-P3) tokens have no `ttl` field; they unmarshal to `TTL: 0`. New SDKs should treat 0 as "no TTL signal, fall back to per-call validation".
- **Migration:** `027_validation_ttl.sql` — additive nullable column on `policies`.
- **Implementation plan:** `docs/superpowers/plans/2026-04-17-p3-validation-ttl.md`.
```

- [ ] **Step 2: Commit**

```bash
git add CLAUDE.md
git commit -m "docs(claude): document P3 validation TTL cascade + re-mint semantics"
```

---

## Task 14: End-to-end scenario

**Files:**
- Create: `e2e/scenarios/22_validation_ttl.hurl`

- [ ] **Step 1: Write the scenario**

Create `e2e/scenarios/22_validation_ttl.hurl`:

```hurl
# P3: validation_ttl_sec — cascade from policy, override wins, re-mint on /validate.

# --- Setup: signup ---
POST {{base_url}}/v1/auth/signup
Content-Type: application/json
{
  "account_name": "TTL Test Co",
  "email": "e2e-ttl@test.com",
  "password": "password123"
}
HTTP 201
[Captures]
api_key: jsonpath "$.api_key"

# --- Create product (auto-creates default policy) ---
POST {{base_url}}/v1/products
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "name": "TTL Product",
  "slug": "ttl-product"
}
HTTP 201
[Captures]
product_id: jsonpath "$.id"

# --- Get the auto-created default policy ---
GET {{base_url}}/v1/products/{{product_id}}/policies
Authorization: Bearer {{api_key}}
HTTP 200
[Captures]
policy_id: jsonpath "$.data[0].id"

# --- Update policy: set validation_ttl_sec = 600 ---
PATCH {{base_url}}/v1/policies/{{policy_id}}
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "validation_ttl_sec": 600
}
HTTP 200
[Asserts]
jsonpath "$.validation_ttl_sec" == 600

# --- Reject TTL below minimum ---
PATCH {{base_url}}/v1/policies/{{policy_id}}
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "validation_ttl_sec": 30
}
HTTP 422
[Asserts]
jsonpath "$.error.code" == "policy_invalid_ttl"

# --- Reject TTL above maximum ---
PATCH {{base_url}}/v1/policies/{{policy_id}}
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "validation_ttl_sec": 2592001
}
HTTP 422
[Asserts]
jsonpath "$.error.code" == "policy_invalid_ttl"

# --- Create license under the policy (no override) ---
POST {{base_url}}/v1/products/{{product_id}}/licenses
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "customer": {"email": "ttl-user@example.com"}
}
HTTP 201
[Captures]
license_id_a: jsonpath "$.license.id"
license_key_a: jsonpath "$.license_key"

# --- Validate license A — TTL mirrors policy value (600) ---
POST {{base_url}}/v1/validate
Content-Type: application/json
{
  "license_key": "{{license_key_a}}"
}
HTTP 200
[Asserts]
jsonpath "$.valid" == true
jsonpath "$.validation_ttl_sec" == 600

# --- Create license B with an override of 120 ---
POST {{base_url}}/v1/products/{{product_id}}/licenses
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "customer": {"email": "ttl-override@example.com"},
  "overrides": {"validation_ttl_sec": 120}
}
HTTP 201
[Captures]
license_key_b: jsonpath "$.license_key"

# --- Validate license B — override wins (120) ---
POST {{base_url}}/v1/validate
Content-Type: application/json
{
  "license_key": "{{license_key_b}}"
}
HTTP 200
[Asserts]
jsonpath "$.valid" == true
jsonpath "$.validation_ttl_sec" == 120

# --- Reject license-create with bogus override TTL ---
POST {{base_url}}/v1/products/{{product_id}}/licenses
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "customer": {"email": "ttl-bogus@example.com"},
  "overrides": {"validation_ttl_sec": 10}
}
HTTP 422
[Asserts]
jsonpath "$.error.code" == "policy_invalid_ttl"

# --- Cascade: bump policy TTL to 900, re-validate license A → new TTL ---
PATCH {{base_url}}/v1/policies/{{policy_id}}
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "validation_ttl_sec": 900
}
HTTP 200

POST {{base_url}}/v1/validate
Content-Type: application/json
{
  "license_key": "{{license_key_a}}"
}
HTTP 200
[Asserts]
jsonpath "$.valid" == true
jsonpath "$.validation_ttl_sec" == 900

# --- License B still pinned to its override (120) even after policy change ---
POST {{base_url}}/v1/validate
Content-Type: application/json
{
  "license_key": "{{license_key_b}}"
}
HTTP 200
[Asserts]
jsonpath "$.valid" == true
jsonpath "$.validation_ttl_sec" == 120

# --- Clear policy TTL → falls back to server default (3600 in tests) ---
PATCH {{base_url}}/v1/policies/{{policy_id}}
Authorization: Bearer {{api_key}}
Content-Type: application/json
{
  "validation_ttl_sec": null
}
HTTP 200

POST {{base_url}}/v1/validate
Content-Type: application/json
{
  "license_key": "{{license_key_a}}"
}
HTTP 200
[Asserts]
jsonpath "$.valid" == true
jsonpath "$.validation_ttl_sec" == 3600
```

- [ ] **Step 2: Run e2e**

Run: `make e2e`
Expected: PASS — the new scenario plus all existing scenarios.

If existing scenarios fail due to the new `validation_ttl_sec` required field on `ValidateResult`: the field IS in every `/v1/validate` response regardless of policy config, so hurl assertions in `05_validate.hurl` etc. that only assert on `$.valid` / `$.license.status` keep passing. If any scenario explicitly asserts the response shape and breaks, update it minimally to include `validation_ttl_sec`.

- [ ] **Step 3: Commit**

```bash
git add e2e/scenarios/22_validation_ttl.hurl
git commit -m "test(e2e): p3 validation_ttl cascade + override + bounds"
```

---

## Task 15: Final verification pass

- [ ] **Step 1: Unit + integration tests**

Run: `make test-all`
Expected: PASS — everything green.

- [ ] **Step 2: Lint**

Run: `golangci-lint run ./...`
Expected: PASS — no new lint findings. Fix any introduced (most likely: unused-var or missing-comment warnings in new code).

- [ ] **Step 3: Full e2e**

Run: `make e2e`
Expected: PASS — all existing scenarios plus the new `22_validation_ttl.hurl`.

- [ ] **Step 4: Self-check against SDK developer's acceptance list**

Open the original P3 feedback note and verify each item:

- [ ] Policy-default TTL propagates to minted tokens (Task 10 + Task 15 license A initial validate).
- [ ] License override takes precedence over policy (Task 15 license B).
- [ ] Server default fills in when both are null (Task 15 final clear-policy step).
- [ ] Invalid ranges rejected at the policy / override API level (Task 6 + Task 9 + Task 15 bounds asserts).
- [ ] Token's `ttl` claim round-trips through sign/verify (Task 7).
- [ ] Legacy tokens without `ttl` still verify cleanly (Task 7 backwards compat test).
- [ ] OpenAPI documents `validation_ttl_sec` on Policy, LicenseOverrides, ValidateResult, and the token claim set (Task 13).

- [ ] **Step 5: Stop here — no push**

Do not `git push` automatically. Report the final commit list + verification output back to the user and let them decide when to push or open a PR.

---

## Appendix: Out-of-Scope

- **SDK changes.** The SDK developer will run `make generate` in `types/v1/` and resume P3 on their side once this lands. No SDK edits in this plan.
- **`gl2` lease token TTL.** Lease tokens have their own expiry semantics. Not touched.
- **Resigning stored `licenses.token`.** The stored token column keeps the creation-time TTL forever. Only Validate returns a fresh token. Documented in CLAUDE.md.
- **Per-environment TTL defaults.** The env var is a single server-wide default. If a future deployment needs per-env overrides, that's a follow-up.
- **Dashboard UI for the new fields.** Policy dashboard may want a TTL input. Not in this API-only plan.
