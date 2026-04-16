package db

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Integration tests for MachineRepo.
//
// Gating, harness, and cleanup conventions mirror customer_repo_test.go:
// `-short` skips, `make test-all` runs against the dev Postgres, each
// test begins its own top-level tx and ROLLs it back on cleanup so
// nothing survives.

// machineFixture seeds account → product → policy → customer → license
// under a fresh rollback-only tx, with the RLS session vars populated.
type machineFixture struct {
	ctx        context.Context
	tx         pgx.Tx
	accountID  core.AccountID
	productID  core.ProductID
	policyID   core.PolicyID
	customerID core.CustomerID
	licenseID  core.LicenseID
}

func newMachineFixture(t *testing.T, pool *pgxpool.Pool) *machineFixture {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })

	accountID := core.NewAccountID()
	env := core.Environment("live")

	if _, err := tx.Exec(ctx,
		`SELECT set_config('app.current_account_id', $1, true)`, accountID.String()); err != nil {
		t.Fatalf("set_config account: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`SELECT set_config('app.current_environment', $1, true)`, string(env)); err != nil {
		t.Fatalf("set_config env: %v", err)
	}

	slug := "test-" + accountID.String()[:8]
	if _, err := tx.Exec(ctx,
		`INSERT INTO accounts (id, name, slug, created_at) VALUES ($1, $2, $3, NOW())`,
		uuid.UUID(accountID), "Test Account", slug,
	); err != nil {
		t.Fatalf("seed account: %v", err)
	}

	productID := core.NewProductID()
	if _, err := tx.Exec(ctx,
		`INSERT INTO products (id, account_id, name, slug, public_key, private_key_enc, metadata, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, NOW())`,
		uuid.UUID(productID), uuid.UUID(accountID),
		"Test Product", "test-product-"+accountID.String()[:8], "test-pub-key", []byte{0x00},
		`{}`,
	); err != nil {
		t.Fatalf("seed product: %v", err)
	}

	ctx = context.WithValue(ctx, ctxKey{}, tx)

	// Seed a default policy with require_checkout enabled.
	policyID := core.NewPolicyID()
	now := time.Now().UTC()
	pol := &domain.Policy{
		ID:                        policyID,
		AccountID:                 accountID,
		ProductID:                 productID,
		Name:                      "Default",
		IsDefault:                 true,
		RequireCheckout:           true,
		CheckoutIntervalSec:       3600,
		MaxCheckoutDurationSec:    86400,
		CheckoutGraceSec:          3600,
		ExpirationStrategy:        core.ExpirationStrategyRevokeAccess,
		ExpirationBasis:           core.ExpirationBasisFromCreation,
		ComponentMatchingStrategy: core.ComponentMatchingAny,
		CreatedAt:                 now,
		UpdatedAt:                 now,
	}
	if err := NewPolicyRepo(pool).Create(ctx, pol); err != nil {
		t.Fatalf("seed policy: %v", err)
	}

	// Seed a customer.
	customerID := core.NewCustomerID()
	if _, err := tx.Exec(ctx,
		`INSERT INTO customers (id, account_id, email, metadata, created_at, updated_at)
		 VALUES ($1, $2, $3, '{}'::jsonb, NOW(), NOW())`,
		uuid.UUID(customerID), uuid.UUID(accountID),
		"fixture-"+accountID.String()[:8]+"@example.com",
	); err != nil {
		t.Fatalf("seed customer: %v", err)
	}

	// Seed a license.
	licenseID := core.NewLicenseID()
	lic := &domain.License{
		ID:                 licenseID,
		AccountID:          accountID,
		ProductID:          productID,
		PolicyID:           policyID,
		CustomerID:         customerID,
		KeyPrefix:          "GL_TEST_M",
		KeyHash:            "hash_" + licenseID.String(),
		Token:              "tok_" + licenseID.String(),
		Status:             core.LicenseStatusActive,
		Environment:        env,
		CreatedAt:          now,
		UpdatedAt:          now,
		CreatedByAccountID: accountID,
	}
	if err := NewLicenseRepo(pool).Create(ctx, lic); err != nil {
		t.Fatalf("seed license: %v", err)
	}

	return &machineFixture{
		ctx:        ctx,
		tx:         tx,
		accountID:  accountID,
		productID:  productID,
		policyID:   policyID,
		customerID: customerID,
		licenseID:  licenseID,
	}
}

// newMachine returns a minimally populated domain.Machine for the fixture.
func newMachine(f *machineFixture, fingerprint string) *domain.Machine {
	now := time.Now().UTC()
	return &domain.Machine{
		ID:             core.NewMachineID(),
		AccountID:      f.accountID,
		LicenseID:      f.licenseID,
		Fingerprint:    fingerprint,
		Metadata:       json.RawMessage("{}"),
		LeaseIssuedAt:  now,
		LeaseExpiresAt: now.Add(time.Hour),
		LastCheckinAt:  now,
		Status:         core.MachineStatusActive,
		Environment:    core.Environment("live"),
		CreatedAt:      now,
	}
}

// seedLicenseForPolicy creates a new license referencing the given policy.
func seedLicenseForPolicy(t *testing.T, f *machineFixture, pool *pgxpool.Pool, policyID core.PolicyID, suffix string) core.LicenseID {
	t.Helper()
	licenseID := core.NewLicenseID()
	now := time.Now().UTC()
	lic := &domain.License{
		ID:                 licenseID,
		AccountID:          f.accountID,
		ProductID:          f.productID,
		PolicyID:           policyID,
		CustomerID:         f.customerID,
		KeyPrefix:          "GL_TEST_" + suffix,
		KeyHash:            "hash_" + licenseID.String(),
		Token:              "tok_" + licenseID.String(),
		Status:             core.LicenseStatusActive,
		Environment:        core.Environment("live"),
		CreatedAt:          now,
		UpdatedAt:          now,
		CreatedByAccountID: f.accountID,
	}
	if err := NewLicenseRepo(pool).Create(f.ctx, lic); err != nil {
		t.Fatalf("seed license %s: %v", suffix, err)
	}
	return licenseID
}

// ---------- Tests ----------

func TestMachineRepo_UpsertActivation_NewRow(t *testing.T) {
	pool := integrationPool(t)
	f := newMachineFixture(t, pool)
	repo := NewMachineRepo(pool)

	m := newMachine(f, "fp-new-activation")
	if err := repo.UpsertActivation(f.ctx, m); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	got, err := repo.GetByFingerprint(f.ctx, f.licenseID, "fp-new-activation")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil machine after activation")
	}
	if got.Status != core.MachineStatusActive {
		t.Errorf("status = %q, want active", got.Status)
	}
	if got.Fingerprint != "fp-new-activation" {
		t.Errorf("fingerprint = %q, want fp-new-activation", got.Fingerprint)
	}
	if got.LeaseIssuedAt.IsZero() {
		t.Error("lease_issued_at is zero")
	}
	if got.LeaseExpiresAt.IsZero() {
		t.Error("lease_expires_at is zero")
	}
}

func TestMachineRepo_UpsertActivation_Resurrection(t *testing.T) {
	pool := integrationPool(t)
	f := newMachineFixture(t, pool)
	repo := NewMachineRepo(pool)

	// First activation.
	m := newMachine(f, "fp-resurrect")
	if err := repo.UpsertActivation(f.ctx, m); err != nil {
		t.Fatalf("upsert 1: %v", err)
	}
	originalID := m.ID

	// Manually mark dead.
	if _, err := f.tx.Exec(f.ctx,
		`UPDATE machines SET status = 'dead' WHERE id = $1`,
		uuid.UUID(originalID),
	); err != nil {
		t.Fatalf("mark dead: %v", err)
	}

	// Re-activate with the same fingerprint.
	m2 := newMachine(f, "fp-resurrect")
	if err := repo.UpsertActivation(f.ctx, m2); err != nil {
		t.Fatalf("upsert 2: %v", err)
	}

	// Should reuse the same ID.
	if m2.ID != originalID {
		t.Errorf("resurrected ID = %v, want %v (same row)", m2.ID, originalID)
	}
	if m2.Status != core.MachineStatusActive {
		t.Errorf("resurrected status = %q, want active", m2.Status)
	}

	// Verify via DB read.
	got, err := repo.GetByFingerprint(f.ctx, f.licenseID, "fp-resurrect")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil machine after resurrection")
	}
	if got.Status != core.MachineStatusActive {
		t.Errorf("db status = %q, want active", got.Status)
	}
}

func TestMachineRepo_RenewLease_StaleToActive(t *testing.T) {
	pool := integrationPool(t)
	f := newMachineFixture(t, pool)
	repo := NewMachineRepo(pool)

	m := newMachine(f, "fp-renew")
	if err := repo.UpsertActivation(f.ctx, m); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	// Mark stale manually.
	if _, err := f.tx.Exec(f.ctx,
		`UPDATE machines SET status = 'stale' WHERE id = $1`,
		uuid.UUID(m.ID),
	); err != nil {
		t.Fatalf("mark stale: %v", err)
	}

	// RenewLease should set status back to active.
	now := time.Now().UTC()
	m.LeaseIssuedAt = now
	m.LeaseExpiresAt = now.Add(time.Hour)
	m.LastCheckinAt = now
	if err := repo.RenewLease(f.ctx, m); err != nil {
		t.Fatalf("renew: %v", err)
	}

	got, err := repo.GetByID(f.ctx, m.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil machine after renew")
	}
	if got.Status != core.MachineStatusActive {
		t.Errorf("status = %q, want active", got.Status)
	}
	if !got.LeaseExpiresAt.After(now.Add(-time.Second)) {
		t.Errorf("lease_expires_at not advanced: %v", got.LeaseExpiresAt)
	}
}

func TestMachineRepo_RenewLease_NotFound(t *testing.T) {
	pool := integrationPool(t)
	f := newMachineFixture(t, pool)
	repo := NewMachineRepo(pool)

	m := &domain.Machine{
		ID:             core.NewMachineID(),
		LeaseIssuedAt:  time.Now().UTC(),
		LeaseExpiresAt: time.Now().UTC().Add(time.Hour),
		LastCheckinAt:  time.Now().UTC(),
	}
	err := repo.RenewLease(f.ctx, m)
	if err == nil {
		t.Fatal("expected error for non-existent machine; got nil")
	}
	var appErr *core.AppError
	if !errors.As(err, &appErr) {
		t.Fatalf("expected *core.AppError; got %T: %v", err, err)
	}
	if appErr.Code != core.ErrMachineNotFound {
		t.Errorf("code = %q, want %q", appErr.Code, core.ErrMachineNotFound)
	}
}

func TestMachineRepo_CountAliveByLicense_ExcludesDead(t *testing.T) {
	pool := integrationPool(t)
	f := newMachineFixture(t, pool)
	repo := NewMachineRepo(pool)

	// Seed 3 machines: active, stale, dead.
	statuses := []struct {
		fp     string
		status core.MachineStatus
	}{
		{"fp-alive-active", core.MachineStatusActive},
		{"fp-alive-stale", core.MachineStatusStale},
		{"fp-dead", core.MachineStatusDead},
	}
	for _, s := range statuses {
		m := newMachine(f, s.fp)
		if err := repo.UpsertActivation(f.ctx, m); err != nil {
			t.Fatalf("upsert %s: %v", s.fp, err)
		}
		if s.status != core.MachineStatusActive {
			if _, err := f.tx.Exec(f.ctx,
				`UPDATE machines SET status = $1 WHERE id = $2`,
				string(s.status), uuid.UUID(m.ID),
			); err != nil {
				t.Fatalf("set status %s: %v", s.fp, err)
			}
		}
	}

	count, err := repo.CountAliveByLicense(f.ctx, f.licenseID)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 2 {
		t.Errorf("count = %d, want 2 (active + stale; dead excluded)", count)
	}
}

func TestMachineRepo_MarkStaleExpired_OnlyRequireCheckout(t *testing.T) {
	pool := integrationPool(t)
	f := newMachineFixture(t, pool)
	repo := NewMachineRepo(pool)

	// The fixture's default policy has require_checkout=true.
	// Create a second policy with require_checkout=false.
	noCheckoutPolicyID := core.NewPolicyID()
	now := time.Now().UTC()
	noCheckoutPol := &domain.Policy{
		ID:                        noCheckoutPolicyID,
		AccountID:                 f.accountID,
		ProductID:                 f.productID,
		Name:                      "No Checkout",
		IsDefault:                 false,
		RequireCheckout:           false,
		CheckoutIntervalSec:       3600,
		MaxCheckoutDurationSec:    86400,
		CheckoutGraceSec:          3600,
		ExpirationStrategy:        core.ExpirationStrategyRevokeAccess,
		ExpirationBasis:           core.ExpirationBasisFromCreation,
		ComponentMatchingStrategy: core.ComponentMatchingAny,
		CreatedAt:                 now,
		UpdatedAt:                 now,
	}
	if err := NewPolicyRepo(pool).Create(f.ctx, noCheckoutPol); err != nil {
		t.Fatalf("create no-checkout policy: %v", err)
	}

	// Create a license referencing the no-checkout policy.
	noCheckoutLicenseID := seedLicenseForPolicy(t, f, pool, noCheckoutPolicyID, "NC")

	// Seed machine under require_checkout=true policy (fixture's license).
	mCheckout := newMachine(f, "fp-checkout-true")
	if err := repo.UpsertActivation(f.ctx, mCheckout); err != nil {
		t.Fatalf("upsert checkout: %v", err)
	}

	// Seed machine under require_checkout=false policy.
	mNoCheckout := &domain.Machine{
		ID:             core.NewMachineID(),
		AccountID:      f.accountID,
		LicenseID:      noCheckoutLicenseID,
		Fingerprint:    "fp-checkout-false",
		Metadata:       json.RawMessage("{}"),
		LeaseIssuedAt:  now,
		LeaseExpiresAt: now.Add(time.Hour),
		LastCheckinAt:  now,
		Status:         core.MachineStatusActive,
		Environment:    core.Environment("live"),
		CreatedAt:      now,
	}
	if err := repo.UpsertActivation(f.ctx, mNoCheckout); err != nil {
		t.Fatalf("upsert no-checkout: %v", err)
	}

	// Set both machines' lease_expires_at to the past.
	pastTime := now.Add(-10 * time.Minute)
	for _, id := range []core.MachineID{mCheckout.ID, mNoCheckout.ID} {
		if _, err := f.tx.Exec(f.ctx,
			`UPDATE machines SET lease_expires_at = $1 WHERE id = $2`,
			pastTime, uuid.UUID(id),
		); err != nil {
			t.Fatalf("set past lease: %v", err)
		}
	}

	// Run MarkStaleExpired.
	n, err := repo.MarkStaleExpired(f.ctx)
	if err != nil {
		t.Fatalf("mark stale: %v", err)
	}
	if n != 1 {
		t.Errorf("marked stale = %d, want 1 (only require_checkout=true)", n)
	}

	// Verify the checkout=true machine is stale.
	gotCheckout, err := repo.GetByID(f.ctx, mCheckout.ID)
	if err != nil {
		t.Fatalf("get checkout: %v", err)
	}
	if gotCheckout.Status != core.MachineStatusStale {
		t.Errorf("checkout machine status = %q, want stale", gotCheckout.Status)
	}

	// Verify the checkout=false machine is still active.
	gotNoCheckout, err := repo.GetByID(f.ctx, mNoCheckout.ID)
	if err != nil {
		t.Fatalf("get no-checkout: %v", err)
	}
	if gotNoCheckout.Status != core.MachineStatusActive {
		t.Errorf("no-checkout machine status = %q, want active", gotNoCheckout.Status)
	}
}

func TestMachineRepo_MarkDeadExpired_RespectsGracePeriod(t *testing.T) {
	pool := integrationPool(t)
	f := newMachineFixture(t, pool)
	repo := NewMachineRepo(pool)

	// The fixture policy has checkout_grace_sec=3600 (1 hour). Update
	// it to 86400 (24 hours) for this test.
	if _, err := f.tx.Exec(f.ctx,
		`UPDATE policies SET checkout_grace_sec = 86400 WHERE id = $1`,
		uuid.UUID(f.policyID),
	); err != nil {
		t.Fatalf("update grace: %v", err)
	}

	m := newMachine(f, "fp-grace")
	if err := repo.UpsertActivation(f.ctx, m); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	// Mark stale (prerequisite for MarkDeadExpired).
	if _, err := f.tx.Exec(f.ctx,
		`UPDATE machines SET status = 'stale' WHERE id = $1`,
		uuid.UUID(m.ID),
	); err != nil {
		t.Fatalf("mark stale: %v", err)
	}

	// Phase 1: lease_expires_at = now-100s. With grace=86400, the grace
	// window extends 86400s past lease expiry. 100s < 86400s → not dead.
	now := time.Now().UTC()
	if _, err := f.tx.Exec(f.ctx,
		`UPDATE machines SET lease_expires_at = $1 WHERE id = $2`,
		now.Add(-100*time.Second), uuid.UUID(m.ID),
	); err != nil {
		t.Fatalf("set lease past 100s: %v", err)
	}

	n, err := repo.MarkDeadExpired(f.ctx)
	if err != nil {
		t.Fatalf("mark dead (phase 1): %v", err)
	}
	if n != 0 {
		t.Errorf("phase 1: marked dead = %d, want 0 (within grace period)", n)
	}

	got, err := repo.GetByID(f.ctx, m.ID)
	if err != nil {
		t.Fatalf("get phase 1: %v", err)
	}
	if got.Status != core.MachineStatusStale {
		t.Errorf("phase 1 status = %q, want stale", got.Status)
	}

	// Phase 2: lease_expires_at = now-90000s. 90000 > 86400 → past grace → dead.
	if _, err := f.tx.Exec(f.ctx,
		`UPDATE machines SET lease_expires_at = $1 WHERE id = $2`,
		now.Add(-90000*time.Second), uuid.UUID(m.ID),
	); err != nil {
		t.Fatalf("set lease past 90000s: %v", err)
	}

	n, err = repo.MarkDeadExpired(f.ctx)
	if err != nil {
		t.Fatalf("mark dead (phase 2): %v", err)
	}
	if n != 1 {
		t.Errorf("phase 2: marked dead = %d, want 1", n)
	}

	got, err = repo.GetByID(f.ctx, m.ID)
	if err != nil {
		t.Fatalf("get phase 2: %v", err)
	}
	if got.Status != core.MachineStatusDead {
		t.Errorf("phase 2 status = %q, want dead", got.Status)
	}
}

func TestMachineRepo_DeleteByFingerprint(t *testing.T) {
	pool := integrationPool(t)
	f := newMachineFixture(t, pool)
	repo := NewMachineRepo(pool)

	// Happy path: activate then delete.
	m := newMachine(f, "fp-delete")
	if err := repo.UpsertActivation(f.ctx, m); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	if err := repo.DeleteByFingerprint(f.ctx, f.licenseID, "fp-delete"); err != nil {
		t.Fatalf("delete: %v", err)
	}

	got, err := repo.GetByFingerprint(f.ctx, f.licenseID, "fp-delete")
	if err != nil {
		t.Fatalf("get after delete: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil after delete; got %+v", got)
	}

	// Not-found path.
	err = repo.DeleteByFingerprint(f.ctx, f.licenseID, "fp-nonexistent")
	if err == nil {
		t.Fatal("expected error for non-existent fingerprint; got nil")
	}
	var appErr *core.AppError
	if !errors.As(err, &appErr) {
		t.Fatalf("expected *core.AppError; got %T: %v", err, err)
	}
	if appErr.Code != core.ErrMachineNotFound {
		t.Errorf("code = %q, want %q", appErr.Code, core.ErrMachineNotFound)
	}
}
