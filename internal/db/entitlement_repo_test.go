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
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Integration tests for EntitlementRepo.
//
// Gating, harness, and cleanup conventions mirror policy_repo_test.go:
// `-short` skips, `make test-all` runs against the dev Postgres, each
// test begins its own top-level tx and ROLLs it back on cleanup so
// nothing survives.

// entitlementFixture seeds account → product → policy → customer →
// license under a fresh rollback-only tx, with the RLS session vars
// populated. The full chain is needed because license_entitlements has
// a FK to licenses.
type entitlementFixture struct {
	ctx        context.Context
	tx         pgx.Tx
	accountID  core.AccountID
	productID  core.ProductID
	policyID   core.PolicyID
	customerID core.CustomerID
	licenseID  core.LicenseID
}

func newEntitlementFixture(t *testing.T, pool *pgxpool.Pool) *entitlementFixture {
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

	// Seed a default policy.
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
		KeyPrefix:          "GL_TEST_E",
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

	return &entitlementFixture{
		ctx:        ctx,
		tx:         tx,
		accountID:  accountID,
		productID:  productID,
		policyID:   policyID,
		customerID: customerID,
		licenseID:  licenseID,
	}
}

// newEntitlement returns a minimally populated domain.Entitlement for
// the fixture's account.
func newEntitlement(f *entitlementFixture, code, name string) *domain.Entitlement {
	now := time.Now().UTC()
	return &domain.Entitlement{
		ID:        core.NewEntitlementID(),
		AccountID: f.accountID,
		Code:      code,
		Name:      name,
		Metadata:  json.RawMessage("{}"),
		CreatedAt: now,
		UpdatedAt: now,
	}
}

// ---------- Tests ----------

func TestEntitlementRepo_CreateAndGet(t *testing.T) {
	pool := integrationPool(t)
	f := newEntitlementFixture(t, pool)
	repo := NewEntitlementRepo(pool)

	e := newEntitlement(f, "OFFLINE_SUPPORT", "Offline Support")
	e.Metadata = json.RawMessage(`{"tier":"premium"}`)
	if err := repo.Create(f.ctx, e); err != nil {
		t.Fatalf("create: %v", err)
	}

	got, err := repo.Get(f.ctx, e.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got == nil {
		t.Fatal("get: expected non-nil entitlement")
	}
	if got.ID != e.ID {
		t.Errorf("id = %v, want %v", got.ID, e.ID)
	}
	if got.Code != "OFFLINE_SUPPORT" {
		t.Errorf("code = %q, want OFFLINE_SUPPORT", got.Code)
	}
	if got.Name != "Offline Support" {
		t.Errorf("name = %q, want Offline Support", got.Name)
	}
	if got.AccountID != f.accountID {
		t.Errorf("account_id = %v, want %v", got.AccountID, f.accountID)
	}
	if got.CreatedAt.IsZero() {
		t.Error("created_at is zero")
	}
}

func TestEntitlementRepo_GetByCodes_CaseInsensitive(t *testing.T) {
	pool := integrationPool(t)
	f := newEntitlementFixture(t, pool)
	repo := NewEntitlementRepo(pool)

	e := newEntitlement(f, "OFFLINE_SUPPORT", "Offline Support")
	if err := repo.Create(f.ctx, e); err != nil {
		t.Fatalf("create: %v", err)
	}

	// Query with lowercase — should match via lower(code) = ANY($2).
	got, err := repo.GetByCodes(f.ctx, f.accountID, []string{"offline_support"})
	if err != nil {
		t.Fatalf("get by codes: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d rows, want 1", len(got))
	}
	if got[0].ID != e.ID {
		t.Errorf("id = %v, want %v", got[0].ID, e.ID)
	}
	// Code should come back in its original casing.
	if got[0].Code != "OFFLINE_SUPPORT" {
		t.Errorf("code = %q, want OFFLINE_SUPPORT (original casing preserved)", got[0].Code)
	}
}

func TestEntitlementRepo_UniqueCodePerAccount(t *testing.T) {
	pool := integrationPool(t)
	f := newEntitlementFixture(t, pool)
	repo := NewEntitlementRepo(pool)

	first := newEntitlement(f, "DUPE_CODE", "First")
	if err := repo.Create(f.ctx, first); err != nil {
		t.Fatalf("create first: %v", err)
	}

	// The unique index triggers at statement time and aborts the tx.
	// Wrap in a savepoint so the outer fixture tx stays alive.
	sp, err := f.tx.Begin(f.ctx)
	if err != nil {
		t.Fatalf("begin savepoint: %v", err)
	}
	spCtx := context.WithValue(f.ctx, ctxKey{}, sp)

	// Case-insensitive duplicate must collide too.
	second := newEntitlement(f, "dupe_code", "Second")
	err = repo.Create(spCtx, second)
	if err == nil {
		t.Fatal("expected unique violation; got nil")
	}
	_ = sp.Rollback(f.ctx)

	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		t.Fatalf("expected *pgconn.PgError; got %T: %v", err, err)
	}
	if pgErr.Code != "23505" {
		t.Errorf("code = %q, want 23505 (unique_violation)", pgErr.Code)
	}
}

func TestEntitlementRepo_AttachToPolicy_Idempotent(t *testing.T) {
	pool := integrationPool(t)
	f := newEntitlementFixture(t, pool)
	repo := NewEntitlementRepo(pool)

	e := newEntitlement(f, "FEAT_A", "Feature A")
	if err := repo.Create(f.ctx, e); err != nil {
		t.Fatalf("create: %v", err)
	}

	// Attach once.
	if err := repo.AttachToPolicy(f.ctx, f.policyID, []core.EntitlementID{e.ID}); err != nil {
		t.Fatalf("attach 1: %v", err)
	}

	// Attach the same code again — idempotent, no error.
	if err := repo.AttachToPolicy(f.ctx, f.policyID, []core.EntitlementID{e.ID}); err != nil {
		t.Fatalf("attach 2 (idempotent): %v", err)
	}

	codes, err := repo.ListPolicyCodes(f.ctx, f.policyID)
	if err != nil {
		t.Fatalf("list policy codes: %v", err)
	}
	if len(codes) != 1 {
		t.Errorf("len(codes) = %d, want 1 (no duplicates)", len(codes))
	}
	if len(codes) > 0 && codes[0] != "FEAT_A" {
		t.Errorf("codes[0] = %q, want FEAT_A", codes[0])
	}
}

func TestEntitlementRepo_ReplacePolicyAttachments(t *testing.T) {
	pool := integrationPool(t)
	f := newEntitlementFixture(t, pool)
	repo := NewEntitlementRepo(pool)

	eA := newEntitlement(f, "OLD_A", "Old A")
	eB := newEntitlement(f, "OLD_B", "Old B")
	eC := newEntitlement(f, "NEW_C", "New C")
	for _, e := range []*domain.Entitlement{eA, eB, eC} {
		if err := repo.Create(f.ctx, e); err != nil {
			t.Fatalf("create %s: %v", e.Code, err)
		}
	}

	// Attach old set.
	if err := repo.AttachToPolicy(f.ctx, f.policyID, []core.EntitlementID{eA.ID, eB.ID}); err != nil {
		t.Fatalf("attach old: %v", err)
	}

	// Replace with new set containing only NEW_C.
	if err := repo.ReplacePolicyAttachments(f.ctx, f.policyID, []core.EntitlementID{eC.ID}); err != nil {
		t.Fatalf("replace: %v", err)
	}

	codes, err := repo.ListPolicyCodes(f.ctx, f.policyID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(codes) != 1 {
		t.Fatalf("len(codes) = %d, want 1", len(codes))
	}
	if codes[0] != "NEW_C" {
		t.Errorf("codes[0] = %q, want NEW_C", codes[0])
	}
}

func TestEntitlementRepo_AttachToLicense(t *testing.T) {
	pool := integrationPool(t)
	f := newEntitlementFixture(t, pool)
	repo := NewEntitlementRepo(pool)

	e := newEntitlement(f, "LICENSE_FEAT", "License Feature")
	if err := repo.Create(f.ctx, e); err != nil {
		t.Fatalf("create: %v", err)
	}

	if err := repo.AttachToLicense(f.ctx, f.licenseID, []core.EntitlementID{e.ID}); err != nil {
		t.Fatalf("attach: %v", err)
	}

	codes, err := repo.ListLicenseCodes(f.ctx, f.licenseID)
	if err != nil {
		t.Fatalf("list license codes: %v", err)
	}
	if len(codes) != 1 {
		t.Fatalf("len(codes) = %d, want 1", len(codes))
	}
	if codes[0] != "LICENSE_FEAT" {
		t.Errorf("codes[0] = %q, want LICENSE_FEAT", codes[0])
	}
}

func TestEntitlementRepo_ResolveEffective_Union(t *testing.T) {
	pool := integrationPool(t)
	f := newEntitlementFixture(t, pool)
	repo := NewEntitlementRepo(pool)

	eA := newEntitlement(f, "ALPHA", "Alpha")
	eB := newEntitlement(f, "BETA", "Beta")
	for _, e := range []*domain.Entitlement{eA, eB} {
		if err := repo.Create(f.ctx, e); err != nil {
			t.Fatalf("create %s: %v", e.Code, err)
		}
	}

	// Attach ALPHA to policy, BETA to license.
	if err := repo.AttachToPolicy(f.ctx, f.policyID, []core.EntitlementID{eA.ID}); err != nil {
		t.Fatalf("attach to policy: %v", err)
	}
	if err := repo.AttachToLicense(f.ctx, f.licenseID, []core.EntitlementID{eB.ID}); err != nil {
		t.Fatalf("attach to license: %v", err)
	}

	effective, err := repo.ResolveEffective(f.ctx, f.licenseID)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(effective) != 2 {
		t.Fatalf("len(effective) = %d, want 2", len(effective))
	}
	// Sorted alphabetically.
	if effective[0] != "ALPHA" {
		t.Errorf("effective[0] = %q, want ALPHA", effective[0])
	}
	if effective[1] != "BETA" {
		t.Errorf("effective[1] = %q, want BETA", effective[1])
	}
}

func TestEntitlementRepo_DeleteBlockedByFK(t *testing.T) {
	pool := integrationPool(t)
	f := newEntitlementFixture(t, pool)
	repo := NewEntitlementRepo(pool)

	e := newEntitlement(f, "PINNED", "Pinned Feature")
	if err := repo.Create(f.ctx, e); err != nil {
		t.Fatalf("create: %v", err)
	}

	// Attach to policy so the FK constraint fires on delete.
	if err := repo.AttachToPolicy(f.ctx, f.policyID, []core.EntitlementID{e.ID}); err != nil {
		t.Fatalf("attach: %v", err)
	}

	// Wrap delete in a savepoint — the FK violation aborts the statement.
	sp, err := f.tx.Begin(f.ctx)
	if err != nil {
		t.Fatalf("begin savepoint: %v", err)
	}
	spCtx := context.WithValue(f.ctx, ctxKey{}, sp)
	err = repo.Delete(spCtx, e.ID)
	if err == nil {
		t.Fatal("expected FK violation; got nil")
	}
	_ = sp.Rollback(f.ctx)

	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		t.Fatalf("expected *pgconn.PgError; got %T: %v", err, err)
	}
	if pgErr.Code != "23503" {
		t.Errorf("code = %q, want 23503 (foreign_key_violation)", pgErr.Code)
	}
}

func TestEntitlementRepo_ListPolicyCodes_Sorted(t *testing.T) {
	pool := integrationPool(t)
	f := newEntitlementFixture(t, pool)
	repo := NewEntitlementRepo(pool)

	// Create 3 entitlements with codes that are NOT alphabetically ordered
	// by creation time.
	codes := []string{"CHARLIE", "ALPHA", "BRAVO"}
	var ids []core.EntitlementID
	for _, code := range codes {
		e := newEntitlement(f, code, code+" Feature")
		if err := repo.Create(f.ctx, e); err != nil {
			t.Fatalf("create %s: %v", code, err)
		}
		ids = append(ids, e.ID)
	}

	// Attach all to the policy.
	if err := repo.AttachToPolicy(f.ctx, f.policyID, ids); err != nil {
		t.Fatalf("attach: %v", err)
	}

	got, err := repo.ListPolicyCodes(f.ctx, f.policyID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3", len(got))
	}
	// Expect alphabetical order: ALPHA, BRAVO, CHARLIE.
	want := []string{"ALPHA", "BRAVO", "CHARLIE"}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("got[%d] = %q, want %q", i, got[i], w)
		}
	}
}

func TestEntitlementRepo_List_Pagination(t *testing.T) {
	pool := integrationPool(t)
	f := newEntitlementFixture(t, pool)
	repo := NewEntitlementRepo(pool)

	// Seed 7 entitlements with strictly increasing created_at so the
	// (created_at DESC, id DESC) keyset ordering is deterministic.
	base := time.Now().UTC().Add(-time.Hour)
	want := make([]core.EntitlementID, 0, 7)
	for i := 0; i < 7; i++ {
		e := newEntitlement(f, "CODE_"+string(rune('A'+i)), "Entitlement "+string(rune('A'+i)))
		e.CreatedAt = base.Add(time.Duration(i) * time.Second)
		e.UpdatedAt = e.CreatedAt
		if err := repo.Create(f.ctx, e); err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
		// want is highest-created-at first (descending order).
		want = append([]core.EntitlementID{e.ID}, want...)
	}

	// Page 1 (3 rows).
	page1, hasMore1, err := repo.List(f.ctx, f.accountID, "", core.Cursor{}, 3)
	if err != nil {
		t.Fatalf("page1: %v", err)
	}
	if len(page1) != 3 {
		t.Fatalf("page1 len = %d, want 3", len(page1))
	}
	if !hasMore1 {
		t.Error("page1 has_more = false, want true")
	}
	for i := 0; i < 3; i++ {
		if page1[i].ID != want[i] {
			t.Errorf("page1[%d] = %v, want %v", i, page1[i].ID, want[i])
		}
	}

	// Page 2 (3 rows).
	last1 := page1[len(page1)-1]
	cursor2 := core.Cursor{CreatedAt: last1.CreatedAt, ID: uuid.UUID(last1.ID)}
	page2, hasMore2, err := repo.List(f.ctx, f.accountID, "", cursor2, 3)
	if err != nil {
		t.Fatalf("page2: %v", err)
	}
	if len(page2) != 3 {
		t.Fatalf("page2 len = %d, want 3", len(page2))
	}
	if !hasMore2 {
		t.Error("page2 has_more = false, want true")
	}
	for i := 0; i < 3; i++ {
		if page2[i].ID != want[3+i] {
			t.Errorf("page2[%d] = %v, want %v", i, page2[i].ID, want[3+i])
		}
	}

	// Page 3 (1 row, tail).
	last2 := page2[len(page2)-1]
	cursor3 := core.Cursor{CreatedAt: last2.CreatedAt, ID: uuid.UUID(last2.ID)}
	page3, hasMore3, err := repo.List(f.ctx, f.accountID, "", cursor3, 3)
	if err != nil {
		t.Fatalf("page3: %v", err)
	}
	if len(page3) != 1 {
		t.Fatalf("page3 len = %d, want 1", len(page3))
	}
	if hasMore3 {
		t.Error("page3 has_more = true, want false")
	}
	if page3[0].ID != want[6] {
		t.Errorf("page3[0] = %v, want %v", page3[0].ID, want[6])
	}
}
