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

// Integration tests for CustomerRepo.
//
// Gating, harness, and cleanup conventions mirror policy_repo_test.go:
// `-short` skips, `make test-all` runs against the dev Postgres, each
// test begins its own top-level tx and ROLLs it back on cleanup so
// nothing survives.

// newCustomerIntegrationFixture seeds an account + product (no customer,
// no license) under a fresh rollback-only tx, with the RLS session vars
// populated. Separate from the policy fixture because several customer
// tests want to assert on the empty-state before inserting any rows.
type customerFixture struct {
	ctx       context.Context
	tx        pgx.Tx
	accountID core.AccountID
	productID core.ProductID
	policyID  core.PolicyID
}

func newCustomerFixture(t *testing.T, pool *pgxpool.Pool) *customerFixture {
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
		"Test Product", "test-product", "test-pub-key", []byte{0x00},
		`{}`,
	); err != nil {
		t.Fatalf("seed product: %v", err)
	}

	ctx = context.WithValue(ctx, ctxKey{}, tx)

	// Seed a default policy via PolicyRepo so we get the exact column
	// set and default metadata handling. CountReferencingLicenses needs
	// a valid policy_id FK to insert licenses.
	policyID := core.NewPolicyID()
	now := time.Now().UTC()
	policy := &domain.Policy{
		ID:                        policyID,
		AccountID:                 accountID,
		ProductID:                 productID,
		Name:                      "Default",
		IsDefault:                 true,
		ExpirationStrategy:        core.ExpirationStrategyRevokeAccess,
		ExpirationBasis:           core.ExpirationBasisFromCreation,
		CheckoutIntervalSec:       86400,
		MaxCheckoutDurationSec:    604800,
		ComponentMatchingStrategy: core.ComponentMatchingAny,
		CreatedAt:                 now,
		UpdatedAt:                 now,
	}
	if err := NewPolicyRepo(pool).Create(ctx, policy); err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	return &customerFixture{
		ctx:       ctx,
		tx:        tx,
		accountID: accountID,
		productID: productID,
		policyID:  policyID,
	}
}

// newCustomer returns a minimally populated domain.Customer for the
// fixture's account. Callers override email/name/metadata as needed.
func newCustomer(f *customerFixture, email string) *domain.Customer {
	now := time.Now().UTC()
	return &domain.Customer{
		ID:        core.NewCustomerID(),
		AccountID: f.accountID,
		Email:     email,
		Metadata:  json.RawMessage("{}"),
		CreatedAt: now,
		UpdatedAt: now,
	}
}

// newCustomerLicense returns a minimally-valid license owned by the
// given customer. Key prefix / hash / token are unique per call.
func newCustomerLicense(f *customerFixture, customerID core.CustomerID, suffix string) *domain.License {
	id := core.NewLicenseID()
	now := time.Now().UTC()
	return &domain.License{
		ID:                 id,
		AccountID:          f.accountID,
		ProductID:          f.productID,
		PolicyID:           f.policyID,
		CustomerID:         customerID,
		KeyPrefix:          "GL_TEST_" + suffix,
		KeyHash:            "hash_" + id.String(),
		Token:              "tok_" + id.String(),
		Status:             core.LicenseStatusActive,
		Environment:        core.Environment("live"),
		CreatedAt:          now,
		UpdatedAt:          now,
		CreatedByAccountID: f.accountID,
	}
}

func TestCustomerRepo_CreateAndGet(t *testing.T) {
	pool := integrationPool(t)
	f := newCustomerFixture(t, pool)
	repo := NewCustomerRepo(pool)

	name := "Alice"
	c := newCustomer(f, "alice@example.com")
	c.Name = &name
	c.Metadata = json.RawMessage(`{"tier":"gold"}`)
	if err := repo.Create(f.ctx, c); err != nil {
		t.Fatalf("create: %v", err)
	}

	got, err := repo.Get(f.ctx, c.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got == nil {
		t.Fatal("get: expected non-nil customer")
	}
	if got.ID != c.ID {
		t.Errorf("id = %v, want %v", got.ID, c.ID)
	}
	if got.Email != "alice@example.com" {
		t.Errorf("email = %q, want alice@example.com", got.Email)
	}
	if got.Name == nil || *got.Name != "Alice" {
		t.Errorf("name = %v, want Alice", got.Name)
	}
	if !jsonEqual(t, got.Metadata, `{"tier":"gold"}`) {
		t.Errorf("metadata = %s, want {\"tier\":\"gold\"}", string(got.Metadata))
	}
}

// jsonEqual compares two JSON payloads for semantic equality. Postgres
// jsonb normalizes whitespace (adding spaces after colons), so a byte
// compare against the raw input string fails spuriously.
func jsonEqual(t *testing.T, got json.RawMessage, want string) bool {
	t.Helper()
	var a, b any
	if err := json.Unmarshal(got, &a); err != nil {
		t.Fatalf("jsonEqual: unmarshal got %q: %v", string(got), err)
	}
	if err := json.Unmarshal([]byte(want), &b); err != nil {
		t.Fatalf("jsonEqual: unmarshal want %q: %v", want, err)
	}
	ga, _ := json.Marshal(a)
	gb, _ := json.Marshal(b)
	return string(ga) == string(gb)
}

func TestCustomerRepo_GetByEmail_CaseInsensitive(t *testing.T) {
	pool := integrationPool(t)
	f := newCustomerFixture(t, pool)
	repo := NewCustomerRepo(pool)

	c := newCustomer(f, "Alice@Example.com")
	if err := repo.Create(f.ctx, c); err != nil {
		t.Fatalf("create: %v", err)
	}

	got, err := repo.GetByEmail(f.ctx, f.accountID, "alice@example.com")
	if err != nil {
		t.Fatalf("get by email: %v", err)
	}
	if got == nil {
		t.Fatal("expected match; got nil")
	}
	if got.ID != c.ID {
		t.Errorf("id = %v, want %v", got.ID, c.ID)
	}
	// Email should come back in its original casing.
	if got.Email != "Alice@Example.com" {
		t.Errorf("email = %q, want Alice@Example.com (original casing preserved)", got.Email)
	}
}

func TestCustomerRepo_GetByEmail_NotFound(t *testing.T) {
	pool := integrationPool(t)
	f := newCustomerFixture(t, pool)
	repo := NewCustomerRepo(pool)

	got, err := repo.GetByEmail(f.ctx, f.accountID, "nobody@example.com")
	if err != nil {
		t.Fatalf("get by email: %v", err)
	}
	if got != nil {
		t.Errorf("expected (nil, nil); got %+v", got)
	}
}

func TestCustomerRepo_UniqueEmailPerAccount(t *testing.T) {
	pool := integrationPool(t)
	f := newCustomerFixture(t, pool)
	repo := NewCustomerRepo(pool)

	first := newCustomer(f, "dup@example.com")
	if err := repo.Create(f.ctx, first); err != nil {
		t.Fatalf("create first: %v", err)
	}

	// The unique index triggers at statement time and aborts the tx.
	// Wrap in a savepoint (pgx: tx.Begin on an existing tx) so the
	// outer fixture tx stays alive for subsequent assertions / cleanup.
	sp, err := f.tx.Begin(f.ctx)
	if err != nil {
		t.Fatalf("begin savepoint: %v", err)
	}
	spCtx := context.WithValue(f.ctx, ctxKey{}, sp)

	// Case-insensitive duplicate must collide too. The repo now translates
	// the 23505 unique-violation into a typed AppError so handlers return
	// 409 instead of leaking a 500 on the direct POST /v1/customers path.
	second := newCustomer(f, "DUP@example.com")
	err = repo.Create(spCtx, second)
	if err == nil {
		t.Fatal("expected unique violation; got nil")
	}
	_ = sp.Rollback(f.ctx)

	var appErr *core.AppError
	if !errors.As(err, &appErr) {
		t.Fatalf("expected *core.AppError; got %T: %v", err, err)
	}
	if appErr.Code != core.ErrCustomerAlreadyExists {
		t.Errorf("code = %q, want %q", appErr.Code, core.ErrCustomerAlreadyExists)
	}

	// Sanity check: outer tx is still usable after rollback-to-savepoint.
	got, gerr := repo.Get(f.ctx, first.ID)
	if gerr != nil {
		t.Fatalf("get first after savepoint rollback: %v", gerr)
	}
	if got == nil || got.ID != first.ID {
		t.Errorf("first row missing after savepoint rollback")
	}
}

func TestCustomerRepo_UpsertByEmail_Idempotent(t *testing.T) {
	pool := integrationPool(t)
	f := newCustomerFixture(t, pool)
	repo := NewCustomerRepo(pool)

	name1 := "Alice"
	got1, inserted1, err := repo.UpsertByEmail(f.ctx, f.accountID, "alice@example.com", &name1, nil, nil)
	if err != nil {
		t.Fatalf("upsert 1: %v", err)
	}
	if !inserted1 {
		t.Error("first upsert: inserted = false, want true")
	}
	if got1 == nil {
		t.Fatal("first upsert: nil customer")
	}

	// Second call with the same email but different name must return
	// the existing row UNCHANGED (first-write-wins, inserted=false).
	name2 := "Different"
	got2, inserted2, err := repo.UpsertByEmail(f.ctx, f.accountID, "Alice@Example.com", &name2, nil, nil)
	if err != nil {
		t.Fatalf("upsert 2: %v", err)
	}
	if inserted2 {
		t.Error("second upsert: inserted = true, want false")
	}
	if got2 == nil {
		t.Fatal("second upsert: nil customer")
	}
	if got2.ID != got1.ID {
		t.Errorf("second upsert: id = %v, want %v", got2.ID, got1.ID)
	}
	if got2.Name == nil || *got2.Name != "Alice" {
		t.Errorf("second upsert: name = %v, want Alice (first-write-wins)", got2.Name)
	}
}

func TestCustomerRepo_UpsertByEmail_DifferentAccountsDistinct(t *testing.T) {
	pool := integrationPool(t)
	f := newCustomerFixture(t, pool)
	repo := NewCustomerRepo(pool)

	// Seed a second account inside the same tx so both writes roll back.
	account2ID := core.NewAccountID()
	slug2 := "test2-" + account2ID.String()[:8]
	if _, err := f.tx.Exec(f.ctx,
		`INSERT INTO accounts (id, name, slug, created_at) VALUES ($1, $2, $3, NOW())`,
		uuid.UUID(account2ID), "Test Account 2", slug2,
	); err != nil {
		t.Fatalf("seed account 2: %v", err)
	}

	got1, inserted1, err := repo.UpsertByEmail(f.ctx, f.accountID, "shared@example.com", nil, nil, nil)
	if err != nil {
		t.Fatalf("upsert acc1: %v", err)
	}
	if !inserted1 {
		t.Error("upsert acc1: inserted = false, want true")
	}

	// Switch RLS context to account 2 so the insert is allowed and the
	// GetByEmail inside UpsertByEmail doesn't trip the unique constraint
	// from account 1.
	if _, err := f.tx.Exec(f.ctx,
		`SELECT set_config('app.current_account_id', $1, true)`, account2ID.String()); err != nil {
		t.Fatalf("set_config account 2: %v", err)
	}

	got2, inserted2, err := repo.UpsertByEmail(f.ctx, account2ID, "shared@example.com", nil, nil, nil)
	if err != nil {
		t.Fatalf("upsert acc2: %v", err)
	}
	if !inserted2 {
		t.Error("upsert acc2: inserted = false, want true")
	}
	if got1.ID == got2.ID {
		t.Errorf("expected distinct IDs across accounts; got same: %v", got1.ID)
	}
	if got2.AccountID != account2ID {
		t.Errorf("acc2 account_id = %v, want %v", got2.AccountID, account2ID)
	}
}

func TestCustomerRepo_Update(t *testing.T) {
	pool := integrationPool(t)
	f := newCustomerFixture(t, pool)
	repo := NewCustomerRepo(pool)

	original := "Alice"
	c := newCustomer(f, "alice@example.com")
	c.Name = &original
	c.Metadata = json.RawMessage(`{"tier":"gold"}`)
	// Force a visibly-old updated_at so NOW() on UPDATE is strictly greater.
	c.CreatedAt = time.Now().UTC().Add(-1 * time.Hour)
	c.UpdatedAt = c.CreatedAt
	if err := repo.Create(f.ctx, c); err != nil {
		t.Fatalf("create: %v", err)
	}
	originalUpdatedAt := c.UpdatedAt

	// Mutate name + metadata and call Update.
	newName := "Alice Renamed"
	c.Name = &newName
	c.Metadata = json.RawMessage(`{"tier":"platinum"}`)
	if err := repo.Update(f.ctx, c); err != nil {
		t.Fatalf("update: %v", err)
	}
	if c.Name == nil || *c.Name != "Alice Renamed" {
		t.Errorf("after update c.Name = %v, want Alice Renamed", c.Name)
	}
	if !c.UpdatedAt.After(originalUpdatedAt) {
		t.Errorf("updated_at = %v, want after %v", c.UpdatedAt, originalUpdatedAt)
	}

	got, err := repo.Get(f.ctx, c.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got == nil {
		t.Fatal("get: nil after update")
	}
	if got.Name == nil || *got.Name != "Alice Renamed" {
		t.Errorf("persisted name = %v, want Alice Renamed", got.Name)
	}
	if !jsonEqual(t, got.Metadata, `{"tier":"platinum"}`) {
		t.Errorf("persisted metadata = %s, want {\"tier\":\"platinum\"}", string(got.Metadata))
	}
}

func TestCustomerRepo_Delete_Success(t *testing.T) {
	pool := integrationPool(t)
	f := newCustomerFixture(t, pool)
	repo := NewCustomerRepo(pool)

	c := newCustomer(f, "doomed@example.com")
	if err := repo.Create(f.ctx, c); err != nil {
		t.Fatalf("create: %v", err)
	}

	if err := repo.Delete(f.ctx, c.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}

	got, err := repo.Get(f.ctx, c.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got != nil {
		t.Errorf("expected (nil, nil) after delete; got %+v", got)
	}

	// Deleting again reports customer_not_found via the typed AppError.
	err = repo.Delete(f.ctx, c.ID)
	if err == nil {
		t.Fatal("expected not-found on second delete; got nil")
	}
}

func TestCustomerRepo_CountReferencingLicenses(t *testing.T) {
	pool := integrationPool(t)
	f := newCustomerFixture(t, pool)
	repo := NewCustomerRepo(pool)
	lrepo := NewLicenseRepo(pool)

	c := newCustomer(f, "active@example.com")
	if err := repo.Create(f.ctx, c); err != nil {
		t.Fatalf("create customer: %v", err)
	}

	// Empty state: zero references.
	n, err := repo.CountReferencingLicenses(f.ctx, c.ID)
	if err != nil {
		t.Fatalf("count empty: %v", err)
	}
	if n != 0 {
		t.Errorf("count empty = %d, want 0", n)
	}

	// Seed two licenses pointing at this customer.
	for i, suffix := range []string{"a", "b"} {
		if err := lrepo.Create(f.ctx, newCustomerLicense(f, c.ID, suffix)); err != nil {
			t.Fatalf("create license %d: %v", i, err)
		}
	}

	n, err = repo.CountReferencingLicenses(f.ctx, c.ID)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 2 {
		t.Errorf("count = %d, want 2", n)
	}
}

func TestCustomerRepo_List_Pagination(t *testing.T) {
	pool := integrationPool(t)
	f := newCustomerFixture(t, pool)
	repo := NewCustomerRepo(pool)

	// 7 customers with strictly-increasing created_at so the
	// (created_at DESC, id DESC) keyset ordering is deterministic.
	base := time.Now().UTC().Add(-time.Hour)
	want := make([]core.CustomerID, 0, 7)
	for i := 0; i < 7; i++ {
		c := newCustomer(f, "user"+uuid.NewString()[:8]+"@example.com")
		c.CreatedAt = base.Add(time.Duration(i) * time.Second)
		c.UpdatedAt = c.CreatedAt
		if err := repo.Create(f.ctx, c); err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
		// highest created_at first
		want = append([]core.CustomerID{c.ID}, want...)
	}

	// Page 1 (3 rows).
	page1, hasMore1, err := repo.List(f.ctx, f.accountID, domain.CustomerListFilter{}, core.Cursor{}, 3)
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
	page2, hasMore2, err := repo.List(f.ctx, f.accountID, domain.CustomerListFilter{}, cursor2, 3)
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
	page3, hasMore3, err := repo.List(f.ctx, f.accountID, domain.CustomerListFilter{}, cursor3, 3)
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

func TestCustomerRepo_List_EmailFilter(t *testing.T) {
	pool := integrationPool(t)
	f := newCustomerFixture(t, pool)
	repo := NewCustomerRepo(pool)

	// Seed a mix: 3 alice-prefixed, 2 bob-prefixed.
	seedEmails := []string{
		"alice1@example.com",
		"alice2@example.com",
		"Alice3@Example.com", // case-insensitive match
		"bob1@example.com",
		"bob2@example.com",
	}
	for i, e := range seedEmails {
		c := newCustomer(f, e)
		// Spread created_at so ordering is deterministic.
		c.CreatedAt = time.Now().UTC().Add(time.Duration(-len(seedEmails)+i) * time.Second)
		c.UpdatedAt = c.CreatedAt
		if err := repo.Create(f.ctx, c); err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
	}

	// Filter by "alic" — must match all three alices (case-insensitive),
	// not the bobs.
	got, hasMore, err := repo.List(
		f.ctx, f.accountID,
		domain.CustomerListFilter{Email: "alic"},
		core.Cursor{}, 50,
	)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if hasMore {
		t.Error("has_more = true, want false (single page)")
	}
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3", len(got))
	}
	for _, c := range got {
		lower := c.Email
		if len(lower) < 5 || (lower[:5] != "alice" && lower[:5] != "Alice") {
			t.Errorf("unexpected email in filtered result: %q", c.Email)
		}
	}

	// Filter by "nobody" — must return zero rows.
	empty, _, err := repo.List(
		f.ctx, f.accountID,
		domain.CustomerListFilter{Email: "nobody"},
		core.Cursor{}, 50,
	)
	if err != nil {
		t.Fatalf("list nobody: %v", err)
	}
	if len(empty) != 0 {
		t.Errorf("len = %d, want 0", len(empty))
	}
}

// seedPartnerAccount inserts a second account row inside the fixture tx
// and returns its id + name + slug, mirroring the pattern used by
// TestCustomerRepo_UpsertByEmail_DifferentAccountsDistinct. The row is
// rolled back with the fixture.
func seedPartnerAccount(t *testing.T, f *customerFixture, name string) (core.AccountID, string, string) {
	t.Helper()
	id := core.NewAccountID()
	slug := "partner-" + id.String()[:8]
	if _, err := f.tx.Exec(f.ctx,
		`INSERT INTO accounts (id, name, slug, created_at) VALUES ($1, $2, $3, NOW())`,
		uuid.UUID(id), name, slug,
	); err != nil {
		t.Fatalf("seed partner account: %v", err)
	}
	return id, name, slug
}

// Sharing v2 regression: Get must populate CreatedByAccount for
// grantee-created customers so the dashboard can badge partner-sourced
// rows without an N+1 lookup. Seeds a second account in the fixture tx,
// creates a customer whose created_by_account_id points at it, and
// asserts the embedded AccountSummary echoes the partner row's
// name + slug.
func TestCustomerRepo_GetByID_PopulatesCreatedByAccountWhenPresent(t *testing.T) {
	pool := integrationPool(t)
	f := newCustomerFixture(t, pool)
	repo := NewCustomerRepo(pool)

	partnerID, partnerName, partnerSlug := seedPartnerAccount(t, f, "Acme Partner")

	c := newCustomer(f, "partner-customer@example.com")
	c.CreatedByAccountID = &partnerID
	if err := repo.Create(f.ctx, c); err != nil {
		t.Fatalf("create: %v", err)
	}

	got, err := repo.Get(f.ctx, c.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got == nil {
		t.Fatal("get: expected non-nil customer")
	}
	if got.CreatedByAccountID == nil || *got.CreatedByAccountID != partnerID {
		t.Fatalf("created_by_account_id = %v, want %v", got.CreatedByAccountID, partnerID)
	}
	if got.CreatedByAccount == nil {
		t.Fatal("expected CreatedByAccount populated via JOIN; got nil")
	}
	if got.CreatedByAccount.ID != partnerID {
		t.Errorf("CreatedByAccount.ID = %v, want %v", got.CreatedByAccount.ID, partnerID)
	}
	if got.CreatedByAccount.Name != partnerName {
		t.Errorf("CreatedByAccount.Name = %q, want %q", got.CreatedByAccount.Name, partnerName)
	}
	if got.CreatedByAccount.Slug != partnerSlug {
		t.Errorf("CreatedByAccount.Slug = %q, want %q", got.CreatedByAccount.Slug, partnerSlug)
	}
}

// Sharing v2 regression: Get must leave CreatedByAccount == nil for
// vendor-created customers (created_by_account_id IS NULL). Confirms
// the LEFT JOIN returns the customer row even when no creator account
// matches, and that the adapter's FK-nil guard keeps the embedded
// summary suppressed in that case.
func TestCustomerRepo_GetByID_NilCreatedByAccountForVendorCreated(t *testing.T) {
	pool := integrationPool(t)
	f := newCustomerFixture(t, pool)
	repo := NewCustomerRepo(pool)

	c := newCustomer(f, "vendor-customer@example.com") // no CreatedByAccountID
	if err := repo.Create(f.ctx, c); err != nil {
		t.Fatalf("create: %v", err)
	}

	got, err := repo.Get(f.ctx, c.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got == nil {
		t.Fatal("get: expected non-nil customer")
	}
	if got.CreatedByAccountID != nil {
		t.Errorf("created_by_account_id = %v, want nil", got.CreatedByAccountID)
	}
	if got.CreatedByAccount != nil {
		t.Errorf("CreatedByAccount = %+v, want nil", got.CreatedByAccount)
	}
}
