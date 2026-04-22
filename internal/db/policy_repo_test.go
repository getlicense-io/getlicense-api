package db

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Integration tests for PolicyRepo.
//
// Gated on `go test -short`: `make test` passes `-short` and skips;
// `make test-all` runs them against the dev Postgres reached via
// DATABASE_URL (default postgres://getlicense:getlicense@localhost:5432/getlicense).
// The codebase does not use a //go:build integration tag — `make
// test-all` runs `go test ./... -count=1` with no tags, so tests behind
// a build tag would be silently skipped.
//
// Each test opens its own pool, begins a top-level tx, injects it into
// the context under ctxKey{} so the repo's conn(ctx, pool) helper picks
// it up, sets the RLS session vars via set_config, seeds an account +
// product, and ALWAYS rolls back on cleanup. No test pollutes the dev DB.

const integrationDefaultDBURL = "postgres://getlicense:getlicense@localhost:5432/getlicense?sslmode=disable"

// integrationPool connects to the test Postgres. Skips the test when
// `-short` is passed or the DB is unreachable.
func integrationPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test (-short)")
	}
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		url = integrationDefaultDBURL
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Skipf("integration DB unavailable (pool): %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Skipf("integration DB unavailable (ping): %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// integrationFixture returns a context whose ambient tx is already
// scoped to a freshly-seeded (account, product, customer) in the
// live environment, plus those seeded IDs. The tx is rolled back on
// cleanup so nothing survives the test.
type integrationFixture struct {
	ctx        context.Context
	tx         pgx.Tx
	accountID  core.AccountID
	productID  core.ProductID
	customerID core.CustomerID
}

func newIntegrationFixture(t *testing.T, pool *pgxpool.Pool) *integrationFixture {
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

	// Seed account. Slug is unique per-row; use the UUID so parallel
	// runs never collide.
	slug := "test-" + accountID.String()[:8]
	if _, err := tx.Exec(ctx,
		`INSERT INTO accounts (id, name, slug, created_at) VALUES ($1, $2, $3, NOW())`,
		uuid.UUID(accountID), "Test Account", slug,
	); err != nil {
		t.Fatalf("seed account: %v", err)
	}

	// Seed product. Raw INSERT — we don't need real crypto material
	// for policy-repo tests; the schema just needs non-null bytes.
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

	// Seed a customer so licenses created in fixture-driven tests
	// satisfy the NOT NULL customer_id FK added in migration 021.
	customerID := core.NewCustomerID()
	if _, err := tx.Exec(ctx,
		`INSERT INTO customers (id, account_id, email, metadata, created_at, updated_at)
		 VALUES ($1, $2, $3, '{}'::jsonb, NOW(), NOW())`,
		uuid.UUID(customerID), uuid.UUID(accountID),
		"fixture-"+accountID.String()[:8]+"@example.com",
	); err != nil {
		t.Fatalf("seed customer: %v", err)
	}

	ctx = context.WithValue(ctx, ctxKey{}, tx)
	return &integrationFixture{
		ctx:        ctx,
		tx:         tx,
		accountID:  accountID,
		productID:  productID,
		customerID: customerID,
	}
}

// newPolicy returns a populated *domain.Policy with sensible defaults
// for the fixture. Callers override fields as needed.
func newPolicy(f *integrationFixture) *domain.Policy {
	now := time.Now().UTC()
	return &domain.Policy{
		ID:                        core.NewPolicyID(),
		AccountID:                 f.accountID,
		ProductID:                 f.productID,
		Name:                      "Default",
		IsDefault:                 false,
		ExpirationStrategy:        core.ExpirationStrategyRevokeAccess,
		ExpirationBasis:           core.ExpirationBasisFromCreation,
		CheckoutIntervalSec:       86400,
		MaxCheckoutDurationSec:    604800,
		ComponentMatchingStrategy: core.ComponentMatchingAny,
		CreatedAt:                 now,
		UpdatedAt:                 now,
	}
}

// newLicense returns a minimally-valid *domain.License attached to the
// given policy. Every license gets a unique key_prefix + key_hash so
// inserts don't collide inside a single test.
func newLicense(f *integrationFixture, policyID core.PolicyID, suffix string) *domain.License {
	id := core.NewLicenseID()
	now := time.Now().UTC()
	return &domain.License{
		ID:                 id,
		AccountID:          f.accountID,
		ProductID:          f.productID,
		PolicyID:           policyID,
		CustomerID:         f.customerID,
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

func TestPolicyRepo_CreateAndGet(t *testing.T) {
	pool := integrationPool(t)
	f := newIntegrationFixture(t, pool)
	repo := NewPolicyRepo(pool)

	p := newPolicy(f)
	p.Name = "Premium"
	if err := repo.Create(f.ctx, p); err != nil {
		t.Fatalf("create: %v", err)
	}

	got, err := repo.Get(f.ctx, p.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got == nil {
		t.Fatal("get: expected non-nil policy")
	}
	if got.ID != p.ID {
		t.Errorf("id = %v, want %v", got.ID, p.ID)
	}
	if got.Name != "Premium" {
		t.Errorf("name = %q, want Premium", got.Name)
	}
	if got.ProductID != f.productID {
		t.Errorf("product_id = %v, want %v", got.ProductID, f.productID)
	}
	if got.ExpirationStrategy != core.ExpirationStrategyRevokeAccess {
		t.Errorf("expiration_strategy = %q", got.ExpirationStrategy)
	}
}

// TestPolicyRepo_Create_BogusProduct_ReturnsProductNotFound covers the
// FK-violation classification in PolicyRepo.Create. Without the
// classification, POST /v1/products/:missing/policies leaked a 500
// (raw 23503 bubbling through the error handler) instead of a 404.
func TestPolicyRepo_Create_BogusProduct_ReturnsProductNotFound(t *testing.T) {
	pool := integrationPool(t)
	f := newIntegrationFixture(t, pool)
	repo := NewPolicyRepo(pool)

	// The FK violation aborts the outer tx so we wrap in a savepoint
	// to keep the fixture's rollback-on-cleanup semantic intact.
	sp, err := f.tx.Begin(f.ctx)
	if err != nil {
		t.Fatalf("begin savepoint: %v", err)
	}
	spCtx := context.WithValue(f.ctx, ctxKey{}, sp)

	p := newPolicy(f)
	p.ProductID = core.NewProductID() // bogus — no such product
	err = repo.Create(spCtx, p)
	_ = sp.Rollback(f.ctx)

	if err == nil {
		t.Fatal("expected error; got nil")
	}
	var appErr *core.AppError
	if !errors.As(err, &appErr) {
		t.Fatalf("expected *core.AppError; got %T: %v", err, err)
	}
	if appErr.Code != core.ErrProductNotFound {
		t.Errorf("code = %q, want %q", appErr.Code, core.ErrProductNotFound)
	}
}

func TestPolicyRepo_GetNotFound(t *testing.T) {
	pool := integrationPool(t)
	f := newIntegrationFixture(t, pool)
	repo := NewPolicyRepo(pool)

	got, err := repo.Get(f.ctx, core.NewPolicyID())
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got != nil {
		t.Errorf("expected (nil, nil); got %+v", got)
	}
}

func TestPolicyRepo_UniqueDefaultPerProduct(t *testing.T) {
	pool := integrationPool(t)
	f := newIntegrationFixture(t, pool)
	repo := NewPolicyRepo(pool)

	first := newPolicy(f)
	first.Name = "First"
	first.IsDefault = true
	if err := repo.Create(f.ctx, first); err != nil {
		t.Fatalf("create first: %v", err)
	}

	second := newPolicy(f)
	second.Name = "Second"
	second.IsDefault = true
	err := repo.Create(f.ctx, second)
	if err == nil {
		t.Fatal("expected unique violation; got nil")
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		t.Fatalf("expected *pgconn.PgError; got %T: %v", err, err)
	}
	if pgErr.Code != "23505" {
		t.Errorf("code = %q, want 23505", pgErr.Code)
	}
	if pgErr.ConstraintName != "policies_default_per_product" {
		t.Errorf("constraint = %q, want policies_default_per_product", pgErr.ConstraintName)
	}
}

func TestPolicyRepo_GetDefaultForProduct(t *testing.T) {
	pool := integrationPool(t)
	f := newIntegrationFixture(t, pool)
	repo := NewPolicyRepo(pool)

	// No default yet — should return (nil, nil).
	got, err := repo.GetDefaultForProduct(f.ctx, f.productID)
	if err != nil {
		t.Fatalf("get default (empty): %v", err)
	}
	if got != nil {
		t.Errorf("expected nil before any default exists; got %+v", got)
	}

	p := newPolicy(f)
	p.Name = "Default"
	p.IsDefault = true
	if err := repo.Create(f.ctx, p); err != nil {
		t.Fatalf("create: %v", err)
	}

	got, err = repo.GetDefaultForProduct(f.ctx, f.productID)
	if err != nil {
		t.Fatalf("get default: %v", err)
	}
	if got == nil || got.ID != p.ID {
		t.Errorf("got = %+v, want id %v", got, p.ID)
	}
}

func TestPolicyRepo_SetDefault(t *testing.T) {
	pool := integrationPool(t)
	f := newIntegrationFixture(t, pool)
	repo := NewPolicyRepo(pool)

	first := newPolicy(f)
	first.Name = "First"
	first.IsDefault = true
	if err := repo.Create(f.ctx, first); err != nil {
		t.Fatalf("create first: %v", err)
	}

	second := newPolicy(f)
	second.Name = "Second"
	second.IsDefault = false
	if err := repo.Create(f.ctx, second); err != nil {
		t.Fatalf("create second: %v", err)
	}

	if err := repo.SetDefault(f.ctx, f.productID, second.ID); err != nil {
		t.Fatalf("set default: %v", err)
	}

	gotFirst, err := repo.Get(f.ctx, first.ID)
	if err != nil {
		t.Fatalf("get first: %v", err)
	}
	if gotFirst.IsDefault {
		t.Errorf("first.IsDefault = true, want false after demotion")
	}

	gotSecond, err := repo.Get(f.ctx, second.ID)
	if err != nil {
		t.Fatalf("get second: %v", err)
	}
	if !gotSecond.IsDefault {
		t.Errorf("second.IsDefault = false, want true after promotion")
	}

	gotDefault, err := repo.GetDefaultForProduct(f.ctx, f.productID)
	if err != nil {
		t.Fatalf("get default for product: %v", err)
	}
	if gotDefault == nil || gotDefault.ID != second.ID {
		t.Errorf("default = %+v, want id %v", gotDefault, second.ID)
	}
}

func TestPolicyRepo_ReassignLicensesFromPolicy(t *testing.T) {
	pool := integrationPool(t)
	f := newIntegrationFixture(t, pool)
	repo := NewPolicyRepo(pool)
	lrepo := NewLicenseRepo(pool)

	from := newPolicy(f)
	from.Name = "From"
	from.IsDefault = true
	if err := repo.Create(f.ctx, from); err != nil {
		t.Fatalf("create from: %v", err)
	}
	to := newPolicy(f)
	to.Name = "To"
	to.IsDefault = false
	if err := repo.Create(f.ctx, to); err != nil {
		t.Fatalf("create to: %v", err)
	}

	l1 := newLicense(f, from.ID, "one")
	l2 := newLicense(f, from.ID, "two")
	if err := lrepo.Create(f.ctx, l1); err != nil {
		t.Fatalf("create l1: %v", err)
	}
	if err := lrepo.Create(f.ctx, l2); err != nil {
		t.Fatalf("create l2: %v", err)
	}

	n, err := repo.ReassignLicensesFromPolicy(f.ctx, from.ID, to.ID)
	if err != nil {
		t.Fatalf("reassign: %v", err)
	}
	if n != 2 {
		t.Errorf("reassigned = %d, want 2", n)
	}

	for _, id := range []core.LicenseID{l1.ID, l2.ID} {
		got, err := lrepo.GetByID(f.ctx, id)
		if err != nil {
			t.Fatalf("get license %v: %v", id, err)
		}
		if got == nil {
			t.Fatalf("license %v missing", id)
		}
		if got.PolicyID != to.ID {
			t.Errorf("license %v policy_id = %v, want %v", id, got.PolicyID, to.ID)
		}
	}
}

func TestPolicyRepo_CountReferencingLicenses(t *testing.T) {
	pool := integrationPool(t)
	f := newIntegrationFixture(t, pool)
	repo := NewPolicyRepo(pool)
	lrepo := NewLicenseRepo(pool)

	p := newPolicy(f)
	p.IsDefault = true
	if err := repo.Create(f.ctx, p); err != nil {
		t.Fatalf("create: %v", err)
	}

	n, err := repo.CountReferencingLicenses(f.ctx, p.ID)
	if err != nil {
		t.Fatalf("count (empty): %v", err)
	}
	if n != 0 {
		t.Errorf("count (empty) = %d, want 0", n)
	}

	for i, suffix := range []string{"a", "b", "c"} {
		if err := lrepo.Create(f.ctx, newLicense(f, p.ID, suffix)); err != nil {
			t.Fatalf("create license %d: %v", i, err)
		}
	}

	n, err = repo.CountReferencingLicenses(f.ctx, p.ID)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 3 {
		t.Errorf("count = %d, want 3", n)
	}
}

func TestPolicyRepo_DeleteInUseFails(t *testing.T) {
	pool := integrationPool(t)
	f := newIntegrationFixture(t, pool)
	repo := NewPolicyRepo(pool)
	lrepo := NewLicenseRepo(pool)

	p := newPolicy(f)
	p.IsDefault = true
	if err := repo.Create(f.ctx, p); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := lrepo.Create(f.ctx, newLicense(f, p.ID, "one")); err != nil {
		t.Fatalf("create license: %v", err)
	}

	// licenses.policy_id REFERENCES policies(id) with the default
	// NO ACTION behavior — attempting to delete a referenced policy
	// must raise a foreign-key violation (SQLSTATE 23503).
	//
	// The FK is enforced at statement time, which aborts the ambient
	// tx. Wrap the delete in a savepoint so the outer fixture tx
	// stays alive for subsequent assertions / cleanup.
	sp, err := f.tx.Begin(f.ctx)
	if err != nil {
		t.Fatalf("begin savepoint: %v", err)
	}
	spCtx := context.WithValue(f.ctx, ctxKey{}, sp)
	err = repo.Delete(spCtx, p.ID)
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

func TestPolicyRepo_ListByProduct_Pagination(t *testing.T) {
	pool := integrationPool(t)
	f := newIntegrationFixture(t, pool)
	repo := NewPolicyRepo(pool)

	// Create 10 policies with strictly increasing created_at so the
	// (created_at DESC, id DESC) keyset ordering is deterministic.
	// Only one can be is_default, so the rest stay non-default.
	base := time.Now().UTC().Add(-time.Hour)
	want := make([]core.PolicyID, 0, 10)
	for i := 0; i < 10; i++ {
		p := newPolicy(f)
		p.Name = "p"
		p.IsDefault = false
		p.CreatedAt = base.Add(time.Duration(i) * time.Second)
		p.UpdatedAt = p.CreatedAt
		if err := repo.Create(f.ctx, p); err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
		// want is highest-created-at first (descending order).
		want = append([]core.PolicyID{p.ID}, want...)
	}

	// Page 1.
	page1, hasMore1, err := repo.GetByProduct(f.ctx, f.productID, core.Cursor{}, 3)
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

	// Page 2.
	last1 := page1[len(page1)-1]
	cursor2 := core.Cursor{CreatedAt: last1.CreatedAt, ID: uuid.UUID(last1.ID)}
	page2, hasMore2, err := repo.GetByProduct(f.ctx, f.productID, cursor2, 3)
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

	// Page 3.
	last2 := page2[len(page2)-1]
	cursor3 := core.Cursor{CreatedAt: last2.CreatedAt, ID: uuid.UUID(last2.ID)}
	page3, hasMore3, err := repo.GetByProduct(f.ctx, f.productID, cursor3, 3)
	if err != nil {
		t.Fatalf("page3: %v", err)
	}
	if len(page3) != 3 {
		t.Fatalf("page3 len = %d, want 3", len(page3))
	}
	if !hasMore3 {
		t.Error("page3 has_more = false, want true")
	}
	for i := 0; i < 3; i++ {
		if page3[i].ID != want[6+i] {
			t.Errorf("page3[%d] = %v, want %v", i, page3[i].ID, want[6+i])
		}
	}

	// Page 4 (tail — 1 row, has_more=false).
	last3 := page3[len(page3)-1]
	cursor4 := core.Cursor{CreatedAt: last3.CreatedAt, ID: uuid.UUID(last3.ID)}
	page4, hasMore4, err := repo.GetByProduct(f.ctx, f.productID, cursor4, 3)
	if err != nil {
		t.Fatalf("page4: %v", err)
	}
	if len(page4) != 1 {
		t.Fatalf("page4 len = %d, want 1", len(page4))
	}
	if hasMore4 {
		t.Error("page4 has_more = true, want false")
	}
	if page4[0].ID != want[9] {
		t.Errorf("page4[0] = %v, want %v", page4[0].ID, want[9])
	}
}
