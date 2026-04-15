package product

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/crypto"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/getlicense-io/getlicense-api/internal/policy"
)

// --- mock TxManager (passthrough) ---

type mockTxManager struct{}

func (m *mockTxManager) WithTargetAccount(_ context.Context, _ core.AccountID, _ core.Environment, fn func(context.Context) error) error {
	return fn(context.Background())
}

func (m *mockTxManager) WithTx(_ context.Context, fn func(context.Context) error) error {
	return fn(context.Background())
}

// --- mock ProductRepository ---

type mockProductRepo struct {
	byID map[core.ProductID]*domain.Product
	list []*domain.Product
	// forceUpdateErr and forceDeleteErr allow failure injection.
	forceUpdateErr error
	forceDeleteErr error
}

func newMockProductRepo() *mockProductRepo {
	return &mockProductRepo{
		byID: make(map[core.ProductID]*domain.Product),
	}
}

func (r *mockProductRepo) Create(_ context.Context, p *domain.Product) error {
	r.byID[p.ID] = p
	r.list = append(r.list, p)
	return nil
}

func (r *mockProductRepo) GetByID(_ context.Context, id core.ProductID) (*domain.Product, error) {
	p, ok := r.byID[id]
	if !ok {
		return nil, nil // nil, nil => not found (service should treat nil as not found)
	}
	return p, nil
}

func (r *mockProductRepo) Update(_ context.Context, id core.ProductID, params domain.UpdateProductParams) (*domain.Product, error) {
	if r.forceUpdateErr != nil {
		return nil, r.forceUpdateErr
	}
	p, ok := r.byID[id]
	if !ok {
		return nil, errors.New("not found")
	}
	if params.Name != nil {
		p.Name = *params.Name
	}
	if params.Metadata != nil {
		p.Metadata = *params.Metadata
	}
	return p, nil
}

func (r *mockProductRepo) List(_ context.Context, _ core.Cursor, limit int) ([]domain.Product, bool, error) {
	total := len(r.list)
	if total <= limit {
		out := make([]domain.Product, total)
		for i, p := range r.list {
			out[i] = *p
		}
		return out, false, nil
	}
	out := make([]domain.Product, limit)
	for i, p := range r.list[:limit] {
		out[i] = *p
	}
	return out, true, nil
}

func (r *mockProductRepo) Delete(_ context.Context, id core.ProductID) error {
	if r.forceDeleteErr != nil {
		return r.forceDeleteErr
	}
	p, ok := r.byID[id]
	if !ok {
		return errors.New("not found")
	}
	delete(r.byID, id)
	newList := r.list[:0]
	for _, item := range r.list {
		if item.ID != id {
			newList = append(newList, item)
		}
	}
	r.list = newList
	_ = p
	return nil
}

// --- fake PolicyRepository (in-package copy; the canonical fakeRepo in
// internal/policy is package-private to policy_test so we can't share it).

type fakePolicyRepo struct {
	policies map[core.PolicyID]*domain.Policy
	defaults map[core.ProductID]core.PolicyID
}

func newFakePolicyRepo() *fakePolicyRepo {
	return &fakePolicyRepo{
		policies: make(map[core.PolicyID]*domain.Policy),
		defaults: make(map[core.ProductID]core.PolicyID),
	}
}

func (r *fakePolicyRepo) Create(_ context.Context, p *domain.Policy) error {
	r.policies[p.ID] = p
	if p.IsDefault {
		r.defaults[p.ProductID] = p.ID
	}
	return nil
}

func (r *fakePolicyRepo) Get(_ context.Context, id core.PolicyID) (*domain.Policy, error) {
	p, ok := r.policies[id]
	if !ok {
		return nil, nil
	}
	return p, nil
}

func (r *fakePolicyRepo) GetByProduct(_ context.Context, _ core.ProductID, _ core.Cursor, _ int) ([]domain.Policy, bool, error) {
	return nil, false, nil
}

func (r *fakePolicyRepo) GetDefaultForProduct(_ context.Context, productID core.ProductID) (*domain.Policy, error) {
	id, ok := r.defaults[productID]
	if !ok {
		return nil, nil
	}
	return r.policies[id], nil
}

func (r *fakePolicyRepo) Update(_ context.Context, p *domain.Policy) error {
	r.policies[p.ID] = p
	return nil
}

func (r *fakePolicyRepo) Delete(_ context.Context, id core.PolicyID) error {
	delete(r.policies, id)
	return nil
}

func (r *fakePolicyRepo) SetDefault(_ context.Context, _ core.ProductID, _ core.PolicyID) error {
	return nil
}

func (r *fakePolicyRepo) ReassignLicensesFromPolicy(_ context.Context, _, _ core.PolicyID) (int, error) {
	return 0, nil
}

func (r *fakePolicyRepo) CountReferencingLicenses(_ context.Context, _ core.PolicyID) (int, error) {
	return 0, nil
}

// --- test helpers ---

func testMasterKey(t *testing.T) *crypto.MasterKey {
	t.Helper()
	mk, err := crypto.NewMasterKey("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
	require.NoError(t, err)
	return mk
}

// --- mock LicenseRepository (minimal for delete guard) ---

type mockLicenseRepo struct {
	countByProduct int
}

func (m *mockLicenseRepo) CountByProduct(_ context.Context, _ core.ProductID) (int, error) {
	return m.countByProduct, nil
}

func (m *mockLicenseRepo) CountsByProductStatus(_ context.Context, _ core.ProductID) (domain.LicenseStatusCounts, error) {
	return domain.LicenseStatusCounts{}, nil
}

func (m *mockLicenseRepo) BulkRevokeByProduct(_ context.Context, _ core.ProductID) (int, error) {
	return 0, nil
}

func (m *mockLicenseRepo) HasBlocking(_ context.Context) (bool, error) { return false, nil }

// Unused interface methods.
func (m *mockLicenseRepo) Create(_ context.Context, _ *domain.License) error       { return nil }
func (m *mockLicenseRepo) BulkCreate(_ context.Context, _ []*domain.License) error { return nil }
func (m *mockLicenseRepo) GetByID(_ context.Context, _ core.LicenseID) (*domain.License, error) {
	return nil, nil
}
func (m *mockLicenseRepo) GetByIDForUpdate(_ context.Context, _ core.LicenseID) (*domain.License, error) {
	return nil, nil
}
func (m *mockLicenseRepo) GetByKeyHash(_ context.Context, _ string) (*domain.License, error) {
	return nil, nil
}
func (m *mockLicenseRepo) List(_ context.Context, _ domain.LicenseListFilters, _ core.Cursor, _ int) ([]domain.License, bool, error) {
	return nil, false, nil
}
func (m *mockLicenseRepo) ListByProduct(_ context.Context, _ core.ProductID, _ domain.LicenseListFilters, _ core.Cursor, _ int) ([]domain.License, bool, error) {
	return nil, false, nil
}
func (m *mockLicenseRepo) UpdateStatus(_ context.Context, _ core.LicenseID, _, _ core.LicenseStatus) (time.Time, error) {
	return time.Time{}, nil
}
func (m *mockLicenseRepo) ExpireActive(_ context.Context) ([]domain.License, error) { return nil, nil }

func newTestService(t *testing.T) (*Service, *mockProductRepo, *fakePolicyRepo) {
	t.Helper()
	repo := newMockProductRepo()
	policyRepo := newFakePolicyRepo()
	policySvc := policy.NewService(&mockTxManager{}, policyRepo)
	mk := testMasterKey(t)
	svc := NewService(&mockTxManager{}, repo, &mockLicenseRepo{}, policySvc, mk)
	return svc, repo, policyRepo
}

var testAccountID = core.NewAccountID()

// --- tests ---

func TestCreate_HappyPath(t *testing.T) {
	svc, repo, policyRepo := newTestService(t)
	mk := testMasterKey(t)

	result, err := svc.Create(context.Background(), testAccountID, core.EnvironmentLive, CreateRequest{
		Name: "My Product",
		Slug: "my-product",
	})
	require.NoError(t, err)
	require.NotNil(t, result)

	// Basic fields.
	assert.Equal(t, "My Product", result.Name)
	assert.Equal(t, "my-product", result.Slug)
	assert.Equal(t, testAccountID, result.AccountID)
	assert.False(t, result.CreatedAt.IsZero())

	// Public key is valid base64url (no padding) of a 32-byte Ed25519 key.
	pubBytes, err := base64.RawURLEncoding.DecodeString(result.PublicKey)
	require.NoError(t, err, "public key must be valid base64url")
	assert.Len(t, pubBytes, 32, "Ed25519 public key must be 32 bytes")

	// Private key is encrypted and non-empty.
	assert.NotEmpty(t, result.PrivateKeyEnc)

	// Decryption must yield a 64-byte Ed25519 private key.
	privBytes, err := mk.Decrypt(result.PrivateKeyEnc)
	require.NoError(t, err, "private key must be decryptable with the master encryption key")
	assert.Len(t, privBytes, 64, "Ed25519 private key must be 64 bytes")

	// Product stored in repo.
	stored, ok := repo.byID[result.ID]
	require.True(t, ok, "product must be persisted in the repository")
	assert.Equal(t, result.PublicKey, stored.PublicKey)

	// A Default policy must have been auto-created for this product.
	require.Len(t, policyRepo.policies, 1, "expected exactly one default policy after Create")
	var defaultPol *domain.Policy
	for _, p := range policyRepo.policies {
		defaultPol = p
	}
	require.NotNil(t, defaultPol)
	assert.True(t, defaultPol.IsDefault, "auto-created policy must be marked IsDefault")
	assert.Equal(t, result.ID, defaultPol.ProductID, "default policy must point to the new product")
	assert.Equal(t, testAccountID, defaultPol.AccountID)
	assert.Equal(t, "Default", defaultPol.Name)
}

func TestCreate_KeypairIsUnique(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()

	p1, err := svc.Create(ctx, testAccountID, core.EnvironmentLive, CreateRequest{Name: "P1", Slug: "p1"})
	require.NoError(t, err)

	p2, err := svc.Create(ctx, testAccountID, core.EnvironmentLive, CreateRequest{Name: "P2", Slug: "p2"})
	require.NoError(t, err)

	// Each product must have a distinct public key.
	assert.NotEqual(t, p1.PublicKey, p2.PublicKey, "each product must have a unique keypair")
}

func TestGet_NotFound(t *testing.T) {
	svc, _, _ := newTestService(t)

	unknownID := core.NewProductID()
	_, err := svc.Get(context.Background(), testAccountID, core.EnvironmentLive, unknownID)
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrProductNotFound, appErr.Code)
}

func TestGet_HappyPath(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()

	created, err := svc.Create(ctx, testAccountID, core.EnvironmentLive, CreateRequest{Name: "Find Me", Slug: "find-me"})
	require.NoError(t, err)

	found, err := svc.Get(ctx, testAccountID, core.EnvironmentLive, created.ID)
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, created.ID, found.ID)
	assert.Equal(t, "Find Me", found.Name)
}

func TestList_DelegatesCorrectly(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()

	for i := range 3 {
		_, err := svc.Create(ctx, testAccountID, core.EnvironmentLive, CreateRequest{
			Name: "Product",
			Slug: "product-" + string(rune('a'+i)),
		})
		require.NoError(t, err)
	}

	products, hasMore, err := svc.List(ctx, testAccountID, core.EnvironmentLive, core.Cursor{}, 10)
	require.NoError(t, err)
	assert.False(t, hasMore)
	assert.Len(t, products, 3)

	page1, hasMore1, err := svc.List(ctx, testAccountID, core.EnvironmentLive, core.Cursor{}, 2)
	require.NoError(t, err)
	assert.True(t, hasMore1)
	assert.Len(t, page1, 2)
}

func TestUpdate_HappyPath(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()

	created, err := svc.Create(ctx, testAccountID, core.EnvironmentLive, CreateRequest{Name: "Before", Slug: "before"})
	require.NoError(t, err)

	newName := "After"
	updated, err := svc.Update(ctx, testAccountID, core.EnvironmentLive, created.ID, UpdateRequest{
		Name: &newName,
	})
	require.NoError(t, err)
	require.NotNil(t, updated)
	assert.Equal(t, "After", updated.Name)
}

func TestDelete_HappyPath(t *testing.T) {
	svc, repo, _ := newTestService(t)
	ctx := context.Background()

	created, err := svc.Create(ctx, testAccountID, core.EnvironmentLive, CreateRequest{Name: "Delete Me", Slug: "delete-me"})
	require.NoError(t, err)

	err = svc.Delete(ctx, testAccountID, core.EnvironmentLive, created.ID)
	require.NoError(t, err)

	_, ok := repo.byID[created.ID]
	assert.False(t, ok, "product must be removed from the repository after deletion")
}
