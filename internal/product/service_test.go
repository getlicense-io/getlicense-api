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
)

// --- mock TxManager (passthrough) ---

type mockTxManager struct{}

func (m *mockTxManager) WithTenant(_ context.Context, _ core.AccountID, _ core.Environment, fn func(context.Context) error) error {
	return fn(context.Background())
}

func (m *mockTxManager) WithTx(_ context.Context, fn func(context.Context) error) error {
	return fn(context.Background())
}

// --- mock ProductRepository ---

type mockProductRepo struct {
	byID   map[core.ProductID]*domain.Product
	list   []*domain.Product
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

func (r *mockProductRepo) List(_ context.Context, limit, offset int) ([]domain.Product, int, error) {
	total := len(r.list)
	if offset >= total {
		return nil, total, nil
	}
	end := offset + limit
	if end > total {
		end = total
	}
	out := make([]domain.Product, end-offset)
	for i, p := range r.list[offset:end] {
		out[i] = *p
	}
	return out, total, nil
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
	if params.ValidationTTL != nil {
		p.ValidationTTL = *params.ValidationTTL
	}
	if params.GracePeriod != nil {
		p.GracePeriod = *params.GracePeriod
	}
	if params.Metadata != nil {
		p.Metadata = *params.Metadata
	}
	if params.HeartbeatTimeout != nil {
		p.HeartbeatTimeout = params.HeartbeatTimeout
	}
	return p, nil
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

func (m *mockLicenseRepo) CountBlocking(_ context.Context) (int, error) { return 0, nil }

// Unused interface methods.
func (m *mockLicenseRepo) Create(_ context.Context, _ *domain.License) error   { return nil }
func (m *mockLicenseRepo) BulkCreate(_ context.Context, _ []*domain.License) error { return nil }
func (m *mockLicenseRepo) GetByID(_ context.Context, _ core.LicenseID) (*domain.License, error) { return nil, nil }
func (m *mockLicenseRepo) GetByIDForUpdate(_ context.Context, _ core.LicenseID) (*domain.License, error) { return nil, nil }
func (m *mockLicenseRepo) GetByKeyHash(_ context.Context, _ string) (*domain.License, error) { return nil, nil }
func (m *mockLicenseRepo) List(_ context.Context, _, _ int) ([]domain.License, int, error) { return nil, 0, nil }
func (m *mockLicenseRepo) UpdateStatus(_ context.Context, _ core.LicenseID, _, _ core.LicenseStatus) (time.Time, error) { return time.Time{}, nil }
func (m *mockLicenseRepo) ExpireActive(_ context.Context) ([]domain.License, error) { return nil, nil }

func newTestService(t *testing.T) (*Service, *mockProductRepo) {
	t.Helper()
	repo := newMockProductRepo()
	mk := testMasterKey(t)
	svc := NewService(&mockTxManager{}, repo, &mockLicenseRepo{}, mk)
	return svc, repo
}

var testAccountID = core.NewAccountID()

// --- tests ---

func TestCreate_HappyPath(t *testing.T) {
	svc, repo := newTestService(t)
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

	// Defaults applied.
	assert.Equal(t, defaultValidationTTL, result.ValidationTTL)
	assert.Equal(t, defaultGracePeriod, result.GracePeriod)

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
}

func TestCreate_CustomTTLAndGracePeriod(t *testing.T) {
	svc, _ := newTestService(t)

	ttl := 3600
	grace := 7200

	result, err := svc.Create(context.Background(), testAccountID, core.EnvironmentLive, CreateRequest{
		Name:          "Custom TTL Product",
		Slug:          "custom-ttl",
		ValidationTTL: &ttl,
		GracePeriod:   &grace,
	})
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, ttl, result.ValidationTTL)
	assert.Equal(t, grace, result.GracePeriod)
}

func TestCreate_KeypairIsUnique(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	p1, err := svc.Create(ctx, testAccountID, core.EnvironmentLive, CreateRequest{Name: "P1", Slug: "p1"})
	require.NoError(t, err)

	p2, err := svc.Create(ctx, testAccountID, core.EnvironmentLive, CreateRequest{Name: "P2", Slug: "p2"})
	require.NoError(t, err)

	// Each product must have a distinct public key.
	assert.NotEqual(t, p1.PublicKey, p2.PublicKey, "each product must have a unique keypair")
}

func TestGet_NotFound(t *testing.T) {
	svc, _ := newTestService(t)

	unknownID := core.NewProductID()
	_, err := svc.Get(context.Background(), testAccountID, core.EnvironmentLive, unknownID)
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrProductNotFound, appErr.Code)
}

func TestGet_HappyPath(t *testing.T) {
	svc, _ := newTestService(t)
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
	svc, _ := newTestService(t)
	ctx := context.Background()

	// Create 3 products.
	for i := range 3 {
		_, err := svc.Create(ctx, testAccountID, core.EnvironmentLive, CreateRequest{
			Name: "Product",
			Slug: "product-" + string(rune('a'+i)),
		})
		require.NoError(t, err)
	}

	// List all.
	products, total, err := svc.List(ctx, testAccountID, core.EnvironmentLive,10, 0)
	require.NoError(t, err)
	assert.Equal(t, 3, total)
	assert.Len(t, products, 3)

	// Paginate: first page of 2.
	page1, total1, err := svc.List(ctx, testAccountID, core.EnvironmentLive,2, 0)
	require.NoError(t, err)
	assert.Equal(t, 3, total1)
	assert.Len(t, page1, 2)

	// Paginate: second page.
	page2, total2, err := svc.List(ctx, testAccountID, core.EnvironmentLive,2, 2)
	require.NoError(t, err)
	assert.Equal(t, 3, total2)
	assert.Len(t, page2, 1)
}

func TestUpdate_HappyPath(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	created, err := svc.Create(ctx, testAccountID, core.EnvironmentLive, CreateRequest{Name: "Before", Slug: "before"})
	require.NoError(t, err)

	newName := "After"
	newTTL := 1800
	updated, err := svc.Update(ctx, testAccountID, core.EnvironmentLive, created.ID, UpdateRequest{
		Name:          &newName,
		ValidationTTL: &newTTL,
	})
	require.NoError(t, err)
	require.NotNil(t, updated)
	assert.Equal(t, "After", updated.Name)
	assert.Equal(t, 1800, updated.ValidationTTL)
}

func TestDelete_HappyPath(t *testing.T) {
	svc, repo := newTestService(t)
	ctx := context.Background()

	created, err := svc.Create(ctx, testAccountID, core.EnvironmentLive, CreateRequest{Name: "Delete Me", Slug: "delete-me"})
	require.NoError(t, err)

	err = svc.Delete(ctx, testAccountID, core.EnvironmentLive, created.ID)
	require.NoError(t, err)

	_, ok := repo.byID[created.ID]
	assert.False(t, ok, "product must be removed from the repository after deletion")
}
