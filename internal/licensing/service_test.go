package licensing

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/crypto"
	"github.com/getlicense-io/getlicense-api/internal/customer"
	"github.com/getlicense-io/getlicense-api/internal/domain"
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
}

func newMockProductRepo() *mockProductRepo {
	return &mockProductRepo{byID: make(map[core.ProductID]*domain.Product)}
}

func (r *mockProductRepo) Create(_ context.Context, p *domain.Product) error {
	r.byID[p.ID] = p
	return nil
}

func (r *mockProductRepo) GetByID(_ context.Context, id core.ProductID) (*domain.Product, error) {
	p, ok := r.byID[id]
	if !ok {
		return nil, nil
	}
	return p, nil
}

func (r *mockProductRepo) List(_ context.Context, _ core.Cursor, _ int) ([]domain.Product, bool, error) {
	return nil, false, nil
}

func (r *mockProductRepo) Update(_ context.Context, _ core.ProductID, _ domain.UpdateProductParams) (*domain.Product, error) {
	return nil, nil
}

func (r *mockProductRepo) Delete(_ context.Context, _ core.ProductID) error {
	return nil
}

// --- mock PolicyRepository ---

type mockPolicyRepo struct {
	byID     map[core.PolicyID]*domain.Policy
	defaults map[core.ProductID]core.PolicyID
}

func newMockPolicyRepo() *mockPolicyRepo {
	return &mockPolicyRepo{
		byID:     make(map[core.PolicyID]*domain.Policy),
		defaults: make(map[core.ProductID]core.PolicyID),
	}
}

func (r *mockPolicyRepo) Create(_ context.Context, p *domain.Policy) error {
	r.byID[p.ID] = p
	if p.IsDefault {
		r.defaults[p.ProductID] = p.ID
	}
	return nil
}

func (r *mockPolicyRepo) Get(_ context.Context, id core.PolicyID) (*domain.Policy, error) {
	p, ok := r.byID[id]
	if !ok {
		return nil, nil
	}
	return p, nil
}

func (r *mockPolicyRepo) GetByProduct(_ context.Context, _ core.ProductID, _ core.Cursor, _ int) ([]domain.Policy, bool, error) {
	return nil, false, nil
}

func (r *mockPolicyRepo) GetDefaultForProduct(_ context.Context, productID core.ProductID) (*domain.Policy, error) {
	id, ok := r.defaults[productID]
	if !ok {
		return nil, nil
	}
	p := r.byID[id]
	return p, nil
}

func (r *mockPolicyRepo) Update(_ context.Context, p *domain.Policy) error {
	r.byID[p.ID] = p
	return nil
}

func (r *mockPolicyRepo) Delete(_ context.Context, id core.PolicyID) error {
	delete(r.byID, id)
	return nil
}

func (r *mockPolicyRepo) SetDefault(_ context.Context, _ core.ProductID, _ core.PolicyID) error {
	return nil
}

func (r *mockPolicyRepo) ReassignLicensesFromPolicy(_ context.Context, _, _ core.PolicyID) (int, error) {
	return 0, nil
}

func (r *mockPolicyRepo) CountReferencingLicenses(_ context.Context, _ core.PolicyID) (int, error) {
	return 0, nil
}

// --- mock LicenseRepository ---

type mockLicenseRepo struct {
	byID      map[core.LicenseID]*domain.License
	byKeyHash map[string]*domain.License
	list      []*domain.License
	// customerLookup is set by the test harness so List/ListByProduct's
	// search filter can evaluate against the referenced customer's
	// name/email — the real repo achieves this via an EXISTS subquery
	// over the customers table.
	customerLookup func(core.CustomerID) (*domain.Customer, bool)
}

func newMockLicenseRepo() *mockLicenseRepo {
	return &mockLicenseRepo{
		byID:      make(map[core.LicenseID]*domain.License),
		byKeyHash: make(map[string]*domain.License),
	}
}

func (r *mockLicenseRepo) Create(_ context.Context, l *domain.License) error {
	r.byID[l.ID] = l
	r.byKeyHash[l.KeyHash] = l
	r.list = append(r.list, l)
	return nil
}

func (r *mockLicenseRepo) BulkCreate(ctx context.Context, licenses []*domain.License) error {
	for _, l := range licenses {
		if err := r.Create(ctx, l); err != nil {
			return err
		}
	}
	return nil
}

func (r *mockLicenseRepo) GetByID(_ context.Context, id core.LicenseID) (*domain.License, error) {
	l, ok := r.byID[id]
	if !ok {
		return nil, nil
	}
	return l, nil
}

func (r *mockLicenseRepo) GetByIDForUpdate(_ context.Context, id core.LicenseID) (*domain.License, error) {
	l, ok := r.byID[id]
	if !ok {
		return nil, nil
	}
	return l, nil
}

func (r *mockLicenseRepo) GetByKeyHash(_ context.Context, keyHash string) (*domain.License, error) {
	l, ok := r.byKeyHash[keyHash]
	if !ok {
		return nil, nil
	}
	return l, nil
}

// mockLicenseListMatches mirrors the domain filter semantics so tests
// that drive filters through the service exercise the same narrowing
// the real repo does. The customer resolver is optional — when nil,
// the search only matches against key_prefix.
func mockLicenseListMatches(l *domain.License, f domain.LicenseListFilters, resolveCustomer func(core.CustomerID) (*domain.Customer, bool)) bool {
	if f.Status != "" && l.Status != f.Status {
		return false
	}
	if f.Q != "" {
		needle := strings.ToLower(f.Q)
		hay := strings.ToLower(l.KeyPrefix)
		if resolveCustomer != nil {
			if c, ok := resolveCustomer(l.CustomerID); ok && c != nil {
				if c.Name != nil {
					hay += " " + strings.ToLower(*c.Name)
				}
				hay += " " + strings.ToLower(c.Email)
			}
		}
		if !strings.Contains(hay, needle) {
			return false
		}
	}
	return true
}

func (r *mockLicenseRepo) Update(_ context.Context, l *domain.License) error {
	existing, ok := r.byID[l.ID]
	if !ok {
		return errors.New("not found")
	}
	existing.PolicyID = l.PolicyID
	existing.Overrides = l.Overrides
	existing.ExpiresAt = l.ExpiresAt
	existing.FirstActivatedAt = l.FirstActivatedAt
	existing.CustomerID = l.CustomerID
	existing.UpdatedAt = time.Now().UTC()
	return nil
}

func (r *mockLicenseRepo) UpdateStatus(_ context.Context, id core.LicenseID, _, to core.LicenseStatus) (time.Time, error) {
	l, ok := r.byID[id]
	if !ok {
		return time.Time{}, errors.New("not found")
	}
	l.Status = to
	return time.Now().UTC(), nil
}

func (r *mockLicenseRepo) CountByProduct(_ context.Context, _ core.ProductID) (int, error) {
	return 0, nil
}

func (r *mockLicenseRepo) CountsByProductStatus(_ context.Context, _ core.ProductID) (domain.LicenseStatusCounts, error) {
	return domain.LicenseStatusCounts{}, nil
}

func (r *mockLicenseRepo) BulkRevokeByProduct(_ context.Context, _ core.ProductID) (int, error) {
	return 0, nil
}

func (r *mockLicenseRepo) List(_ context.Context, filters domain.LicenseListFilters, _ core.Cursor, limit int) ([]domain.License, bool, error) {
	matched := make([]*domain.License, 0, len(r.list))
	for _, l := range r.list {
		if mockLicenseListMatches(l, filters, r.customerLookup) {
			matched = append(matched, l)
		}
	}
	hasMore := len(matched) > limit
	if hasMore {
		matched = matched[:limit]
	}
	out := make([]domain.License, len(matched))
	for i, l := range matched {
		out[i] = *l
	}
	return out, hasMore, nil
}

func (r *mockLicenseRepo) ListByProduct(_ context.Context, productID core.ProductID, filters domain.LicenseListFilters, _ core.Cursor, limit int) ([]domain.License, bool, error) {
	matched := make([]*domain.License, 0, len(r.list))
	for _, l := range r.list {
		if l.ProductID != productID {
			continue
		}
		if !mockLicenseListMatches(l, filters, r.customerLookup) {
			continue
		}
		matched = append(matched, l)
	}
	hasMore := len(matched) > limit
	if hasMore {
		matched = matched[:limit]
	}
	out := make([]domain.License, len(matched))
	for i, l := range matched {
		out[i] = *l
	}
	return out, hasMore, nil
}

func (r *mockLicenseRepo) HasBlocking(_ context.Context) (bool, error) { return false, nil }

func (r *mockLicenseRepo) ExpireActive(_ context.Context) ([]domain.License, error) {
	return nil, nil
}

// --- mock MachineRepository ---

type machineKey struct {
	licenseID   core.LicenseID
	fingerprint string
}

type mockMachineRepo struct {
	byKey map[machineKey]*domain.Machine
}

func newMockMachineRepo() *mockMachineRepo {
	return &mockMachineRepo{
		byKey: make(map[machineKey]*domain.Machine),
	}
}

func (r *mockMachineRepo) Create(_ context.Context, m *domain.Machine) error {
	key := machineKey{licenseID: m.LicenseID, fingerprint: m.Fingerprint}
	r.byKey[key] = m
	return nil
}

func (r *mockMachineRepo) GetByFingerprint(_ context.Context, licenseID core.LicenseID, fingerprint string) (*domain.Machine, error) {
	key := machineKey{licenseID: licenseID, fingerprint: fingerprint}
	m, ok := r.byKey[key]
	if !ok {
		return nil, nil
	}
	return m, nil
}

func (r *mockMachineRepo) CountByLicense(_ context.Context, licenseID core.LicenseID) (int, error) {
	count := 0
	for k := range r.byKey {
		if k.licenseID == licenseID {
			count++
		}
	}
	return count, nil
}

func (r *mockMachineRepo) DeleteByFingerprint(_ context.Context, licenseID core.LicenseID, fingerprint string) error {
	key := machineKey{licenseID: licenseID, fingerprint: fingerprint}
	if _, ok := r.byKey[key]; !ok {
		return core.NewAppError(core.ErrMachineNotFound, "Machine not found")
	}
	delete(r.byKey, key)
	return nil
}

func (r *mockMachineRepo) UpdateHeartbeat(_ context.Context, licenseID core.LicenseID, fingerprint string) (*domain.Machine, error) {
	key := machineKey{licenseID: licenseID, fingerprint: fingerprint}
	m, ok := r.byKey[key]
	if !ok {
		return nil, core.NewAppError(core.ErrMachineNotFound, "Machine not found")
	}
	now := time.Now().UTC()
	m.LastSeenAt = &now
	return m, nil
}

// --- mock CustomerRepository ---

// fakeCustomerRepo is an in-memory CustomerRepository used by the
// licensing service tests. Mirrors the shape of customer.fakeRepo
// but lives in the licensing test package so we can share test state
// with the license mocks via the testEnv.
type fakeCustomerRepo struct {
	mu      sync.Mutex
	byID    map[core.CustomerID]*domain.Customer
	byEmail map[string]core.CustomerID // "accountID|lower(email)"
}

func newFakeCustomerRepo() *fakeCustomerRepo {
	return &fakeCustomerRepo{
		byID:    map[core.CustomerID]*domain.Customer{},
		byEmail: map[string]core.CustomerID{},
	}
}

func customerEmailKey(a core.AccountID, e string) string {
	return a.String() + "|" + strings.ToLower(e)
}

func (r *fakeCustomerRepo) Create(_ context.Context, c *domain.Customer) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	k := customerEmailKey(c.AccountID, c.Email)
	if _, exists := r.byEmail[k]; exists {
		return errors.New("unique violation")
	}
	r.byID[c.ID] = c
	r.byEmail[k] = c.ID
	return nil
}

func (r *fakeCustomerRepo) Get(_ context.Context, id core.CustomerID) (*domain.Customer, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.byID[id]
	if !ok {
		return nil, nil
	}
	return c, nil
}

func (r *fakeCustomerRepo) GetByEmail(_ context.Context, accountID core.AccountID, email string) (*domain.Customer, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id, ok := r.byEmail[customerEmailKey(accountID, email)]
	if !ok {
		return nil, nil
	}
	return r.byID[id], nil
}

func (r *fakeCustomerRepo) List(_ context.Context, _ core.AccountID, _ domain.CustomerListFilter, _ core.Cursor, _ int) ([]domain.Customer, bool, error) {
	return nil, false, nil
}

func (r *fakeCustomerRepo) Update(_ context.Context, c *domain.Customer) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.byID[c.ID]; !ok {
		return core.NewAppError(core.ErrCustomerNotFound, "not found")
	}
	r.byID[c.ID] = c
	return nil
}

func (r *fakeCustomerRepo) Delete(_ context.Context, id core.CustomerID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.byID[id]
	if !ok {
		return core.NewAppError(core.ErrCustomerNotFound, "not found")
	}
	delete(r.byID, id)
	delete(r.byEmail, customerEmailKey(c.AccountID, c.Email))
	return nil
}

func (r *fakeCustomerRepo) CountReferencingLicenses(_ context.Context, _ core.CustomerID) (int, error) {
	return 0, nil
}

func (r *fakeCustomerRepo) UpsertByEmail(_ context.Context, accountID core.AccountID, email string, name *string, metadata json.RawMessage, createdByAccountID *core.AccountID) (*domain.Customer, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	k := customerEmailKey(accountID, email)
	if id, ok := r.byEmail[k]; ok {
		return r.byID[id], false, nil
	}
	now := time.Now().UTC()
	c := &domain.Customer{
		ID:                 core.NewCustomerID(),
		AccountID:          accountID,
		Email:              email,
		Name:               name,
		Metadata:           metadata,
		CreatedByAccountID: createdByAccountID,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	r.byID[c.ID] = c
	r.byEmail[k] = c.ID
	return c, true, nil
}

// --- test helpers ---

func testMasterKey(t *testing.T) *crypto.MasterKey {
	t.Helper()
	mk, err := crypto.NewMasterKey("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
	require.NoError(t, err)
	return mk
}

// createTestProduct creates an encrypted product in the mock repo and returns it.
func createTestProduct(t *testing.T, repo *mockProductRepo, mk *crypto.MasterKey, accountID core.AccountID) *domain.Product {
	t.Helper()

	pub, priv, err := crypto.GenerateEd25519Keypair()
	require.NoError(t, err)

	privEnc, err := mk.Encrypt(priv)
	require.NoError(t, err)

	product := &domain.Product{
		ID:            core.NewProductID(),
		AccountID:     accountID,
		Name:          "Test Product",
		Slug:          "test-product",
		PublicKey:     crypto.EncodePublicKey(pub),
		PrivateKeyEnc: privEnc,
		CreatedAt:     time.Now().UTC(),
	}
	repo.byID[product.ID] = product
	return product
}

// seedDefaultPolicy inserts a default policy for the given product with
// the provided tweaks applied. The returned policy is stored in the mock
// and registered as the product's default.
func seedDefaultPolicy(t *testing.T, repo *mockPolicyRepo, accountID core.AccountID, productID core.ProductID, tweak func(p *domain.Policy)) *domain.Policy {
	t.Helper()
	now := time.Now().UTC()
	p := &domain.Policy{
		ID:                        core.NewPolicyID(),
		AccountID:                 accountID,
		ProductID:                 productID,
		Name:                      "Default",
		IsDefault:                 true,
		ExpirationStrategy:        core.ExpirationStrategyRevokeAccess,
		ExpirationBasis:           core.ExpirationBasisFromCreation,
		ComponentMatchingStrategy: core.ComponentMatchingAny,
		CheckoutIntervalSec:       86400,
		MaxCheckoutDurationSec:    604800,
		CreatedAt:                 now,
		UpdatedAt:                 now,
	}
	if tweak != nil {
		tweak(p)
	}
	require.NoError(t, repo.Create(context.Background(), p))
	return p
}

type testEnv struct {
	svc         *Service
	products    *mockProductRepo
	policies    *mockPolicyRepo
	licenses    *mockLicenseRepo
	machines    *mockMachineRepo
	customers   *fakeCustomerRepo
	customerSvc *customer.Service
	mk          *crypto.MasterKey
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	mk := testMasterKey(t)
	products := newMockProductRepo()
	policies := newMockPolicyRepo()
	licenses := newMockLicenseRepo()
	machines := newMockMachineRepo()
	customers := newFakeCustomerRepo()
	// Wire the license mock's search-filter customer resolver to the
	// in-memory fake so `?q=` tests match the real repo's behaviour.
	licenses.customerLookup = func(id core.CustomerID) (*domain.Customer, bool) {
		customers.mu.Lock()
		defer customers.mu.Unlock()
		c, ok := customers.byID[id]
		return c, ok
	}
	customerSvc := customer.NewService(customers)
	svc := NewService(&mockTxManager{}, licenses, products, machines, policies, customerSvc, mk, nil)
	return &testEnv{
		svc:         svc,
		products:    products,
		policies:    policies,
		licenses:    licenses,
		machines:    machines,
		customers:   customers,
		customerSvc: customerSvc,
		mk:          mk,
	}
}

var testAccountID = core.NewAccountID()

// seedCustomer inserts a customer row directly into the fake repo,
// bypassing the service's email-normalization path. Returns the
// stored customer so tests can reference its ID.
func seedCustomer(t *testing.T, env *testEnv, accountID core.AccountID, email string, name *string) *domain.Customer {
	t.Helper()
	now := time.Now().UTC()
	c := &domain.Customer{
		ID:        core.NewCustomerID(),
		AccountID: accountID,
		Email:     strings.ToLower(strings.TrimSpace(email)),
		Name:      name,
		CreatedAt: now,
		UpdatedAt: now,
	}
	require.NoError(t, env.customers.Create(context.Background(), c))
	return c
}

// customerIDPtr is a helper for tests that pass a CustomerID by
// pointer into CreateRequest / UpdateRequest.
func customerIDPtr(id core.CustomerID) *core.CustomerID { return &id }

// inlineCustomer returns a CustomerInlineRequest pointer with the
// given email (no name or metadata).
func inlineCustomer(email string) *CustomerInlineRequest {
	return &CustomerInlineRequest{Email: email}
}

// --- Create tests ---

func TestCreate_HappyPath(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	result, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)
	require.NotNil(t, result)

	// License key is in the expected format.
	assert.True(t, strings.HasPrefix(result.LicenseKey, "GETL-"))
	assert.Len(t, result.LicenseKey, 19) // GETL-XXXX-XXXX-XXXX

	// License is persisted with the default policy attached.
	require.NotNil(t, result.License)
	assert.Equal(t, core.LicenseStatusActive, result.License.Status)
	assert.Equal(t, testAccountID, result.License.AccountID)
	assert.Equal(t, product.ID, result.License.ProductID)
	assert.NotEqual(t, core.PolicyID{}, result.License.PolicyID)

	// Token is non-empty and stored.
	assert.True(t, strings.HasPrefix(result.License.Token, "gl1."))

	// Key hash is stored (HMAC of the full key).
	expectedHash := env.mk.HMAC(result.LicenseKey)
	assert.Equal(t, expectedHash, result.License.KeyHash)

	// Prefix matches the first 9 chars.
	assert.Equal(t, result.LicenseKey[:9], result.License.KeyPrefix)

	// Stored in repo.
	stored, ok := env.licenses.byID[result.License.ID]
	require.True(t, ok)
	assert.Equal(t, result.License.KeyHash, stored.KeyHash)
}

func TestCreate_NoDefaultPolicy(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)

	_, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{CreatedByAccountID: testAccountID})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrPolicyNotFound, appErr.Code)
}

func TestCreate_ExplicitPolicyFromOtherProductRejected(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	otherProductID := core.NewProductID()
	otherPolicy := seedDefaultPolicy(t, env.policies, testAccountID, otherProductID, nil)

	_, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		PolicyID: &otherPolicy.ID,
		Customer: inlineCustomer("user@example.com"),
	}, CreateOptions{CreatedByAccountID: testAccountID})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrPolicyProductMismatch, appErr.Code)
}

func TestCreate_FromCreation_StampsExpiresAtFromPolicyDuration(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	dur := 30 * 24 * 60 * 60 // 30 days
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, func(p *domain.Policy) {
		p.DurationSeconds = &dur
		p.ExpirationBasis = core.ExpirationBasisFromCreation
	})

	before := time.Now().UTC()
	result, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)
	after := time.Now().UTC()

	require.NotNil(t, result.License.ExpiresAt)
	expectedMin := before.Add(time.Duration(dur) * time.Second)
	expectedMax := after.Add(time.Duration(dur) * time.Second)
	assert.True(t, !result.License.ExpiresAt.Before(expectedMin), "expires_at before expected min")
	assert.True(t, !result.License.ExpiresAt.After(expectedMax), "expires_at after expected max")
}

func TestCreate_FromFirstActivation_LeavesExpiresAtNil(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	dur := 30 * 24 * 60 * 60
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, func(p *domain.Policy) {
		p.DurationSeconds = &dur
		p.ExpirationBasis = core.ExpirationBasisFromFirstActivation
	})

	result, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)
	assert.Nil(t, result.License.ExpiresAt)
	assert.Nil(t, result.License.FirstActivatedAt)
}

func TestCreate_ProductNotFound(t *testing.T) {
	env := newTestEnv(t)

	unknownProductID := core.NewProductID()
	_, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, unknownProductID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{CreatedByAccountID: testAccountID})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrProductNotFound, appErr.Code)
}

// --- AllowedPolicyIDs (grant allowlist) tests ---

// seedNonDefaultPolicy creates an additional policy attached to the
// same product without flipping the default flag.
func seedNonDefaultPolicy(t *testing.T, repo *mockPolicyRepo, accountID core.AccountID, productID core.ProductID) *domain.Policy {
	t.Helper()
	now := time.Now().UTC()
	p := &domain.Policy{
		ID:                        core.NewPolicyID(),
		AccountID:                 accountID,
		ProductID:                 productID,
		Name:                      "Alt",
		IsDefault:                 false,
		ExpirationStrategy:        core.ExpirationStrategyRevokeAccess,
		ExpirationBasis:           core.ExpirationBasisFromCreation,
		ComponentMatchingStrategy: core.ComponentMatchingAny,
		CheckoutIntervalSec:       86400,
		MaxCheckoutDurationSec:    604800,
		CreatedAt:                 now,
		UpdatedAt:                 now,
	}
	repo.byID[p.ID] = p
	return p
}

func TestCreateLicense_AllowedPolicyIDs_EmptyAllows(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	// Nil allowlist — any policy permitted.
	result, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{
		CreatedByAccountID: testAccountID,
		AllowedPolicyIDs:   nil,
	})
	require.NoError(t, err)
	require.NotNil(t, result)

	// Empty-but-non-nil allowlist — same semantics as nil.
	result2, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{
		CreatedByAccountID: testAccountID,
		AllowedPolicyIDs:   []core.PolicyID{},
	})
	require.NoError(t, err)
	require.NotNil(t, result2)
}

func TestCreateLicense_AllowedPolicyIDs_ExplicitPolicy_InSet(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)
	alt := seedNonDefaultPolicy(t, env.policies, testAccountID, product.ID)

	result, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		PolicyID: &alt.ID,
		Customer: inlineCustomer("user@example.com"),
	}, CreateOptions{
		CreatedByAccountID: testAccountID,
		AllowedPolicyIDs:   []core.PolicyID{alt.ID},
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, alt.ID, result.License.PolicyID)
}

func TestCreateLicense_AllowedPolicyIDs_ExplicitPolicy_NotInSet(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)
	alt := seedNonDefaultPolicy(t, env.policies, testAccountID, product.ID)
	other := seedNonDefaultPolicy(t, env.policies, testAccountID, product.ID)

	_, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		PolicyID: &alt.ID,
		Customer: inlineCustomer("user@example.com"),
	}, CreateOptions{
		CreatedByAccountID: testAccountID,
		AllowedPolicyIDs:   []core.PolicyID{other.ID},
	})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrGrantPolicyNotAllowed, appErr.Code)
}

func TestCreateLicense_AllowedPolicyIDs_DefaultPolicy_Resolved(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	def := seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	// The caller omits PolicyID; the default resolves; the allowlist
	// contains a different ID; the check rejects.
	other := seedNonDefaultPolicy(t, env.policies, testAccountID, product.ID)
	_, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{
		CreatedByAccountID: testAccountID,
		AllowedPolicyIDs:   []core.PolicyID{other.ID},
	})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrGrantPolicyNotAllowed, appErr.Code)

	// Same setup but the allowlist contains the default policy —
	// omitted req.PolicyID succeeds because the resolved default is
	// a member.
	result, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{
		CreatedByAccountID: testAccountID,
		AllowedPolicyIDs:   []core.PolicyID{def.ID},
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, def.ID, result.License.PolicyID)
}

// --- Get tests ---

func TestGet_NotFound(t *testing.T) {
	env := newTestEnv(t)

	_, err := env.svc.Get(context.Background(), testAccountID, core.EnvironmentLive, core.NewLicenseID())
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrLicenseNotFound, appErr.Code)
}

func TestGet_HappyPath(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	found, err := env.svc.Get(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID)
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, created.License.ID, found.ID)
}

// --- Validate tests ---

func TestValidate_HappyPath(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	result, err := env.svc.Validate(context.Background(), created.LicenseKey)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Valid)
	assert.Equal(t, created.License.ID, result.License.ID)
}

func TestValidate_InvalidKey(t *testing.T) {
	env := newTestEnv(t)

	_, err := env.svc.Validate(context.Background(), "GETL-FAKE-FAKE-FAKE")
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrInvalidLicenseKey, appErr.Code)
}

func TestValidate_RevokeAccessExpiredLicense(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, func(p *domain.Policy) {
		p.ExpirationStrategy = core.ExpirationStrategyRevokeAccess
	})

	past := time.Now().Add(-1 * time.Hour)
	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		ExpiresAt: &past,
		Customer:  inlineCustomer("user@example.com"),
	}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	_, err = env.svc.Validate(context.Background(), created.LicenseKey)
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrLicenseExpired, appErr.Code)
}

func TestValidate_MaintainAccessIgnoresExpiry(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, func(p *domain.Policy) {
		p.ExpirationStrategy = core.ExpirationStrategyMaintainAccess
	})

	past := time.Now().Add(-1 * time.Hour)
	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		ExpiresAt: &past,
		Customer:  inlineCustomer("user@example.com"),
	}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	result, err := env.svc.Validate(context.Background(), created.LicenseKey)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Valid)
}

// --- Suspend / Revoke / Reinstate tests ---

func TestSuspend_HappyPath(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	suspended, err := env.svc.Suspend(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID)
	require.NoError(t, err)
	assert.Equal(t, core.LicenseStatusSuspended, suspended.Status)
}

func TestSuspend_InvalidTransition(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	// Revoke first, then try to suspend.
	err = env.svc.Revoke(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID)
	require.NoError(t, err)

	_, err = env.svc.Suspend(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID)
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrLicenseRevoked, appErr.Code)
}

func TestRevoke_HappyPath(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	err = env.svc.Revoke(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID)
	require.NoError(t, err)

	stored := env.licenses.byID[created.License.ID]
	assert.Equal(t, core.LicenseStatusRevoked, stored.Status)
}

func TestReinstate_HappyPath(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	_, err = env.svc.Suspend(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID)
	require.NoError(t, err)

	reinstated, err := env.svc.Reinstate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID)
	require.NoError(t, err)
	assert.Equal(t, core.LicenseStatusActive, reinstated.Status)
}

func TestReinstate_InvalidTransition(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	_, err = env.svc.Reinstate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID)
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrLicenseInvalidTransition, appErr.Code)
}

// --- Activate tests ---

func TestActivate_HappyPath(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	maxM := 3
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, func(p *domain.Policy) {
		p.MaxMachines = &maxM
	})

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	machine, err := env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{
		Fingerprint: "fp-abc-123",
	})
	require.NoError(t, err)
	require.NotNil(t, machine)
	assert.Equal(t, "fp-abc-123", machine.Fingerprint)
	assert.Equal(t, created.License.ID, machine.LicenseID)
	assert.Equal(t, testAccountID, machine.AccountID)
}

func TestActivate_DuplicateFingerprint(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	maxM := 3
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, func(p *domain.Policy) {
		p.MaxMachines = &maxM
	})

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	_, err = env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{
		Fingerprint: "fp-dup",
	})
	require.NoError(t, err)

	_, err = env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{
		Fingerprint: "fp-dup",
	})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrMachineAlreadyActivated, appErr.Code)
}

func TestActivate_MachineLimitExceeded_FromPolicy(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	maxM := 2
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, func(p *domain.Policy) {
		p.MaxMachines = &maxM
	})

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	for _, fp := range []string{"fp-1", "fp-2"} {
		_, err := env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{
			Fingerprint: fp,
		})
		require.NoError(t, err)
	}

	_, err = env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{
		Fingerprint: "fp-3",
	})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrMachineLimitExceeded, appErr.Code)
}

func TestActivate_MachineLimitFromOverrideBeatsPolicy(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	// Policy caps at 1 but the per-license override raises it to 3.
	policyCap := 1
	overrideCap := 3
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, func(p *domain.Policy) {
		p.MaxMachines = &policyCap
	})

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		Overrides: domain.LicenseOverrides{MaxMachines: &overrideCap},
		Customer:  inlineCustomer("user@example.com"),
	}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	for _, fp := range []string{"fp-a", "fp-b", "fp-c"} {
		_, err := env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{
			Fingerprint: fp,
		})
		require.NoError(t, err)
	}
}

func TestActivate_LicenseNotFound(t *testing.T) {
	env := newTestEnv(t)

	_, err := env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, core.NewLicenseID(), ActivateRequest{
		Fingerprint: "fp-orphan",
	})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrLicenseNotFound, appErr.Code)
}

func TestActivate_RevokedLicense_ReturnsError(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	// Force the license into a revoked state directly in the mock so
	// Activate hits the terminal-status guard before any policy lookup.
	env.licenses.byID[created.License.ID].Status = core.LicenseStatusRevoked

	_, err = env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{
		Fingerprint: "fp-revoked",
	})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrLicenseRevoked, appErr.Code)
}

func TestActivate_SuspendedLicense_ReturnsError(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	env.licenses.byID[created.License.ID].Status = core.LicenseStatusSuspended

	_, err = env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{
		Fingerprint: "fp-suspended",
	})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrLicenseSuspended, appErr.Code)
}

func TestActivate_ExpiredLicense_ReturnsError(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	env.licenses.byID[created.License.ID].Status = core.LicenseStatusExpired

	_, err = env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{
		Fingerprint: "fp-expired",
	})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrLicenseExpired, appErr.Code)
}

func TestActivate_NoMachineLimit(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	for i := range 5 {
		fp := "fp-" + string(rune('a'+i))
		_, err = env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{
			Fingerprint: fp,
		})
		require.NoError(t, err)
	}
}

func TestActivate_FromFirstActivation_StampsFirstActivatedAtAndExpiresAt(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	dur := 7 * 24 * 60 * 60
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, func(p *domain.Policy) {
		p.DurationSeconds = &dur
		p.ExpirationBasis = core.ExpirationBasisFromFirstActivation
	})

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)
	assert.Nil(t, created.License.ExpiresAt)

	before := time.Now().UTC()
	_, err = env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{
		Fingerprint: "fp-first",
	})
	require.NoError(t, err)
	after := time.Now().UTC()

	stored := env.licenses.byID[created.License.ID]
	require.NotNil(t, stored.FirstActivatedAt)
	assert.True(t, !stored.FirstActivatedAt.Before(before) && !stored.FirstActivatedAt.After(after))
	require.NotNil(t, stored.ExpiresAt)
	assert.True(t, stored.ExpiresAt.After(before.Add(time.Duration(dur)*time.Second-time.Second)))

	// A second activation must not re-stamp first_activated_at.
	origStamp := *stored.FirstActivatedAt
	time.Sleep(2 * time.Millisecond)
	_, err = env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{
		Fingerprint: "fp-second",
	})
	require.NoError(t, err)
	assert.Equal(t, origStamp, *stored.FirstActivatedAt)
}

// --- Deactivate tests ---

func TestDeactivate_HappyPath(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	_, err = env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{
		Fingerprint: "fp-remove",
	})
	require.NoError(t, err)

	err = env.svc.Deactivate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, DeactivateRequest{
		Fingerprint: "fp-remove",
	})
	require.NoError(t, err)

	key := machineKey{licenseID: created.License.ID, fingerprint: "fp-remove"}
	_, ok := env.machines.byKey[key]
	assert.False(t, ok)
}

func TestDeactivate_EmptyFingerprint(t *testing.T) {
	env := newTestEnv(t)

	err := env.svc.Deactivate(context.Background(), testAccountID, core.EnvironmentLive, core.NewLicenseID(), DeactivateRequest{
		Fingerprint: "",
	})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrValidationError, appErr.Code)
}

// --- Heartbeat tests ---

func TestHeartbeat_HappyPath(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	_, err = env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{
		Fingerprint: "fp-heartbeat",
	})
	require.NoError(t, err)

	machine, err := env.svc.Heartbeat(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, HeartbeatRequest{
		Fingerprint: "fp-heartbeat",
	})
	require.NoError(t, err)
	require.NotNil(t, machine)
	assert.NotNil(t, machine.LastSeenAt)
}

// --- Freeze + AttachPolicy tests ---

func TestFreeze_SnapshotsEffectiveOverrides(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	maxM := 5
	checkout := 3600
	maxCheckout := 7200
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, func(p *domain.Policy) {
		p.MaxMachines = &maxM
		p.CheckoutIntervalSec = checkout
		p.MaxCheckoutDurationSec = maxCheckout
	})

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)
	assert.Nil(t, created.License.Overrides.MaxMachines)

	frozen, err := env.svc.Freeze(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID)
	require.NoError(t, err)
	require.NotNil(t, frozen)

	require.NotNil(t, frozen.Overrides.MaxMachines)
	assert.Equal(t, maxM, *frozen.Overrides.MaxMachines)
	require.NotNil(t, frozen.Overrides.CheckoutIntervalSec)
	assert.Equal(t, checkout, *frozen.Overrides.CheckoutIntervalSec)
	require.NotNil(t, frozen.Overrides.MaxCheckoutDurationSec)
	assert.Equal(t, maxCheckout, *frozen.Overrides.MaxCheckoutDurationSec)
}

func TestAttachPolicy_MovesLicense(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	// Second policy under the same product.
	newPolicy := &domain.Policy{
		ID:                        core.NewPolicyID(),
		AccountID:                 testAccountID,
		ProductID:                 product.ID,
		Name:                      "Premium",
		ExpirationStrategy:        core.ExpirationStrategyRevokeAccess,
		ExpirationBasis:           core.ExpirationBasisFromCreation,
		ComponentMatchingStrategy: core.ComponentMatchingAny,
		CheckoutIntervalSec:       86400,
		MaxCheckoutDurationSec:    604800,
		CreatedAt:                 time.Now().UTC(),
		UpdatedAt:                 time.Now().UTC(),
	}
	require.NoError(t, env.policies.Create(context.Background(), newPolicy))

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	result, err := env.svc.AttachPolicy(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, newPolicy.ID, false)
	require.NoError(t, err)
	assert.Equal(t, newPolicy.ID, result.PolicyID)
}

func TestAttachPolicy_RejectsForeignProduct(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	otherProductID := core.NewProductID()
	otherPolicy := seedDefaultPolicy(t, env.policies, testAccountID, otherProductID, nil)

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	_, err = env.svc.AttachPolicy(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, otherPolicy.ID, false)
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrPolicyProductMismatch, appErr.Code)
}

// --- List tests ---

func TestList_HappyPath(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	for range 3 {
		_, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{CreatedByAccountID: testAccountID})
		require.NoError(t, err)
	}

	licenses, hasMore, err := env.svc.List(context.Background(), testAccountID, core.EnvironmentLive, domain.LicenseListFilters{}, core.Cursor{}, 10)
	require.NoError(t, err)
	assert.False(t, hasMore)
	assert.Len(t, licenses, 3)
}

// --- Customer integration tests (L4 Task 6) ---

func TestCreate_WithCustomerID(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)
	existing := seedCustomer(t, env, testAccountID, "alice@example.com", nil)

	result, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		CustomerID: customerIDPtr(existing.ID),
	}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, existing.ID, result.License.CustomerID)
}

func TestCreate_WithInlineCustomer_NewEmail_CreatesRow(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	result, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		Customer: inlineCustomer("brand-new@example.com"),
	}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)
	require.NotNil(t, result)

	// Customer row was inserted under the target account.
	c, err := env.customers.GetByEmail(context.Background(), testAccountID, "brand-new@example.com")
	require.NoError(t, err)
	require.NotNil(t, c)
	assert.Equal(t, result.License.CustomerID, c.ID)
}

func TestCreate_WithInlineCustomer_ExistingEmail_ReusesRow(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	first, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		Customer: inlineCustomer("shared@example.com"),
	}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	second, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		Customer: inlineCustomer("shared@example.com"),
	}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	// Both licenses reference the same customer row — upsert hit the
	// existing row on the second call.
	assert.Equal(t, first.License.CustomerID, second.License.CustomerID)
}

func TestCreate_BothCustomerAndCustomerID_Returns422(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)
	existing := seedCustomer(t, env, testAccountID, "alice@example.com", nil)

	_, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		CustomerID: customerIDPtr(existing.ID),
		Customer:   inlineCustomer("alice@example.com"),
	}, CreateOptions{CreatedByAccountID: testAccountID})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrCustomerAmbiguous, appErr.Code)
}

func TestCreate_NeitherCustomerNorCustomerID_Returns422(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	_, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{}, CreateOptions{CreatedByAccountID: testAccountID})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrCustomerRequired, appErr.Code)
}

func TestCreate_GrantScopedInline_SetsCreatedByAccountID(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	granteeAccountID := core.NewAccountID()
	grantID := core.NewGrantID()

	_, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		Customer: inlineCustomer("grantee-inline@example.com"),
	}, CreateOptions{
		GrantID:            &grantID,
		CreatedByAccountID: granteeAccountID,
	})
	require.NoError(t, err)

	c, err := env.customers.GetByEmail(context.Background(), testAccountID, "grantee-inline@example.com")
	require.NoError(t, err)
	require.NotNil(t, c)
	require.NotNil(t, c.CreatedByAccountID)
	assert.Equal(t, granteeAccountID, *c.CreatedByAccountID)
}

func TestCreate_CustomerEmailPattern_Enforced(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	// Pattern rejects the inline email.
	_, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		Customer: inlineCustomer("user@other.com"),
	}, CreateOptions{
		CreatedByAccountID:   testAccountID,
		CustomerEmailPattern: `.*@example\.com`,
	})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrGrantConstraintViolated, appErr.Code)

	// Pattern accepts the matching email.
	_, err = env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		Customer: inlineCustomer("user@example.com"),
	}, CreateOptions{
		CreatedByAccountID:   testAccountID,
		CustomerEmailPattern: `.*@example\.com`,
	})
	require.NoError(t, err)
}

// TestCreate_CustomerEmailPattern_Unanchored_IsAnchored is the
// regression test for the security fix that wraps the grantor-supplied
// pattern in full-match anchors. A pattern like `.*@example\.com`
// without an explicit trailing anchor should still match the intended
// "user@example.com" but MUST reject "user@example.com.evil.net" —
// which the prior unanchored regexp.MatchString silently allowed
// because the substring `@example.com` matched anywhere in the input.
func TestCreate_CustomerEmailPattern_Unanchored_IsAnchored(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	// Pattern lacking a trailing $ accepts the intended match — the
	// helper wraps with ^(?:...)$ so the .* prefix can absorb the
	// local-part.
	_, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		Customer: inlineCustomer("user@example.com"),
	}, CreateOptions{
		CreatedByAccountID:   testAccountID,
		CustomerEmailPattern: `.*@example\.com`,
	})
	require.NoError(t, err)

	// Same pattern MUST reject the substring-evasion attempt. Without
	// the helper's full-match anchors, the substring "@example.com"
	// would match anywhere in "user@example.com.evil.net" and the
	// grantor's intent (restrict to the example.com domain) would be
	// silently bypassed.
	_, err = env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		Customer: inlineCustomer("user@example.com.evil.net"),
	}, CreateOptions{
		CreatedByAccountID:   testAccountID,
		CustomerEmailPattern: `.*@example\.com`,
	})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrGrantConstraintViolated, appErr.Code)
}

func TestCreate_CustomerEmailPattern_InvalidRegex_ReturnsError(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	_, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		Customer: inlineCustomer("user@example.com"),
	}, CreateOptions{
		CreatedByAccountID:   testAccountID,
		CustomerEmailPattern: `[invalid(`,
	})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrGrantConstraintViolated, appErr.Code)
}

func TestUpdate_ReassignCustomer(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		Customer: inlineCustomer("original@example.com"),
	}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	newCustomer := seedCustomer(t, env, testAccountID, "replacement@example.com", nil)

	updated, err := env.svc.Update(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, UpdateRequest{
		CustomerID: customerIDPtr(newCustomer.ID),
	})
	require.NoError(t, err)
	assert.Equal(t, newCustomer.ID, updated.CustomerID)
}

func TestUpdate_ReassignCustomer_AccountMismatch_Returns422(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		Customer: inlineCustomer("original@example.com"),
	}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	// Seed a customer under a DIFFERENT account.
	otherAccountID := core.NewAccountID()
	foreign := seedCustomer(t, env, otherAccountID, "foreign@example.com", nil)

	_, err = env.svc.Update(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, UpdateRequest{
		CustomerID: customerIDPtr(foreign.ID),
	})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrCustomerAccountMismatch, appErr.Code)
}

func TestList_SearchByCustomerEmail(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	_, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		Customer: inlineCustomer("target-search@example.com"),
	}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	_, err = env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		Customer: inlineCustomer("someone-else@other.com"),
	}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	licenses, _, err := env.svc.List(context.Background(), testAccountID, core.EnvironmentLive, domain.LicenseListFilters{Q: "target-search"}, core.Cursor{}, 10)
	require.NoError(t, err)
	require.Len(t, licenses, 1)
}
