package licensing

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlicense-io/getlicense-api/internal/audit"
	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/crypto"
	"github.com/getlicense-io/getlicense-api/internal/customer"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/getlicense-io/getlicense-api/internal/entitlement"
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

func (r *mockProductRepo) Search(_ context.Context, _ string, _ int) ([]domain.Product, error) {
	return nil, nil
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

type mockMachineRepo struct {
	byID          map[core.MachineID]*domain.Machine
	byFingerprint map[string]core.MachineID // key: licenseID|fingerprint
}

func newMockMachineRepo() *mockMachineRepo {
	return &mockMachineRepo{
		byID:          map[core.MachineID]*domain.Machine{},
		byFingerprint: map[string]core.MachineID{},
	}
}

func machineKey(lid core.LicenseID, fp string) string {
	return lid.String() + "|" + fp
}

func (r *mockMachineRepo) GetByID(_ context.Context, id core.MachineID) (*domain.Machine, error) {
	m, ok := r.byID[id]
	if !ok {
		return nil, nil
	}
	return m, nil
}

func (r *mockMachineRepo) GetByFingerprint(_ context.Context, lid core.LicenseID, fp string) (*domain.Machine, error) {
	id, ok := r.byFingerprint[machineKey(lid, fp)]
	if !ok {
		return nil, nil
	}
	return r.byID[id], nil
}

func (r *mockMachineRepo) CountAliveByLicense(_ context.Context, lid core.LicenseID) (int, error) {
	count := 0
	for _, m := range r.byID {
		if m.LicenseID == lid && m.Status != core.MachineStatusDead {
			count++
		}
	}
	return count, nil
}

func (r *mockMachineRepo) UpsertActivation(_ context.Context, m *domain.Machine) error {
	if existingID, ok := r.byFingerprint[machineKey(m.LicenseID, m.Fingerprint)]; ok {
		m.ID = existingID
		m.CreatedAt = r.byID[existingID].CreatedAt
	}
	r.byID[m.ID] = m
	r.byFingerprint[machineKey(m.LicenseID, m.Fingerprint)] = m.ID
	return nil
}

func (r *mockMachineRepo) RenewLease(_ context.Context, m *domain.Machine) error {
	if _, ok := r.byID[m.ID]; !ok {
		return core.NewAppError(core.ErrMachineNotFound, "not found")
	}
	r.byID[m.ID] = m
	return nil
}

func (r *mockMachineRepo) DeleteByFingerprint(_ context.Context, lid core.LicenseID, fp string) error {
	key := machineKey(lid, fp)
	id, ok := r.byFingerprint[key]
	if !ok {
		return core.NewAppError(core.ErrMachineNotFound, "Machine not found")
	}
	delete(r.byID, id)
	delete(r.byFingerprint, key)
	return nil
}

func (r *mockMachineRepo) MarkStaleExpired(context.Context) (int, error) { return 0, nil }
func (r *mockMachineRepo) MarkDeadExpired(context.Context) (int, error)  { return 0, nil }

func (r *mockMachineRepo) Search(_ context.Context, _ string, _ int) ([]domain.Machine, error) {
	return nil, nil
}

func (r *mockMachineRepo) ListByLicense(_ context.Context, _ core.LicenseID, _ string, _ core.Cursor, _ int) ([]domain.Machine, bool, error) {
	return nil, false, nil
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

// --- fakeEntitlementRepo ---

// fakeEntitlementRepo is an in-memory EntitlementRepository used to
// back the entitlement.Service inside the licensing test harness.
type fakeEntitlementRepo struct {
	mu            sync.Mutex
	byID          map[core.EntitlementID]*domain.Entitlement
	byCode        map[string]core.EntitlementID // "accountID|lower(code)"
	policyAttach  map[core.PolicyID]map[core.EntitlementID]bool
	licenseAttach map[core.LicenseID]map[core.EntitlementID]bool

	// licenseToPolicyID maps license → policy so ResolveEffective can
	// compute the union of policy + license entitlements.
	licenseToPolicyID map[core.LicenseID]core.PolicyID
}

func newFakeEntitlementRepo() *fakeEntitlementRepo {
	return &fakeEntitlementRepo{
		byID:              map[core.EntitlementID]*domain.Entitlement{},
		byCode:            map[string]core.EntitlementID{},
		policyAttach:      map[core.PolicyID]map[core.EntitlementID]bool{},
		licenseAttach:     map[core.LicenseID]map[core.EntitlementID]bool{},
		licenseToPolicyID: map[core.LicenseID]core.PolicyID{},
	}
}

func entCodeKey(accountID core.AccountID, code string) string {
	return accountID.String() + "|" + strings.ToLower(code)
}

func (r *fakeEntitlementRepo) SetLicensePolicy(licenseID core.LicenseID, policyID core.PolicyID) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.licenseToPolicyID[licenseID] = policyID
}

func (r *fakeEntitlementRepo) Create(_ context.Context, e *domain.Entitlement) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byID[e.ID] = e
	r.byCode[entCodeKey(e.AccountID, e.Code)] = e.ID
	return nil
}

func (r *fakeEntitlementRepo) Get(_ context.Context, id core.EntitlementID) (*domain.Entitlement, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.byID[id]
	if !ok {
		return nil, nil
	}
	return e, nil
}

func (r *fakeEntitlementRepo) GetByCodes(_ context.Context, accountID core.AccountID, codes []string) ([]domain.Entitlement, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var result []domain.Entitlement
	for _, c := range codes {
		if id, ok := r.byCode[entCodeKey(accountID, c)]; ok {
			if e, ok := r.byID[id]; ok {
				result = append(result, *e)
			}
		}
	}
	return result, nil
}

func (r *fakeEntitlementRepo) List(_ context.Context, _ core.AccountID, _ string, _ core.Cursor, _ int) ([]domain.Entitlement, bool, error) {
	return nil, false, nil
}

func (r *fakeEntitlementRepo) Update(_ context.Context, e *domain.Entitlement) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byID[e.ID] = e
	return nil
}

func (r *fakeEntitlementRepo) Delete(_ context.Context, id core.EntitlementID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.byID, id)
	return nil
}

func (r *fakeEntitlementRepo) AttachToPolicy(_ context.Context, policyID core.PolicyID, entIDs []core.EntitlementID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.policyAttach[policyID] == nil {
		r.policyAttach[policyID] = map[core.EntitlementID]bool{}
	}
	for _, id := range entIDs {
		r.policyAttach[policyID][id] = true
	}
	return nil
}

func (r *fakeEntitlementRepo) DetachFromPolicy(_ context.Context, policyID core.PolicyID, entIDs []core.EntitlementID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, id := range entIDs {
		delete(r.policyAttach[policyID], id)
	}
	return nil
}

func (r *fakeEntitlementRepo) ReplacePolicyAttachments(_ context.Context, policyID core.PolicyID, entIDs []core.EntitlementID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.policyAttach[policyID] = map[core.EntitlementID]bool{}
	for _, id := range entIDs {
		r.policyAttach[policyID][id] = true
	}
	return nil
}

func (r *fakeEntitlementRepo) ListPolicyCodes(_ context.Context, policyID core.PolicyID) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var codes []string
	for id := range r.policyAttach[policyID] {
		if e, ok := r.byID[id]; ok {
			codes = append(codes, e.Code)
		}
	}
	sort.Strings(codes)
	return codes, nil
}

func (r *fakeEntitlementRepo) AttachToLicense(_ context.Context, licenseID core.LicenseID, entIDs []core.EntitlementID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.licenseAttach[licenseID] == nil {
		r.licenseAttach[licenseID] = map[core.EntitlementID]bool{}
	}
	for _, id := range entIDs {
		r.licenseAttach[licenseID][id] = true
	}
	return nil
}

func (r *fakeEntitlementRepo) DetachFromLicense(_ context.Context, licenseID core.LicenseID, entIDs []core.EntitlementID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, id := range entIDs {
		delete(r.licenseAttach[licenseID], id)
	}
	return nil
}

func (r *fakeEntitlementRepo) ReplaceLicenseAttachments(_ context.Context, licenseID core.LicenseID, entIDs []core.EntitlementID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.licenseAttach[licenseID] = map[core.EntitlementID]bool{}
	for _, id := range entIDs {
		r.licenseAttach[licenseID][id] = true
	}
	return nil
}

func (r *fakeEntitlementRepo) ListLicenseCodes(_ context.Context, licenseID core.LicenseID) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var codes []string
	for id := range r.licenseAttach[licenseID] {
		if e, ok := r.byID[id]; ok {
			codes = append(codes, e.Code)
		}
	}
	sort.Strings(codes)
	return codes, nil
}

func (r *fakeEntitlementRepo) ResolveEffective(_ context.Context, licenseID core.LicenseID) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	seen := map[string]bool{}

	// Policy codes (via license → policy mapping).
	if policyID, ok := r.licenseToPolicyID[licenseID]; ok {
		for id := range r.policyAttach[policyID] {
			if e, ok := r.byID[id]; ok {
				seen[e.Code] = true
			}
		}
	}

	// License codes.
	for id := range r.licenseAttach[licenseID] {
		if e, ok := r.byID[id]; ok {
			seen[e.Code] = true
		}
	}

	codes := make([]string, 0, len(seen))
	for c := range seen {
		codes = append(codes, c)
	}
	sort.Strings(codes)
	return codes, nil
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
	svc            *Service
	products       *mockProductRepo
	policies       *mockPolicyRepo
	licenses       *mockLicenseRepo
	machines       *mockMachineRepo
	customers      *fakeCustomerRepo
	customerSvc    *customer.Service
	entitlements   *fakeEntitlementRepo
	entitlementSvc *entitlement.Service
	mk             *crypto.MasterKey
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	mk := testMasterKey(t)
	products := newMockProductRepo()
	policies := newMockPolicyRepo()
	licenses := newMockLicenseRepo()
	machines := newMockMachineRepo()
	customers := newFakeCustomerRepo()
	entitlements := newFakeEntitlementRepo()
	// Wire the license mock's search-filter customer resolver to the
	// in-memory fake so `?q=` tests match the real repo's behaviour.
	licenses.customerLookup = func(id core.CustomerID) (*domain.Customer, bool) {
		customers.mu.Lock()
		defer customers.mu.Unlock()
		c, ok := customers.byID[id]
		return c, ok
	}
	customerSvc := customer.NewService(customers)
	entitlementSvc := entitlement.NewService(entitlements)
	svc := NewService(&mockTxManager{}, licenses, products, machines, policies, customerSvc, entitlementSvc, mk, nil, 3600)
	return &testEnv{
		svc:            svc,
		products:       products,
		policies:       policies,
		licenses:       licenses,
		machines:       machines,
		customers:      customers,
		customerSvc:    customerSvc,
		entitlements:   entitlements,
		entitlementSvc: entitlementSvc,
		mk:             mk,
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

func TestValidate_ReMintsTokenWithCurrentEffectiveTTL(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	initialTTL := 600
	policySeeded := seedDefaultPolicy(t, env.policies, testAccountID, product.ID, func(p *domain.Policy) {
		p.ValidationTTLSec = &initialTTL
	})

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		Customer: inlineCustomer("user@example.com"),
	}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	// Load the product's Ed25519 public key so we can verify the re-minted token.
	productRow, ok := env.products.byID[product.ID]
	require.True(t, ok)
	privBytes, err := env.mk.Decrypt(productRow.PrivateKeyEnc)
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
	policySeeded.ValidationTTLSec = &newTTL
	require.NoError(t, env.policies.Update(context.Background(), policySeeded))

	result, err = env.svc.Validate(context.Background(), created.LicenseKey)
	require.NoError(t, err)
	assert.Equal(t, 900, result.ValidationTTLSec)
	claims, err = crypto.VerifyToken(result.License.Token, pub)
	require.NoError(t, err)
	assert.Equal(t, 900, claims.TTL)
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

	suspended, err := env.svc.Suspend(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, audit.Attribution{})
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
	err = env.svc.Revoke(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, audit.Attribution{})
	require.NoError(t, err)

	_, err = env.svc.Suspend(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, audit.Attribution{})
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

	err = env.svc.Revoke(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, audit.Attribution{})
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

	_, err = env.svc.Suspend(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, audit.Attribution{})
	require.NoError(t, err)

	reinstated, err := env.svc.Reinstate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, audit.Attribution{})
	require.NoError(t, err)
	assert.Equal(t, core.LicenseStatusActive, reinstated.Status)
}

func TestReinstate_InvalidTransition(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	_, err = env.svc.Reinstate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, audit.Attribution{})
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

	result, err := env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{
		Fingerprint: "fp-abc-123",
	}, audit.Attribution{})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "fp-abc-123", result.Machine.Fingerprint)
	assert.Equal(t, created.License.ID, result.Machine.LicenseID)
	assert.Equal(t, testAccountID, result.Machine.AccountID)
	assert.NotEmpty(t, result.LeaseToken)
	assert.True(t, strings.HasPrefix(result.LeaseToken, "gl2."))
}

func TestActivate_DuplicateFingerprint_Idempotent(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	maxM := 3
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, func(p *domain.Policy) {
		p.MaxMachines = &maxM
	})

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	first, err := env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{
		Fingerprint: "fp-dup",
	}, audit.Attribution{})
	require.NoError(t, err)

	// Re-activate same fingerprint is idempotent — reuses the machine ID.
	second, err := env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{
		Fingerprint: "fp-dup",
	}, audit.Attribution{})
	require.NoError(t, err)
	assert.Equal(t, first.Machine.ID, second.Machine.ID)
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
		_, err = env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{
			Fingerprint: fp,
		}, audit.Attribution{})
		require.NoError(t, err)
	}

	_, err = env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{
		Fingerprint: "fp-3",
	}, audit.Attribution{})
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
		_, err = env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{
			Fingerprint: fp,
		}, audit.Attribution{})
		require.NoError(t, err)
	}
}

func TestActivate_LicenseNotFound(t *testing.T) {
	env := newTestEnv(t)

	_, err := env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, core.NewLicenseID(), ActivateRequest{
		Fingerprint: "fp-orphan",
	}, audit.Attribution{})
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
	}, audit.Attribution{})
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
	}, audit.Attribution{})
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
	}, audit.Attribution{})
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
		_, err := env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{
			Fingerprint: fp,
		}, audit.Attribution{})
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
	}, audit.Attribution{})
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
	}, audit.Attribution{})
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
	}, audit.Attribution{})
	require.NoError(t, err)

	err = env.svc.Deactivate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, DeactivateRequest{
		Fingerprint: "fp-remove",
	}, audit.Attribution{})
	require.NoError(t, err)

	key := machineKey(created.License.ID, "fp-remove")
	_, ok := env.machines.byFingerprint[key]
	assert.False(t, ok)
}

func TestDeactivate_EmptyFingerprint(t *testing.T) {
	env := newTestEnv(t)

	err := env.svc.Deactivate(context.Background(), testAccountID, core.EnvironmentLive, core.NewLicenseID(), DeactivateRequest{
		Fingerprint: "",
	}, audit.Attribution{})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrValidationError, appErr.Code)
}

// --- Checkin tests ---

func TestCheckin_HappyPath(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, func(p *domain.Policy) {
		p.RequireCheckout = true
		p.CheckoutIntervalSec = 3600
	})

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	activated, err := env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{
		Fingerprint: "fp-1",
	}, audit.Attribution{})
	require.NoError(t, err)
	originalLeaseExp := activated.Machine.LeaseExpiresAt

	// Wait one tick to ensure lease times advance.
	time.Sleep(10 * time.Millisecond)

	checkin, err := env.svc.Checkin(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, "fp-1", audit.Attribution{})
	require.NoError(t, err)
	if !checkin.Machine.LeaseExpiresAt.After(originalLeaseExp) {
		t.Errorf("checkin lease should be later than initial activation lease")
	}
	assert.NotEmpty(t, checkin.LeaseToken)
	assert.True(t, strings.HasPrefix(checkin.LeaseToken, "gl2."))
	assert.NotEmpty(t, checkin.LeaseClaims.LicenseID)
}

func TestCheckin_DeadMachineRejected(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	activated, err := env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{Fingerprint: "fp-1"}, audit.Attribution{})
	require.NoError(t, err)

	// Force dead status via the mock.
	env.machines.byID[activated.Machine.ID].Status = core.MachineStatusDead

	_, err = env.svc.Checkin(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, "fp-1", audit.Attribution{})
	var appErr *core.AppError
	if !errors.As(err, &appErr) || appErr.Code != core.ErrMachineDead {
		t.Errorf("want machine_dead, got %v", err)
	}
}

func TestActivate_ResurrectsDeadMachine(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	first, err := env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{Fingerprint: "fp-1"}, audit.Attribution{})
	require.NoError(t, err)
	originalID := first.Machine.ID

	// Mark dead.
	env.machines.byID[originalID].Status = core.MachineStatusDead

	// Re-activate same fingerprint.
	second, err := env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{Fingerprint: "fp-1"}, audit.Attribution{})
	require.NoError(t, err)
	assert.Equal(t, originalID, second.Machine.ID, "resurrection should reuse machine id")
	assert.Equal(t, core.MachineStatusActive, second.Machine.Status, "resurrected machine should be active")
}

func TestActivate_DeadMachinesDontCountTowardCap(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	one := 1
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, func(p *domain.Policy) {
		p.MaxMachines = &one
	})

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		Customer: inlineCustomer("u@example.com"),
	}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	// Activate and kill.
	first, err := env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{Fingerprint: "fp-a"}, audit.Attribution{})
	require.NoError(t, err)
	env.machines.byID[first.Machine.ID].Status = core.MachineStatusDead

	// New fingerprint should now be allowed because dead doesn't count.
	_, err = env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{Fingerprint: "fp-b"}, audit.Attribution{})
	if err != nil {
		t.Errorf("dead machine should not count toward cap; got %v", err)
	}
}

func TestActivate_StaleStillCounts(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	one := 1
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, func(p *domain.Policy) {
		p.MaxMachines = &one
	})

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		Customer: inlineCustomer("u@example.com"),
	}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	first, err := env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{Fingerprint: "fp-a"}, audit.Attribution{})
	require.NoError(t, err)
	env.machines.byID[first.Machine.ID].Status = core.MachineStatusStale

	_, err = env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{Fingerprint: "fp-b"}, audit.Attribution{})
	var appErr *core.AppError
	if !errors.As(err, &appErr) || appErr.Code != core.ErrMachineLimitExceeded {
		t.Errorf("stale should still count; want machine_limit_exceeded, got %v", err)
	}
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

// --- Entitlement integration tests (L3 Task 7) ---

// seedEntitlement creates an entitlement in the fake repo and returns it.
func seedEntitlement(t *testing.T, env *testEnv, accountID core.AccountID, code string) *domain.Entitlement {
	t.Helper()
	e, err := env.entitlementSvc.Create(context.Background(), accountID, entitlement.CreateRequest{
		Code: code,
		Name: code + " feature",
	})
	require.NoError(t, err)
	return e
}

func TestActivate_LeaseTokenContainsEntitlements(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	pol := seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	// Create two entitlements and attach one to the policy.
	entA := seedEntitlement(t, env, testAccountID, "FEATURE_A")
	entB := seedEntitlement(t, env, testAccountID, "FEATURE_B")

	err := env.entitlementSvc.AttachToPolicy(context.Background(), pol.ID, []string{entA.Code}, testAccountID)
	require.NoError(t, err)

	// Create a license and attach entB to the license directly.
	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		Customer: inlineCustomer("ent-test@example.com"),
	}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	err = env.entitlementSvc.AttachToLicense(context.Background(), created.License.ID, []string{entB.Code}, testAccountID)
	require.NoError(t, err)

	// Seed the license → policy mapping in the fake repo so
	// ResolveEffective can compute the union.
	env.entitlements.SetLicensePolicy(created.License.ID, pol.ID)

	result, err := env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{
		Fingerprint: "fp-ent-1",
	}, audit.Attribution{})
	require.NoError(t, err)

	// Lease claims should contain both entitlements sorted.
	assert.Equal(t, []string{"FEATURE_A", "FEATURE_B"}, result.LeaseClaims.Entitlements)
}

func TestValidate_ReturnsEntitlements(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	pol := seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	entA := seedEntitlement(t, env, testAccountID, "OFFLINE_ACCESS")

	err := env.entitlementSvc.AttachToPolicy(context.Background(), pol.ID, []string{entA.Code}, testAccountID)
	require.NoError(t, err)

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		Customer: inlineCustomer("validate-ent@example.com"),
	}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	// Seed the license → policy mapping.
	env.entitlements.SetLicensePolicy(created.License.ID, pol.ID)

	result, err := env.svc.Validate(context.Background(), created.LicenseKey)
	require.NoError(t, err)
	assert.True(t, result.Valid)
	assert.Equal(t, []string{"OFFLINE_ACCESS"}, result.Entitlements)
}

func TestCreate_InlineEntitlements(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	seedEntitlement(t, env, testAccountID, "CODE_A")
	seedEntitlement(t, env, testAccountID, "CODE_B")

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		Customer:     inlineCustomer("inline-ent@example.com"),
		Entitlements: []string{"CODE_A", "CODE_B"},
	}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)
	require.NotNil(t, created)

	// Verify the entitlements were attached to the license.
	codes, err := env.entitlementSvc.ListLicenseCodes(context.Background(), created.License.ID)
	require.NoError(t, err)
	assert.Equal(t, []string{"CODE_A", "CODE_B"}, codes)
}

func TestCreate_InlineEntitlements_AllowedCodesRejectsUnknown(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	seedEntitlement(t, env, testAccountID, "ALLOWED")
	seedEntitlement(t, env, testAccountID, "FORBIDDEN")

	_, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		Customer:     inlineCustomer("restricted@example.com"),
		Entitlements: []string{"ALLOWED", "FORBIDDEN"},
	}, CreateOptions{
		CreatedByAccountID:      testAccountID,
		AllowedEntitlementCodes: []string{"ALLOWED"},
	})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrGrantEntitlementNotAllowed, appErr.Code)
}

// --- Grant AllowedEntitlementCodes enforcement (L3 Task 8) ---

func TestCreateLicense_AllowedEntitlementCodes_Allowed(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	seedEntitlement(t, env, testAccountID, "FEATURE_X")
	seedEntitlement(t, env, testAccountID, "FEATURE_Y")

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		Customer:     inlineCustomer("allowed-ent@example.com"),
		Entitlements: []string{"FEATURE_X", "FEATURE_Y"},
	}, CreateOptions{
		CreatedByAccountID:      testAccountID,
		AllowedEntitlementCodes: []string{"FEATURE_X", "FEATURE_Y"},
	})
	require.NoError(t, err)
	require.NotNil(t, created)

	// Verify entitlements were attached.
	codes, err := env.entitlementSvc.ListLicenseCodes(context.Background(), created.License.ID)
	require.NoError(t, err)
	assert.Equal(t, []string{"FEATURE_X", "FEATURE_Y"}, codes)
}

func TestCreateLicense_AllowedEntitlementCodes_NotAllowed(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	seedEntitlement(t, env, testAccountID, "APPROVED")
	seedEntitlement(t, env, testAccountID, "BLOCKED")

	_, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		Customer:     inlineCustomer("blocked-ent@example.com"),
		Entitlements: []string{"APPROVED", "BLOCKED"},
	}, CreateOptions{
		CreatedByAccountID:      testAccountID,
		AllowedEntitlementCodes: []string{"APPROVED"},
	})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrGrantEntitlementNotAllowed, appErr.Code)
}

func TestCreateLicense_AllowedEntitlementCodes_Empty_AllowsAll(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	seedEntitlement(t, env, testAccountID, "ANY_CODE")
	seedEntitlement(t, env, testAccountID, "ANY_OTHER")

	// Empty AllowedEntitlementCodes means no constraint — all codes are permitted.
	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		Customer:     inlineCustomer("unrestricted@example.com"),
		Entitlements: []string{"ANY_CODE", "ANY_OTHER"},
	}, CreateOptions{
		CreatedByAccountID:      testAccountID,
		AllowedEntitlementCodes: []string{},
	})
	require.NoError(t, err)
	require.NotNil(t, created)

	// Verify entitlements were attached.
	codes, err := env.entitlementSvc.ListLicenseCodes(context.Background(), created.License.ID)
	require.NoError(t, err)
	assert.Equal(t, []string{"ANY_CODE", "ANY_OTHER"}, codes)
}

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
