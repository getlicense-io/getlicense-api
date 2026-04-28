package licensing

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/crypto"
	"github.com/getlicense-io/getlicense-api/internal/customer"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/getlicense-io/getlicense-api/internal/entitlement"
	"github.com/getlicense-io/getlicense-api/internal/server/middleware"
	"github.com/getlicense-io/getlicense-api/internal/testfakes"
)

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
	if f.ProductID != nil && l.ProductID != *f.ProductID {
		return false
	}
	if f.CustomerID != nil && l.CustomerID != *f.CustomerID {
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

func (r *mockLicenseRepo) CountByStatus(_ context.Context) (domain.LicenseStatusCounts, error) {
	return domain.LicenseStatusCounts{}, nil
}

func (r *mockLicenseRepo) CountIssuedByGrant(_ context.Context) (int, error) {
	return 0, nil
}

// --- mock MachineRepository ---

type mockMachineRepo struct {
	byID          map[core.MachineID]*domain.Machine
	byFingerprint map[string]core.MachineID // key: licenseID|fingerprint

	// listByLicenseRows is returned verbatim by ListByLicense when set.
	// nil means "return empty slice". Tests that want to assert on the
	// filtered slice inspect listByLicenseCalls after the service call.
	listByLicenseRows    []domain.Machine
	listByLicenseHasMore bool
	listByLicenseErr     error
	listByLicenseCalls   []listByLicenseCall
}

// listByLicenseCall records the arguments passed to ListByLicense so
// tests can assert the service forwarded the right status filter /
// cursor / limit.
type listByLicenseCall struct {
	licenseID    core.LicenseID
	statusFilter string
	cursor       core.Cursor
	limit        int
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

func (r *mockMachineRepo) ListByLicense(_ context.Context, licenseID core.LicenseID, statusFilter string, cursor core.Cursor, limit int) ([]domain.Machine, bool, error) {
	r.listByLicenseCalls = append(r.listByLicenseCalls, listByLicenseCall{
		licenseID:    licenseID,
		statusFilter: statusFilter,
		cursor:       cursor,
		limit:        limit,
	})
	if r.listByLicenseErr != nil {
		return nil, false, r.listByLicenseErr
	}
	return r.listByLicenseRows, r.listByLicenseHasMore, nil
}

func (r *mockMachineRepo) CountByStatus(_ context.Context) (domain.MachineStatusCounts, error) {
	return domain.MachineStatusCounts{}, nil
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

func (r *fakeCustomerRepo) Count(_ context.Context) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.byID), nil
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
	mk, err := crypto.NewMasterKey("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20", "", "")
	require.NoError(t, err)
	return mk
}

// createTestProduct creates an encrypted product in the mock repo and returns it.
func createTestProduct(t *testing.T, repo *testfakes.ProductRepo, mk *crypto.MasterKey, accountID core.AccountID) *domain.Product {
	t.Helper()

	pub, priv, err := crypto.GenerateEd25519Keypair()
	require.NoError(t, err)

	productID := core.NewProductID()
	privEnc, err := mk.Encrypt(priv, crypto.ProductPrivateKeyAAD(productID))
	require.NoError(t, err)

	product := &domain.Product{
		ID:            productID,
		AccountID:     accountID,
		Name:          "Test Product",
		Slug:          "test-product",
		PublicKey:     crypto.EncodePublicKey(pub),
		PrivateKeyEnc: privEnc,
		CreatedAt:     time.Now().UTC(),
	}
	repo.Seed(product)
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
	products       *testfakes.ProductRepo
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
	products := testfakes.NewProductRepo()
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
	svc := NewService(testfakes.TxManager{}, licenses, products, machines, policies, customerSvc, entitlementSvc, mk, nil, 3600)
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

// seedLicenseForListMachines inserts a bare license into the mock repo
// with the supplied grant attribution. No key generation / token signing
// — ListMachines only cares about existence and GrantID.
func seedLicenseForListMachines(t *testing.T, env *testEnv, grantID *core.GrantID) *domain.License {
	t.Helper()
	now := time.Now().UTC()
	l := &domain.License{
		ID:                 core.NewLicenseID(),
		AccountID:          testAccountID,
		ProductID:          core.NewProductID(),
		PolicyID:           core.NewPolicyID(),
		CustomerID:         core.NewCustomerID(),
		KeyPrefix:          "GETL-AAAA",
		KeyHash:            "hash-" + core.NewLicenseID().String(),
		Status:             core.LicenseStatusActive,
		Environment:        core.EnvironmentLive,
		CreatedAt:          now,
		UpdatedAt:          now,
		GrantID:            grantID,
		CreatedByAccountID: testAccountID,
	}
	env.licenses.byID[l.ID] = l
	return l
}

// productScopedKeyCtx builds a context carrying an API-key AuthContext
// scoped to keyProductID. Use this to simulate a request made with a
// product-scoped API key whose bound product may or may not match the
// resource's product.
func productScopedKeyCtx(keyProductID core.ProductID) context.Context {
	return middleware.WithAuthForTest(context.Background(), &middleware.AuthContext{
		ActorKind:       middleware.ActorKindAPIKey,
		ActingAccountID: testAccountID,
		TargetAccountID: testAccountID,
		Environment:     core.EnvironmentLive,
		APIKeyScope:     core.APIKeyScopeProduct,
		APIKeyProductID: &keyProductID,
	})
}
