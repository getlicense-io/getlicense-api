package search

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/getlicense-io/getlicense-api/internal/rbac"
)

// passthroughTxManager invokes fn synchronously without opening a real
// transaction. It mirrors the canonical test pattern used in
// internal/product/service_test.go.
type passthroughTxManager struct{}

func (passthroughTxManager) WithTargetAccount(ctx context.Context, _ core.AccountID, _ core.Environment, fn func(context.Context) error) error {
	return fn(ctx)
}

func (passthroughTxManager) WithTx(ctx context.Context, fn func(context.Context) error) error {
	return fn(ctx)
}

func (passthroughTxManager) WithSystemContext(ctx context.Context, fn func(context.Context) error) error {
	return fn(ctx)
}

// stubLicenseRepo records whether List was called and returns one
// canned license. Only the methods actually exercised by Search need
// real behavior; the rest are unreachable stubs included to satisfy
// the interface.
type stubLicenseRepo struct {
	called atomic.Bool
	item   domain.License
}

func (r *stubLicenseRepo) List(ctx context.Context, _ domain.LicenseListFilters, _ core.Cursor, _ int) ([]domain.License, bool, error) {
	r.called.Store(true)
	return []domain.License{r.item}, false, nil
}

// Unused interface methods; included to satisfy domain.LicenseRepository.
func (r *stubLicenseRepo) Create(context.Context, *domain.License) error { return nil }
func (r *stubLicenseRepo) BulkCreate(context.Context, []*domain.License) error {
	return nil
}
func (r *stubLicenseRepo) GetByID(context.Context, core.LicenseID) (*domain.License, error) {
	return nil, nil
}
func (r *stubLicenseRepo) GetByIDForUpdate(context.Context, core.LicenseID) (*domain.License, error) {
	return nil, nil
}
func (r *stubLicenseRepo) GetByKeyHash(context.Context, string) (*domain.License, error) {
	return nil, nil
}
func (r *stubLicenseRepo) ListByProduct(context.Context, core.ProductID, domain.LicenseListFilters, core.Cursor, int) ([]domain.License, bool, error) {
	return nil, false, nil
}
func (r *stubLicenseRepo) Update(context.Context, *domain.License) error { return nil }
func (r *stubLicenseRepo) UpdateStatus(context.Context, core.LicenseID, core.LicenseStatus, core.LicenseStatus) (time.Time, error) {
	return time.Time{}, nil
}
func (r *stubLicenseRepo) CountByProduct(context.Context, core.ProductID) (int, error) {
	return 0, nil
}
func (r *stubLicenseRepo) CountsByProductStatus(context.Context, core.ProductID) (domain.LicenseStatusCounts, error) {
	return domain.LicenseStatusCounts{}, nil
}
func (r *stubLicenseRepo) BulkRevokeByProduct(context.Context, core.ProductID) (int, error) {
	return 0, nil
}
func (r *stubLicenseRepo) HasBlocking(context.Context) (bool, error) { return false, nil }
func (r *stubLicenseRepo) ExpireActive(context.Context) ([]domain.License, error) {
	return nil, nil
}

// stubMachineRepo records whether Search was called.
type stubMachineRepo struct {
	called atomic.Bool
	item   domain.Machine
}

func (r *stubMachineRepo) Search(ctx context.Context, _ string, _ int) ([]domain.Machine, error) {
	r.called.Store(true)
	return []domain.Machine{r.item}, nil
}

func (r *stubMachineRepo) GetByID(context.Context, core.MachineID) (*domain.Machine, error) {
	return nil, nil
}
func (r *stubMachineRepo) GetByFingerprint(context.Context, core.LicenseID, string) (*domain.Machine, error) {
	return nil, nil
}
func (r *stubMachineRepo) CountAliveByLicense(context.Context, core.LicenseID) (int, error) {
	return 0, nil
}
func (r *stubMachineRepo) UpsertActivation(context.Context, *domain.Machine) error { return nil }
func (r *stubMachineRepo) RenewLease(context.Context, *domain.Machine) error       { return nil }
func (r *stubMachineRepo) DeleteByFingerprint(context.Context, core.LicenseID, string) error {
	return nil
}
func (r *stubMachineRepo) MarkStaleExpired(context.Context) (int, error) { return 0, nil }
func (r *stubMachineRepo) MarkDeadExpired(context.Context) (int, error)  { return 0, nil }
func (r *stubMachineRepo) ListByLicense(context.Context, core.LicenseID, string, core.Cursor, int) ([]domain.Machine, bool, error) {
	return nil, false, nil
}

// stubCustomerRepo records whether List was called.
type stubCustomerRepo struct {
	called atomic.Bool
	item   domain.Customer
}

func (r *stubCustomerRepo) List(ctx context.Context, _ core.AccountID, _ domain.CustomerListFilter, _ core.Cursor, _ int) ([]domain.Customer, bool, error) {
	r.called.Store(true)
	return []domain.Customer{r.item}, false, nil
}

func (r *stubCustomerRepo) Create(context.Context, *domain.Customer) error { return nil }
func (r *stubCustomerRepo) Get(context.Context, core.CustomerID) (*domain.Customer, error) {
	return nil, nil
}
func (r *stubCustomerRepo) GetByEmail(context.Context, core.AccountID, string) (*domain.Customer, error) {
	return nil, nil
}
func (r *stubCustomerRepo) Update(context.Context, *domain.Customer) error { return nil }
func (r *stubCustomerRepo) Delete(context.Context, core.CustomerID) error  { return nil }
func (r *stubCustomerRepo) CountReferencingLicenses(context.Context, core.CustomerID) (int, error) {
	return 0, nil
}
func (r *stubCustomerRepo) UpsertByEmail(context.Context, core.AccountID, string, *string, json.RawMessage, *core.AccountID) (*domain.Customer, bool, error) {
	return nil, false, nil
}

// stubProductRepo records whether Search was called.
type stubProductRepo struct {
	called atomic.Bool
	item   domain.Product
}

func (r *stubProductRepo) Search(ctx context.Context, _ string, _ int) ([]domain.Product, error) {
	r.called.Store(true)
	return []domain.Product{r.item}, nil
}

func (r *stubProductRepo) Create(context.Context, *domain.Product) error { return nil }
func (r *stubProductRepo) GetByID(context.Context, core.ProductID) (*domain.Product, error) {
	return nil, nil
}
func (r *stubProductRepo) List(context.Context, core.Cursor, int) ([]domain.Product, bool, error) {
	return nil, false, nil
}
func (r *stubProductRepo) Update(context.Context, core.ProductID, domain.UpdateProductParams) (*domain.Product, error) {
	return nil, nil
}
func (r *stubProductRepo) Delete(context.Context, core.ProductID) error { return nil }
func (r *stubProductRepo) GetSummariesByIDs(context.Context, []core.ProductID) ([]domain.ProductSummary, error) {
	return nil, nil
}

// newTestService wires the four stubs into a Service. Returns the
// service plus the stubs so tests can assert on their `called` flags
// and inspect the result payload.
func newTestService() (*Service, *stubLicenseRepo, *stubMachineRepo, *stubCustomerRepo, *stubProductRepo) {
	lic := &stubLicenseRepo{item: domain.License{ID: core.NewLicenseID(), KeyPrefix: "abc"}}
	mch := &stubMachineRepo{item: domain.Machine{ID: core.NewMachineID(), Fingerprint: "fp1"}}
	cus := &stubCustomerRepo{item: domain.Customer{ID: core.NewCustomerID(), Email: "alice@example.com"}}
	prod := &stubProductRepo{item: domain.Product{ID: core.NewProductID(), Slug: "demo"}}
	svc := NewService(passthroughTxManager{}, lic, mch, cus, prod)
	return svc, lic, mch, cus, prod
}

func roleWith(perms ...string) *domain.Role {
	return &domain.Role{
		Slug:        "test-role",
		Name:        "test role",
		Permissions: perms,
	}
}

// fullReadRole grants the four read permissions Search gates on.
func fullReadRole() *domain.Role {
	return roleWith(rbac.LicenseRead, rbac.MachineRead, rbac.CustomerRead, rbac.ProductRead)
}

func TestSearch_FullReadRole_IncludesAllTypes(t *testing.T) {
	svc, lic, mch, cus, prod := newTestService()

	res, err := svc.Search(
		context.Background(),
		core.NewAccountID(),
		core.EnvironmentLive,
		fullReadRole(),
		"acme",
		nil,
		10,
	)
	require.NoError(t, err)
	require.NotNil(t, res)

	assert.True(t, lic.called.Load(), "license sub-query should run")
	assert.True(t, mch.called.Load(), "machine sub-query should run")
	assert.True(t, cus.called.Load(), "customer sub-query should run")
	assert.True(t, prod.called.Load(), "product sub-query should run")

	assert.Len(t, res.Licenses, 1, "licenses should be populated")
	assert.Len(t, res.Machines, 1, "machines should be populated")
	assert.Len(t, res.Customers, 1, "customers should be populated")
	assert.Len(t, res.Products, 1, "products should be populated")
}

func TestSearch_ReadOnlyRole_OmitsRestrictedTypes(t *testing.T) {
	svc, lic, mch, cus, prod := newTestService()

	// Synthetic role with ONLY product:read — verifies the gate, not
	// the seeded read_only preset (which has zero permissions across
	// all four resources).
	res, err := svc.Search(
		context.Background(),
		core.NewAccountID(),
		core.EnvironmentLive,
		roleWith(rbac.ProductRead),
		"acme",
		nil,
		10,
	)
	require.NoError(t, err)
	require.NotNil(t, res)

	assert.False(t, lic.called.Load(), "license sub-query MUST NOT run without license:read")
	assert.False(t, mch.called.Load(), "machine sub-query MUST NOT run without machine:read")
	assert.False(t, cus.called.Load(), "customer sub-query MUST NOT run without customer:read")
	assert.True(t, prod.called.Load(), "product sub-query should run with product:read")

	assert.Empty(t, res.Licenses)
	assert.Empty(t, res.Machines)
	assert.Empty(t, res.Customers)
	assert.Len(t, res.Products, 1)
}

func TestSearch_NoReadPermissions_ReturnsEmpty(t *testing.T) {
	svc, lic, mch, cus, prod := newTestService()

	// Caller has an unrelated permission (billing:read) but none of
	// the four search-gated reads. Result must be empty, no error.
	res, err := svc.Search(
		context.Background(),
		core.NewAccountID(),
		core.EnvironmentLive,
		roleWith(rbac.BillingRead),
		"acme",
		nil,
		10,
	)
	require.NoError(t, err)
	require.NotNil(t, res)

	assert.False(t, lic.called.Load())
	assert.False(t, mch.called.Load())
	assert.False(t, cus.called.Load())
	assert.False(t, prod.called.Load())

	assert.Empty(t, res.Licenses)
	assert.Empty(t, res.Machines)
	assert.Empty(t, res.Customers)
	assert.Empty(t, res.Products)
}

func TestSearch_NilRole_ReturnsEmpty(t *testing.T) {
	svc, lic, mch, cus, prod := newTestService()

	// Defensive: rbac.NewChecker(nil) is documented as deny-all, so a
	// nil role must NOT panic and must produce an empty result. This
	// guards against accidental nil-deref if a future caller forgets
	// to pass a role.
	res, err := svc.Search(
		context.Background(),
		core.NewAccountID(),
		core.EnvironmentLive,
		nil,
		"acme",
		nil,
		10,
	)
	require.NoError(t, err)
	require.NotNil(t, res)

	assert.False(t, lic.called.Load())
	assert.False(t, mch.called.Load())
	assert.False(t, cus.called.Load())
	assert.False(t, prod.called.Load())

	assert.Empty(t, res.Licenses)
	assert.Empty(t, res.Machines)
	assert.Empty(t, res.Customers)
	assert.Empty(t, res.Products)
}

func TestSearch_PartialPermsWithExplicitTypeFilter(t *testing.T) {
	svc, lic, mch, cus, prod := newTestService()

	// Caller has license:read AND product:read, but the DSL restricts
	// to type:license — only the license sub-query should fire, even
	// though product:read would otherwise allow products through.
	res, err := svc.Search(
		context.Background(),
		core.NewAccountID(),
		core.EnvironmentLive,
		roleWith(rbac.LicenseRead, rbac.ProductRead),
		"type:license acme",
		nil,
		10,
	)
	require.NoError(t, err)

	assert.True(t, lic.called.Load(), "license should run (type+perm both allow)")
	assert.False(t, prod.called.Load(), "product should NOT run (type filter excludes)")
	assert.False(t, mch.called.Load())
	assert.False(t, cus.called.Load())
	assert.Len(t, res.Licenses, 1)
}
