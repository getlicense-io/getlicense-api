package grant

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlicense-io/getlicense-api/internal/audit"
	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

// --- test helpers ---

var (
	grantorID = core.NewAccountID()
	granteeID = core.NewAccountID()
)

type testEnv struct {
	svc      *Service
	repo     *fakeGrantRepo
	products *fakeProductRepo
	events   *fakeEventRepo
}

func newTestEnv() *testEnv {
	repo := newFakeGrantRepo()
	products := newFakeProductRepo()
	events := newFakeEventRepo()
	svc := NewService(&fakeTxManager{}, repo, products, audit.NewWriter(events))
	return &testEnv{svc: svc, repo: repo, products: products, events: events}
}

// seedProduct creates a product owned by ownerID and returns it.
func (e *testEnv) seedProduct(ownerID core.AccountID) *domain.Product {
	p := &domain.Product{
		ID:        core.NewProductID(),
		AccountID: ownerID,
		Name:      "Test Product",
		Slug:      "test-product",
	}
	_ = e.products.Create(context.Background(), p)
	return p
}

func defaultIssueReq(productID core.ProductID) IssueRequest {
	return IssueRequest{
		GranteeAccountID: granteeID,
		ProductID:        productID,
		Capabilities:     []domain.GrantCapability{domain.GrantCapLicenseCreate},
	}
}

// --- Issue tests ---

func TestIssue_HappyPath(t *testing.T) {
	env := newTestEnv()
	p := env.seedProduct(grantorID)

	g, err := env.svc.Issue(context.Background(), grantorID, core.EnvironmentLive, defaultIssueReq(p.ID), audit.Attribution{})
	require.NoError(t, err)
	require.NotNil(t, g)

	assert.Equal(t, grantorID, g.GrantorAccountID)
	assert.Equal(t, granteeID, g.GranteeAccountID)
	assert.Equal(t, p.ID, g.ProductID)
	assert.Equal(t, domain.GrantStatusPending, g.Status)
	assert.Equal(t, []domain.GrantCapability{domain.GrantCapLicenseCreate}, g.Capabilities)
	assert.False(t, g.CreatedAt.IsZero())

	// Stored in repo.
	stored, ok := env.repo.byID[g.ID]
	require.True(t, ok)
	assert.Equal(t, g.ID, stored.ID)
}

func TestIssue_SameAccount(t *testing.T) {
	env := newTestEnv()
	p := env.seedProduct(grantorID)

	req := IssueRequest{
		GranteeAccountID: grantorID, // same as grantor
		ProductID:        p.ID,
		Capabilities:     []domain.GrantCapability{domain.GrantCapLicenseCreate},
	}
	_, err := env.svc.Issue(context.Background(), grantorID, core.EnvironmentLive, req, audit.Attribution{})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrValidationError, appErr.Code)
}

// F-003: Issue must reject unknown capability strings so the grant
// is never stored with a value RequireCapability will later refuse.
func TestIssue_RejectsUnknownCapability(t *testing.T) {
	env := newTestEnv()
	p := env.seedProduct(grantorID)

	badCases := []domain.GrantCapability{
		"license.create",   // wrong case / dot form
		"TOTALLY_FAKE",     // not in enum
		"../../etc/passwd", // path traversal payload
		"",                 // empty
	}
	for _, c := range badCases {
		t.Run(string(c), func(t *testing.T) {
			req := IssueRequest{
				GranteeAccountID: granteeID,
				ProductID:        p.ID,
				Capabilities:     []domain.GrantCapability{c},
			}
			_, err := env.svc.Issue(context.Background(), grantorID, core.EnvironmentLive, req, audit.Attribution{})
			require.Error(t, err)

			var appErr *core.AppError
			require.ErrorAs(t, err, &appErr)
			assert.Equal(t, core.ErrValidationError, appErr.Code)
		})
	}

	// Repo must have zero grants — none of the bad issues landed.
	assert.Len(t, env.repo.byID, 0, "invalid grants must not be stored")
}

func TestIssue_NoCapabilities(t *testing.T) {
	env := newTestEnv()
	p := env.seedProduct(grantorID)

	req := IssueRequest{
		GranteeAccountID: granteeID,
		ProductID:        p.ID,
		Capabilities:     []domain.GrantCapability{},
	}
	_, err := env.svc.Issue(context.Background(), grantorID, core.EnvironmentLive, req, audit.Attribution{})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrValidationError, appErr.Code)
}

func TestIssue_RejectsForeignProduct(t *testing.T) {
	env := newTestEnv()
	otherAccountID := core.NewAccountID()
	p := env.seedProduct(otherAccountID) // product belongs to a different account

	_, err := env.svc.Issue(context.Background(), grantorID, core.EnvironmentLive, defaultIssueReq(p.ID), audit.Attribution{})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrProductNotFound, appErr.Code)
}

// --- Accept tests ---

func TestAccept_HappyPath(t *testing.T) {
	env := newTestEnv()
	p := env.seedProduct(grantorID)

	issued, err := env.svc.Issue(context.Background(), grantorID, core.EnvironmentLive, defaultIssueReq(p.ID), audit.Attribution{})
	require.NoError(t, err)

	accepted, err := env.svc.Accept(context.Background(), granteeID, core.EnvironmentLive, issued.ID, audit.Attribution{})
	require.NoError(t, err)
	require.NotNil(t, accepted)

	assert.Equal(t, domain.GrantStatusActive, accepted.Status)
	assert.NotNil(t, accepted.AcceptedAt)

	// Stored status is updated.
	stored := env.repo.byID[issued.ID]
	assert.Equal(t, domain.GrantStatusActive, stored.Status)
}

func TestAccept_WrongGrantee(t *testing.T) {
	env := newTestEnv()
	p := env.seedProduct(grantorID)

	issued, err := env.svc.Issue(context.Background(), grantorID, core.EnvironmentLive, defaultIssueReq(p.ID), audit.Attribution{})
	require.NoError(t, err)

	wrongAccount := core.NewAccountID()
	_, err = env.svc.Accept(context.Background(), wrongAccount, core.EnvironmentLive, issued.ID, audit.Attribution{})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrGrantNotFound, appErr.Code)
}

func TestAccept_NotPending(t *testing.T) {
	env := newTestEnv()
	p := env.seedProduct(grantorID)

	issued, err := env.svc.Issue(context.Background(), grantorID, core.EnvironmentLive, defaultIssueReq(p.ID), audit.Attribution{})
	require.NoError(t, err)

	// Accept once.
	_, err = env.svc.Accept(context.Background(), granteeID, core.EnvironmentLive, issued.ID, audit.Attribution{})
	require.NoError(t, err)

	// Accept again — now active, not pending.
	_, err = env.svc.Accept(context.Background(), granteeID, core.EnvironmentLive, issued.ID, audit.Attribution{})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrGrantNotActive, appErr.Code)
}

func TestAccept_NotFound(t *testing.T) {
	env := newTestEnv()

	_, err := env.svc.Accept(context.Background(), granteeID, core.EnvironmentLive, core.NewGrantID(), audit.Attribution{})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrGrantNotFound, appErr.Code)
}

// --- Suspend tests ---

func TestSuspend_HappyPath(t *testing.T) {
	env := newTestEnv()
	p := env.seedProduct(grantorID)

	issued, err := env.svc.Issue(context.Background(), grantorID, core.EnvironmentLive, defaultIssueReq(p.ID), audit.Attribution{})
	require.NoError(t, err)
	_, err = env.svc.Accept(context.Background(), granteeID, core.EnvironmentLive, issued.ID, audit.Attribution{})
	require.NoError(t, err)

	suspended, err := env.svc.Suspend(context.Background(), grantorID, core.EnvironmentLive, issued.ID, audit.Attribution{})
	require.NoError(t, err)

	assert.Equal(t, domain.GrantStatusSuspended, suspended.Status)

	stored := env.repo.byID[issued.ID]
	require.NotNil(t, stored)
	assert.Equal(t, domain.GrantStatusSuspended, stored.Status)
}

func TestSuspend_NotActive(t *testing.T) {
	env := newTestEnv()
	p := env.seedProduct(grantorID)

	// Grant is pending — cannot suspend.
	issued, err := env.svc.Issue(context.Background(), grantorID, core.EnvironmentLive, defaultIssueReq(p.ID), audit.Attribution{})
	require.NoError(t, err)

	_, err = env.svc.Suspend(context.Background(), grantorID, core.EnvironmentLive, issued.ID, audit.Attribution{})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrGrantNotActive, appErr.Code)
}

func TestSuspend_WrongGrantor(t *testing.T) {
	env := newTestEnv()
	p := env.seedProduct(grantorID)

	issued, err := env.svc.Issue(context.Background(), grantorID, core.EnvironmentLive, defaultIssueReq(p.ID), audit.Attribution{})
	require.NoError(t, err)
	_, err = env.svc.Accept(context.Background(), granteeID, core.EnvironmentLive, issued.ID, audit.Attribution{})
	require.NoError(t, err)

	wrongAccount := core.NewAccountID()
	_, err = env.svc.Suspend(context.Background(), wrongAccount, core.EnvironmentLive, issued.ID, audit.Attribution{})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrGrantNotFound, appErr.Code)
}

// --- Revoke tests ---

func TestRevoke_HappyPath(t *testing.T) {
	env := newTestEnv()
	p := env.seedProduct(grantorID)

	issued, err := env.svc.Issue(context.Background(), grantorID, core.EnvironmentLive, defaultIssueReq(p.ID), audit.Attribution{})
	require.NoError(t, err)
	_, err = env.svc.Accept(context.Background(), granteeID, core.EnvironmentLive, issued.ID, audit.Attribution{})
	require.NoError(t, err)

	revoked, err := env.svc.Revoke(context.Background(), grantorID, core.EnvironmentLive, issued.ID, audit.Attribution{})
	require.NoError(t, err)

	assert.Equal(t, domain.GrantStatusRevoked, revoked.Status)

	stored := env.repo.byID[issued.ID]
	require.NotNil(t, stored)
	assert.Equal(t, domain.GrantStatusRevoked, stored.Status)
}

func TestRevoke_AlreadyRevoked(t *testing.T) {
	env := newTestEnv()
	p := env.seedProduct(grantorID)

	issued, err := env.svc.Issue(context.Background(), grantorID, core.EnvironmentLive, defaultIssueReq(p.ID), audit.Attribution{})
	require.NoError(t, err)

	_, err = env.svc.Revoke(context.Background(), grantorID, core.EnvironmentLive, issued.ID, audit.Attribution{})
	require.NoError(t, err)

	_, err = env.svc.Revoke(context.Background(), grantorID, core.EnvironmentLive, issued.ID, audit.Attribution{})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrValidationError, appErr.Code)
}

func TestRevoke_WrongGrantor(t *testing.T) {
	env := newTestEnv()
	p := env.seedProduct(grantorID)

	issued, err := env.svc.Issue(context.Background(), grantorID, core.EnvironmentLive, defaultIssueReq(p.ID), audit.Attribution{})
	require.NoError(t, err)

	wrongAccount := core.NewAccountID()
	_, err = env.svc.Revoke(context.Background(), wrongAccount, core.EnvironmentLive, issued.ID, audit.Attribution{})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrGrantNotFound, appErr.Code)
}

// --- Leave tests ---

func TestLeave_ActiveGrant_TransitionsToLeft(t *testing.T) {
	env := newTestEnv()
	p := env.seedProduct(grantorID)

	issued, err := env.svc.Issue(context.Background(), grantorID, core.EnvironmentLive, defaultIssueReq(p.ID), audit.Attribution{})
	require.NoError(t, err)
	_, err = env.svc.Accept(context.Background(), granteeID, core.EnvironmentLive, issued.ID, audit.Attribution{})
	require.NoError(t, err)

	got, err := env.svc.Leave(context.Background(), granteeID, core.EnvironmentLive, issued.ID, audit.Attribution{})
	require.NoError(t, err)
	assert.Equal(t, domain.GrantStatusLeft, got.Status)

	stored := env.repo.byID[issued.ID]
	require.NotNil(t, stored)
	assert.Equal(t, domain.GrantStatusLeft, stored.Status)
}

func TestLeave_NonGrantee_Returns404(t *testing.T) {
	env := newTestEnv()
	p := env.seedProduct(grantorID)

	issued, err := env.svc.Issue(context.Background(), grantorID, core.EnvironmentLive, defaultIssueReq(p.ID), audit.Attribution{})
	require.NoError(t, err)
	_, err = env.svc.Accept(context.Background(), granteeID, core.EnvironmentLive, issued.ID, audit.Attribution{})
	require.NoError(t, err)

	stranger := core.NewAccountID()
	_, err = env.svc.Leave(context.Background(), stranger, core.EnvironmentLive, issued.ID, audit.Attribution{})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrGrantNotFound, appErr.Code)
}

func TestLeave_AlreadyLeft_Returns422(t *testing.T) {
	env := newTestEnv()
	p := env.seedProduct(grantorID)

	issued, err := env.svc.Issue(context.Background(), grantorID, core.EnvironmentLive, defaultIssueReq(p.ID), audit.Attribution{})
	require.NoError(t, err)
	_, err = env.svc.Accept(context.Background(), granteeID, core.EnvironmentLive, issued.ID, audit.Attribution{})
	require.NoError(t, err)
	_, err = env.svc.Leave(context.Background(), granteeID, core.EnvironmentLive, issued.ID, audit.Attribution{})
	require.NoError(t, err)

	_, err = env.svc.Leave(context.Background(), granteeID, core.EnvironmentLive, issued.ID, audit.Attribution{})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrGrantAlreadyLeft, appErr.Code)
}

func TestLeave_RevokedGrant_Returns422(t *testing.T) {
	env := newTestEnv()
	p := env.seedProduct(grantorID)

	issued, err := env.svc.Issue(context.Background(), grantorID, core.EnvironmentLive, defaultIssueReq(p.ID), audit.Attribution{})
	require.NoError(t, err)
	_, err = env.svc.Accept(context.Background(), granteeID, core.EnvironmentLive, issued.ID, audit.Attribution{})
	require.NoError(t, err)
	require.NoError(t, env.repo.UpdateStatus(context.Background(), issued.ID, domain.GrantStatusRevoked))

	_, err = env.svc.Leave(context.Background(), granteeID, core.EnvironmentLive, issued.ID, audit.Attribution{})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrGrantNotActive, appErr.Code)
}

// --- Get tests ---

func TestGet_HappyPath_AsGrantor(t *testing.T) {
	env := newTestEnv()
	p := env.seedProduct(grantorID)

	issued, err := env.svc.Issue(context.Background(), grantorID, core.EnvironmentLive, defaultIssueReq(p.ID), audit.Attribution{})
	require.NoError(t, err)

	g, err := env.svc.Get(context.Background(), grantorID, core.EnvironmentLive, issued.ID)
	require.NoError(t, err)
	assert.Equal(t, issued.ID, g.ID)
}

func TestGet_HappyPath_AsGrantee(t *testing.T) {
	env := newTestEnv()
	p := env.seedProduct(grantorID)

	issued, err := env.svc.Issue(context.Background(), grantorID, core.EnvironmentLive, defaultIssueReq(p.ID), audit.Attribution{})
	require.NoError(t, err)

	g, err := env.svc.Get(context.Background(), granteeID, core.EnvironmentLive, issued.ID)
	require.NoError(t, err)
	assert.Equal(t, issued.ID, g.ID)
}

func TestGet_UnrelatedAccount(t *testing.T) {
	env := newTestEnv()
	p := env.seedProduct(grantorID)

	issued, err := env.svc.Issue(context.Background(), grantorID, core.EnvironmentLive, defaultIssueReq(p.ID), audit.Attribution{})
	require.NoError(t, err)

	unrelated := core.NewAccountID()
	_, err = env.svc.Get(context.Background(), unrelated, core.EnvironmentLive, issued.ID)
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrGrantNotFound, appErr.Code)
}

func TestGet_NotFound(t *testing.T) {
	env := newTestEnv()

	_, err := env.svc.Get(context.Background(), grantorID, core.EnvironmentLive, core.NewGrantID())
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrGrantNotFound, appErr.Code)
}

// Get populates the Usage aggregate so dashboards get per-grant
// counts in the single-grant response. The fake repo's license-count
// map backs all three counts; CountDistinctCustomers currently
// returns 0 in the fake — the assertion here is scoped to
// LicensesTotal, which is the most load-bearing usage field.
func TestGet_PopulatesUsage(t *testing.T) {
	env := newTestEnv()
	g := env.issueAndAccept(t)
	env.repo.licenseCounts[g.ID] = 2

	got, err := env.svc.Get(context.Background(), g.GrantorAccountID, core.EnvironmentLive, g.ID)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.NotNil(t, got.Usage, "Get must populate Usage on the single-grant response")
	assert.Equal(t, 2, got.Usage.LicensesTotal)
	assert.Equal(t, 2, got.Usage.LicensesThisMonth) // fake repo returns same count regardless of `since`
	assert.Equal(t, 0, got.Usage.CustomersTotal)    // fake repo returns 0
}

// --- RequireCapability tests ---

func TestRequireCapability_HappyPath(t *testing.T) {
	g := &domain.Grant{
		Status:       domain.GrantStatusActive,
		Capabilities: []domain.GrantCapability{domain.GrantCapLicenseCreate, domain.GrantCapLicenseRevoke},
	}

	err := (&Service{}).RequireCapability(g, domain.GrantCapLicenseCreate)
	require.NoError(t, err)
}

func TestRequireCapability_CapabilityDenied(t *testing.T) {
	g := &domain.Grant{
		Status:       domain.GrantStatusActive,
		Capabilities: []domain.GrantCapability{domain.GrantCapLicenseCreate},
	}

	err := (&Service{}).RequireCapability(g, domain.GrantCapLicenseRevoke)
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrGrantCapabilityDenied, appErr.Code)
}

func TestRequireCapability_NotActive(t *testing.T) {
	g := &domain.Grant{
		Status:       domain.GrantStatusSuspended,
		Capabilities: []domain.GrantCapability{domain.GrantCapLicenseCreate},
	}

	err := (&Service{}).RequireCapability(g, domain.GrantCapLicenseCreate)
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrGrantNotActive, appErr.Code)
}

// --- Resolve tests ---

func TestResolve_HappyPath(t *testing.T) {
	env := newTestEnv()
	p := env.seedProduct(grantorID)

	issued, err := env.svc.Issue(context.Background(), grantorID, core.EnvironmentLive, defaultIssueReq(p.ID), audit.Attribution{})
	require.NoError(t, err)

	g, err := env.svc.Resolve(context.Background(), issued.ID, granteeID)
	require.NoError(t, err)
	require.NotNil(t, g)
	assert.Equal(t, issued.ID, g.ID)
	assert.Equal(t, granteeID, g.GranteeAccountID)
}

func TestResolve_RejectsNonGrantee(t *testing.T) {
	env := newTestEnv()
	p := env.seedProduct(grantorID)

	issued, err := env.svc.Issue(context.Background(), grantorID, core.EnvironmentLive, defaultIssueReq(p.ID), audit.Attribution{})
	require.NoError(t, err)

	otherAccountID := core.NewAccountID()
	_, err = env.svc.Resolve(context.Background(), issued.ID, otherAccountID)
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrPermissionDenied, appErr.Code)
}

// --- RequireActive tests ---

func TestRequireActive_Active(t *testing.T) {
	g := &domain.Grant{Status: domain.GrantStatusActive}
	err := (&Service{}).RequireActive(g)
	require.NoError(t, err)
}

func TestRequireActive_Suspended(t *testing.T) {
	g := &domain.Grant{Status: domain.GrantStatusSuspended}
	err := (&Service{}).RequireActive(g)
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrGrantNotActive, appErr.Code)
}

func TestRequireActive_Expired(t *testing.T) {
	past := time.Now().UTC().Add(-time.Hour)
	g := &domain.Grant{
		Status:    domain.GrantStatusActive,
		ExpiresAt: &past,
	}
	err := (&Service{}).RequireActive(g)
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrGrantNotActive, appErr.Code)
}

// --- CheckLicenseCreateConstraints tests ---

func TestCheckLicenseCreateConstraints_NoConstraints(t *testing.T) {
	env := newTestEnv()
	g := &domain.Grant{
		ID:           core.NewGrantID(),
		Capabilities: []domain.GrantCapability{domain.GrantCapLicenseCreate, domain.GrantCapCustomerCreate},
		Constraints:  json.RawMessage(`{}`),
	}

	err := env.svc.CheckLicenseCreateConstraints(context.Background(), g, true)
	require.NoError(t, err)
}

func TestCheckLicenseCreateConstraints_MaxTotalExceeded(t *testing.T) {
	env := newTestEnv()
	grantID := core.NewGrantID()
	env.repo.licenseCounts[grantID] = 5

	g := &domain.Grant{
		ID:           grantID,
		Capabilities: []domain.GrantCapability{domain.GrantCapLicenseCreate, domain.GrantCapCustomerCreate},
		Constraints:  json.RawMessage(`{"max_licenses_total":5}`),
	}

	err := env.svc.CheckLicenseCreateConstraints(context.Background(), g, true)
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrGrantConstraintViolated, appErr.Code)
}

func TestCheckLicenseCreateConstraints_MaxPerMonthExceeded(t *testing.T) {
	env := newTestEnv()
	grantID := core.NewGrantID()
	env.repo.licenseCounts[grantID] = 10

	g := &domain.Grant{
		ID:           grantID,
		Capabilities: []domain.GrantCapability{domain.GrantCapLicenseCreate, domain.GrantCapCustomerCreate},
		Constraints:  json.RawMessage(`{"max_licenses_per_month":10}`),
	}

	err := env.svc.CheckLicenseCreateConstraints(context.Background(), g, true)
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrGrantConstraintViolated, appErr.Code)
}

// CustomerEmailPattern enforcement moved to licensing.Service.Create
// in L4 where the resolved customer email is available. See
// internal/licensing/service_test.go for the replacement coverage.

// L4: CheckLicenseCreateConstraints now discriminates between the
// inline-customer path (requires CUSTOMER_CREATE) and the attach-
// existing path (requires CUSTOMER_READ).

func TestCheckLicenseCreate_InlineCustomer_RequiresCustomerCreate(t *testing.T) {
	env := newTestEnv()
	g := &domain.Grant{
		ID:           core.NewGrantID(),
		Status:       domain.GrantStatusActive,
		Capabilities: []domain.GrantCapability{domain.GrantCapLicenseCreate},
	}
	err := env.svc.CheckLicenseCreateConstraints(context.Background(), g, true)
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrGrantCapabilityMissing, appErr.Code)
}

func TestCheckLicenseCreate_InlineCustomer_WithCustomerCreate_Allows(t *testing.T) {
	env := newTestEnv()
	g := &domain.Grant{
		ID:           core.NewGrantID(),
		Status:       domain.GrantStatusActive,
		Capabilities: []domain.GrantCapability{domain.GrantCapLicenseCreate, domain.GrantCapCustomerCreate},
	}
	err := env.svc.CheckLicenseCreateConstraints(context.Background(), g, true)
	require.NoError(t, err)
}

func TestCheckLicenseCreate_AttachExisting_RequiresCustomerRead(t *testing.T) {
	env := newTestEnv()
	g := &domain.Grant{
		ID:           core.NewGrantID(),
		Status:       domain.GrantStatusActive,
		Capabilities: []domain.GrantCapability{domain.GrantCapLicenseCreate},
	}
	err := env.svc.CheckLicenseCreateConstraints(context.Background(), g, false)
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrGrantCapabilityMissing, appErr.Code)
}

func TestCheckLicenseCreate_AttachExisting_WithCustomerRead_Allows(t *testing.T) {
	env := newTestEnv()
	g := &domain.Grant{
		ID:           core.NewGrantID(),
		Status:       domain.GrantStatusActive,
		Capabilities: []domain.GrantCapability{domain.GrantCapLicenseCreate, domain.GrantCapCustomerRead},
	}
	err := env.svc.CheckLicenseCreateConstraints(context.Background(), g, false)
	require.NoError(t, err)
}

// --- Update tests ---

// issueAndAccept seeds a product under grantorID, issues a grant to
// granteeID, accepts it, and returns the active grant. Used by the
// Update tests to start from a known-editable state.
func (e *testEnv) issueAndAccept(t *testing.T) *domain.Grant {
	t.Helper()
	p := e.seedProduct(grantorID)
	issued, err := e.svc.Issue(context.Background(), grantorID, core.EnvironmentLive, defaultIssueReq(p.ID), audit.Attribution{})
	require.NoError(t, err)
	accepted, err := e.svc.Accept(context.Background(), granteeID, core.EnvironmentLive, issued.ID, audit.Attribution{})
	require.NoError(t, err)
	return accepted
}

func TestUpdate_CapabilitiesReplacement(t *testing.T) {
	env := newTestEnv()
	g := env.issueAndAccept(t)

	newCaps := []domain.GrantCapability{domain.GrantCapLicenseRead, domain.GrantCapMachineRead}
	got, err := env.svc.Update(context.Background(), g.GrantorAccountID, core.EnvironmentLive, g.ID, UpdateRequest{
		Capabilities: &newCaps,
	}, audit.Attribution{})
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, newCaps, got.Capabilities)

	// Persisted.
	stored := env.repo.byID[g.ID]
	require.NotNil(t, stored)
	assert.Equal(t, newCaps, stored.Capabilities)
}

func TestUpdate_RejectsEmptyCapabilities(t *testing.T) {
	env := newTestEnv()
	g := env.issueAndAccept(t)

	empty := []domain.GrantCapability{}
	_, err := env.svc.Update(context.Background(), g.GrantorAccountID, core.EnvironmentLive, g.ID, UpdateRequest{
		Capabilities: &empty,
	}, audit.Attribution{})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrValidationError, appErr.Code)
}

func TestUpdate_RejectsUnknownCapability(t *testing.T) {
	env := newTestEnv()
	g := env.issueAndAccept(t)

	bad := []domain.GrantCapability{"TOTALLY_FAKE"}
	_, err := env.svc.Update(context.Background(), g.GrantorAccountID, core.EnvironmentLive, g.ID, UpdateRequest{
		Capabilities: &bad,
	}, audit.Attribution{})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrValidationError, appErr.Code)
}

func TestUpdate_RejectsLabelOver100(t *testing.T) {
	env := newTestEnv()
	g := env.issueAndAccept(t)

	long := make([]byte, 101)
	for i := range long {
		long[i] = 'a'
	}
	s := string(long)
	p := &s
	_, err := env.svc.Update(context.Background(), g.GrantorAccountID, core.EnvironmentLive, g.ID, UpdateRequest{
		Label: &p,
	}, audit.Attribution{})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrGrantLabelTooLong, appErr.Code)
}

func TestUpdate_ClearLabel(t *testing.T) {
	env := newTestEnv()
	g := env.issueAndAccept(t)

	// First set a label.
	initial := "initial-label"
	initialPtr := &initial
	got, err := env.svc.Update(context.Background(), g.GrantorAccountID, core.EnvironmentLive, g.ID, UpdateRequest{
		Label: &initialPtr,
	}, audit.Attribution{})
	require.NoError(t, err)
	require.NotNil(t, got.Label)
	assert.Equal(t, "initial-label", *got.Label)

	// Now clear it: outer non-nil, inner nil.
	var clear *string // nil
	got, err = env.svc.Update(context.Background(), g.GrantorAccountID, core.EnvironmentLive, g.ID, UpdateRequest{
		Label: &clear,
	}, audit.Attribution{})
	require.NoError(t, err)
	assert.Nil(t, got.Label)

	// Persisted cleared.
	stored := env.repo.byID[g.ID]
	require.NotNil(t, stored)
	assert.Nil(t, stored.Label)
}

func TestUpdate_RevokedGrant_Returns422(t *testing.T) {
	env := newTestEnv()
	g := env.issueAndAccept(t)

	// Move grant to revoked directly via repo so Update hits the
	// terminal-state guard.
	require.NoError(t, env.repo.UpdateStatus(context.Background(), g.ID, domain.GrantStatusRevoked))

	newCaps := []domain.GrantCapability{domain.GrantCapLicenseRead}
	_, err := env.svc.Update(context.Background(), g.GrantorAccountID, core.EnvironmentLive, g.ID, UpdateRequest{
		Capabilities: &newCaps,
	}, audit.Attribution{})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrGrantNotEditable, appErr.Code)
}

func TestUpdate_NonGrantor_Returns404(t *testing.T) {
	env := newTestEnv()
	g := env.issueAndAccept(t)

	// Grantee attempts to update — must get 404 (existence leak prevention).
	newCaps := []domain.GrantCapability{domain.GrantCapLicenseRead}
	_, err := env.svc.Update(context.Background(), g.GranteeAccountID, core.EnvironmentLive, g.ID, UpdateRequest{
		Capabilities: &newCaps,
	}, audit.Attribution{})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrGrantNotFound, appErr.Code)
}

// --- Reinstate tests ---

func TestReinstate_SuspendedGrant_ReturnsActive(t *testing.T) {
	env := newTestEnv()
	g := env.issueAndAccept(t)

	// Move grant to suspended directly via repo so Reinstate hits the
	// suspended → active transition.
	require.NoError(t, env.repo.UpdateStatus(context.Background(), g.ID, domain.GrantStatusSuspended))

	got, err := env.svc.Reinstate(context.Background(), g.GrantorAccountID, core.EnvironmentLive, g.ID, audit.Attribution{})
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, domain.GrantStatusActive, got.Status)

	stored := env.repo.byID[g.ID]
	require.NotNil(t, stored)
	assert.Equal(t, domain.GrantStatusActive, stored.Status)
}

func TestReinstate_ActiveGrant_Returns422(t *testing.T) {
	env := newTestEnv()
	g := env.issueAndAccept(t)

	// Grant is already active — cannot reinstate.
	_, err := env.svc.Reinstate(context.Background(), g.GrantorAccountID, core.EnvironmentLive, g.ID, audit.Attribution{})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrGrantNotSuspended, appErr.Code)
}

func TestReinstate_NonGrantor_Returns404(t *testing.T) {
	env := newTestEnv()
	g := env.issueAndAccept(t)
	require.NoError(t, env.repo.UpdateStatus(context.Background(), g.ID, domain.GrantStatusSuspended))

	// Grantee attempts to reinstate — must get 404 (existence leak prevention).
	_, err := env.svc.Reinstate(context.Background(), g.GranteeAccountID, core.EnvironmentLive, g.ID, audit.Attribution{})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrGrantNotFound, appErr.Code)
}

// --- Lifecycle event emission tests ---
//
// These smoke tests confirm each lifecycle method records the
// corresponding core.EventType via audit.Writer. Payload shape is
// not asserted — audit.Writer has its own tests for that.

// assertEventType scans the fake event repo for an event of the given
// type recorded against the given grant. Fails if none is found.
func assertGrantEventRecorded(t *testing.T, env *testEnv, eventType core.EventType, grantID core.GrantID) {
	t.Helper()
	for _, e := range env.events.events {
		if e.EventType == eventType && e.ResourceType == "grant" && e.ResourceID != nil && *e.ResourceID == grantID.String() {
			return
		}
	}
	t.Fatalf("expected event %q for grant %s, saw %v", eventType, grantID.String(), env.events.eventTypes())
}

func TestIssue_EmitsGrantCreatedEvent(t *testing.T) {
	env := newTestEnv()
	p := env.seedProduct(grantorID)

	g, err := env.svc.Issue(context.Background(), grantorID, core.EnvironmentLive, defaultIssueReq(p.ID), audit.Attribution{})
	require.NoError(t, err)

	assertGrantEventRecorded(t, env, core.EventTypeGrantCreated, g.ID)
}

func TestAccept_EmitsGrantAcceptedEvent(t *testing.T) {
	env := newTestEnv()
	p := env.seedProduct(grantorID)

	issued, err := env.svc.Issue(context.Background(), grantorID, core.EnvironmentLive, defaultIssueReq(p.ID), audit.Attribution{})
	require.NoError(t, err)
	_, err = env.svc.Accept(context.Background(), granteeID, core.EnvironmentLive, issued.ID, audit.Attribution{})
	require.NoError(t, err)

	assertGrantEventRecorded(t, env, core.EventTypeGrantAccepted, issued.ID)
}

func TestSuspend_EmitsGrantSuspendedEvent(t *testing.T) {
	env := newTestEnv()
	g := env.issueAndAccept(t)

	_, err := env.svc.Suspend(context.Background(), g.GrantorAccountID, core.EnvironmentLive, g.ID, audit.Attribution{})
	require.NoError(t, err)

	assertGrantEventRecorded(t, env, core.EventTypeGrantSuspended, g.ID)
}

func TestRevoke_EmitsGrantRevokedEvent(t *testing.T) {
	env := newTestEnv()
	g := env.issueAndAccept(t)

	_, err := env.svc.Revoke(context.Background(), g.GrantorAccountID, core.EnvironmentLive, g.ID, audit.Attribution{})
	require.NoError(t, err)

	assertGrantEventRecorded(t, env, core.EventTypeGrantRevoked, g.ID)
}

func TestLeave_EmitsGrantLeftEvent(t *testing.T) {
	env := newTestEnv()
	g := env.issueAndAccept(t)

	_, err := env.svc.Leave(context.Background(), g.GranteeAccountID, core.EnvironmentLive, g.ID, audit.Attribution{})
	require.NoError(t, err)

	assertGrantEventRecorded(t, env, core.EventTypeGrantLeft, g.ID)
}

func TestReinstate_EmitsGrantReinstatedEvent(t *testing.T) {
	env := newTestEnv()
	g := env.issueAndAccept(t)
	require.NoError(t, env.repo.UpdateStatus(context.Background(), g.ID, domain.GrantStatusSuspended))

	_, err := env.svc.Reinstate(context.Background(), g.GrantorAccountID, core.EnvironmentLive, g.ID, audit.Attribution{})
	require.NoError(t, err)

	assertGrantEventRecorded(t, env, core.EventTypeGrantReinstated, g.ID)
}

// TestUpdate_EmitsGrantUpdatedEvent confirms the grant.updated event
// fires on successful PATCH. Payload shape (changed_fields list) is
// deliberately not asserted — the smoke test only pins the event type.
func TestUpdate_EmitsGrantUpdatedEvent(t *testing.T) {
	env := newTestEnv()
	g := env.issueAndAccept(t)

	newCaps := []domain.GrantCapability{domain.GrantCapLicenseRead}
	_, err := env.svc.Update(context.Background(), g.GrantorAccountID, core.EnvironmentLive, g.ID, UpdateRequest{
		Capabilities: &newCaps,
	}, audit.Attribution{})
	require.NoError(t, err)

	assertGrantEventRecorded(t, env, core.EventTypeGrantUpdated, g.ID)
}
