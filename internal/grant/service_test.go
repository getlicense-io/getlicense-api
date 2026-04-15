package grant

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
}

func newTestEnv() *testEnv {
	repo := newFakeGrantRepo()
	products := newFakeProductRepo()
	svc := NewService(&fakeTxManager{}, repo, products)
	return &testEnv{svc: svc, repo: repo, products: products}
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

	g, err := env.svc.Issue(context.Background(), grantorID, core.EnvironmentLive, defaultIssueReq(p.ID))
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
	_, err := env.svc.Issue(context.Background(), grantorID, core.EnvironmentLive, req)
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
		"license.create",       // wrong case / dot form
		"TOTALLY_FAKE",         // not in enum
		"../../etc/passwd",     // path traversal payload
		"",                     // empty
	}
	for _, c := range badCases {
		t.Run(string(c), func(t *testing.T) {
			req := IssueRequest{
				GranteeAccountID: granteeID,
				ProductID:        p.ID,
				Capabilities:     []domain.GrantCapability{c},
			}
			_, err := env.svc.Issue(context.Background(), grantorID, core.EnvironmentLive, req)
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
	_, err := env.svc.Issue(context.Background(), grantorID, core.EnvironmentLive, req)
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrValidationError, appErr.Code)
}

func TestIssue_RejectsForeignProduct(t *testing.T) {
	env := newTestEnv()
	otherAccountID := core.NewAccountID()
	p := env.seedProduct(otherAccountID) // product belongs to a different account

	_, err := env.svc.Issue(context.Background(), grantorID, core.EnvironmentLive, defaultIssueReq(p.ID))
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrProductNotFound, appErr.Code)
}

// --- Accept tests ---

func TestAccept_HappyPath(t *testing.T) {
	env := newTestEnv()
	p := env.seedProduct(grantorID)

	issued, err := env.svc.Issue(context.Background(), grantorID, core.EnvironmentLive, defaultIssueReq(p.ID))
	require.NoError(t, err)

	accepted, err := env.svc.Accept(context.Background(), granteeID, core.EnvironmentLive, issued.ID)
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

	issued, err := env.svc.Issue(context.Background(), grantorID, core.EnvironmentLive, defaultIssueReq(p.ID))
	require.NoError(t, err)

	wrongAccount := core.NewAccountID()
	_, err = env.svc.Accept(context.Background(), wrongAccount, core.EnvironmentLive, issued.ID)
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrGrantNotFound, appErr.Code)
}

func TestAccept_NotPending(t *testing.T) {
	env := newTestEnv()
	p := env.seedProduct(grantorID)

	issued, err := env.svc.Issue(context.Background(), grantorID, core.EnvironmentLive, defaultIssueReq(p.ID))
	require.NoError(t, err)

	// Accept once.
	_, err = env.svc.Accept(context.Background(), granteeID, core.EnvironmentLive, issued.ID)
	require.NoError(t, err)

	// Accept again — now active, not pending.
	_, err = env.svc.Accept(context.Background(), granteeID, core.EnvironmentLive, issued.ID)
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrGrantNotActive, appErr.Code)
}

func TestAccept_NotFound(t *testing.T) {
	env := newTestEnv()

	_, err := env.svc.Accept(context.Background(), granteeID, core.EnvironmentLive, core.NewGrantID())
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrGrantNotFound, appErr.Code)
}

// --- Suspend tests ---

func TestSuspend_HappyPath(t *testing.T) {
	env := newTestEnv()
	p := env.seedProduct(grantorID)

	issued, err := env.svc.Issue(context.Background(), grantorID, core.EnvironmentLive, defaultIssueReq(p.ID))
	require.NoError(t, err)
	_, err = env.svc.Accept(context.Background(), granteeID, core.EnvironmentLive, issued.ID)
	require.NoError(t, err)

	suspended, err := env.svc.Suspend(context.Background(), grantorID, core.EnvironmentLive, issued.ID)
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
	issued, err := env.svc.Issue(context.Background(), grantorID, core.EnvironmentLive, defaultIssueReq(p.ID))
	require.NoError(t, err)

	_, err = env.svc.Suspend(context.Background(), grantorID, core.EnvironmentLive, issued.ID)
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrGrantNotActive, appErr.Code)
}

func TestSuspend_WrongGrantor(t *testing.T) {
	env := newTestEnv()
	p := env.seedProduct(grantorID)

	issued, err := env.svc.Issue(context.Background(), grantorID, core.EnvironmentLive, defaultIssueReq(p.ID))
	require.NoError(t, err)
	_, err = env.svc.Accept(context.Background(), granteeID, core.EnvironmentLive, issued.ID)
	require.NoError(t, err)

	wrongAccount := core.NewAccountID()
	_, err = env.svc.Suspend(context.Background(), wrongAccount, core.EnvironmentLive, issued.ID)
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrGrantNotFound, appErr.Code)
}

// --- Revoke tests ---

func TestRevoke_HappyPath(t *testing.T) {
	env := newTestEnv()
	p := env.seedProduct(grantorID)

	issued, err := env.svc.Issue(context.Background(), grantorID, core.EnvironmentLive, defaultIssueReq(p.ID))
	require.NoError(t, err)
	_, err = env.svc.Accept(context.Background(), granteeID, core.EnvironmentLive, issued.ID)
	require.NoError(t, err)

	revoked, err := env.svc.Revoke(context.Background(), grantorID, core.EnvironmentLive, issued.ID)
	require.NoError(t, err)

	assert.Equal(t, domain.GrantStatusRevoked, revoked.Status)

	stored := env.repo.byID[issued.ID]
	require.NotNil(t, stored)
	assert.Equal(t, domain.GrantStatusRevoked, stored.Status)
}

func TestRevoke_AlreadyRevoked(t *testing.T) {
	env := newTestEnv()
	p := env.seedProduct(grantorID)

	issued, err := env.svc.Issue(context.Background(), grantorID, core.EnvironmentLive, defaultIssueReq(p.ID))
	require.NoError(t, err)

	_, err = env.svc.Revoke(context.Background(), grantorID, core.EnvironmentLive, issued.ID)
	require.NoError(t, err)

	_, err = env.svc.Revoke(context.Background(), grantorID, core.EnvironmentLive, issued.ID)
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrValidationError, appErr.Code)
}

func TestRevoke_WrongGrantor(t *testing.T) {
	env := newTestEnv()
	p := env.seedProduct(grantorID)

	issued, err := env.svc.Issue(context.Background(), grantorID, core.EnvironmentLive, defaultIssueReq(p.ID))
	require.NoError(t, err)

	wrongAccount := core.NewAccountID()
	_, err = env.svc.Revoke(context.Background(), wrongAccount, core.EnvironmentLive, issued.ID)
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrGrantNotFound, appErr.Code)
}

// --- Get tests ---

func TestGet_HappyPath_AsGrantor(t *testing.T) {
	env := newTestEnv()
	p := env.seedProduct(grantorID)

	issued, err := env.svc.Issue(context.Background(), grantorID, core.EnvironmentLive, defaultIssueReq(p.ID))
	require.NoError(t, err)

	g, err := env.svc.Get(context.Background(), grantorID, core.EnvironmentLive, issued.ID)
	require.NoError(t, err)
	assert.Equal(t, issued.ID, g.ID)
}

func TestGet_HappyPath_AsGrantee(t *testing.T) {
	env := newTestEnv()
	p := env.seedProduct(grantorID)

	issued, err := env.svc.Issue(context.Background(), grantorID, core.EnvironmentLive, defaultIssueReq(p.ID))
	require.NoError(t, err)

	g, err := env.svc.Get(context.Background(), granteeID, core.EnvironmentLive, issued.ID)
	require.NoError(t, err)
	assert.Equal(t, issued.ID, g.ID)
}

func TestGet_UnrelatedAccount(t *testing.T) {
	env := newTestEnv()
	p := env.seedProduct(grantorID)

	issued, err := env.svc.Issue(context.Background(), grantorID, core.EnvironmentLive, defaultIssueReq(p.ID))
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

	issued, err := env.svc.Issue(context.Background(), grantorID, core.EnvironmentLive, defaultIssueReq(p.ID))
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

	issued, err := env.svc.Issue(context.Background(), grantorID, core.EnvironmentLive, defaultIssueReq(p.ID))
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
		ID:          core.NewGrantID(),
		Constraints: json.RawMessage(`{}`),
	}

	err := env.svc.CheckLicenseCreateConstraints(context.Background(), g, "user@example.com")
	require.NoError(t, err)
}

func TestCheckLicenseCreateConstraints_MaxTotalExceeded(t *testing.T) {
	env := newTestEnv()
	grantID := core.NewGrantID()
	env.repo.licenseCounts[grantID] = 5

	g := &domain.Grant{
		ID:          grantID,
		Constraints: json.RawMessage(`{"max_licenses_total":5}`),
	}

	err := env.svc.CheckLicenseCreateConstraints(context.Background(), g, "user@example.com")
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
		ID:          grantID,
		Constraints: json.RawMessage(`{"max_licenses_per_month":10}`),
	}

	err := env.svc.CheckLicenseCreateConstraints(context.Background(), g, "user@example.com")
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrGrantConstraintViolated, appErr.Code)
}

func TestCheckLicenseCreateConstraints_EmailPatternMismatch(t *testing.T) {
	env := newTestEnv()
	g := &domain.Grant{
		ID:          core.NewGrantID(),
		Constraints: json.RawMessage(`{"licensee_email_pattern":"@example.com"}`),
	}

	err := env.svc.CheckLicenseCreateConstraints(context.Background(), g, "user@other.com")
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrGrantConstraintViolated, appErr.Code)
}

func TestCheckLicenseCreateConstraints_EmailPatternMatchExact(t *testing.T) {
	env := newTestEnv()
	g := &domain.Grant{
		ID:          core.NewGrantID(),
		Constraints: json.RawMessage(`{"licensee_email_pattern":"@example.com"}`),
	}

	err := env.svc.CheckLicenseCreateConstraints(context.Background(), g, "user@example.com")
	require.NoError(t, err)
}

func TestCheckLicenseCreateConstraints_EmailPatternMatchWildcard(t *testing.T) {
	env := newTestEnv()
	g := &domain.Grant{
		ID:          core.NewGrantID(),
		Constraints: json.RawMessage(`{"licensee_email_pattern":"*.example.com"}`),
	}

	err := env.svc.CheckLicenseCreateConstraints(context.Background(), g, "user@api.example.com")
	require.NoError(t, err)
}
