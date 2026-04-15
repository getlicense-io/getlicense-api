package grant

import (
	"context"
	"testing"

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
	svc   *Service
	repo  *fakeGrantRepo
}

func newTestEnv() *testEnv {
	repo := newFakeGrantRepo()
	svc := NewService(&fakeTxManager{}, repo)
	return &testEnv{svc: svc, repo: repo}
}

func defaultIssueReq() IssueRequest {
	return IssueRequest{
		GranteeAccountID: granteeID,
		Capabilities:     []domain.GrantCapability{"license.create"},
	}
}

// --- Issue tests ---

func TestIssue_HappyPath(t *testing.T) {
	env := newTestEnv()

	g, err := env.svc.Issue(context.Background(), grantorID, core.EnvironmentLive, defaultIssueReq())
	require.NoError(t, err)
	require.NotNil(t, g)

	assert.Equal(t, grantorID, g.GrantorAccountID)
	assert.Equal(t, granteeID, g.GranteeAccountID)
	assert.Equal(t, domain.GrantStatusPending, g.Status)
	assert.Equal(t, []domain.GrantCapability{"license.create"}, g.Capabilities)
	assert.Equal(t, core.EnvironmentLive, g.Environment)
	assert.False(t, g.CreatedAt.IsZero())

	// Stored in repo.
	stored, ok := env.repo.byID[g.ID]
	require.True(t, ok)
	assert.Equal(t, g.ID, stored.ID)
}

func TestIssue_SameAccount(t *testing.T) {
	env := newTestEnv()

	req := IssueRequest{
		GranteeAccountID: grantorID, // same as grantor
		Capabilities:     []domain.GrantCapability{"license.create"},
	}
	_, err := env.svc.Issue(context.Background(), grantorID, core.EnvironmentLive, req)
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrValidationError, appErr.Code)
}

func TestIssue_NoCapabilities(t *testing.T) {
	env := newTestEnv()

	req := IssueRequest{
		GranteeAccountID: granteeID,
		Capabilities:     []domain.GrantCapability{},
	}
	_, err := env.svc.Issue(context.Background(), grantorID, core.EnvironmentLive, req)
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrValidationError, appErr.Code)
}

// --- Accept tests ---

func TestAccept_HappyPath(t *testing.T) {
	env := newTestEnv()

	issued, err := env.svc.Issue(context.Background(), grantorID, core.EnvironmentLive, defaultIssueReq())
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

	issued, err := env.svc.Issue(context.Background(), grantorID, core.EnvironmentLive, defaultIssueReq())
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

	issued, err := env.svc.Issue(context.Background(), grantorID, core.EnvironmentLive, defaultIssueReq())
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

	issued, err := env.svc.Issue(context.Background(), grantorID, core.EnvironmentLive, defaultIssueReq())
	require.NoError(t, err)
	_, err = env.svc.Accept(context.Background(), granteeID, core.EnvironmentLive, issued.ID)
	require.NoError(t, err)

	suspended, err := env.svc.Suspend(context.Background(), grantorID, core.EnvironmentLive, issued.ID)
	require.NoError(t, err)

	assert.Equal(t, domain.GrantStatusSuspended, suspended.Status)
	assert.NotNil(t, suspended.SuspendedAt)
}

func TestSuspend_NotActive(t *testing.T) {
	env := newTestEnv()

	// Grant is pending — cannot suspend.
	issued, err := env.svc.Issue(context.Background(), grantorID, core.EnvironmentLive, defaultIssueReq())
	require.NoError(t, err)

	_, err = env.svc.Suspend(context.Background(), grantorID, core.EnvironmentLive, issued.ID)
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrGrantNotActive, appErr.Code)
}

func TestSuspend_WrongGrantor(t *testing.T) {
	env := newTestEnv()

	issued, err := env.svc.Issue(context.Background(), grantorID, core.EnvironmentLive, defaultIssueReq())
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

	issued, err := env.svc.Issue(context.Background(), grantorID, core.EnvironmentLive, defaultIssueReq())
	require.NoError(t, err)
	_, err = env.svc.Accept(context.Background(), granteeID, core.EnvironmentLive, issued.ID)
	require.NoError(t, err)

	revoked, err := env.svc.Revoke(context.Background(), grantorID, core.EnvironmentLive, issued.ID)
	require.NoError(t, err)

	assert.Equal(t, domain.GrantStatusRevoked, revoked.Status)
	assert.NotNil(t, revoked.RevokedAt)
}

func TestRevoke_AlreadyRevoked(t *testing.T) {
	env := newTestEnv()

	issued, err := env.svc.Issue(context.Background(), grantorID, core.EnvironmentLive, defaultIssueReq())
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

	issued, err := env.svc.Issue(context.Background(), grantorID, core.EnvironmentLive, defaultIssueReq())
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

	issued, err := env.svc.Issue(context.Background(), grantorID, core.EnvironmentLive, defaultIssueReq())
	require.NoError(t, err)

	g, err := env.svc.Get(context.Background(), grantorID, core.EnvironmentLive, issued.ID)
	require.NoError(t, err)
	assert.Equal(t, issued.ID, g.ID)
}

func TestGet_HappyPath_AsGrantee(t *testing.T) {
	env := newTestEnv()

	issued, err := env.svc.Issue(context.Background(), grantorID, core.EnvironmentLive, defaultIssueReq())
	require.NoError(t, err)

	g, err := env.svc.Get(context.Background(), granteeID, core.EnvironmentLive, issued.ID)
	require.NoError(t, err)
	assert.Equal(t, issued.ID, g.ID)
}

func TestGet_UnrelatedAccount(t *testing.T) {
	env := newTestEnv()

	issued, err := env.svc.Issue(context.Background(), grantorID, core.EnvironmentLive, defaultIssueReq())
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
		Capabilities: []domain.GrantCapability{"license.create", "license.revoke"},
	}

	err := (&Service{}).RequireCapability(g, "license.create")
	require.NoError(t, err)
}

func TestRequireCapability_CapabilityDenied(t *testing.T) {
	g := &domain.Grant{
		Status:       domain.GrantStatusActive,
		Capabilities: []domain.GrantCapability{"license.create"},
	}

	err := (&Service{}).RequireCapability(g, "license.revoke")
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrGrantCapabilityDenied, appErr.Code)
}

func TestRequireCapability_NotActive(t *testing.T) {
	g := &domain.Grant{
		Status:       domain.GrantStatusSuspended,
		Capabilities: []domain.GrantCapability{"license.create"},
	}

	err := (&Service{}).RequireCapability(g, "license.create")
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrGrantNotActive, appErr.Code)
}
