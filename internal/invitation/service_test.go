package invitation_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlicense-io/getlicense-api/internal/audit"
	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/crypto"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/getlicense-io/getlicense-api/internal/invitation"
)

const testMasterKeyHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// newTestService constructs a Service with all fakes and two preset
// fixtures: an account named "Acme" and an "admin" role.
//
// The optional dashboardURL argument overrides the default
// "https://dashboard.example" prefix used to construct accept URLs —
// useful for asserting that the dashboardURL plumbing from config
// flows through to the URL-building code path.
func newTestService(t *testing.T, dashboardURL ...string) (*invitation.Service, *fakeInvitationRepo, *fakeMembershipRepo, *fakeIdentityRepo, *fakeMailer, core.AccountID, core.RoleID) {
	t.Helper()
	svc, invRepo, memRepo, identRepo, mailer, _, accountID, roleID := newTestServiceWithEvents(t, dashboardURL...)
	return svc, invRepo, memRepo, identRepo, mailer, accountID, roleID
}

// newTestServiceWithEvents is the extended constructor that also
// returns the fakeEventRepo so tests can assert lifecycle events
// recorded via audit.Writer.
func newTestServiceWithEvents(t *testing.T, dashboardURL ...string) (*invitation.Service, *fakeInvitationRepo, *fakeMembershipRepo, *fakeIdentityRepo, *fakeMailer, *fakeEventRepo, core.AccountID, core.RoleID) {
	t.Helper()
	mk, err := crypto.NewMasterKey(testMasterKeyHex)
	require.NoError(t, err)

	invRepo := newFakeInvitationRepo()
	memRepo := newFakeMembershipRepo()
	identRepo := newFakeIdentityRepo()
	mailer := &fakeMailer{}
	roleRepo := newFakeRoleRepo()
	acctRepo := newFakeAccountRepo()
	eventRepo := newFakeEventRepo()

	accountID := core.NewAccountID()
	acct := &domain.Account{ID: accountID, Name: "Acme", Slug: "acme"}
	acctRepo.seed(acct)

	roleID := core.NewRoleID()
	role := &domain.Role{ID: roleID, Slug: "admin", Name: "Admin", Permissions: []string{"user:invite"}}
	roleRepo.seed(role)

	url := "https://dashboard.example"
	if len(dashboardURL) > 0 && dashboardURL[0] != "" {
		url = dashboardURL[0]
	}

	svc := invitation.NewService(
		fakeTxManager{},
		invRepo,
		identRepo,
		memRepo,
		roleRepo,
		acctRepo,
		mk,
		mailer,
		url,
		nil, // grants service — not needed for unit tests
		audit.NewWriter(eventRepo),
	)
	return svc, invRepo, memRepo, identRepo, mailer, eventRepo, accountID, roleID
}

// seedIdentity registers a fake identity so invitation.Accept can resolve it.
// F-014: Accept verifies that the authenticated identity's email matches the
// invitation's email, so every TestAccept_* that does not want to hit that
// check must pre-seed the identity with the same email the invitation uses.
func seedIdentity(t *testing.T, repo *fakeIdentityRepo, id core.IdentityID, email string) {
	t.Helper()
	err := repo.Create(t.Context(), &domain.Identity{ID: id, Email: email})
	require.NoError(t, err)
}

// rawTokenFromURL extracts the token from an accept URL like
// "https://dashboard.example/invitations/rt_<hex>".
func rawTokenFromURL(acceptURL string) string {
	parts := strings.Split(acceptURL, "/")
	return parts[len(parts)-1]
}

func TestCreateMembership_StoresTokenHashAndReturnsAcceptURL(t *testing.T) {
	svc, invRepo, _, _, mailer, accountID, _ := newTestService(t)

	issuerID := core.NewIdentityID()
	req := invitation.CreateMembershipRequest{Email: "invitee@example.com", RoleSlug: "admin"}
	result, err := svc.CreateMembership(t.Context(), accountID, core.EnvironmentLive, issuerID, req, audit.Attribution{})
	require.NoError(t, err)
	require.NotNil(t, result)

	inv := result.Invitation
	assert.Equal(t, domain.InvitationKindMembership, inv.Kind)
	assert.NotNil(t, inv.AccountID)
	assert.NotNil(t, inv.RoleID)
	assert.NotEmpty(t, inv.TokenHash)

	// AcceptURL must contain the raw token after the last slash.
	rawToken := rawTokenFromURL(result.AcceptURL)
	assert.NotEmpty(t, rawToken)
	assert.Contains(t, result.AcceptURL, "/invitations/")

	// The stored hash must match the HMAC of the raw token.
	mk, _ := crypto.NewMasterKey(testMasterKeyHex)
	assert.Equal(t, mk.HMAC(rawToken), inv.TokenHash)

	// Repo has exactly one invitation keyed by the hash.
	stored, err := invRepo.GetByTokenHash(t.Context(), inv.TokenHash)
	require.NoError(t, err)
	require.NotNil(t, stored)

	// Mailer was called once with the correct recipient.
	assert.Equal(t, 1, mailer.callCount)
	assert.Equal(t, "invitee@example.com", mailer.lastTo)
}

func TestCreateMembership_FailsWhenRoleSlugUnknown(t *testing.T) {
	svc, _, _, _, _, accountID, _ := newTestService(t)

	issuerID := core.NewIdentityID()
	req := invitation.CreateMembershipRequest{Email: "x@example.com", RoleSlug: "nonexistent"}
	result, err := svc.CreateMembership(t.Context(), accountID, core.EnvironmentLive, issuerID, req, audit.Attribution{})
	require.Error(t, err)
	assert.Nil(t, result)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrRoleNotFound, appErr.Code)
}

func TestLookup_ReturnsPreview(t *testing.T) {
	svc, _, _, _, _, accountID, _ := newTestService(t)

	issuerID := core.NewIdentityID()
	req := invitation.CreateMembershipRequest{Email: "preview@example.com", RoleSlug: "admin"}
	created, err := svc.CreateMembership(t.Context(), accountID, core.EnvironmentLive, issuerID, req, audit.Attribution{})
	require.NoError(t, err)

	rawToken := rawTokenFromURL(created.AcceptURL)
	result, err := svc.Lookup(t.Context(), rawToken)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, domain.InvitationKindMembership, result.Kind)
	assert.Equal(t, "preview@example.com", result.Email)
	assert.Equal(t, "Acme", result.AccountName)
	assert.Equal(t, "Admin", result.RoleName)
	// token_hash is not a field on LookupResult — no sensitive data exposed.
}

func TestLookup_FailsOnExpiredInvitation(t *testing.T) {
	svc, invRepo, _, _, _, accountID, _ := newTestService(t)

	issuerID := core.NewIdentityID()
	req := invitation.CreateMembershipRequest{Email: "expired@example.com", RoleSlug: "admin"}
	created, err := svc.CreateMembership(t.Context(), accountID, core.EnvironmentLive, issuerID, req, audit.Attribution{})
	require.NoError(t, err)

	// Manually expire the invitation.
	rawToken := rawTokenFromURL(created.AcceptURL)
	mk, _ := crypto.NewMasterKey(testMasterKeyHex)
	stored, _ := invRepo.GetByTokenHash(t.Context(), mk.HMAC(rawToken))
	stored.ExpiresAt = time.Now().UTC().Add(-time.Hour)

	_, err = svc.Lookup(t.Context(), rawToken)
	require.Error(t, err)
	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrInvitationExpired, appErr.Code)
}

func TestLookup_FailsOnAlreadyAccepted(t *testing.T) {
	svc, invRepo, _, _, _, accountID, _ := newTestService(t)

	issuerID := core.NewIdentityID()
	req := invitation.CreateMembershipRequest{Email: "used@example.com", RoleSlug: "admin"}
	created, err := svc.CreateMembership(t.Context(), accountID, core.EnvironmentLive, issuerID, req, audit.Attribution{})
	require.NoError(t, err)

	rawToken := rawTokenFromURL(created.AcceptURL)
	mk, _ := crypto.NewMasterKey(testMasterKeyHex)
	stored, _ := invRepo.GetByTokenHash(t.Context(), mk.HMAC(rawToken))
	now := time.Now().UTC()
	stored.AcceptedAt = &now

	_, err = svc.Lookup(t.Context(), rawToken)
	require.Error(t, err)
	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrInvitationAlreadyUsed, appErr.Code)
}

func TestAccept_CreatesMembership(t *testing.T) {
	svc, _, memRepo, identRepo, _, accountID, roleID := newTestService(t)

	issuerID := core.NewIdentityID()
	req := invitation.CreateMembershipRequest{Email: "accept@example.com", RoleSlug: "admin"}
	created, err := svc.CreateMembership(t.Context(), accountID, core.EnvironmentLive, issuerID, req, audit.Attribution{})
	require.NoError(t, err)

	rawToken := rawTokenFromURL(created.AcceptURL)
	inviteeID := core.NewIdentityID()
	seedIdentity(t, identRepo, inviteeID, "accept@example.com")

	result, err := svc.Accept(t.Context(), rawToken, inviteeID, audit.Attribution{})
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.NotNil(t, result.MembershipID)
	assert.Equal(t, accountID, result.AccountID)

	// Membership was created in the fake repo.
	key := [2]string{inviteeID.String(), accountID.String()}
	m := memRepo.byIdentityAndAccount[key]
	require.NotNil(t, m)
	assert.Equal(t, domain.MembershipStatusActive, m.Status)
	assert.Equal(t, roleID, m.RoleID)
}

func TestAccept_CreatesMembership_InvitationMarkedAccepted(t *testing.T) {
	svc, invRepo, _, identRepo, _, accountID, _ := newTestService(t)

	issuerID := core.NewIdentityID()
	req := invitation.CreateMembershipRequest{Email: "mark@example.com", RoleSlug: "admin"}
	created, err := svc.CreateMembership(t.Context(), accountID, core.EnvironmentLive, issuerID, req, audit.Attribution{})
	require.NoError(t, err)

	rawToken := rawTokenFromURL(created.AcceptURL)
	inviteeID := core.NewIdentityID()
	seedIdentity(t, identRepo, inviteeID, "mark@example.com")

	_, err = svc.Accept(t.Context(), rawToken, inviteeID, audit.Attribution{})
	require.NoError(t, err)

	mk, _ := crypto.NewMasterKey(testMasterKeyHex)
	stored, _ := invRepo.GetByTokenHash(t.Context(), mk.HMAC(rawToken))
	require.NotNil(t, stored)
	assert.NotNil(t, stored.AcceptedAt, "invitation AcceptedAt must be set after accept")
}

func TestAccept_RefusesWhenIdentityAlreadyMember(t *testing.T) {
	svc, _, memRepo, identRepo, _, accountID, roleID := newTestService(t)

	inviteeID := core.NewIdentityID()
	seedIdentity(t, identRepo, inviteeID, "already@example.com")
	// Pre-seed an existing membership.
	existing := &domain.AccountMembership{
		ID:         core.NewMembershipID(),
		AccountID:  accountID,
		IdentityID: inviteeID,
		RoleID:     roleID,
		Status:     domain.MembershipStatusActive,
		JoinedAt:   time.Now().UTC(),
		CreatedAt:  time.Now().UTC(),
		UpdatedAt:  time.Now().UTC(),
	}
	require.NoError(t, memRepo.Create(t.Context(), existing))

	issuerID := core.NewIdentityID()
	req := invitation.CreateMembershipRequest{Email: "already@example.com", RoleSlug: "admin"}
	created, err := svc.CreateMembership(t.Context(), accountID, core.EnvironmentLive, issuerID, req, audit.Attribution{})
	require.NoError(t, err)

	rawToken := rawTokenFromURL(created.AcceptURL)
	_, err = svc.Accept(t.Context(), rawToken, inviteeID, audit.Attribution{})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrInvitationAlreadyUsed, appErr.Code)
}

func TestAccept_GrantKindNoAccountReturnsError(t *testing.T) {
	svc, _, _, identRepo, _, accountID, _ := newTestService(t)

	issuerID := core.NewIdentityID()
	productID := core.NewProductID()
	granteeAccountID := core.NewAccountID()
	draft := json.RawMessage(`{"product_id":"` + productID.String() + `","grantee_account_id":"` + granteeAccountID.String() + `","capabilities":["LICENSE_CREATE"]}`)
	created, err := svc.CreateGrant(t.Context(), accountID, core.EnvironmentLive, issuerID, "grant@example.com", draft, audit.Attribution{})
	require.NoError(t, err)

	rawToken := rawTokenFromURL(created.AcceptURL)
	// The accepting identity has no memberships — expect a validation error.
	inviteeID := core.NewIdentityID()
	seedIdentity(t, identRepo, inviteeID, "grant@example.com")

	_, err = svc.Accept(t.Context(), rawToken, inviteeID, audit.Attribution{})
	require.Error(t, err)
	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrValidationError, appErr.Code)
}

// F-014: regression test — the invitation accept flow must verify that
// the authenticated identity's email matches the invitation's email.
// Without this check, anyone with a leaked token can join the target
// account as their own identity.
func TestAccept_RejectsEmailMismatch(t *testing.T) {
	svc, _, _, identRepo, _, accountID, _ := newTestService(t)

	issuerID := core.NewIdentityID()
	req := invitation.CreateMembershipRequest{Email: "target@example.com", RoleSlug: "admin"}
	created, err := svc.CreateMembership(t.Context(), accountID, core.EnvironmentLive, issuerID, req, audit.Attribution{})
	require.NoError(t, err)

	// Attacker holds a different identity with a different email.
	attackerID := core.NewIdentityID()
	seedIdentity(t, identRepo, attackerID, "attacker@example.com")

	rawToken := rawTokenFromURL(created.AcceptURL)
	_, err = svc.Accept(t.Context(), rawToken, attackerID, audit.Attribution{})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrPermissionDenied, appErr.Code, "must refuse accept when identity email does not match invitation email")
}

// F-014 (grant branch): the same BOLA exists on grant-kind invitations,
// fixed by the same email check. Verify grant-kind also refuses.
func TestAccept_GrantKindRejectsEmailMismatch(t *testing.T) {
	svc, _, _, identRepo, _, accountID, _ := newTestService(t)

	issuerID := core.NewIdentityID()
	productID := core.NewProductID()
	granteeAccountID := core.NewAccountID()
	draft := json.RawMessage(`{"product_id":"` + productID.String() + `","grantee_account_id":"` + granteeAccountID.String() + `","capabilities":["LICENSE_CREATE"]}`)
	created, err := svc.CreateGrant(t.Context(), accountID, core.EnvironmentLive, issuerID, "target@example.com", draft, audit.Attribution{})
	require.NoError(t, err)

	attackerID := core.NewIdentityID()
	seedIdentity(t, identRepo, attackerID, "attacker@example.com")

	rawToken := rawTokenFromURL(created.AcceptURL)
	_, err = svc.Accept(t.Context(), rawToken, attackerID, audit.Attribution{})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrPermissionDenied, appErr.Code, "grant-kind accept must also refuse email mismatch")
}

// TestCreateMembership_UsesDashboardURLFromConfig asserts that the
// dashboardURL value passed to NewService is the prefix of every
// invitation accept URL. This pins the wiring from
// cfg.DashboardURL → invitation.Service.dashboardURL → accept URL.
func TestCreateMembership_UsesDashboardURLFromConfig(t *testing.T) {
	svc, _, _, _, _, accountID, _ := newTestService(t, "https://dash.example.com")

	issuerID := core.NewIdentityID()
	req := invitation.CreateMembershipRequest{Email: "ttl@example.com", RoleSlug: "admin"}
	res, err := svc.CreateMembership(t.Context(), accountID, core.EnvironmentLive, issuerID, req, audit.Attribution{})
	require.NoError(t, err)
	require.NotNil(t, res)

	assert.True(t, strings.HasPrefix(res.AcceptURL, "https://dash.example.com/invitations/"),
		"accept_url must derive from dashboardURL, got %q", res.AcceptURL)
}

// F-014: case-insensitive comparison — invitation for FOO@EXAMPLE.COM
// must accept identity foo@example.com.
func TestAccept_EmailCheckIsCaseInsensitive(t *testing.T) {
	svc, _, _, identRepo, _, accountID, _ := newTestService(t)

	issuerID := core.NewIdentityID()
	req := invitation.CreateMembershipRequest{Email: "Mixed.Case@Example.Com", RoleSlug: "admin"}
	created, err := svc.CreateMembership(t.Context(), accountID, core.EnvironmentLive, issuerID, req, audit.Attribution{})
	require.NoError(t, err)

	inviteeID := core.NewIdentityID()
	seedIdentity(t, identRepo, inviteeID, "mixed.case@example.com")

	rawToken := rawTokenFromURL(created.AcceptURL)
	_, err = svc.Accept(t.Context(), rawToken, inviteeID, audit.Attribution{})
	require.NoError(t, err, "case-insensitive email comparison must allow accept")
}

// --- List / Get tests ---
//
// List and Get run inside the account's tenant tx, which the fake
// tx manager simulates by stashing the account id into context; the
// fake invitation repo filters by CreatedByAccountID on that key.
// This mirrors the production RLS behavior (created_by_account_id
// scopes every read) without needing a real Postgres connection.

func TestList_FiltersByKind(t *testing.T) {
	svc, _, _, _, _, accountID, _ := newTestService(t)

	issuerID := core.NewIdentityID()
	// Seed one membership invitation and one grant invitation under the
	// same inviter account so the Kind filter is the discriminator.
	_, err := svc.CreateMembership(t.Context(), accountID, core.EnvironmentLive, issuerID,
		invitation.CreateMembershipRequest{Email: "m@example.com", RoleSlug: "admin"},
		audit.Attribution{})
	require.NoError(t, err)

	productID := core.NewProductID()
	granteeAccountID := core.NewAccountID()
	draft := json.RawMessage(`{"product_id":"` + productID.String() + `","grantee_account_id":"` + granteeAccountID.String() + `","capabilities":["LICENSE_CREATE"]}`)
	_, err = svc.CreateGrant(t.Context(), accountID, core.EnvironmentLive, issuerID,
		"g@example.com", draft, audit.Attribution{})
	require.NoError(t, err)

	kindGrant := domain.InvitationKindGrant
	rows, _, err := svc.List(t.Context(), accountID, domain.InvitationListFilter{
		Kind: &kindGrant,
	}, core.Cursor{}, 50)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, domain.InvitationKindGrant, rows[0].Kind)
}

func TestGet_NotFound_Returns404(t *testing.T) {
	svc, _, _, _, _, accountID, _ := newTestService(t)

	bogusID := core.NewInvitationID()
	_, err := svc.Get(t.Context(), accountID, bogusID)
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrInvitationNotFound, appErr.Code)
}

func TestGet_WrongAccount_Returns404(t *testing.T) {
	svc, _, _, _, _, accountID, _ := newTestService(t)

	issuerID := core.NewIdentityID()
	created, err := svc.CreateMembership(t.Context(), accountID, core.EnvironmentLive, issuerID,
		invitation.CreateMembershipRequest{Email: "wa@example.com", RoleSlug: "admin"},
		audit.Attribution{})
	require.NoError(t, err)

	// Stranger account asking for an invitation it did not create must
	// get 404, not 403 — the RLS scope (simulated here by the fake)
	// hides the row's existence entirely.
	strangerAccount := core.NewAccountID()
	_, err = svc.Get(t.Context(), strangerAccount, created.Invitation.ID)
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrInvitationNotFound, appErr.Code)
}

// --- Lifecycle event emission tests ---
//
// Smoke tests confirming the invitation.created / invitation.accepted
// events are recorded via audit.Writer. Payload shape is not asserted.

func assertInvitationEventRecorded(t *testing.T, events *fakeEventRepo, eventType core.EventType, invID core.InvitationID) {
	t.Helper()
	for _, e := range events.events {
		if e.EventType == eventType && e.ResourceType == "invitation" && e.ResourceID != nil && *e.ResourceID == invID.String() {
			return
		}
	}
	t.Fatalf("expected event %q for invitation %s, saw %v", eventType, invID.String(), events.eventTypes())
}

func TestCreateMembership_EmitsInvitationCreatedEvent(t *testing.T) {
	svc, _, _, _, _, events, accountID, _ := newTestServiceWithEvents(t)

	issuerID := core.NewIdentityID()
	req := invitation.CreateMembershipRequest{Email: "invitee@example.com", RoleSlug: "admin"}
	result, err := svc.CreateMembership(t.Context(), accountID, core.EnvironmentLive, issuerID, req, audit.Attribution{})
	require.NoError(t, err)

	assertInvitationEventRecorded(t, events, core.EventTypeInvitationCreated, result.Invitation.ID)
}

func TestAccept_EmitsInvitationAcceptedEvent(t *testing.T) {
	svc, _, _, identRepo, _, events, accountID, _ := newTestServiceWithEvents(t)

	issuerID := core.NewIdentityID()
	req := invitation.CreateMembershipRequest{Email: "invitee@example.com", RoleSlug: "admin"}
	created, err := svc.CreateMembership(t.Context(), accountID, core.EnvironmentLive, issuerID, req, audit.Attribution{})
	require.NoError(t, err)

	inviteeID := core.NewIdentityID()
	seedIdentity(t, identRepo, inviteeID, "invitee@example.com")
	rawToken := rawTokenFromURL(created.AcceptURL)

	// Accept with a different AccountID on the attribution — the service
	// must rewrite it to the invitation's tenant before recording so the
	// event lands under the inviter's audit log, not the accepting
	// identity's default acting account.
	acceptingAccountAttr := audit.Attribution{AccountID: core.NewAccountID(), Environment: core.EnvironmentLive}
	_, err = svc.Accept(t.Context(), rawToken, inviteeID, acceptingAccountAttr)
	require.NoError(t, err)

	assertInvitationEventRecorded(t, events, core.EventTypeInvitationAccepted, created.Invitation.ID)

	// Find the invitation.accepted event and confirm it is filed under
	// the inviter's account, not the accepting identity's.
	var found bool
	for _, e := range events.events {
		if e.EventType == core.EventTypeInvitationAccepted {
			found = true
			assert.Equal(t, accountID, e.AccountID, "invitation.accepted must be filed under the inviter's tenant")
		}
	}
	require.True(t, found)
}
