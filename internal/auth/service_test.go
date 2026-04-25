package auth

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/crypto"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/getlicense-io/getlicense-api/internal/identity"
)

// --- fake TxManager ---

type fakeTxManager struct{}

func (fakeTxManager) WithTargetAccount(ctx context.Context, _ core.AccountID, _ core.Environment, fn func(context.Context) error) error {
	return fn(ctx)
}
func (fakeTxManager) WithTx(ctx context.Context, fn func(context.Context) error) error {
	return fn(ctx)
}

// --- fake AccountRepository ---

type fakeAccountRepo struct {
	byID   map[core.AccountID]*domain.Account
	bySlug map[string]*domain.Account
}

func newFakeAccountRepo() *fakeAccountRepo {
	return &fakeAccountRepo{
		byID:   make(map[core.AccountID]*domain.Account),
		bySlug: make(map[string]*domain.Account),
	}
}

func (r *fakeAccountRepo) Create(_ context.Context, a *domain.Account) error {
	r.byID[a.ID] = a
	r.bySlug[a.Slug] = a
	return nil
}
func (r *fakeAccountRepo) GetByID(_ context.Context, id core.AccountID) (*domain.Account, error) {
	a := r.byID[id]
	return a, nil
}
func (r *fakeAccountRepo) GetBySlug(_ context.Context, slug string) (*domain.Account, error) {
	a := r.bySlug[slug]
	return a, nil
}
func (r *fakeAccountRepo) GetIfAccessible(
	_ context.Context,
	_ core.AccountID,
	_ core.AccountID,
	_ core.IdentityID,
) (*domain.Account, error) {
	return nil, errors.New("not implemented")
}

// --- fake IdentityRepository ---

type fakeIdentityRepo struct {
	byID    map[core.IdentityID]*domain.Identity
	byEmail map[string]*domain.Identity
}

func newFakeIdentityRepo() *fakeIdentityRepo {
	return &fakeIdentityRepo{
		byID:    make(map[core.IdentityID]*domain.Identity),
		byEmail: make(map[string]*domain.Identity),
	}
}

func (r *fakeIdentityRepo) Create(_ context.Context, i *domain.Identity) error {
	r.byID[i.ID] = i
	r.byEmail[i.Email] = i
	return nil
}
func (r *fakeIdentityRepo) GetByID(_ context.Context, id core.IdentityID) (*domain.Identity, error) {
	return r.byID[id], nil
}
func (r *fakeIdentityRepo) GetByEmail(_ context.Context, email string) (*domain.Identity, error) {
	return r.byEmail[email], nil
}
func (r *fakeIdentityRepo) Update(_ context.Context, _ *domain.Identity) error {
	return errors.New("not implemented")
}
func (r *fakeIdentityRepo) UpdatePassword(_ context.Context, _ core.IdentityID, _ string) error {
	return errors.New("not implemented")
}
func (r *fakeIdentityRepo) UpdateTOTP(_ context.Context, _ core.IdentityID, _ []byte, _ *time.Time, _ []byte) error {
	return errors.New("not implemented")
}

// --- fake AccountMembershipRepository ---

type fakeMembershipRepo struct {
	byID                 map[core.MembershipID]*domain.AccountMembership
	byIdentity           map[core.IdentityID][]domain.AccountMembership
	byIdentityAndAccount map[[2]string]*domain.AccountMembership
}

func newFakeMembershipRepo() *fakeMembershipRepo {
	return &fakeMembershipRepo{
		byID:                 make(map[core.MembershipID]*domain.AccountMembership),
		byIdentity:           make(map[core.IdentityID][]domain.AccountMembership),
		byIdentityAndAccount: make(map[[2]string]*domain.AccountMembership),
	}
}

func (r *fakeMembershipRepo) Create(_ context.Context, m *domain.AccountMembership) error {
	r.byID[m.ID] = m
	r.byIdentity[m.IdentityID] = append(r.byIdentity[m.IdentityID], *m)
	key := [2]string{m.IdentityID.String(), m.AccountID.String()}
	r.byIdentityAndAccount[key] = m
	return nil
}
func (r *fakeMembershipRepo) GetByID(_ context.Context, id core.MembershipID) (*domain.AccountMembership, error) {
	return r.byID[id], nil
}
func (r *fakeMembershipRepo) GetByIDWithRole(_ context.Context, _ core.MembershipID) (*domain.AccountMembership, *domain.Role, error) {
	return nil, nil, errors.New("not implemented")
}
func (r *fakeMembershipRepo) GetByIdentityAndAccount(_ context.Context, identityID core.IdentityID, accountID core.AccountID) (*domain.AccountMembership, error) {
	key := [2]string{identityID.String(), accountID.String()}
	return r.byIdentityAndAccount[key], nil
}
func (r *fakeMembershipRepo) ListByIdentity(_ context.Context, identityID core.IdentityID) ([]domain.AccountMembership, error) {
	return r.byIdentity[identityID], nil
}
func (r *fakeMembershipRepo) ListByAccount(_ context.Context, _ core.Cursor, _ int) ([]domain.AccountMembership, bool, error) {
	return nil, false, errors.New("not implemented")
}
func (r *fakeMembershipRepo) UpdateRole(_ context.Context, _ core.MembershipID, _ core.RoleID) error {
	return errors.New("not implemented")
}
func (r *fakeMembershipRepo) UpdateStatus(_ context.Context, _ core.MembershipID, _ domain.MembershipStatus) error {
	return errors.New("not implemented")
}
func (r *fakeMembershipRepo) Delete(_ context.Context, _ core.MembershipID) error {
	return errors.New("not implemented")
}
func (r *fakeMembershipRepo) CountOwners(_ context.Context, _ core.AccountID) (int, error) {
	return 0, errors.New("not implemented")
}
func (r *fakeMembershipRepo) ListAccountWithDetails(_ context.Context, _ core.Cursor, _ int) ([]domain.MembershipDetail, bool, error) {
	return nil, false, errors.New("not implemented")
}

// --- fake RoleRepository ---

type fakeRoleRepo struct {
	byID   map[core.RoleID]*domain.Role
	bySlug map[string]*domain.Role
}

func newFakeRoleRepo() *fakeRoleRepo {
	return &fakeRoleRepo{
		byID:   make(map[core.RoleID]*domain.Role),
		bySlug: make(map[string]*domain.Role),
	}
}

func (r *fakeRoleRepo) seed(role *domain.Role) {
	r.byID[role.ID] = role
	r.bySlug[role.Slug] = role
}

func (r *fakeRoleRepo) GetByID(_ context.Context, id core.RoleID) (*domain.Role, error) {
	return r.byID[id], nil
}
func (r *fakeRoleRepo) GetBySlug(_ context.Context, _ *core.AccountID, slug string) (*domain.Role, error) {
	return r.bySlug[slug], nil
}
func (r *fakeRoleRepo) ListPresets(_ context.Context) ([]domain.Role, error) {
	return nil, errors.New("not implemented")
}
func (r *fakeRoleRepo) ListByAccount(_ context.Context) ([]domain.Role, error) {
	return nil, errors.New("not implemented")
}

// --- fake APIKeyRepository ---

type fakeAPIKeyRepo struct {
	byID   map[core.APIKeyID]*domain.APIKey
	byHash map[string]*domain.APIKey
	list   []*domain.APIKey
}

func newFakeAPIKeyRepo() *fakeAPIKeyRepo {
	return &fakeAPIKeyRepo{
		byID:   make(map[core.APIKeyID]*domain.APIKey),
		byHash: make(map[string]*domain.APIKey),
	}
}

func (r *fakeAPIKeyRepo) Create(_ context.Context, k *domain.APIKey) error {
	r.byID[k.ID] = k
	r.byHash[k.KeyHash] = k
	r.list = append(r.list, k)
	return nil
}
func (r *fakeAPIKeyRepo) GetByHash(_ context.Context, hash string) (*domain.APIKey, error) {
	return r.byHash[hash], nil
}
func (r *fakeAPIKeyRepo) ListByAccount(_ context.Context, env core.Environment, _ core.Cursor, limit int) ([]domain.APIKey, bool, error) {
	var matched []domain.APIKey
	for _, k := range r.list {
		if k.Environment == env {
			matched = append(matched, *k)
		}
	}
	hasMore := len(matched) > limit
	if hasMore {
		matched = matched[:limit]
	}
	return matched, hasMore, nil
}
func (r *fakeAPIKeyRepo) Delete(_ context.Context, id core.APIKeyID) error {
	k, ok := r.byID[id]
	if !ok {
		return errors.New("not found")
	}
	delete(r.byHash, k.KeyHash)
	delete(r.byID, id)
	var newList []*domain.APIKey
	for _, item := range r.list {
		if item.ID != id {
			newList = append(newList, item)
		}
	}
	r.list = newList
	return nil
}

// --- fake RefreshTokenRepository ---

// fakeRefreshTokenRepo is an in-memory implementation. The mutex is
// load-bearing: TestRefresh_ConcurrentRequests_OnlyOneSucceeds spawns
// goroutines racing on Consume, and the lock simulates the DB-level
// atomic semantics of `DELETE ... RETURNING` so exactly one caller
// wins. Without the lock the map race would also fail under -race.
type fakeRefreshTokenRepo struct {
	mu         sync.Mutex
	byHash     map[string]*domain.RefreshToken
	byIdentity map[core.IdentityID][]*domain.RefreshToken
}

func newFakeRefreshTokenRepo() *fakeRefreshTokenRepo {
	return &fakeRefreshTokenRepo{
		byHash:     make(map[string]*domain.RefreshToken),
		byIdentity: make(map[core.IdentityID][]*domain.RefreshToken),
	}
}

func (r *fakeRefreshTokenRepo) Create(_ context.Context, t *domain.RefreshToken) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byHash[t.TokenHash] = t
	r.byIdentity[t.IdentityID] = append(r.byIdentity[t.IdentityID], t)
	return nil
}
func (r *fakeRefreshTokenRepo) GetByHash(_ context.Context, hash string) (*domain.RefreshToken, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	t := r.byHash[hash]
	return t, nil
}
func (r *fakeRefreshTokenRepo) DeleteByHash(_ context.Context, hash string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.deleteByHashLocked(hash)
	return nil
}
func (r *fakeRefreshTokenRepo) deleteByHashLocked(hash string) {
	t, ok := r.byHash[hash]
	if !ok {
		return
	}
	delete(r.byHash, hash)
	var newList []*domain.RefreshToken
	for _, item := range r.byIdentity[t.IdentityID] {
		if item.TokenHash != hash {
			newList = append(newList, item)
		}
	}
	r.byIdentity[t.IdentityID] = newList
}
func (r *fakeRefreshTokenRepo) DeleteByIdentityID(_ context.Context, identityID core.IdentityID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	tokens := r.byIdentity[identityID]
	for _, t := range tokens {
		delete(r.byHash, t.TokenHash)
	}
	delete(r.byIdentity, identityID)
	return nil
}

// Consume mirrors the SQL contract of `DELETE ... RETURNING identity_id`:
// returns (identity_id, nil) on success and (zero, nil) when the token
// is missing OR expired. The mutex makes the read+delete atomic so
// concurrent Refresh calls see DB-equivalent semantics.
func (r *fakeRefreshTokenRepo) Consume(_ context.Context, hash string) (core.IdentityID, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.byHash[hash]
	if !ok {
		return core.IdentityID{}, nil
	}
	if time.Now().UTC().After(t.ExpiresAt) {
		// Mirror the `expires_at > NOW()` predicate: do NOT delete the
		// row when the predicate fails (matching SQL semantics) and
		// return zero ID.
		return core.IdentityID{}, nil
	}
	identityID := t.IdentityID
	r.deleteByHashLocked(hash)
	return identityID, nil
}

// --- fake EnvironmentRepository ---

type fakeEnvironmentRepo struct{}

func (r *fakeEnvironmentRepo) Create(_ context.Context, _ *domain.Environment) error { return nil }
func (r *fakeEnvironmentRepo) ListByAccount(_ context.Context) ([]domain.Environment, error) {
	return nil, nil
}
func (r *fakeEnvironmentRepo) GetBySlug(_ context.Context, _ core.Environment) (*domain.Environment, error) {
	return nil, nil
}
func (r *fakeEnvironmentRepo) Delete(_ context.Context, _ core.EnvironmentID) error { return nil }
func (r *fakeEnvironmentRepo) CountByAccount(_ context.Context) (int, error)        { return 0, nil }

// --- fake ProductRepository ---

type fakeProductRepo struct {
	products map[core.ProductID]*domain.Product
}

func newFakeProductRepo() *fakeProductRepo {
	return &fakeProductRepo{products: make(map[core.ProductID]*domain.Product)}
}

func (f *fakeProductRepo) Create(_ context.Context, p *domain.Product) error {
	f.products[p.ID] = p
	return nil
}
func (f *fakeProductRepo) GetByID(_ context.Context, id core.ProductID) (*domain.Product, error) {
	return f.products[id], nil
}
func (f *fakeProductRepo) List(_ context.Context, _ core.Cursor, _ int) ([]domain.Product, bool, error) {
	return nil, false, nil
}
func (f *fakeProductRepo) Update(_ context.Context, _ core.ProductID, _ domain.UpdateProductParams) (*domain.Product, error) {
	return nil, nil
}
func (f *fakeProductRepo) Delete(_ context.Context, _ core.ProductID) error { return nil }
func (f *fakeProductRepo) Search(_ context.Context, _ string, _ int) ([]domain.Product, error) {
	return nil, nil
}

// --- test helpers ---

func testMasterKey(t *testing.T) *crypto.MasterKey {
	t.Helper()
	mk, err := crypto.NewMasterKey("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
	require.NoError(t, err)
	return mk
}

// presetRoles returns a fakeRoleRepo seeded with owner/admin/member presets.
func presetRoles() *fakeRoleRepo {
	r := newFakeRoleRepo()
	r.seed(&domain.Role{ID: core.NewRoleID(), Slug: "owner", Name: "Owner"})
	r.seed(&domain.Role{ID: core.NewRoleID(), Slug: "admin", Name: "Admin"})
	r.seed(&domain.Role{ID: core.NewRoleID(), Slug: "member", Name: "Member"})
	return r
}

func newTestService(t *testing.T) (*Service, *fakeIdentityRepo, *fakeAccountRepo, *fakeMembershipRepo, *fakeRoleRepo, *fakeAPIKeyRepo, *fakeRefreshTokenRepo) {
	t.Helper()
	svc, h := newTestServiceFull(t)
	return svc, h.identities, h.accounts, h.memberships, h.roles, h.apiKeys, h.refreshTkns
}

// testServiceHarness bundles all fakes a test might need to seed or inspect.
// Used by tests that need access to repos beyond the 7-tuple returned by
// newTestService — e.g. seeding a product for scope validation.
type testServiceHarness struct {
	identities  *fakeIdentityRepo
	accounts    *fakeAccountRepo
	memberships *fakeMembershipRepo
	roles       *fakeRoleRepo
	apiKeys     *fakeAPIKeyRepo
	refreshTkns *fakeRefreshTokenRepo
	products    *fakeProductRepo
}

func newTestServiceFull(t *testing.T) (*Service, *testServiceHarness) {
	t.Helper()
	identities := newFakeIdentityRepo()
	accounts := newFakeAccountRepo()
	memberships := newFakeMembershipRepo()
	roles := presetRoles()
	apiKeys := newFakeAPIKeyRepo()
	refreshTkns := newFakeRefreshTokenRepo()
	envs := &fakeEnvironmentRepo{}
	products := newFakeProductRepo()
	mk := testMasterKey(t)
	idSvc := identity.NewService(identities, mk)
	svc := NewService(fakeTxManager{}, accounts, identities, memberships, roles, apiKeys, refreshTkns, envs, products, mk, idSvc)
	t.Cleanup(svc.Close)
	return svc, &testServiceHarness{
		identities:  identities,
		accounts:    accounts,
		memberships: memberships,
		roles:       roles,
		apiKeys:     apiKeys,
		refreshTkns: refreshTkns,
		products:    products,
	}
}

// --- tests ---

func TestSignup_CreatesIdentityAccountMembership(t *testing.T) {
	svc, identities, accounts, memberships, _, apiKeys, _ := newTestService(t)

	result, err := svc.Signup(context.Background(), SignupRequest{
		AccountName: "Acme Corp",
		Email:       "alice@example.com",
		Password:    "supersecret123",
	})
	require.NoError(t, err)
	require.NotNil(t, result)

	// Identity created.
	assert.Equal(t, "alice@example.com", result.Identity.Email)
	assert.NotEmpty(t, result.Identity.PasswordHash)
	assert.NotEqual(t, "supersecret123", result.Identity.PasswordHash)
	_, ok := identities.byID[result.Identity.ID]
	assert.True(t, ok, "identity should be stored")

	// Account created.
	assert.Equal(t, "Acme Corp", result.Account.Name)
	assert.Equal(t, "acme-corp", result.Account.Slug)
	_, ok = accounts.byID[result.Account.ID]
	assert.True(t, ok, "account should be stored")

	// Membership created with owner role.
	assert.Equal(t, "owner", result.Membership.RoleSlug)
	assert.Equal(t, result.Account.ID, result.Membership.Account.ID)
	var found bool
	for _, m := range memberships.byIdentity[result.Identity.ID] {
		if m.AccountID == result.Account.ID {
			found = true
			assert.Equal(t, domain.MembershipStatusActive, m.Status)
		}
	}
	assert.True(t, found, "membership should be stored")

	// Tokens non-empty.
	assert.NotEmpty(t, result.AccessToken)
	assert.NotEmpty(t, result.RefreshToken)
	assert.Equal(t, 900, result.ExpiresIn)

	// API key stored.
	assert.NotEmpty(t, result.APIKey)
	mk := testMasterKey(t)
	stored, err := apiKeys.GetByHash(context.Background(), mk.HMAC(result.APIKey))
	require.NoError(t, err)
	require.NotNil(t, stored)
	assert.Equal(t, core.EnvironmentLive, stored.Environment)
	assert.Equal(t, result.Account.ID, stored.AccountID)
}

func TestSignup_DuplicateEmailFails(t *testing.T) {
	svc, _, _, _, _, _, _ := newTestService(t)
	ctx := context.Background()

	req := SignupRequest{
		AccountName: "First",
		Email:       "dup@example.com",
		Password:    "password123",
	}
	_, err := svc.Signup(ctx, req)
	require.NoError(t, err)

	req.AccountName = "Second"
	_, err = svc.Signup(ctx, req)
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrEmailAlreadyExists, appErr.Code)
}

func TestLogin_VerifiesPasswordAndReturnsMemberships(t *testing.T) {
	svc, _, _, _, _, _, refreshTkns := newTestService(t)
	ctx := context.Background()

	_, err := svc.Signup(ctx, SignupRequest{
		AccountName: "Login Co",
		Email:       "user@example.com",
		Password:    "mypassword1",
	})
	require.NoError(t, err)

	result, err := svc.Login(ctx, LoginRequest{
		Email:    "user@example.com",
		Password: "mypassword1",
	})
	require.NoError(t, err)
	require.NotNil(t, result)

	// Identity without TOTP: NeedsTOTP should be false, LoginResult populated.
	assert.False(t, result.NeedsTOTP)
	require.NotNil(t, result.LoginResult)
	assert.NotEmpty(t, result.AccessToken)
	assert.NotEmpty(t, result.RefreshToken)
	assert.Equal(t, "Bearer", result.TokenType)
	assert.Equal(t, 900, result.ExpiresIn)
	assert.Greater(t, len(result.Memberships), 0)

	// Refresh token is stored.
	mk := testMasterKey(t)
	stored, err := refreshTkns.GetByHash(ctx, mk.HMAC(result.RefreshToken))
	require.NoError(t, err)
	require.NotNil(t, stored)
	assert.True(t, stored.ExpiresAt.After(time.Now()))
}

func TestLogin_BadPasswordFails(t *testing.T) {
	svc, _, _, _, _, _, _ := newTestService(t)
	ctx := context.Background()

	_, err := svc.Signup(ctx, SignupRequest{
		AccountName: "Bad PW Co",
		Email:       "bp@example.com",
		Password:    "correctpassword",
	})
	require.NoError(t, err)

	_, err = svc.Login(ctx, LoginRequest{
		Email:    "bp@example.com",
		Password: "wrongpassword",
	})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrAuthenticationRequired, appErr.Code)
}

func TestLogin_TOTPEnabled_ReturnsPendingToken(t *testing.T) {
	svc, identities, _, _, _, _, _ := newTestService(t)
	ctx := context.Background()

	// Signup first to create the identity.
	signupResult, err := svc.Signup(ctx, SignupRequest{
		AccountName: "TOTP Co",
		Email:       "totp-login@example.com",
		Password:    "password123",
	})
	require.NoError(t, err)

	// Seed TOTP state directly on the fake store (avoid going through
	// identitySvc.EnrollTOTP/ActivateTOTP which would hit UpdateTOTP="not implemented").
	mk := testMasterKey(t)
	secret, _, err := crypto.GenerateTOTPSecret("GetLicense", "totp-login@example.com")
	require.NoError(t, err)
	enc, err := mk.Encrypt([]byte(secret))
	require.NoError(t, err)
	now := time.Now().UTC()
	ident := identities.byID[signupResult.Identity.ID]
	ident.TOTPSecretEnc = enc
	ident.TOTPEnabledAt = &now

	result, err := svc.Login(ctx, LoginRequest{
		Email:    "totp-login@example.com",
		Password: "password123",
	})
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.True(t, result.NeedsTOTP)
	assert.NotEmpty(t, result.PendingToken)
	assert.Nil(t, result.LoginResult)
}

func TestLoginStep2_VerifiesCodeAndReturnsTokenPair(t *testing.T) {
	svc, identities, _, _, _, _, _ := newTestService(t)
	ctx := context.Background()

	// Signup first to create the identity.
	signupResult, err := svc.Signup(ctx, SignupRequest{
		AccountName: "TOTP Step2 Co",
		Email:       "totp-step2@example.com",
		Password:    "password123",
	})
	require.NoError(t, err)

	// Seed TOTP state directly.
	mk := testMasterKey(t)
	secret, _, err := crypto.GenerateTOTPSecret("GetLicense", "totp-step2@example.com")
	require.NoError(t, err)
	enc, err := mk.Encrypt([]byte(secret))
	require.NoError(t, err)
	now := time.Now().UTC()
	ident := identities.byID[signupResult.Identity.ID]
	ident.TOTPSecretEnc = enc
	ident.TOTPEnabledAt = &now

	// Step 1: login with password → get pending token.
	step1, err := svc.Login(ctx, LoginRequest{
		Email:    "totp-step2@example.com",
		Password: "password123",
	})
	require.NoError(t, err)
	require.True(t, step1.NeedsTOTP)
	require.NotEmpty(t, step1.PendingToken)

	// Step 2: submit TOTP code → get full token pair.
	code, err := crypto.TOTPCodeForTest(secret)
	require.NoError(t, err)

	step2, err := svc.LoginStep2(ctx, LoginStep2Request{
		PendingToken: step1.PendingToken,
		Code:         code,
	})
	require.NoError(t, err)
	require.NotNil(t, step2)
	assert.NotEmpty(t, step2.AccessToken)
	assert.NotEmpty(t, step2.RefreshToken)
	assert.NotEmpty(t, step2.Identity)
	assert.Greater(t, len(step2.Memberships), 0)
}

func TestSwitch_RequiresActiveMembership(t *testing.T) {
	svc, _, _, _, _, _, _ := newTestService(t)
	ctx := context.Background()

	result, err := svc.Signup(ctx, SignupRequest{
		AccountName: "Switch Co",
		Email:       "switcher@example.com",
		Password:    "password123",
	})
	require.NoError(t, err)

	loginResult, err := svc.Switch(ctx, result.Identity.ID, result.Membership.MembershipID)
	require.NoError(t, err)
	require.NotNil(t, loginResult)
	assert.NotEmpty(t, loginResult.AccessToken)
	assert.Equal(t, result.Account.ID, loginResult.CurrentAccount.ID)
}

func TestSwitch_NoMembershipFails(t *testing.T) {
	svc, _, _, _, _, _, _ := newTestService(t)
	ctx := context.Background()

	result, err := svc.Signup(ctx, SignupRequest{
		AccountName: "Switch Fail Co",
		Email:       "switchfail@example.com",
		Password:    "password123",
	})
	require.NoError(t, err)

	// A bogus membership id this identity does not own.
	otherMembershipID := core.NewMembershipID()
	_, err = svc.Switch(ctx, result.Identity.ID, otherMembershipID)
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrPermissionDenied, appErr.Code)
}

// TestSwitch_OtherIdentitysMembershipFails closes the subtle bug that
// would let a caller switch into another identity's account by passing
// their membership id. Switch() validates that the membership belongs
// to the caller.
func TestSwitch_OtherIdentitysMembershipFails(t *testing.T) {
	svc, _, _, _, _, _, _ := newTestService(t)
	ctx := context.Background()

	alice, err := svc.Signup(ctx, SignupRequest{
		AccountName: "Alice Co", Email: "alice@example.com", Password: "password123",
	})
	require.NoError(t, err)

	bob, err := svc.Signup(ctx, SignupRequest{
		AccountName: "Bob Co", Email: "bob@example.com", Password: "password123",
	})
	require.NoError(t, err)

	// Alice tries to switch into Bob's membership.
	_, err = svc.Switch(ctx, alice.Identity.ID, bob.Membership.MembershipID)
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrPermissionDenied, appErr.Code)
}

// TestSwitch_ActuallySwitchesBetweenAccounts verifies the real behavior
// of Switch — a multi-account identity ends up with the REQUESTED
// account active, not whichever one ListByIdentity returns first. This
// was the latent bug before: buildLoginResult unconditionally picked
// memberships[0] so Switch silently returned the default account.
func TestSwitch_ActuallySwitchesBetweenAccounts(t *testing.T) {
	svc, _, accounts, memberships, roles, _, _ := newTestService(t)
	ctx := context.Background()

	// Signup creates identity + accountA + owner membership.
	signup, err := svc.Signup(ctx, SignupRequest{
		AccountName: "Account A", Email: "multi@example.com", Password: "password123",
	})
	require.NoError(t, err)
	identityID := signup.Identity.ID
	accountAID := signup.Account.ID
	membershipAID := signup.Membership.MembershipID

	// Seed a second account + membership for the same identity.
	accountB := &domain.Account{
		ID:        core.NewAccountID(),
		Name:      "Account B",
		Slug:      "account-b",
		CreatedAt: time.Now().UTC(),
	}
	// Inject accountB into the fake account repo via the memberships path:
	// we need both the account row and a fresh membership. Reach into the
	// test fakes directly (same pattern as other tests).
	ownerRole, err := roles.GetBySlug(ctx, nil, "owner")
	require.NoError(t, err)
	require.NotNil(t, ownerRole)

	require.NoError(t, accounts.Create(ctx, accountB))

	membershipB := &domain.AccountMembership{
		ID:         core.NewMembershipID(),
		AccountID:  accountB.ID,
		IdentityID: identityID,
		RoleID:     ownerRole.ID,
		Status:     domain.MembershipStatusActive,
		JoinedAt:   time.Now().UTC(),
		CreatedAt:  time.Now().UTC(),
		UpdatedAt:  time.Now().UTC(),
	}
	require.NoError(t, memberships.Create(ctx, membershipB))

	// Default path (Login-style buildLoginResult) picks membershipA since
	// it was created first (oldest-joined).
	defaultResult, err := svc.Switch(ctx, identityID, membershipAID)
	require.NoError(t, err)
	assert.Equal(t, accountAID, defaultResult.CurrentAccount.ID,
		"switching to membership A should return account A")

	// Now the real test: switch to membership B and verify CurrentAccount
	// is account B, not account A (the memberships[0] default).
	switchedResult, err := svc.Switch(ctx, identityID, membershipB.ID)
	require.NoError(t, err)
	assert.Equal(t, accountB.ID, switchedResult.CurrentAccount.ID,
		"switching to membership B should return account B, not the oldest-joined")
	assert.Equal(t, "Account B", switchedResult.CurrentAccount.Name)
}

func TestRefresh_RotatesToken(t *testing.T) {
	svc, _, _, _, _, _, refreshTkns := newTestService(t)
	ctx := context.Background()
	mk := testMasterKey(t)

	_, err := svc.Signup(ctx, SignupRequest{
		AccountName: "Refresh Co",
		Email:       "refresh@example.com",
		Password:    "password123",
	})
	require.NoError(t, err)

	loginResult, err := svc.Login(ctx, LoginRequest{
		Email:    "refresh@example.com",
		Password: "password123",
	})
	require.NoError(t, err)
	oldToken := loginResult.RefreshToken

	// Refresh with the old token.
	newResult, err := svc.Refresh(ctx, oldToken)
	require.NoError(t, err)
	require.NotNil(t, newResult)
	assert.NotEmpty(t, newResult.AccessToken)
	assert.NotEmpty(t, newResult.RefreshToken)
	assert.NotEqual(t, oldToken, newResult.RefreshToken, "refresh token must rotate")

	// Old token must be invalidated.
	oldHash := mk.HMAC(oldToken)
	stored, err := refreshTkns.GetByHash(ctx, oldHash)
	require.NoError(t, err)
	assert.Nil(t, stored, "old refresh token should be deleted")

	// New token must be valid.
	newHash := mk.HMAC(newResult.RefreshToken)
	newStored, err := refreshTkns.GetByHash(ctx, newHash)
	require.NoError(t, err)
	assert.NotNil(t, newStored, "new refresh token should be stored")
}

func TestRefresh_ConcurrentRequests_OnlyOneSucceeds(t *testing.T) {
	// Regression test for the rotation race fix (PR-1.2): two
	// concurrent refresh calls with the same token must produce
	// exactly ONE success and ONE ErrAuthenticationRequired.
	//
	// The fake's Consume holds an internal mutex around the
	// read+delete, mirroring the SQL `DELETE ... RETURNING` atomic
	// semantics. This test models the service-layer contract on top
	// of those semantics — the DB-level atomicity itself is not
	// exercised here (would require a live Postgres test).
	svc, _, _, _, _, _, _ := newTestService(t)
	ctx := context.Background()

	_, err := svc.Signup(ctx, SignupRequest{
		AccountName: "Race Co",
		Email:       "race@example.com",
		Password:    "password123",
	})
	require.NoError(t, err)

	loginResult, err := svc.Login(ctx, LoginRequest{
		Email:    "race@example.com",
		Password: "password123",
	})
	require.NoError(t, err)

	const goroutines = 2
	var (
		wg      sync.WaitGroup
		results [goroutines]error
	)
	wg.Add(goroutines)
	start := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			<-start
			_, results[idx] = svc.Refresh(ctx, loginResult.RefreshToken)
		}(i)
	}
	close(start)
	wg.Wait()

	var successCount, authErrCount int
	for _, err := range results {
		if err == nil {
			successCount++
			continue
		}
		var ae *core.AppError
		if errors.As(err, &ae) && ae.Code == core.ErrAuthenticationRequired {
			authErrCount++
			continue
		}
		t.Fatalf("unexpected error from concurrent refresh: %v", err)
	}
	assert.Equal(t, 1, successCount, "exactly one refresh should succeed")
	assert.Equal(t, 1, authErrCount, "the other should reject as authentication-required")
}

func TestPendingStore_SweepExpired(t *testing.T) {
	ps := newPendingStore()
	t.Cleanup(ps.Close)

	id1 := core.NewIdentityID()
	id2 := core.NewIdentityID()
	ps.put("token-fresh", id1)
	ps.put("token-stale", id2)

	// Manually age token-stale past its TTL.
	ps.mu.Lock()
	stale := ps.m["token-stale"]
	stale.expiresAt = time.Now().UTC().Add(-time.Minute)
	ps.m["token-stale"] = stale
	ps.mu.Unlock()

	ps.sweepExpired(time.Now().UTC())

	// Fresh token survives and is still consumable.
	got, ok := ps.take("token-fresh")
	assert.True(t, ok)
	assert.Equal(t, id1, got)

	// Stale token is gone.
	_, ok = ps.take("token-stale")
	assert.False(t, ok)
}

func TestCreateAPIKey_Validation(t *testing.T) {
	pid := core.NewProductID()
	unknownPID := core.NewProductID()

	cases := []struct {
		name        string
		req         CreateAPIKeyRequest
		productID   *core.ProductID // which product to seed (nil = skip)
		wantErr     core.ErrorCode  // "" means expect success
		wantScope   core.APIKeyScope
		wantProdSet bool // whether the resulting APIKey.ProductID should be non-nil
	}{
		{
			name:      "default scope, no product_id",
			req:       CreateAPIKeyRequest{Environment: "live"},
			wantScope: core.APIKeyScopeAccountWide,
		},
		{
			name:      "explicit account_wide, no product_id",
			req:       CreateAPIKeyRequest{Environment: "live", Scope: core.APIKeyScopeAccountWide},
			wantScope: core.APIKeyScopeAccountWide,
		},
		{
			name:    "account_wide with product_id rejected",
			req:     CreateAPIKeyRequest{Environment: "live", Scope: core.APIKeyScopeAccountWide, ProductID: &pid},
			wantErr: core.ErrValidationError,
		},
		{
			name:    "product without product_id rejected",
			req:     CreateAPIKeyRequest{Environment: "live", Scope: core.APIKeyScopeProduct},
			wantErr: core.ErrValidationError,
		},
		{
			name:    "unknown scope rejected",
			req:     CreateAPIKeyRequest{Environment: "live", Scope: core.APIKeyScope("garbage")},
			wantErr: core.ErrValidationError,
		},
		{
			name:    "product scope + unknown product_id -> 404",
			req:     CreateAPIKeyRequest{Environment: "live", Scope: core.APIKeyScopeProduct, ProductID: &unknownPID},
			wantErr: core.ErrProductNotFound,
		},
		{
			name:        "product scope + valid product_id -> success",
			req:         CreateAPIKeyRequest{Environment: "live", Scope: core.APIKeyScopeProduct, ProductID: &pid},
			productID:   &pid,
			wantScope:   core.APIKeyScopeProduct,
			wantProdSet: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, h := newTestServiceFull(t)
			if tc.productID != nil {
				h.products.products[*tc.productID] = &domain.Product{ID: *tc.productID}
			}

			result, err := svc.CreateAPIKey(context.Background(), core.NewAccountID(), core.EnvironmentLive, tc.req)

			if tc.wantErr == "" {
				require.NoError(t, err)
				require.NotNil(t, result)
				require.NotNil(t, result.APIKey)
				assert.Equal(t, tc.wantScope, result.APIKey.Scope)
				if tc.wantProdSet {
					require.NotNil(t, result.APIKey.ProductID)
					assert.Equal(t, *tc.req.ProductID, *result.APIKey.ProductID)
				} else {
					assert.Nil(t, result.APIKey.ProductID)
				}
				return
			}

			require.Error(t, err)
			var ae *core.AppError
			require.ErrorAs(t, err, &ae)
			assert.Equal(t, tc.wantErr, ae.Code)
		})
	}
}

func TestSlugify(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"Acme Corp", "acme-corp"},
		{"Hello World", "hello-world"},
		{"My  Company!", "my-company"},
		{"123 Numbers", "123-numbers"},
		{"  Leading Trailing  ", "leading-trailing"},
		{"Slash/Backslash", "slashbackslash"},
		{"multi---hyphens", "multi-hyphens"},
		{"Über Café", "ber-caf"},
		{"already-slugified", "already-slugified"},
		{"ALL CAPS", "all-caps"},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got := slugify(tc.input)
			assert.Equal(t, tc.want, got)
		})
	}
}
