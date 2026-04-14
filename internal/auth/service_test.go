package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/crypto"
	"github.com/getlicense-io/getlicense-api/internal/domain"
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
	byID                map[core.MembershipID]*domain.AccountMembership
	byIdentity          map[core.IdentityID][]domain.AccountMembership
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
func (r *fakeAPIKeyRepo) ListByAccount(_ context.Context, env core.Environment, limit, offset int) ([]domain.APIKey, int, error) {
	var matched []domain.APIKey
	for _, k := range r.list {
		if k.Environment == env {
			matched = append(matched, *k)
		}
	}
	total := len(matched)
	if offset >= total {
		return nil, total, nil
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return matched[offset:end], total, nil
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

type fakeRefreshTokenRepo struct {
	byHash      map[string]*domain.RefreshToken
	byIdentity  map[core.IdentityID][]*domain.RefreshToken
}

func newFakeRefreshTokenRepo() *fakeRefreshTokenRepo {
	return &fakeRefreshTokenRepo{
		byHash:     make(map[string]*domain.RefreshToken),
		byIdentity: make(map[core.IdentityID][]*domain.RefreshToken),
	}
}

func (r *fakeRefreshTokenRepo) Create(_ context.Context, t *domain.RefreshToken) error {
	r.byHash[t.TokenHash] = t
	r.byIdentity[t.IdentityID] = append(r.byIdentity[t.IdentityID], t)
	return nil
}
func (r *fakeRefreshTokenRepo) GetByHash(_ context.Context, hash string) (*domain.RefreshToken, error) {
	t := r.byHash[hash]
	return t, nil
}
func (r *fakeRefreshTokenRepo) DeleteByHash(_ context.Context, hash string) error {
	t, ok := r.byHash[hash]
	if !ok {
		return nil
	}
	delete(r.byHash, hash)
	var newList []*domain.RefreshToken
	for _, item := range r.byIdentity[t.IdentityID] {
		if item.TokenHash != hash {
			newList = append(newList, item)
		}
	}
	r.byIdentity[t.IdentityID] = newList
	return nil
}
func (r *fakeRefreshTokenRepo) DeleteByIdentityID(_ context.Context, identityID core.IdentityID) error {
	tokens := r.byIdentity[identityID]
	for _, t := range tokens {
		delete(r.byHash, t.TokenHash)
	}
	delete(r.byIdentity, identityID)
	return nil
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
	identities := newFakeIdentityRepo()
	accounts := newFakeAccountRepo()
	memberships := newFakeMembershipRepo()
	roles := presetRoles()
	apiKeys := newFakeAPIKeyRepo()
	refreshTkns := newFakeRefreshTokenRepo()
	envs := &fakeEnvironmentRepo{}
	mk := testMasterKey(t)
	svc := NewService(fakeTxManager{}, accounts, identities, memberships, roles, apiKeys, refreshTkns, envs, mk)
	return svc, identities, accounts, memberships, roles, apiKeys, refreshTkns
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

func TestSwitch_RequiresActiveMembership(t *testing.T) {
	svc, _, _, _, _, _, _ := newTestService(t)
	ctx := context.Background()

	result, err := svc.Signup(ctx, SignupRequest{
		AccountName: "Switch Co",
		Email:       "switcher@example.com",
		Password:    "password123",
	})
	require.NoError(t, err)

	loginResult, err := svc.Switch(ctx, result.Identity.ID, result.Account.ID)
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

	// Try switching to a random account the identity has no membership in.
	otherAccountID := core.NewAccountID()
	_, err = svc.Switch(ctx, result.Identity.ID, otherAccountID)
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrPermissionDenied, appErr.Code)
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
