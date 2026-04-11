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

// --- mock TxManager ---

type mockTxManager struct{}

func (m *mockTxManager) WithTenant(_ context.Context, _ core.AccountID, fn func(context.Context) error) error {
	return fn(context.Background())
}

func (m *mockTxManager) WithTx(_ context.Context, fn func(context.Context) error) error {
	return fn(context.Background())
}

// --- mock AccountRepository ---

type mockAccountRepo struct {
	byID   map[core.AccountID]*domain.Account
	bySlug map[string]*domain.Account
}

func newMockAccountRepo() *mockAccountRepo {
	return &mockAccountRepo{
		byID:   make(map[core.AccountID]*domain.Account),
		bySlug: make(map[string]*domain.Account),
	}
}

func (r *mockAccountRepo) Create(_ context.Context, a *domain.Account) error {
	r.byID[a.ID] = a
	r.bySlug[a.Slug] = a
	return nil
}

func (r *mockAccountRepo) GetByID(_ context.Context, id core.AccountID) (*domain.Account, error) {
	a, ok := r.byID[id]
	if !ok {
		return nil, errors.New("not found")
	}
	return a, nil
}

func (r *mockAccountRepo) GetBySlug(_ context.Context, slug string) (*domain.Account, error) {
	a, ok := r.bySlug[slug]
	if !ok {
		return nil, errors.New("not found")
	}
	return a, nil
}

// --- mock UserRepository ---

type mockUserRepo struct {
	byID    map[core.UserID]*domain.User
	byEmail map[string]*domain.User
}

func newMockUserRepo() *mockUserRepo {
	return &mockUserRepo{
		byID:    make(map[core.UserID]*domain.User),
		byEmail: make(map[string]*domain.User),
	}
}

func (r *mockUserRepo) Create(_ context.Context, u *domain.User) error {
	r.byID[u.ID] = u
	r.byEmail[u.Email] = u
	return nil
}

func (r *mockUserRepo) GetByID(_ context.Context, id core.UserID) (*domain.User, error) {
	u, ok := r.byID[id]
	if !ok {
		return nil, errors.New("not found")
	}
	return u, nil
}

func (r *mockUserRepo) GetByEmail(_ context.Context, email string) (*domain.User, error) {
	u, ok := r.byEmail[email]
	if !ok {
		return nil, errors.New("not found")
	}
	return u, nil
}

// --- mock APIKeyRepository ---

type mockAPIKeyRepo struct {
	byID   map[core.APIKeyID]*domain.APIKey
	byHash map[string]*domain.APIKey
	list   []*domain.APIKey
}

func newMockAPIKeyRepo() *mockAPIKeyRepo {
	return &mockAPIKeyRepo{
		byID:   make(map[core.APIKeyID]*domain.APIKey),
		byHash: make(map[string]*domain.APIKey),
	}
}

func (r *mockAPIKeyRepo) Create(_ context.Context, k *domain.APIKey) error {
	r.byID[k.ID] = k
	r.byHash[k.KeyHash] = k
	r.list = append(r.list, k)
	return nil
}

func (r *mockAPIKeyRepo) GetByHash(_ context.Context, hash string) (*domain.APIKey, error) {
	k, ok := r.byHash[hash]
	if !ok {
		return nil, errors.New("not found")
	}
	return k, nil
}

func (r *mockAPIKeyRepo) ListByAccount(_ context.Context, limit, offset int) ([]domain.APIKey, int, error) {
	total := len(r.list)
	if offset >= total {
		return nil, total, nil
	}
	end := offset + limit
	if end > total {
		end = total
	}
	out := make([]domain.APIKey, end-offset)
	for i, k := range r.list[offset:end] {
		out[i] = *k
	}
	return out, total, nil
}

func (r *mockAPIKeyRepo) Delete(_ context.Context, id core.APIKeyID) error {
	k, ok := r.byID[id]
	if !ok {
		return errors.New("not found")
	}
	delete(r.byHash, k.KeyHash)
	delete(r.byID, id)
	newList := r.list[:0]
	for _, item := range r.list {
		if item.ID != id {
			newList = append(newList, item)
		}
	}
	r.list = newList
	return nil
}

// --- mock RefreshTokenRepository ---

type mockRefreshTokenRepo struct {
	byHash   map[string]*domain.RefreshToken
	byUserID map[core.UserID][]*domain.RefreshToken
}

func newMockRefreshTokenRepo() *mockRefreshTokenRepo {
	return &mockRefreshTokenRepo{
		byHash:   make(map[string]*domain.RefreshToken),
		byUserID: make(map[core.UserID][]*domain.RefreshToken),
	}
}

func (r *mockRefreshTokenRepo) Create(_ context.Context, t *domain.RefreshToken) error {
	r.byHash[t.TokenHash] = t
	r.byUserID[t.UserID] = append(r.byUserID[t.UserID], t)
	return nil
}

func (r *mockRefreshTokenRepo) GetByHash(_ context.Context, hash string) (*domain.RefreshToken, error) {
	t, ok := r.byHash[hash]
	if !ok {
		return nil, errors.New("not found")
	}
	return t, nil
}

func (r *mockRefreshTokenRepo) DeleteByHash(_ context.Context, hash string) error {
	t, ok := r.byHash[hash]
	if !ok {
		return nil
	}
	delete(r.byHash, hash)
	newList := r.byUserID[t.UserID][:0]
	for _, item := range r.byUserID[t.UserID] {
		if item.TokenHash != hash {
			newList = append(newList, item)
		}
	}
	r.byUserID[t.UserID] = newList
	return nil
}

func (r *mockRefreshTokenRepo) DeleteByUserID(_ context.Context, userID core.UserID) error {
	tokens := r.byUserID[userID]
	for _, t := range tokens {
		delete(r.byHash, t.TokenHash)
	}
	delete(r.byUserID, userID)
	return nil
}

// --- test helpers ---

func testMasterKey(t *testing.T) *crypto.MasterKey {
	t.Helper()
	// 64 hex chars = 32 bytes.
	mk, err := crypto.NewMasterKey("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
	require.NoError(t, err)
	return mk
}

func newTestService(t *testing.T) (*Service, *mockAccountRepo, *mockUserRepo, *mockAPIKeyRepo, *mockRefreshTokenRepo) {
	t.Helper()
	accounts := newMockAccountRepo()
	users := newMockUserRepo()
	apiKeys := newMockAPIKeyRepo()
	refreshTkns := newMockRefreshTokenRepo()
	mk := testMasterKey(t)
	svc := NewService(&mockTxManager{}, accounts, users, apiKeys, refreshTkns, mk)
	return svc, accounts, users, apiKeys, refreshTkns
}

// --- tests ---

func TestSignup_HappyPath(t *testing.T) {
	svc, _, _, apiKeys, _ := newTestService(t)

	result, err := svc.Signup(context.Background(), SignupRequest{
		AccountName: "Acme Corp",
		Email:       "alice@example.com",
		Password:    "supersecret123",
	})
	require.NoError(t, err)
	require.NotNil(t, result)

	// Account created correctly.
	assert.Equal(t, "Acme Corp", result.Account.Name)
	assert.Equal(t, "acme-corp", result.Account.Slug)
	assert.False(t, result.Account.CreatedAt.IsZero())

	// User created correctly.
	assert.Equal(t, "alice@example.com", result.User.Email)
	assert.Equal(t, core.UserRoleOwner, result.User.Role)
	assert.Equal(t, result.Account.ID, result.User.AccountID)
	assert.NotEmpty(t, result.User.PasswordHash)
	assert.NotEqual(t, "supersecret123", result.User.PasswordHash) // must be hashed

	// API key returned.
	assert.NotEmpty(t, result.APIKey)
	assert.True(t, len(result.APIKey) > 8)

	// API key stored (verify by hash lookup).
	mk := testMasterKey(t)
	hash := crypto.HMACSHA256(mk.HMACKey, result.APIKey)
	stored, err := apiKeys.GetByHash(context.Background(), hash)
	require.NoError(t, err)
	assert.Equal(t, core.APIKeyScopeAccountWide, stored.Scope)
	assert.Equal(t, "live", stored.Environment)
	assert.Equal(t, result.Account.ID, stored.AccountID)
}

func TestSignup_DuplicateEmail(t *testing.T) {
	svc, _, _, _, _ := newTestService(t)
	ctx := context.Background()

	req := SignupRequest{
		AccountName: "First",
		Email:       "dup@example.com",
		Password:    "password123",
	}

	_, err := svc.Signup(ctx, req)
	require.NoError(t, err)

	// Second signup with same email.
	req.AccountName = "Second"
	_, err = svc.Signup(ctx, req)
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrEmailAlreadyExists, appErr.Code)
}

func TestLogin_HappyPath(t *testing.T) {
	svc, _, _, _, refreshTkns := newTestService(t)
	ctx := context.Background()

	// Sign up first.
	signupResult, err := svc.Signup(ctx, SignupRequest{
		AccountName: "Login Test Co",
		Email:       "user@example.com",
		Password:    "mypassword1",
	})
	require.NoError(t, err)
	_ = signupResult

	// Login.
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

	// Refresh token stored.
	mk := testMasterKey(t)
	hash := crypto.HMACSHA256(mk.HMACKey, result.RefreshToken)
	stored, err := refreshTkns.GetByHash(ctx, hash)
	require.NoError(t, err)
	assert.True(t, stored.ExpiresAt.After(time.Now()))

	// JWT is verifiable.
	claims, err := crypto.VerifyJWT(result.AccessToken, mk.JWTSigningKey)
	require.NoError(t, err)
	assert.Equal(t, core.UserRoleOwner, claims.Role)
}

func TestLogin_WrongPassword(t *testing.T) {
	svc, _, _, _, _ := newTestService(t)
	ctx := context.Background()

	_, err := svc.Signup(ctx, SignupRequest{
		AccountName: "WP Co",
		Email:       "wp@example.com",
		Password:    "correctpassword",
	})
	require.NoError(t, err)

	_, err = svc.Login(ctx, LoginRequest{
		Email:    "wp@example.com",
		Password: "wrongpassword",
	})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrAuthenticationRequired, appErr.Code)
}

func TestLogin_UnknownEmail(t *testing.T) {
	svc, _, _, _, _ := newTestService(t)

	_, err := svc.Login(context.Background(), LoginRequest{
		Email:    "nobody@example.com",
		Password: "somepassword",
	})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrAuthenticationRequired, appErr.Code)
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
