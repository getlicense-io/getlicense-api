package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/crypto"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

// --- mock APIKeyRepository ---

type mockAPIKeyRepo struct {
	byHash map[string]*domain.APIKey
}

func (r *mockAPIKeyRepo) Create(_ context.Context, _ *domain.APIKey) error {
	return errors.New("not implemented")
}
func (r *mockAPIKeyRepo) GetByHash(_ context.Context, hash string) (*domain.APIKey, error) {
	if k, ok := r.byHash[hash]; ok {
		return k, nil
	}
	return nil, nil
}
func (r *mockAPIKeyRepo) ListByAccount(_ context.Context, _ core.Environment, _ core.Cursor, _ int) ([]domain.APIKey, bool, error) {
	return nil, false, errors.New("not implemented")
}
func (r *mockAPIKeyRepo) RecordUse(_ context.Context, _ core.APIKeyID, _, _ *string, _ time.Time) error {
	return nil
}
func (r *mockAPIKeyRepo) Revoke(_ context.Context, _ core.APIKeyID, _ *core.IdentityID, _ *string, _ time.Time) error {
	return errors.New("not implemented")
}

// --- mock AccountMembershipRepository ---

type mockMembershipRepo struct {
	byID     map[core.MembershipID]*domain.AccountMembership
	roleByID map[core.MembershipID]*domain.Role
}

func (r *mockMembershipRepo) Create(_ context.Context, _ *domain.AccountMembership) error {
	return errors.New("not implemented")
}
func (r *mockMembershipRepo) GetByID(_ context.Context, id core.MembershipID) (*domain.AccountMembership, error) {
	if m, ok := r.byID[id]; ok {
		return m, nil
	}
	return nil, nil
}
func (r *mockMembershipRepo) GetByIDWithRole(_ context.Context, id core.MembershipID) (*domain.AccountMembership, *domain.Role, error) {
	m, ok := r.byID[id]
	if !ok {
		return nil, nil, nil
	}
	role := r.roleByID[id] // may be nil — caller checks
	return m, role, nil
}
func (r *mockMembershipRepo) GetByIdentityAndAccount(_ context.Context, _ core.IdentityID, _ core.AccountID) (*domain.AccountMembership, error) {
	return nil, errors.New("not implemented")
}
func (r *mockMembershipRepo) ListByIdentity(_ context.Context, _ core.IdentityID) ([]domain.AccountMembership, error) {
	return nil, errors.New("not implemented")
}
func (r *mockMembershipRepo) ListByAccount(_ context.Context, _ core.Cursor, _ int) ([]domain.AccountMembership, bool, error) {
	return nil, false, errors.New("not implemented")
}
func (r *mockMembershipRepo) UpdateRole(_ context.Context, _ core.MembershipID, _ core.RoleID) error {
	return errors.New("not implemented")
}
func (r *mockMembershipRepo) UpdateStatus(_ context.Context, _ core.MembershipID, _ domain.MembershipStatus) error {
	return errors.New("not implemented")
}
func (r *mockMembershipRepo) Delete(_ context.Context, _ core.MembershipID) error {
	return errors.New("not implemented")
}
func (r *mockMembershipRepo) CountOwners(_ context.Context, _ core.AccountID) (int, error) {
	return 0, errors.New("not implemented")
}
func (r *mockMembershipRepo) ListAccountWithDetails(_ context.Context, _ core.Cursor, _ int) ([]domain.MembershipDetail, bool, error) {
	return nil, false, errors.New("not implemented")
}

// --- helpers ---

func echoEnvHandler(c fiber.Ctx) error {
	auth := AuthFromContext(c)
	if auth == nil {
		return c.Status(500).SendString("no auth in context")
	}
	return c.SendString(string(auth.Environment))
}

func newTestMasterKey(t *testing.T) *crypto.MasterKey {
	t.Helper()
	mk, err := crypto.NewMasterKey(strings.Repeat("a", 64), "", "")
	require.NoError(t, err)
	return mk
}

func testErrorHandler(c fiber.Ctx, err error) error {
	var appErr *core.AppError
	if errors.As(err, &appErr) {
		return c.Status(appErr.HTTPStatus()).JSON(appErr)
	}
	return c.Status(500).SendString(err.Error())
}

// passthroughTxManager satisfies domain.TxManager by simply running fn
// in the caller's context — no real DB tx is opened. Sufficient for
// middleware tests that exercise only the in-memory mock repos.
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

func newTestDeps(t *testing.T, mk *crypto.MasterKey, apiKeyRepo domain.APIKeyRepository, membershipRepo domain.AccountMembershipRepository, adminRole *domain.Role) Dependencies {
	t.Helper()
	return Dependencies{
		APIKeys:     apiKeyRepo,
		Memberships: membershipRepo,
		MasterKey:   mk,
		TxManager:   passthroughTxManager{},
		AdminRole:   adminRole,
	}
}

func newTestApp(t *testing.T, deps Dependencies) *fiber.App {
	t.Helper()
	app := fiber.New(fiber.Config{ErrorHandler: testErrorHandler})
	app.Get("/probe", RequireAuth(deps), echoEnvHandler)
	return app
}

// issueJWT signs a token for the given identity/account/membership and seeds
// the membership and its role into the provided repo so the middleware can
// resolve them via GetByIDWithRole.
func issueJWT(t *testing.T, mk *crypto.MasterKey, membershipRepo *mockMembershipRepo) string {
	t.Helper()

	identityID := core.NewIdentityID()
	accountID := core.NewAccountID()
	membershipID := core.NewMembershipID()
	roleID := core.NewRoleID()

	role := &domain.Role{
		ID:   roleID,
		Slug: "owner",
		Name: "Owner",
	}

	membershipRepo.byID[membershipID] = &domain.AccountMembership{
		ID:         membershipID,
		AccountID:  accountID,
		IdentityID: identityID,
		RoleID:     roleID,
		Status:     domain.MembershipStatusActive,
		JoinedAt:   time.Now(),
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
	membershipRepo.roleByID[membershipID] = role

	token, err := mk.SignJWT(crypto.JWTClaims{
		IdentityID:      identityID,
		ActingAccountID: accountID,
		MembershipID:    membershipID,
		RoleSlug:        "owner",
	}, time.Hour)
	require.NoError(t, err)
	return token
}

func doRequest(t *testing.T, app *fiber.App, authHeader, envHeader string) (int, string) {
	t.Helper()
	req := httptest.NewRequest("GET", "/probe", nil)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	if envHeader != "" {
		req.Header.Set(HeaderEnvironment, envHeader)
	}
	res, err := app.Test(req)
	require.NoError(t, err)
	defer func() { _ = res.Body.Close() }()
	buf := make([]byte, 256)
	n, _ := res.Body.Read(buf)
	return res.StatusCode, string(buf[:n])
}

// parseErrorCode extracts the error.code field from an AppError JSON
// envelope. Used by tests that need to distinguish between error types
// on non-200 responses.
func parseErrorCode(t *testing.T, body string) string {
	t.Helper()
	var envelope struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &envelope))
	return envelope.Error.Code
}

// --- tests ---

func TestRequireAuth_JWT_DefaultsToLive(t *testing.T) {
	mk := newTestMasterKey(t)
	membershipRepo := &mockMembershipRepo{
		byID:     make(map[core.MembershipID]*domain.AccountMembership),
		roleByID: make(map[core.MembershipID]*domain.Role),
	}
	deps := newTestDeps(t, mk, &mockAPIKeyRepo{}, membershipRepo, nil)
	app := newTestApp(t, deps)
	token := issueJWT(t, mk, membershipRepo)

	status, body := doRequest(t, app, "Bearer "+token, "")
	assert.Equal(t, 200, status)
	assert.Equal(t, "live", body)
}

func TestRequireAuth_JWT_HonorsXEnvironmentTest(t *testing.T) {
	mk := newTestMasterKey(t)
	membershipRepo := &mockMembershipRepo{
		byID:     make(map[core.MembershipID]*domain.AccountMembership),
		roleByID: make(map[core.MembershipID]*domain.Role),
	}
	deps := newTestDeps(t, mk, &mockAPIKeyRepo{}, membershipRepo, nil)
	app := newTestApp(t, deps)
	token := issueJWT(t, mk, membershipRepo)

	status, body := doRequest(t, app, "Bearer "+token, "test")
	assert.Equal(t, 200, status)
	assert.Equal(t, "test", body)
}

func TestRequireAuth_JWT_AcceptsCustomXEnvironment(t *testing.T) {
	// Any slug passing the format regex is accepted at the middleware
	// layer. Whether the slug actually resolves to tenant data is
	// enforced by RLS downstream, not here.
	mk := newTestMasterKey(t)
	membershipRepo := &mockMembershipRepo{
		byID:     make(map[core.MembershipID]*domain.AccountMembership),
		roleByID: make(map[core.MembershipID]*domain.Role),
	}
	deps := newTestDeps(t, mk, &mockAPIKeyRepo{}, membershipRepo, nil)
	app := newTestApp(t, deps)
	token := issueJWT(t, mk, membershipRepo)

	status, body := doRequest(t, app, "Bearer "+token, "staging")
	assert.Equal(t, 200, status)
	assert.Equal(t, "staging", body)
}

func TestRequireAuth_JWT_RejectsMalformedXEnvironment(t *testing.T) {
	mk := newTestMasterKey(t)
	membershipRepo := &mockMembershipRepo{
		byID:     make(map[core.MembershipID]*domain.AccountMembership),
		roleByID: make(map[core.MembershipID]*domain.Role),
	}
	deps := newTestDeps(t, mk, &mockAPIKeyRepo{}, membershipRepo, nil)
	app := newTestApp(t, deps)
	token := issueJWT(t, mk, membershipRepo)

	// Uppercase letters and special chars fail the slug regex → 422.
	status, _ := doRequest(t, app, "Bearer "+token, "Staging!")
	assert.Equal(t, 422, status)
}

func TestRequireAuth_JWT_RejectsInactiveMembership(t *testing.T) {
	mk := newTestMasterKey(t)
	membershipRepo := &mockMembershipRepo{
		byID:     make(map[core.MembershipID]*domain.AccountMembership),
		roleByID: make(map[core.MembershipID]*domain.Role),
	}
	deps := newTestDeps(t, mk, &mockAPIKeyRepo{}, membershipRepo, nil)
	app := newTestApp(t, deps)

	// Build a token but mark the membership as suspended.
	identityID := core.NewIdentityID()
	accountID := core.NewAccountID()
	membershipID := core.NewMembershipID()
	roleID := core.NewRoleID()
	role := &domain.Role{ID: roleID, Slug: "owner", Name: "Owner"}
	membershipRepo.byID[membershipID] = &domain.AccountMembership{
		ID:         membershipID,
		AccountID:  accountID,
		IdentityID: identityID,
		RoleID:     roleID,
		Status:     domain.MembershipStatusSuspended,
	}
	membershipRepo.roleByID[membershipID] = role
	token, err := mk.SignJWT(crypto.JWTClaims{
		IdentityID:      identityID,
		ActingAccountID: accountID,
		MembershipID:    membershipID,
		RoleSlug:        "owner",
	}, time.Hour)
	require.NoError(t, err)

	status, _ := doRequest(t, app, "Bearer "+token, "")
	assert.Equal(t, 401, status)
}

func TestRequireAuth_JWT_RejectsMembershipMismatch(t *testing.T) {
	mk := newTestMasterKey(t)
	membershipRepo := &mockMembershipRepo{
		byID:     make(map[core.MembershipID]*domain.AccountMembership),
		roleByID: make(map[core.MembershipID]*domain.Role),
	}
	deps := newTestDeps(t, mk, &mockAPIKeyRepo{}, membershipRepo, nil)
	app := newTestApp(t, deps)

	// Membership stored under a different identity than what the JWT claims.
	identityID := core.NewIdentityID()
	differentIdentityID := core.NewIdentityID()
	accountID := core.NewAccountID()
	membershipID := core.NewMembershipID()
	roleID := core.NewRoleID()
	role := &domain.Role{ID: roleID, Slug: "owner", Name: "Owner"}
	membershipRepo.byID[membershipID] = &domain.AccountMembership{
		ID:         membershipID,
		AccountID:  accountID,
		IdentityID: differentIdentityID, // mismatch
		RoleID:     roleID,
		Status:     domain.MembershipStatusActive,
	}
	membershipRepo.roleByID[membershipID] = role
	token, err := mk.SignJWT(crypto.JWTClaims{
		IdentityID:      identityID,
		ActingAccountID: accountID,
		MembershipID:    membershipID,
		RoleSlug:        "owner",
	}, time.Hour)
	require.NoError(t, err)

	status, _ := doRequest(t, app, "Bearer "+token, "")
	assert.Equal(t, 401, status)
}

func TestRequireAuth_APIKey_IgnoresXEnvironment(t *testing.T) {
	mk := newTestMasterKey(t)
	rawKey := "gl_live_" + strings.Repeat("a", 32)
	adminRole := &domain.Role{ID: core.NewRoleID(), Slug: "admin", Name: "Admin"}

	repo := &mockAPIKeyRepo{
		byHash: map[string]*domain.APIKey{
			mk.HMAC(rawKey): {
				ID:          core.NewAPIKeyID(),
				AccountID:   core.NewAccountID(),
				Prefix:      "gl_live_aaaa",
				Environment: core.EnvironmentLive,
				Scope:       core.APIKeyScopeAccountWide,
			},
		},
	}
	membershipRepo := &mockMembershipRepo{
		byID:     make(map[core.MembershipID]*domain.AccountMembership),
		roleByID: make(map[core.MembershipID]*domain.Role),
	}
	deps := newTestDeps(t, mk, repo, membershipRepo, adminRole)
	app := newTestApp(t, deps)

	// API key environment is "live" — X-Environment: test is ignored.
	status, body := doRequest(t, app, "Bearer "+rawKey, "test")
	assert.Equal(t, 200, status)
	assert.Equal(t, "live", body)
}

func TestRequireAuth_APIKey_ResolvesAdminRole(t *testing.T) {
	mk := newTestMasterKey(t)
	rawKey := "gl_live_" + strings.Repeat("b", 32)
	adminRole := &domain.Role{ID: core.NewRoleID(), Slug: "admin", Name: "Admin"}

	accountID := core.NewAccountID()
	repo := &mockAPIKeyRepo{
		byHash: map[string]*domain.APIKey{
			mk.HMAC(rawKey): {
				ID:          core.NewAPIKeyID(),
				AccountID:   accountID,
				Prefix:      "gl_live_bbbb",
				Environment: core.EnvironmentLive,
				Scope:       core.APIKeyScopeAccountWide,
			},
		},
	}
	membershipRepo := &mockMembershipRepo{
		byID:     make(map[core.MembershipID]*domain.AccountMembership),
		roleByID: make(map[core.MembershipID]*domain.Role),
	}
	deps := newTestDeps(t, mk, repo, membershipRepo, adminRole)

	var capturedAuth *AuthContext
	var capturedGoAuth *AuthContext
	app := fiber.New(fiber.Config{ErrorHandler: testErrorHandler})
	app.Get("/probe", RequireAuth(deps), func(c fiber.Ctx) error {
		capturedAuth = AuthFromContext(c)
		capturedGoAuth = AuthFromGoContext(c.Context())
		return c.SendString("ok")
	})

	status, _ := doRequest(t, app, "Bearer "+rawKey, "")
	assert.Equal(t, 200, status)
	require.NotNil(t, capturedAuth)
	require.NotNil(t, capturedAuth.Role)
	assert.Equal(t, "admin", capturedAuth.Role.Slug)
	assert.Equal(t, ActorKindAPIKey, capturedAuth.ActorKind)
	// Account-wide API key populates scope but leaves product id nil.
	assert.Equal(t, core.APIKeyScopeAccountWide, capturedAuth.APIKeyScope)
	assert.Nil(t, capturedAuth.APIKeyProductID)
	// AuthFromGoContext must return the SAME pointer as c.Locals-backed
	// AuthFromContext — service-layer helpers rely on this.
	assert.Same(t, capturedAuth, capturedGoAuth)
}

func TestRequireAuth_APIKey_ProductScopedPopulatesProductID(t *testing.T) {
	mk := newTestMasterKey(t)
	rawKey := "gl_live_" + strings.Repeat("d", 32)
	adminRole := &domain.Role{ID: core.NewRoleID(), Slug: "admin", Name: "Admin"}

	accountID := core.NewAccountID()
	productID := core.NewProductID()
	repo := &mockAPIKeyRepo{
		byHash: map[string]*domain.APIKey{
			mk.HMAC(rawKey): {
				ID:          core.NewAPIKeyID(),
				AccountID:   accountID,
				ProductID:   &productID,
				Prefix:      "gl_live_dddd",
				Environment: core.EnvironmentLive,
				Scope:       core.APIKeyScopeProduct,
			},
		},
	}
	membershipRepo := &mockMembershipRepo{
		byID:     make(map[core.MembershipID]*domain.AccountMembership),
		roleByID: make(map[core.MembershipID]*domain.Role),
	}
	deps := newTestDeps(t, mk, repo, membershipRepo, adminRole)

	var capturedAuth *AuthContext
	app := fiber.New(fiber.Config{ErrorHandler: testErrorHandler})
	app.Get("/probe", RequireAuth(deps), func(c fiber.Ctx) error {
		capturedAuth = AuthFromContext(c)
		return c.SendString("ok")
	})

	status, _ := doRequest(t, app, "Bearer "+rawKey, "")
	assert.Equal(t, 200, status)
	require.NotNil(t, capturedAuth)
	assert.Equal(t, core.APIKeyScopeProduct, capturedAuth.APIKeyScope)
	require.NotNil(t, capturedAuth.APIKeyProductID)
	assert.Equal(t, productID, *capturedAuth.APIKeyProductID)
}

func TestRequireAuth_MissingAuthorization(t *testing.T) {
	mk := newTestMasterKey(t)
	membershipRepo := &mockMembershipRepo{
		byID:     make(map[core.MembershipID]*domain.AccountMembership),
		roleByID: make(map[core.MembershipID]*domain.Role),
	}
	deps := newTestDeps(t, mk, &mockAPIKeyRepo{}, membershipRepo, nil)
	app := newTestApp(t, deps)

	status, _ := doRequest(t, app, "", "")
	assert.Equal(t, 401, status)
}

func TestRequireAuth_MalformedAuthorization(t *testing.T) {
	mk := newTestMasterKey(t)
	membershipRepo := &mockMembershipRepo{
		byID:     make(map[core.MembershipID]*domain.AccountMembership),
		roleByID: make(map[core.MembershipID]*domain.Role),
	}
	deps := newTestDeps(t, mk, &mockAPIKeyRepo{}, membershipRepo, nil)
	app := newTestApp(t, deps)

	// No "Bearer " prefix → 401.
	status, _ := doRequest(t, app, "Token somevalue", "")
	assert.Equal(t, 401, status)
}

func TestRequireAuth_JWT_RejectsMembershipNotFound(t *testing.T) {
	mk := newTestMasterKey(t)
	// Empty membership repo — any membership ID lookup returns nil.
	membershipRepo := &mockMembershipRepo{
		byID:     make(map[core.MembershipID]*domain.AccountMembership),
		roleByID: make(map[core.MembershipID]*domain.Role),
	}
	deps := newTestDeps(t, mk, &mockAPIKeyRepo{}, membershipRepo, nil)
	app := newTestApp(t, deps)

	// Sign a JWT for a random membership that doesn't exist in the repo.
	identityID := core.NewIdentityID()
	accountID := core.NewAccountID()
	membershipID := core.NewMembershipID()
	token, err := mk.SignJWT(crypto.JWTClaims{
		IdentityID:      identityID,
		ActingAccountID: accountID,
		MembershipID:    membershipID,
		RoleSlug:        "owner",
	}, time.Hour)
	require.NoError(t, err)

	status, body := doRequest(t, app, "Bearer "+token, "")
	assert.Equal(t, 401, status)
	assert.Equal(t, string(core.ErrAuthenticationRequired), parseErrorCode(t, body))
}

func TestRequireAuth_JWT_RejectsMissingRole(t *testing.T) {
	mk := newTestMasterKey(t)
	membershipRepo := &mockMembershipRepo{
		byID:     make(map[core.MembershipID]*domain.AccountMembership),
		roleByID: make(map[core.MembershipID]*domain.Role),
	}
	deps := newTestDeps(t, mk, &mockAPIKeyRepo{}, membershipRepo, nil)
	app := newTestApp(t, deps)

	// Seed a membership whose role is not seeded in roleByID — role comes
	// back nil from GetByIDWithRole, which the middleware treats as 401.
	identityID := core.NewIdentityID()
	accountID := core.NewAccountID()
	membershipID := core.NewMembershipID()
	missingRoleID := core.NewRoleID() // not seeded into roleByID
	membershipRepo.byID[membershipID] = &domain.AccountMembership{
		ID:         membershipID,
		AccountID:  accountID,
		IdentityID: identityID,
		RoleID:     missingRoleID,
		Status:     domain.MembershipStatusActive,
		JoinedAt:   time.Now(),
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
	// roleByID intentionally not populated for membershipID
	token, err := mk.SignJWT(crypto.JWTClaims{
		IdentityID:      identityID,
		ActingAccountID: accountID,
		MembershipID:    membershipID,
		RoleSlug:        "owner",
	}, time.Hour)
	require.NoError(t, err)

	status, body := doRequest(t, app, "Bearer "+token, "")
	assert.Equal(t, 401, status)
	assert.Equal(t, string(core.ErrAuthenticationRequired), parseErrorCode(t, body))
}

func TestRequireAuth_APIKey_RejectsExpiredKey(t *testing.T) {
	mk := newTestMasterKey(t)
	rawKey := "gl_test_" + strings.Repeat("e", 32)
	adminRole := &domain.Role{ID: core.NewRoleID(), Slug: "admin", Name: "Admin"}

	pastExpiry := time.Now().UTC().Add(-time.Hour)
	repo := &mockAPIKeyRepo{
		byHash: map[string]*domain.APIKey{
			mk.HMAC(rawKey): {
				ID:          core.NewAPIKeyID(),
				AccountID:   core.NewAccountID(),
				Prefix:      "gl_test_eeee",
				Environment: core.EnvironmentTest,
				Scope:       core.APIKeyScopeAccountWide,
				ExpiresAt:   &pastExpiry,
				CreatedAt:   time.Now().UTC().Add(-2 * time.Hour),
			},
		},
	}
	membershipRepo := &mockMembershipRepo{
		byID:     make(map[core.MembershipID]*domain.AccountMembership),
		roleByID: make(map[core.MembershipID]*domain.Role),
	}
	deps := newTestDeps(t, mk, repo, membershipRepo, adminRole)
	app := newTestApp(t, deps)

	status, body := doRequest(t, app, "Bearer "+rawKey, "")
	assert.Equal(t, 401, status)
	assert.Equal(t, string(core.ErrInvalidAPIKey), parseErrorCode(t, body))
	// Distinct "expired" wording differentiates from the generic
	// "Invalid API key" surface used when the hash never matched.
	assert.Contains(t, body, "expired")
}

func TestRequireAuth_APIKey_AllowsKeyWithoutExpiry(t *testing.T) {
	mk := newTestMasterKey(t)
	rawKey := "gl_live_" + strings.Repeat("f", 32)
	adminRole := &domain.Role{ID: core.NewRoleID(), Slug: "admin", Name: "Admin"}

	repo := &mockAPIKeyRepo{
		byHash: map[string]*domain.APIKey{
			mk.HMAC(rawKey): {
				ID:          core.NewAPIKeyID(),
				AccountID:   core.NewAccountID(),
				Prefix:      "gl_live_ffff",
				Environment: core.EnvironmentLive,
				Scope:       core.APIKeyScopeAccountWide,
				ExpiresAt:   nil,
			},
		},
	}
	membershipRepo := &mockMembershipRepo{
		byID:     make(map[core.MembershipID]*domain.AccountMembership),
		roleByID: make(map[core.MembershipID]*domain.Role),
	}
	deps := newTestDeps(t, mk, repo, membershipRepo, adminRole)
	app := newTestApp(t, deps)

	status, body := doRequest(t, app, "Bearer "+rawKey, "")
	assert.Equal(t, 200, status)
	assert.Equal(t, "live", body)
}

func TestRequireAuth_APIKey_AllowsKeyWithFutureExpiry(t *testing.T) {
	mk := newTestMasterKey(t)
	rawKey := "gl_live_" + strings.Repeat("g", 32)
	adminRole := &domain.Role{ID: core.NewRoleID(), Slug: "admin", Name: "Admin"}

	futureExpiry := time.Now().UTC().Add(time.Hour)
	repo := &mockAPIKeyRepo{
		byHash: map[string]*domain.APIKey{
			mk.HMAC(rawKey): {
				ID:          core.NewAPIKeyID(),
				AccountID:   core.NewAccountID(),
				Prefix:      "gl_live_gggg",
				Environment: core.EnvironmentLive,
				Scope:       core.APIKeyScopeAccountWide,
				ExpiresAt:   &futureExpiry,
			},
		},
	}
	membershipRepo := &mockMembershipRepo{
		byID:     make(map[core.MembershipID]*domain.AccountMembership),
		roleByID: make(map[core.MembershipID]*domain.Role),
	}
	deps := newTestDeps(t, mk, repo, membershipRepo, adminRole)
	app := newTestApp(t, deps)

	status, body := doRequest(t, app, "Bearer "+rawKey, "")
	assert.Equal(t, 200, status)
	assert.Equal(t, "live", body)
}

func TestRequireAuth_APIKey_RejectsMissingAdminPreset(t *testing.T) {
	mk := newTestMasterKey(t)
	rawKey := "gl_live_" + strings.Repeat("c", 32)

	// API key exists but AdminRole is nil — simulates missing preset.
	repo := &mockAPIKeyRepo{
		byHash: map[string]*domain.APIKey{
			mk.HMAC(rawKey): {
				ID:          core.NewAPIKeyID(),
				AccountID:   core.NewAccountID(),
				Prefix:      "gl_live_cccc",
				Environment: core.EnvironmentLive,
				Scope:       core.APIKeyScopeAccountWide,
			},
		},
	}
	membershipRepo := &mockMembershipRepo{
		byID:     make(map[core.MembershipID]*domain.AccountMembership),
		roleByID: make(map[core.MembershipID]*domain.Role),
	}
	deps := newTestDeps(t, mk, repo, membershipRepo, nil) // nil AdminRole
	app := newTestApp(t, deps)

	status, body := doRequest(t, app, "Bearer "+rawKey, "")
	assert.Equal(t, 500, status)
	assert.Equal(t, string(core.ErrInternalError), parseErrorCode(t, body))
}

// --- mock JWTRevocationRepository ---

type mockJWTRevocationRepo struct {
	revoked    map[core.JTI]time.Time
	sessionMin map[core.IdentityID]time.Time
	failsOn    string // optional: "is_revoked" or "session_min" to simulate DB error
}

func newMockJWTRevocationRepo() *mockJWTRevocationRepo {
	return &mockJWTRevocationRepo{
		revoked:    make(map[core.JTI]time.Time),
		sessionMin: make(map[core.IdentityID]time.Time),
	}
}

func (r *mockJWTRevocationRepo) RevokeJTI(_ context.Context, jti core.JTI, _ core.IdentityID, expiresAt time.Time, _ string) error {
	r.revoked[jti] = expiresAt
	return nil
}
func (r *mockJWTRevocationRepo) IsJTIRevoked(_ context.Context, jti core.JTI) (bool, error) {
	if r.failsOn == "is_revoked" {
		return false, errors.New("mock IsJTIRevoked error")
	}
	exp, ok := r.revoked[jti]
	if !ok {
		return false, nil
	}
	return exp.After(time.Now().UTC()), nil
}
func (r *mockJWTRevocationRepo) SweepExpired(_ context.Context) (int, error) { return 0, nil }
func (r *mockJWTRevocationRepo) SetSessionInvalidation(_ context.Context, identityID core.IdentityID, minIAT time.Time) error {
	r.sessionMin[identityID] = minIAT
	return nil
}
func (r *mockJWTRevocationRepo) GetSessionMinIAT(_ context.Context, identityID core.IdentityID) (*time.Time, error) {
	if r.failsOn == "session_min" {
		return nil, errors.New("mock GetSessionMinIAT error")
	}
	t, ok := r.sessionMin[identityID]
	if !ok {
		return nil, nil
	}
	return &t, nil
}

// issueJWTAndCaptureClaims signs a token and returns both the raw token
// string and the verified JWTClaims so tests can stage revocations
// keyed by jti or filter by issued-at without re-decoding the JWT.
func issueJWTAndCaptureClaims(t *testing.T, mk *crypto.MasterKey, membershipRepo *mockMembershipRepo) (string, *crypto.JWTClaims) {
	t.Helper()
	token := issueJWT(t, mk, membershipRepo)
	claims, err := mk.VerifyJWT(token)
	require.NoError(t, err)
	return token, claims
}

func TestRequireAuth_RejectsRevokedJTI(t *testing.T) {
	mk := newTestMasterKey(t)
	membershipRepo := &mockMembershipRepo{
		byID:     make(map[core.MembershipID]*domain.AccountMembership),
		roleByID: make(map[core.MembershipID]*domain.Role),
	}
	revocations := newMockJWTRevocationRepo()
	deps := newTestDeps(t, mk, &mockAPIKeyRepo{}, membershipRepo, nil)
	deps.JWTRevocations = revocations
	app := newTestApp(t, deps)
	token, claims := issueJWTAndCaptureClaims(t, mk, membershipRepo)

	// Revoke the jti for the next hour — simulating a logout.
	revocations.revoked[claims.JTI] = time.Now().UTC().Add(time.Hour)

	status, body := doRequest(t, app, "Bearer "+token, "")
	assert.Equal(t, 401, status)
	assert.Equal(t, string(core.ErrAuthenticationRequired), parseErrorCode(t, body))
}

func TestRequireAuth_RejectsTokenIssuedBeforeMinIAT(t *testing.T) {
	mk := newTestMasterKey(t)
	membershipRepo := &mockMembershipRepo{
		byID:     make(map[core.MembershipID]*domain.AccountMembership),
		roleByID: make(map[core.MembershipID]*domain.Role),
	}
	revocations := newMockJWTRevocationRepo()
	deps := newTestDeps(t, mk, &mockAPIKeyRepo{}, membershipRepo, nil)
	deps.JWTRevocations = revocations
	app := newTestApp(t, deps)
	token, claims := issueJWTAndCaptureClaims(t, mk, membershipRepo)

	// Set the session-invalidation cutoff to 1 minute AFTER iat — every
	// JWT minted before this instant must be rejected.
	revocations.sessionMin[claims.IdentityID] = claims.IssuedAt.Add(time.Minute)

	status, body := doRequest(t, app, "Bearer "+token, "")
	assert.Equal(t, 401, status)
	assert.Equal(t, string(core.ErrAuthenticationRequired), parseErrorCode(t, body))
}

func TestRequireAuth_AcceptsTokenIssuedAfterMinIAT(t *testing.T) {
	mk := newTestMasterKey(t)
	membershipRepo := &mockMembershipRepo{
		byID:     make(map[core.MembershipID]*domain.AccountMembership),
		roleByID: make(map[core.MembershipID]*domain.Role),
	}
	revocations := newMockJWTRevocationRepo()
	deps := newTestDeps(t, mk, &mockAPIKeyRepo{}, membershipRepo, nil)
	deps.JWTRevocations = revocations
	app := newTestApp(t, deps)
	token, claims := issueJWTAndCaptureClaims(t, mk, membershipRepo)

	// Set the session-invalidation cutoff to BEFORE iat — every JWT
	// issued AFTER this instant (including ours) must still verify.
	revocations.sessionMin[claims.IdentityID] = claims.IssuedAt.Add(-time.Minute)

	status, _ := doRequest(t, app, "Bearer "+token, "")
	assert.Equal(t, 200, status)
}
