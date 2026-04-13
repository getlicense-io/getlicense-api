package middleware

import (
	"context"
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
func (r *mockAPIKeyRepo) ListByAccount(_ context.Context, _, _ int) ([]domain.APIKey, int, error) {
	return nil, 0, errors.New("not implemented")
}
func (r *mockAPIKeyRepo) Delete(_ context.Context, _ core.APIKeyID) error {
	return errors.New("not implemented")
}

// --- helpers ---

// echoEnvHandler writes the env from auth context to the response body so the
// caller can assert what the middleware put there.
func echoEnvHandler(c fiber.Ctx) error {
	auth := FromContext(c)
	if auth == nil {
		return c.Status(500).SendString("no auth in context")
	}
	return c.SendString(string(auth.Environment))
}

func newTestMasterKey(t *testing.T) *crypto.MasterKey {
	t.Helper()
	mk, err := crypto.NewMasterKey(strings.Repeat("a", 64))
	require.NoError(t, err)
	return mk
}

// testErrorHandler mirrors server.errorHandler enough for tests in this
// package — without importing the parent server package, which would be
// a circular dependency.
func testErrorHandler(c fiber.Ctx, err error) error {
	var appErr *core.AppError
	if errors.As(err, &appErr) {
		return c.Status(appErr.HTTPStatus()).JSON(appErr)
	}
	return c.Status(500).SendString(err.Error())
}

func newTestApp(t *testing.T, repo domain.APIKeyRepository, mk *crypto.MasterKey) *fiber.App {
	t.Helper()
	app := fiber.New(fiber.Config{ErrorHandler: testErrorHandler})
	app.Get("/probe", RequireAuth(repo, mk), echoEnvHandler)
	return app
}

func issueJWT(t *testing.T, mk *crypto.MasterKey) string {
	t.Helper()
	token, err := mk.SignJWT(crypto.JWTClaims{
		UserID:    core.NewUserID(),
		AccountID: core.NewAccountID(),
		Role:      core.UserRoleAdmin,
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

// --- tests ---

func TestRequireAuth_JWT_DefaultsToLive(t *testing.T) {
	mk := newTestMasterKey(t)
	app := newTestApp(t, &mockAPIKeyRepo{}, mk)
	token := issueJWT(t, mk)

	status, body := doRequest(t, app, "Bearer "+token, "")
	assert.Equal(t, 200, status)
	assert.Equal(t, "live", body)
}

func TestRequireAuth_JWT_HonorsXEnvironmentTest(t *testing.T) {
	mk := newTestMasterKey(t)
	app := newTestApp(t, &mockAPIKeyRepo{}, mk)
	token := issueJWT(t, mk)

	status, body := doRequest(t, app, "Bearer "+token, "test")
	assert.Equal(t, 200, status)
	assert.Equal(t, "test", body)
}

func TestRequireAuth_JWT_HonorsXEnvironmentLive(t *testing.T) {
	mk := newTestMasterKey(t)
	app := newTestApp(t, &mockAPIKeyRepo{}, mk)
	token := issueJWT(t, mk)

	status, body := doRequest(t, app, "Bearer "+token, "live")
	assert.Equal(t, 200, status)
	assert.Equal(t, "live", body)
}

func TestRequireAuth_JWT_AcceptsCustomXEnvironment(t *testing.T) {
	// Since environments are now user-defined (up to MaxEnvironments
	// per account), any slug passing the format regex is accepted at
	// the middleware layer. Whether the slug actually resolves to
	// tenant data is enforced by RLS downstream, not here.
	mk := newTestMasterKey(t)
	app := newTestApp(t, &mockAPIKeyRepo{}, mk)
	token := issueJWT(t, mk)

	status, body := doRequest(t, app, "Bearer "+token, "staging")
	assert.Equal(t, 200, status)
	assert.Equal(t, "staging", body)
}

func TestRequireAuth_JWT_RejectsMalformedXEnvironment(t *testing.T) {
	mk := newTestMasterKey(t)
	app := newTestApp(t, &mockAPIKeyRepo{}, mk)
	token := issueJWT(t, mk)

	// Uppercase letters and special chars fail the slug regex.
	status, _ := doRequest(t, app, "Bearer "+token, "Staging!")
	// validation_error → 422 per core.errors.go status mapping
	assert.Equal(t, 422, status)
}

func TestRequireAuth_APIKey_IgnoresXEnvironment(t *testing.T) {
	mk := newTestMasterKey(t)
	rawKey := "gl_live_" + strings.Repeat("a", 32)
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
	app := newTestApp(t, repo, mk)

	// API key is "live" — even with X-Environment: test it stays live.
	status, body := doRequest(t, app, "Bearer "+rawKey, "test")
	assert.Equal(t, 200, status)
	assert.Equal(t, "live", body)
}

func TestRequireAuth_MissingAuthorization(t *testing.T) {
	mk := newTestMasterKey(t)
	app := newTestApp(t, &mockAPIKeyRepo{}, mk)

	status, _ := doRequest(t, app, "", "")
	assert.Equal(t, 401, status)
}
