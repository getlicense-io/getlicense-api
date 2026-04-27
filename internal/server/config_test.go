package server_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlicense-io/getlicense-api/internal/server"
)

// setMinimalEnv populates the always-required env vars for LoadConfig
// and defaults the runtime to development. Tests that need production
// behavior must call setProductionEnv (or override individually).
func setMinimalEnv(t *testing.T) {
	t.Helper()
	t.Setenv("DATABASE_URL", "postgres://test:test@localhost:5432/test?sslmode=disable")
	t.Setenv("GETLICENSE_MASTER_KEY", strings.Repeat("a", 64))
	t.Setenv("GETLICENSE_ENV", "development")
	// Clear vars that some tests want to assert as unset.
	t.Setenv("GETLICENSE_MAILER", "")
	t.Setenv("GETLICENSE_ALLOWED_ORIGINS", "")
	t.Setenv("GETLICENSE_PUBLIC_BASE_URL", "")
	t.Setenv("GETLICENSE_DASHBOARD_URL", "")
}

// setProductionEnv layers the always-required production env vars on
// top of setMinimalEnv. Tests then mutate individual vars to exercise
// the validation paths.
func setProductionEnv(t *testing.T) {
	t.Helper()
	setMinimalEnv(t)
	t.Setenv("GETLICENSE_ENV", "production")
	t.Setenv("GETLICENSE_ALLOWED_ORIGINS", "https://app.example.com")
	t.Setenv("GETLICENSE_PUBLIC_BASE_URL", "https://api.example.com")
	t.Setenv("GETLICENSE_DASHBOARD_URL", "https://dashboard.example.com")
	t.Setenv("GETLICENSE_REDIS_URL", "redis://localhost:6379/0")
}

func TestLoadConfig_DefaultsLogMailerInDev(t *testing.T) {
	setMinimalEnv(t)
	cfg, err := server.LoadConfig()
	require.NoError(t, err)
	assert.Equal(t, "log", cfg.MailerKind)
}

func TestLoadConfig_DefaultsNoopMailerInProduction(t *testing.T) {
	setProductionEnv(t)
	cfg, err := server.LoadConfig()
	require.NoError(t, err)
	assert.Equal(t, "noop", cfg.MailerKind)
}

func TestLoadConfig_RejectsLogMailerInProduction(t *testing.T) {
	setProductionEnv(t)
	t.Setenv("GETLICENSE_MAILER", "log")
	_, err := server.LoadConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GETLICENSE_MAILER=log is forbidden in production")
}

func TestLoadConfig_ProductionRequiresRedisURL(t *testing.T) {
	setProductionEnv(t)
	t.Setenv("GETLICENSE_REDIS_URL", "")
	_, err := server.LoadConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GETLICENSE_REDIS_URL is required in production")
}

func TestLoadConfig_DevAllowsMissingRedisURL(t *testing.T) {
	setMinimalEnv(t)
	cfg, err := server.LoadConfig()
	require.NoError(t, err)
	assert.Empty(t, cfg.RedisURL)
}

func TestLoadConfig_RejectsNonRedisURL(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("GETLICENSE_REDIS_URL", "https://redis.example.com")
	_, err := server.LoadConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GETLICENSE_REDIS_URL must use redis:// or rediss://")
}

// --- Production URL hardening (PR-1.5) ---

func TestLoadConfig_ProductionRequiresDashboardURL(t *testing.T) {
	setProductionEnv(t)
	t.Setenv("GETLICENSE_DASHBOARD_URL", "")
	_, err := server.LoadConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GETLICENSE_DASHBOARD_URL is required in production")
}

func TestLoadConfig_ProductionRequiresPublicBaseURL(t *testing.T) {
	setProductionEnv(t)
	t.Setenv("GETLICENSE_PUBLIC_BASE_URL", "")
	_, err := server.LoadConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GETLICENSE_PUBLIC_BASE_URL is required in production")
}

func TestLoadConfig_ProductionRejectsNonHTTPSDashboardURL(t *testing.T) {
	setProductionEnv(t)
	t.Setenv("GETLICENSE_DASHBOARD_URL", "http://dashboard.example.com")
	_, err := server.LoadConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GETLICENSE_DASHBOARD_URL must use https://")
}

func TestLoadConfig_ProductionRejectsNonHTTPSPublicBaseURL(t *testing.T) {
	setProductionEnv(t)
	t.Setenv("GETLICENSE_PUBLIC_BASE_URL", "http://api.example.com")
	_, err := server.LoadConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GETLICENSE_PUBLIC_BASE_URL must use https://")
}

func TestLoadConfig_ProductionRejectsLocalhostDashboardURL(t *testing.T) {
	setProductionEnv(t)
	t.Setenv("GETLICENSE_DASHBOARD_URL", "https://localhost:3001")
	_, err := server.LoadConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must not point at localhost in production")
}

func TestLoadConfig_ProductionRejectsLoopbackPublicBaseURL(t *testing.T) {
	setProductionEnv(t)
	t.Setenv("GETLICENSE_PUBLIC_BASE_URL", "https://127.0.0.1:3000")
	_, err := server.LoadConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must not point at localhost in production")
}

func TestLoadConfig_DevAllowsLocalhostURLs(t *testing.T) {
	setMinimalEnv(t) // dev mode, no URL env vars set
	cfg, err := server.LoadConfig()
	require.NoError(t, err)
	assert.Equal(t, "http://localhost:3000", cfg.PublicBaseURL)
	assert.Equal(t, "http://localhost:3001", cfg.DashboardURL)
}

func TestLoadConfig_ProductionAcceptsValidHTTPSURLs(t *testing.T) {
	setProductionEnv(t)
	cfg, err := server.LoadConfig()
	require.NoError(t, err)
	assert.Equal(t, "https://api.example.com", cfg.PublicBaseURL)
	assert.Equal(t, "https://dashboard.example.com", cfg.DashboardURL)
}

func TestLoadConfig_RejectsUnknownMailer(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("GETLICENSE_MAILER", "garbage")
	_, err := server.LoadConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must be 'log' or 'noop'")
}

func TestLoadConfig_AcceptsExplicitNoopInDev(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("GETLICENSE_MAILER", "noop")
	cfg, err := server.LoadConfig()
	require.NoError(t, err)
	assert.Equal(t, "noop", cfg.MailerKind)
}
