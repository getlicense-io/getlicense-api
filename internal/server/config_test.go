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
// behavior must override GETLICENSE_ENV (and set
// GETLICENSE_ALLOWED_ORIGINS, which is required in prod).
func setMinimalEnv(t *testing.T) {
	t.Helper()
	t.Setenv("DATABASE_URL", "postgres://test:test@localhost:5432/test?sslmode=disable")
	t.Setenv("GETLICENSE_MASTER_KEY", strings.Repeat("a", 64))
	t.Setenv("GETLICENSE_ENV", "development")
	// Clear vars that some tests want to assert as unset.
	t.Setenv("GETLICENSE_MAILER", "")
	t.Setenv("GETLICENSE_ALLOWED_ORIGINS", "")
}

func TestLoadConfig_DefaultsLogMailerInDev(t *testing.T) {
	setMinimalEnv(t)
	cfg, err := server.LoadConfig()
	require.NoError(t, err)
	assert.Equal(t, "log", cfg.MailerKind)
}

func TestLoadConfig_DefaultsNoopMailerInProduction(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("GETLICENSE_ENV", "production")
	t.Setenv("GETLICENSE_ALLOWED_ORIGINS", "https://app.example.com")
	cfg, err := server.LoadConfig()
	require.NoError(t, err)
	assert.Equal(t, "noop", cfg.MailerKind)
}

func TestLoadConfig_RejectsLogMailerInProduction(t *testing.T) {
	setMinimalEnv(t)
	t.Setenv("GETLICENSE_ENV", "production")
	t.Setenv("GETLICENSE_ALLOWED_ORIGINS", "https://app.example.com")
	t.Setenv("GETLICENSE_MAILER", "log")
	_, err := server.LoadConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GETLICENSE_MAILER=log is forbidden in production")
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
