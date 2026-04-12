package crypto

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/getlicense-io/getlicense-api/internal/core"
)

const apiKeyPrefixLen = 20

func generateRandomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("crypto: generating random bytes: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// GenerateAPIKey generates a new API key for the given environment.
// It returns the full raw key and the first 20 characters as the prefix.
func GenerateAPIKey(env core.Environment) (raw, prefix string, err error) {
	var keyPrefix string
	switch env {
	case core.EnvironmentLive:
		keyPrefix = core.APIKeyPrefixLive
	case core.EnvironmentTest:
		keyPrefix = core.APIKeyPrefixTest
	default:
		return "", "", fmt.Errorf("crypto: invalid environment %q: must be \"live\" or \"test\"", env)
	}

	hexStr, err := generateRandomHex(32)
	if err != nil {
		return "", "", err
	}

	raw = keyPrefix + hexStr
	prefix = raw[:apiKeyPrefixLen]
	return raw, prefix, nil
}

// GenerateRefreshToken generates a new refresh token with the rt_ prefix
// followed by 64 hex characters (32 random bytes).
func GenerateRefreshToken() (string, error) {
	hexStr, err := generateRandomHex(32)
	if err != nil {
		return "", err
	}
	return core.RefreshTokenPrefix + hexStr, nil
}
