package crypto

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/getlicense-io/getlicense-api/internal/core"
)

// GenerateAPIKey generates a new API key for the given environment ("live" or "test").
// It returns the full raw key and the first 20 characters as the prefix.
func GenerateAPIKey(environment string) (raw, prefix string, err error) {
	var keyPrefix string
	switch environment {
	case "live":
		keyPrefix = core.APIKeyPrefixLive
	case "test":
		keyPrefix = core.APIKeyPrefixTest
	default:
		return "", "", fmt.Errorf("crypto: invalid environment %q: must be \"live\" or \"test\"", environment)
	}

	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("crypto: failed to generate API key bytes: %w", err)
	}

	raw = keyPrefix + hex.EncodeToString(b)
	prefix = raw[:20]
	return raw, prefix, nil
}

// GenerateRefreshToken generates a new refresh token with the rt_ prefix
// followed by 64 hex characters (32 random bytes).
func GenerateRefreshToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("crypto: failed to generate refresh token bytes: %w", err)
	}
	return core.RefreshTokenPrefix + hex.EncodeToString(b), nil
}
