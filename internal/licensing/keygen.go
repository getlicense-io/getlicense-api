package licensing

import (
	"crypto/rand"
	"fmt"

	"github.com/getlicense-io/getlicense-api/internal/core"
)

// KeyAlphabet is a 32-character alphabet for license keys.
// Excludes ambiguous characters: 0, O, 1, I, L.
const KeyAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// MaxFingerprintLength is the maximum allowed length for a machine fingerprint.
const MaxFingerprintLength = 256

// GenerateLicenseKey generates a license key in the format GETL-XXXX-XXXX-XXXX.
// Uses 5-bit masking (& 0x1F) for unbiased indexing into the 32-character alphabet.
// Returns the full key and the 9-character prefix.
func GenerateLicenseKey() (fullKey, prefix string, err error) {
	const numChars = 12

	randomBytes := make([]byte, numChars)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", "", fmt.Errorf("licensing: failed to read random bytes: %w", err)
	}

	chars := make([]byte, numChars)
	for i, b := range randomBytes {
		chars[i] = KeyAlphabet[b&0x1F]
	}

	fullKey = fmt.Sprintf("GETL-%s-%s-%s",
		string(chars[0:4]),
		string(chars[4:8]),
		string(chars[8:12]),
	)
	prefix = fullKey[:9] // "GETL-XXXX"
	return fullKey, prefix, nil
}

// ValidateFingerprint checks that a machine fingerprint is non-empty and within
// the maximum length.
func ValidateFingerprint(fp string) error {
	if fp == "" {
		return core.NewAppError(core.ErrValidationError, "fingerprint is required")
	}
	if len(fp) > MaxFingerprintLength {
		return core.NewAppError(core.ErrValidationError, "fingerprint must be at most 256 characters")
	}
	return nil
}

