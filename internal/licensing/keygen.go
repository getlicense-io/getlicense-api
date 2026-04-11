package licensing

import (
	"crypto/rand"
	"fmt"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
)

// KeyAlphabet is a 32-character alphabet for license keys.
// Excludes ambiguous characters: 0, O, 1, I, L.
const KeyAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// MaxFingerprintLength is the maximum allowed length for a machine fingerprint.
const MaxFingerprintLength = 256

// GenerateLicenseKey generates a license key in the format GETL-XXXX-XXXX-XXXX.
// It uses rejection sampling with a 5-bit mask for unbiased indexing into the
// 32-character alphabet. Returns the full key and the 9-character prefix.
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

// ValidateLicenseStatus checks that the license status allows normal operation.
// It returns a typed AppError for revoked, suspended, inactive, and expired
// licenses. An active license with a past expiry is also treated as expired.
func ValidateLicenseStatus(status core.LicenseStatus, expiresAt *time.Time) error {
	switch status {
	case core.LicenseStatusRevoked:
		return core.NewAppError(core.ErrLicenseRevoked, "License has been revoked")
	case core.LicenseStatusSuspended:
		return core.NewAppError(core.ErrLicenseSuspended, "License is suspended")
	case core.LicenseStatusInactive:
		return core.NewAppError(core.ErrLicenseInactive, "License is inactive")
	case core.LicenseStatusExpired:
		return core.NewAppError(core.ErrLicenseExpired, "License has expired")
	case core.LicenseStatusActive:
		if expiresAt != nil && expiresAt.Before(time.Now()) {
			return core.NewAppError(core.ErrLicenseExpired, "License has expired")
		}
		return nil
	default:
		return nil
	}
}
