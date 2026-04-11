package licensing

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlicense-io/getlicense-api/internal/core"
)

func TestGenerateLicenseKey_Format(t *testing.T) {
	fullKey, prefix, err := GenerateLicenseKey()
	require.NoError(t, err)

	// Must match GETL-XXXX-XXXX-XXXX.
	re := regexp.MustCompile(`^GETL-[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}$`)
	assert.Regexp(t, re, fullKey)

	// Prefix is the first 9 characters.
	assert.Equal(t, fullKey[:9], prefix)
	assert.True(t, strings.HasPrefix(prefix, "GETL-"))
}

func TestGenerateLicenseKey_AllCharsInAlphabet(t *testing.T) {
	for range 50 {
		fullKey, _, err := GenerateLicenseKey()
		require.NoError(t, err)

		// Strip dashes and the GETL- prefix.
		chars := strings.ReplaceAll(fullKey[5:], "-", "")
		for _, c := range chars {
			assert.Contains(t, KeyAlphabet, string(c),
				"character %q must be in KeyAlphabet", c)
		}
	}
}

func TestGenerateLicenseKey_Uniqueness(t *testing.T) {
	seen := make(map[string]struct{}, 100)
	for range 100 {
		fullKey, _, err := GenerateLicenseKey()
		require.NoError(t, err)

		_, dup := seen[fullKey]
		assert.False(t, dup, "duplicate key generated: %s", fullKey)
		seen[fullKey] = struct{}{}
	}
}

func TestGenerateLicenseKey_PrefixIsFirst9Chars(t *testing.T) {
	for range 20 {
		fullKey, prefix, err := GenerateLicenseKey()
		require.NoError(t, err)
		assert.Len(t, prefix, 9)
		assert.Equal(t, fullKey[:9], prefix)
	}
}

func TestValidateFingerprint_Empty(t *testing.T) {
	err := ValidateFingerprint("")
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrValidationError, appErr.Code)
	assert.Contains(t, appErr.Message, "fingerprint is required")
}

func TestValidateFingerprint_TooLong(t *testing.T) {
	fp := strings.Repeat("x", MaxFingerprintLength+1)
	err := ValidateFingerprint(fp)
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrValidationError, appErr.Code)
	assert.Contains(t, appErr.Message, "at most 256 characters")
}

func TestValidateFingerprint_Valid(t *testing.T) {
	assert.NoError(t, ValidateFingerprint("abc-123"))
	assert.NoError(t, ValidateFingerprint(strings.Repeat("x", MaxFingerprintLength)))
}

func TestValidateLicenseStatus_Revoked(t *testing.T) {
	err := ValidateLicenseStatus(core.LicenseStatusRevoked, nil)
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrLicenseRevoked, appErr.Code)
}

func TestValidateLicenseStatus_Suspended(t *testing.T) {
	err := ValidateLicenseStatus(core.LicenseStatusSuspended, nil)
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrLicenseSuspended, appErr.Code)
}

func TestValidateLicenseStatus_Inactive(t *testing.T) {
	err := ValidateLicenseStatus(core.LicenseStatusInactive, nil)
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrLicenseInactive, appErr.Code)
}

func TestValidateLicenseStatus_Expired(t *testing.T) {
	err := ValidateLicenseStatus(core.LicenseStatusExpired, nil)
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrLicenseExpired, appErr.Code)
}

func TestValidateLicenseStatus_ActiveButPastExpiry(t *testing.T) {
	past := time.Now().Add(-1 * time.Hour)
	err := ValidateLicenseStatus(core.LicenseStatusActive, &past)
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrLicenseExpired, appErr.Code)
}

func TestValidateLicenseStatus_ActiveNotExpired(t *testing.T) {
	future := time.Now().Add(24 * time.Hour)
	assert.NoError(t, ValidateLicenseStatus(core.LicenseStatusActive, &future))
}

func TestValidateLicenseStatus_ActiveNoExpiry(t *testing.T) {
	assert.NoError(t, ValidateLicenseStatus(core.LicenseStatusActive, nil))
}
