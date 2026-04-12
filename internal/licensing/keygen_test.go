package licensing

import (
	"regexp"
	"strings"
	"testing"

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

