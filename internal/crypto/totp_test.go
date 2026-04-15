package crypto

import (
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateTOTPSecret_ProducesOtpauthURL(t *testing.T) {
	secret, url, err := GenerateTOTPSecret("GetLicense", "test@example.com")
	require.NoError(t, err)
	assert.NotEmpty(t, secret)
	assert.Contains(t, url, "otpauth://totp/")
	assert.Contains(t, url, "GetLicense")
	assert.Contains(t, url, "test@example.com")
}

func TestVerifyTOTP_AcceptsCurrentCode(t *testing.T) {
	secret, _, err := GenerateTOTPSecret("GetLicense", "test@example.com")
	require.NoError(t, err)
	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)
	assert.True(t, VerifyTOTP(secret, code))
}

func TestVerifyTOTP_RejectsWrongCode(t *testing.T) {
	secret, _, err := GenerateTOTPSecret("GetLicense", "test@example.com")
	require.NoError(t, err)
	assert.False(t, VerifyTOTP(secret, "000000"))
}

func TestGenerateRecoveryCodes_ReturnsN(t *testing.T) {
	codes, err := GenerateRecoveryCodes(10)
	require.NoError(t, err)
	assert.Len(t, codes, 10)
	for _, c := range codes {
		assert.Len(t, c, 10)
	}
}
