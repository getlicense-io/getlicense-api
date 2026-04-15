package crypto

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/pquerna/otp/totp"
)

// GenerateTOTPSecret creates a new TOTP secret + otpauth provisioning
// URL for the given issuer and account name. The secret is the raw
// base32 string used for both QR code generation and verification.
func GenerateTOTPSecret(issuer, accountName string) (secret, otpauthURL string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: accountName,
	})
	if err != nil {
		return "", "", fmt.Errorf("crypto: failed to generate TOTP secret: %w", err)
	}
	return key.Secret(), key.URL(), nil
}

// VerifyTOTP checks whether the supplied code matches the secret at
// the current timestamp, using the library's default ±1 skew window.
func VerifyTOTP(secret, code string) bool {
	return totp.Validate(code, secret)
}

// GenerateRecoveryCodes returns n 10-character hex recovery codes. The
// caller is responsible for displaying them exactly once and hashing
// them before persistence.
func GenerateRecoveryCodes(n int) ([]string, error) {
	codes := make([]string, n)
	for i := 0; i < n; i++ {
		raw := make([]byte, 5)
		if _, err := rand.Read(raw); err != nil {
			return nil, fmt.Errorf("crypto: recovery code entropy: %w", err)
		}
		codes[i] = hex.EncodeToString(raw)
	}
	return codes, nil
}

// TOTPCodeForTest returns a valid TOTP code for the given secret at
// the current timestamp. Test-only helper — do NOT call from app code.
// Exported so test files outside package crypto can deterministically
// generate valid codes.
func TOTPCodeForTest(secret string) (string, error) {
	return totp.GenerateCode(secret, time.Now())
}
