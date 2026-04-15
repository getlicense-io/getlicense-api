package identity

import (
	"context"
	"strings"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/crypto"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

// Service manages identity-level operations that fall outside the
// auth.Service scope: TOTP enrollment, activation, verification, and
// recovery. Password management also lives here when it needs more
// than a simple hash update.
type Service struct {
	identities domain.IdentityRepository
	masterKey  *crypto.MasterKey
}

func NewService(identities domain.IdentityRepository, masterKey *crypto.MasterKey) *Service {
	return &Service{identities: identities, masterKey: masterKey}
}

// EnrollTOTP generates a new TOTP secret for an identity and stores
// it encrypted. The identity is NOT yet activated for two-factor
// authentication — the caller must follow up with ActivateTOTP after
// the user proves they can read the secret by entering a valid code.
//
// Returns the raw base32 secret + the otpauth provisioning URL for
// QR-code rendering.
func (s *Service) EnrollTOTP(ctx context.Context, id core.IdentityID) (secret, otpauthURL string, err error) {
	identity, err := s.identities.GetByID(ctx, id)
	if err != nil {
		return "", "", err
	}
	if identity == nil {
		return "", "", core.NewAppError(core.ErrIdentityNotFound, "Identity not found")
	}
	if identity.TOTPEnabled() {
		return "", "", core.NewAppError(core.ErrTOTPAlreadyEnabled, "TOTP already enabled")
	}

	secret, otpauthURL, err = crypto.GenerateTOTPSecret("GetLicense", identity.Email)
	if err != nil {
		return "", "", core.NewAppError(core.ErrInternalError, "Failed to generate TOTP secret")
	}
	enc, err := s.masterKey.Encrypt([]byte(secret))
	if err != nil {
		return "", "", core.NewAppError(core.ErrInternalError, "Failed to encrypt TOTP secret")
	}
	// Set secret but leave enabledAt and recovery codes nil — this is
	// the "enrolled but not activated" state.
	if err := s.identities.UpdateTOTP(ctx, id, enc, nil, nil); err != nil {
		return "", "", err
	}
	return secret, otpauthURL, nil
}

// ActivateTOTP verifies the first code against the enrolled secret
// and, on success, flips TOTPEnabledAt to now and generates recovery
// codes. Recovery codes are returned in plaintext exactly once; only
// their HMAC is stored.
func (s *Service) ActivateTOTP(ctx context.Context, id core.IdentityID, code string) ([]string, error) {
	identity, err := s.identities.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if identity == nil {
		return nil, core.NewAppError(core.ErrIdentityNotFound, "Identity not found")
	}
	if identity.TOTPEnabled() {
		return nil, core.NewAppError(core.ErrTOTPAlreadyEnabled, "TOTP already enabled")
	}
	if identity.TOTPSecretEnc == nil {
		return nil, core.NewAppError(core.ErrTOTPInvalid, "Must enroll before activating")
	}
	secretBytes, err := s.masterKey.Decrypt(identity.TOTPSecretEnc)
	if err != nil {
		return nil, core.NewAppError(core.ErrInternalError, "Failed to decrypt TOTP secret")
	}
	if !crypto.VerifyTOTP(string(secretBytes), code) {
		return nil, core.NewAppError(core.ErrTOTPInvalid, "Invalid TOTP code")
	}

	recovery, err := crypto.GenerateRecoveryCodes(10)
	if err != nil {
		return nil, core.NewAppError(core.ErrInternalError, "Failed to generate recovery codes")
	}
	// Hash each code with the master HMAC key and store the joined
	// string (newline-separated) encrypted at rest. Hash prevents
	// rainbow-table attacks if the encryption key is ever leaked, and
	// the extra layer of encryption prevents offline HMAC brute force.
	hashedJoined := strings.Join(hashRecoveryCodes(s.masterKey, recovery), "\n")
	hashedEnc, err := s.masterKey.Encrypt([]byte(hashedJoined))
	if err != nil {
		return nil, core.NewAppError(core.ErrInternalError, "Failed to store recovery codes")
	}

	now := time.Now().UTC()
	if err := s.identities.UpdateTOTP(ctx, id, identity.TOTPSecretEnc, &now, hashedEnc); err != nil {
		return nil, err
	}
	return recovery, nil
}

// VerifyTOTP validates a code during login. Returns nil on success
// or core.ErrTOTPInvalid on failure. Used by auth.Service.LoginStep2.
func (s *Service) VerifyTOTP(ctx context.Context, id core.IdentityID, code string) error {
	identity, err := s.identities.GetByID(ctx, id)
	if err != nil {
		return err
	}
	if identity == nil || !identity.TOTPEnabled() {
		return core.NewAppError(core.ErrTOTPInvalid, "TOTP not enabled")
	}
	secretBytes, err := s.masterKey.Decrypt(identity.TOTPSecretEnc)
	if err != nil {
		return core.NewAppError(core.ErrInternalError, "Failed to decrypt TOTP secret")
	}
	if !crypto.VerifyTOTP(string(secretBytes), code) {
		return core.NewAppError(core.ErrTOTPInvalid, "Invalid TOTP code")
	}
	return nil
}

// DisableTOTP clears all TOTP state after verifying the current code.
// Requires an identity who knows their current TOTP secret — recovery
// codes alone aren't enough to disable (that flow would need a
// dedicated ConsumeRecoveryCode method which is out of Phase 5 scope).
func (s *Service) DisableTOTP(ctx context.Context, id core.IdentityID, code string) error {
	if err := s.VerifyTOTP(ctx, id, code); err != nil {
		return err
	}
	return s.identities.UpdateTOTP(ctx, id, nil, nil, nil)
}

// hashRecoveryCodes HMACs each recovery code with the master HMAC key.
// Separate from password hashing because recovery codes are
// high-entropy (10 hex chars = 40 bits) — Argon2 would be overkill.
func hashRecoveryCodes(mk *crypto.MasterKey, codes []string) []string {
	hashed := make([]string, len(codes))
	for i, c := range codes {
		hashed[i] = mk.HMAC(c)
	}
	return hashed
}
