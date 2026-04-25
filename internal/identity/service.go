package identity

import (
	"context"
	"crypto/subtle"
	"strings"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/crypto"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

// totpIssuer is the "issuer" label embedded in the otpauth provisioning
// URL. Users see this in their authenticator app as the account source
// ("GetLicense: alice@example.com"). Changes here affect every newly
// enrolled identity — existing TOTP secrets continue to work regardless.
const totpIssuer = "GetLicense"

// Service manages identity-level operations that fall outside the
// auth.Service scope: TOTP enrollment, activation, verification, and
// recovery. Password management also lives here when it needs more
// than a simple hash update.
type Service struct {
	identities    domain.IdentityRepository
	recoveryCodes domain.RecoveryCodeRepository
	masterKey     *crypto.MasterKey
}

func NewService(identities domain.IdentityRepository, recoveryCodes domain.RecoveryCodeRepository, masterKey *crypto.MasterKey) *Service {
	return &Service{identities: identities, recoveryCodes: recoveryCodes, masterKey: masterKey}
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

	secret, otpauthURL, err = crypto.GenerateTOTPSecret(totpIssuer, identity.Email)
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
//
// PR-4.5: recovery codes now persist as one row per code in the
// recovery_codes table so consume can use atomic DELETE-RETURNING.
// The legacy identities.recovery_codes_enc blob is left nil on new
// enrollments — only pre-PR-4.5 identities still carry it, and they
// migrate lazily on first recovery-code use (see consumeRecoveryCode).
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
	// Hash each code with the master HMAC key. Hash prevents rainbow-
	// table attacks if the encryption key is ever leaked, and per-row
	// storage means each code is a single DB row that DELETE-RETURNING
	// can claim atomically.
	hashes := hashRecoveryCodes(s.masterKey, recovery)
	if err := s.recoveryCodes.Insert(ctx, id, hashes); err != nil {
		return nil, core.NewAppError(core.ErrInternalError, "Failed to store recovery codes")
	}

	now := time.Now().UTC()
	// Persist activation state; recoveryEnc stays nil — new enrollments
	// never use the legacy blob.
	if err := s.identities.UpdateTOTP(ctx, id, identity.TOTPSecretEnc, &now, nil); err != nil {
		return nil, err
	}
	return recovery, nil
}

// VerifyTOTP validates a code during login. Returns the loaded identity
// on success or core.ErrTOTPInvalid on failure. Used by
// auth.Service.LoginStep2 — returning the identity avoids a redundant
// GetByID round-trip in the caller.
func (s *Service) VerifyTOTP(ctx context.Context, id core.IdentityID, code string) (*domain.Identity, error) {
	identity, err := s.identities.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if identity == nil || !identity.TOTPEnabled() {
		return nil, core.NewAppError(core.ErrTOTPInvalid, "TOTP not enabled")
	}
	secretBytes, err := s.masterKey.Decrypt(identity.TOTPSecretEnc)
	if err != nil {
		return nil, core.NewAppError(core.ErrInternalError, "Failed to decrypt TOTP secret")
	}
	if !crypto.VerifyTOTP(string(secretBytes), code) {
		return nil, core.NewAppError(core.ErrTOTPInvalid, "Invalid TOTP code")
	}
	return identity, nil
}

// VerifyTOTPOrRecovery tries the supplied code as a TOTP first, then
// as a recovery code. On recovery-code success the consumed code is
// removed from storage so it cannot be replayed. Returns the loaded
// identity on success or core.ErrTOTPInvalid on failure.
//
// F-012: TOTP recovery codes were generated, stored, and returned to
// users at activation time but never actually accepted during login.
// Users who lost their authenticator were locked out despite the UI
// telling them to save the codes. This is the hook that makes them
// real.
func (s *Service) VerifyTOTPOrRecovery(ctx context.Context, id core.IdentityID, code string) (*domain.Identity, error) {
	identity, err := s.identities.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if identity == nil || !identity.TOTPEnabled() {
		return nil, core.NewAppError(core.ErrTOTPInvalid, "TOTP not enabled")
	}

	// Try TOTP first — it's the expected path.
	secretBytes, err := s.masterKey.Decrypt(identity.TOTPSecretEnc)
	if err != nil {
		return nil, core.NewAppError(core.ErrInternalError, "Failed to decrypt TOTP secret")
	}
	if crypto.VerifyTOTP(string(secretBytes), code) {
		return identity, nil
	}

	// Fall through to recovery code consumption.
	if err := s.consumeRecoveryCode(ctx, identity, code); err != nil {
		return nil, err
	}
	return identity, nil
}

// consumeRecoveryCode atomically claims a single-use recovery code.
//
// PR-4.5: the new path is an atomic DELETE ... RETURNING against the
// recovery_codes table. Concurrent uses of the same code race on the
// DELETE and only one wins — closing the read-modify-write race that
// the previous decrypt-list-split-encrypt path exposed. The DB-level
// lookup is constant-time at the application layer (an indexed
// equality predicate on a fixed-length text column) so no early-exit
// timing leak remains for codes generated under the new scheme.
//
// For identities that still have codes only in the legacy encrypted
// blob (recovery_codes_enc), we fall through to consumeLegacyRecoveryCode
// which decrypts, finds with constant-time compare, migrates the
// remainder into the new table, and clears the blob. From the next
// use onward only the new path is exercised.
func (s *Service) consumeRecoveryCode(ctx context.Context, identity *domain.Identity, code string) error {
	hash := s.masterKey.HMAC(strings.TrimSpace(code))

	// New path: atomic delete via the per-row table.
	hit, err := s.recoveryCodes.Consume(ctx, identity.ID, hash)
	if err != nil {
		return core.NewAppError(core.ErrInternalError, "Failed to consume recovery code")
	}
	if hit {
		return nil
	}

	// Legacy fallback: identity still has codes in the encrypted blob.
	// First-use migration moves the remainder to the new table.
	if len(identity.RecoveryCodesEnc) == 0 {
		return core.NewAppError(core.ErrTOTPInvalid, "Invalid TOTP code")
	}
	return s.consumeLegacyRecoveryCode(ctx, identity, hash)
}

// consumeLegacyRecoveryCode handles the lazy migration path for
// identities whose recovery codes still live in the encrypted blob.
// The race that motivated PR-4.5 is technically still present here
// for a single first-use call per legacy identity — acceptable
// because each identity transitions through this path at most once
// before the new table is the only source of truth for them.
//
// `targetHash` has already been computed by the caller so we can
// hand it directly to the constant-time compare without re-HMACing.
func (s *Service) consumeLegacyRecoveryCode(ctx context.Context, identity *domain.Identity, targetHash string) error {
	stored, err := s.masterKey.Decrypt(identity.RecoveryCodesEnc)
	if err != nil {
		return core.NewAppError(core.ErrInternalError, "Failed to decrypt recovery codes")
	}
	hashes := strings.Split(string(stored), "\n")

	// Constant-time compare: subtle.ConstantTimeCompare always reads
	// every byte of both slices instead of returning on first
	// mismatch. All HMAC hashes are the same length (HMAC-SHA256 hex
	// = 64 chars), so the differing-length short-circuit inside
	// ConstantTimeCompare doesn't kick in.
	idx := -1
	target := []byte(targetHash)
	for i, h := range hashes {
		if subtle.ConstantTimeCompare([]byte(h), target) == 1 {
			idx = i
			break
		}
	}
	if idx < 0 {
		return core.NewAppError(core.ErrTOTPInvalid, "Invalid TOTP code")
	}

	// Drop the consumed hash and migrate the rest. Filter empty
	// entries that may exist from a previous re-serialization.
	remaining := append(hashes[:idx:idx], hashes[idx+1:]...)
	cleaned := make([]string, 0, len(remaining))
	for _, h := range remaining {
		if h = strings.TrimSpace(h); h != "" {
			cleaned = append(cleaned, h)
		}
	}
	if err := s.recoveryCodes.Insert(ctx, identity.ID, cleaned); err != nil {
		return core.NewAppError(core.ErrInternalError, "Failed to migrate recovery codes")
	}
	// Clear the legacy blob. From here on this identity only uses
	// the new path. (If this UPDATE fails after Insert succeeds,
	// the next call's Insert is a no-op via ON CONFLICT DO NOTHING
	// and the same migration retries cleanly.)
	if err := s.identities.UpdateTOTP(ctx, identity.ID, identity.TOTPSecretEnc, identity.TOTPEnabledAt, nil); err != nil {
		return core.NewAppError(core.ErrInternalError, "Failed to clear legacy recovery codes")
	}
	return nil
}

// DisableTOTP clears all TOTP state after verifying the current code
// (TOTP or a recovery code). Either proof is sufficient — a user who
// has lost their authenticator can still turn TOTP off with one of
// their saved recovery codes.
//
// PR-4.5: also clears every row from the recovery_codes table so a
// re-enrollment starts from a clean slate.
func (s *Service) DisableTOTP(ctx context.Context, id core.IdentityID, code string) error {
	if _, err := s.VerifyTOTPOrRecovery(ctx, id, code); err != nil {
		return err
	}
	if err := s.recoveryCodes.DeleteAll(ctx, id); err != nil {
		return err
	}
	return s.identities.UpdateTOTP(ctx, id, nil, nil, nil)
}

// hashRecoveryCodes HMACs each recovery code with the master HMAC key.
// Separate from password hashing because recovery codes are
// high-entropy (16 hex chars = 64 bits) — Argon2 would be overkill.
func hashRecoveryCodes(mk *crypto.MasterKey, codes []string) []string {
	hashed := make([]string, len(codes))
	for i, c := range codes {
		hashed[i] = mk.HMAC(c)
	}
	return hashed
}
