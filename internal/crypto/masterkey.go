package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/hkdf"
)

// MasterKey holds derived cryptographic keys and provides methods for all
// key-dependent operations. Callers never touch raw key bytes directly.
type MasterKey struct {
	hmacKey       []byte
	encryptionKey []byte
	jwtSigningKey []byte
}

// NewMasterKey derives a MasterKey from a hex-encoded master key string.
// The hex string must be at least 64 characters (32 bytes).
func NewMasterKey(hexKey string) (*MasterKey, error) {
	if len(hexKey) < 64 {
		return nil, fmt.Errorf("crypto: master key hex string must be at least 64 characters, got %d", len(hexKey))
	}

	raw, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("crypto: invalid hex key: %w", err)
	}

	derive := func(context string) ([]byte, error) {
		r := hkdf.New(sha256.New, raw, nil, []byte(context))
		key := make([]byte, 32)
		if _, err := io.ReadFull(r, key); err != nil {
			return nil, fmt.Errorf("crypto: HKDF derivation failed for %q: %w", context, err)
		}
		return key, nil
	}

	hmacKey, err := derive("getlicense-hmac-key")
	if err != nil {
		return nil, err
	}
	encKey, err := derive("getlicense-encryption-key")
	if err != nil {
		return nil, err
	}
	jwtKey, err := derive("getlicense-jwt-signing-key")
	if err != nil {
		return nil, err
	}

	return &MasterKey{
		hmacKey:       hmacKey,
		encryptionKey: encKey,
		jwtSigningKey: jwtKey,
	}, nil
}

// HMAC computes HMAC-SHA256 of data and returns the hex digest.
func (mk *MasterKey) HMAC(data string) string {
	return HMACSHA256(mk.hmacKey, data)
}

// Encrypt encrypts plaintext with AES-256-GCM (v1 envelope, no AAD).
//
// Retained for backward compat with legacy ciphertexts on disk. New
// code SHOULD use EncryptWithAAD so ciphertexts are bound to their
// (entity, purpose) tuple — moving a v1 blob between rows produces
// a valid (but wrong) plaintext, which is exactly the attack v2
// closes.
func (mk *MasterKey) Encrypt(plaintext []byte) ([]byte, error) {
	return EncryptAESGCM(mk.encryptionKey, plaintext)
}

// Decrypt decrypts ciphertext encrypted with Encrypt (v1 envelope).
//
// Pure v1 — does NOT attempt to detect a v2 envelope. Use this only
// for legacy paths whose blobs are guaranteed to be v1 (e.g. the
// recovery_codes_enc lazy-migration path). Otherwise use DecryptAuto.
func (mk *MasterKey) Decrypt(ciphertext []byte) ([]byte, error) {
	return DecryptAESGCM(mk.encryptionKey, ciphertext)
}

// EncryptWithAAD encrypts plaintext with AES-256-GCM and binds the
// ciphertext to the given associated data. Decryption REQUIRES the
// same AAD — moving an encrypted blob between rows / purposes fails
// GCM authentication, defeating attackers who can write arbitrary
// bytes to encrypted columns but cannot break AES.
//
// AAD convention: "{entity}:{id}:{purpose}", e.g.
//
//	"webhook_endpoint:01J...K:signing_secret"
//	"identity:01J...K:totp_secret"
//	"product:01J...K:private_key"
//
// New code uses this method. Legacy code paths still on Encrypt
// remain backward compatible via the versioned envelope; rotation /
// re-enrollment paths upgrade to v2 automatically.
func (mk *MasterKey) EncryptWithAAD(plaintext, aad []byte) ([]byte, error) {
	return EncryptAESGCMWithAAD(mk.encryptionKey, plaintext, aad)
}

// DecryptWithAAD decrypts a v2 (AAD-bound) envelope. For backward
// compat with v1 ciphertexts written before the AAD migration, use
// DecryptAuto.
func (mk *MasterKey) DecryptWithAAD(envelope, aad []byte) ([]byte, error) {
	return DecryptAESGCMWithAAD(mk.encryptionKey, envelope, aad)
}

// DecryptAuto detects the envelope version and decrypts. v2 (with
// AAD) blobs are decrypted with the supplied AAD; v1 (legacy, no
// AAD) blobs are decrypted ignoring the AAD argument. Use this in
// read paths during the v1→v2 transition window.
//
// The 1/256 collision case — a v1 nonce that begins with the v2
// magic byte 0x02 — is handled by falling through to the v1 path
// after the v2 attempt fails GCM auth. Worst-case cost is one extra
// failed Open per legacy read with a 0x02 first byte.
//
// New code SHOULD prefer DecryptWithAAD where the version is known.
func (mk *MasterKey) DecryptAuto(envelope, aad []byte) ([]byte, error) {
	if len(envelope) > 0 && envelope[0] == envelopeV2Magic {
		// Try v2 path first.
		plaintext, err := DecryptAESGCMWithAAD(mk.encryptionKey, envelope, aad)
		if err == nil {
			return plaintext, nil
		}
		// Fall through: maybe a v1 blob whose nonce starts with 0x02
		// (~1/256 chance). Try v1 below.
	}
	return DecryptAESGCM(mk.encryptionKey, envelope)
}

// SignJWT creates a signed JWT access token.
func (mk *MasterKey) SignJWT(claims JWTClaims, ttl time.Duration) (string, error) {
	return SignJWT(claims, mk.jwtSigningKey, ttl)
}

// VerifyJWT validates a JWT and returns the claims.
func (mk *MasterKey) VerifyJWT(token string) (*JWTClaims, error) {
	return VerifyJWT(token, mk.jwtSigningKey)
}
