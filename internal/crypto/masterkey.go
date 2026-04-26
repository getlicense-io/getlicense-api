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
//
// The JWT signing path goes through jwtRegistry rather than a single
// signing key field. The registry holds one or more named keys plus
// the kid currently being used to mint new tokens. Every signed JWT
// embeds the current kid in its JOSE header; the verifier routes to
// the matching key by kid lookup.
type MasterKey struct {
	hmacKey       []byte
	encryptionKey []byte
	jwtRegistry   *JWTKeyRegistry
}

// NewMasterKey derives a MasterKey from a hex-encoded master key string.
// The hex string must be at least 64 characters (32 bytes).
//
// jwtKeysSpec / jwtKidCurrent come from the GETLICENSE_JWT_KEYS and
// GETLICENSE_JWT_KID_CURRENT env vars (parsed by server.LoadConfig).
// When both are empty the registry runs in implicit mode and registers
// the HKDF-derived key under crypto.ImplicitDefaultKID ("v0"). See
// NewJWTKeyRegistryFromConfig for the explicit-key format and
// validation rules.
func NewMasterKey(hexKey, jwtKeysSpec, jwtKidCurrent string) (*MasterKey, error) {
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

	registry, err := NewJWTKeyRegistryFromConfig(jwtKeysSpec, jwtKidCurrent, jwtKey)
	if err != nil {
		return nil, err
	}

	return &MasterKey{
		hmacKey:       hmacKey,
		encryptionKey: encKey,
		jwtRegistry:   registry,
	}, nil
}

// JWTRegistry exposes the registry for callers that need to inspect
// the current kid (e.g. tests). Production code should not need it —
// SignJWT / VerifyJWT thread the registry internally.
func (mk *MasterKey) JWTRegistry() *JWTKeyRegistry { return mk.jwtRegistry }

// HMAC computes HMAC-SHA256 of data and returns the hex digest.
func (mk *MasterKey) HMAC(data string) string {
	return HMACSHA256(mk.hmacKey, data)
}

// Encrypt encrypts plaintext with AES-256-GCM, binding the
// ciphertext to the given associated data. AAD MUST match at
// decrypt time.
//
// Use the per-purpose helpers in aad.go to construct AAD strings —
// never pass nil. AAD format convention is "{entity}:{id}:{purpose}",
// e.g. "webhook_endpoint:01J...K:signing_secret". Binding the
// ciphertext to its (entity, purpose) tuple prevents an attacker with
// DB write access from swapping encrypted columns between rows or
// purposes; GCM auth fails on a mismatched AAD.
func (mk *MasterKey) Encrypt(plaintext, aad []byte) ([]byte, error) {
	return EncryptAESGCM(mk.encryptionKey, plaintext, aad)
}

// Decrypt decrypts ciphertext encrypted with Encrypt. AAD MUST match
// the encrypt-time value.
func (mk *MasterKey) Decrypt(ciphertext, aad []byte) ([]byte, error) {
	return DecryptAESGCM(mk.encryptionKey, ciphertext, aad)
}

// DecryptLegacyNoAAD decrypts a pre-AAD-migration ciphertext that was
// written without associated data. MIGRATION-ONLY — exported so the
// one-shot startup migration in cmd/server/migrate_aad.go can port
// legacy blobs to the AAD-required format.
//
// Production code MUST always use Decrypt with the correct AAD. Once
// no v1 ciphertexts remain on disk this method becomes dead and can be
// removed.
func (mk *MasterKey) DecryptLegacyNoAAD(ciphertext []byte) ([]byte, error) {
	return decryptLegacyNoAAD(mk.encryptionKey, ciphertext)
}

// SignJWT creates a signed JWT access token. Embeds the registry's
// current kid in the JOSE header and a fresh random jti in the claim
// set so the middleware revocation path can identify individual tokens.
func (mk *MasterKey) SignJWT(claims JWTClaims, ttl time.Duration) (string, error) {
	return SignJWT(claims, mk.jwtRegistry, ttl)
}

// VerifyJWT validates a JWT and returns the claims. Routes to a key
// in the registry by the JOSE kid header; tokens without a kid header
// or jti claim, or with an unknown kid, are rejected.
func (mk *MasterKey) VerifyJWT(token string) (*JWTClaims, error) {
	return VerifyJWT(token, mk.jwtRegistry)
}
