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

// Encrypt encrypts plaintext with AES-256-GCM.
func (mk *MasterKey) Encrypt(plaintext []byte) ([]byte, error) {
	return EncryptAESGCM(mk.encryptionKey, plaintext)
}

// Decrypt decrypts ciphertext encrypted with Encrypt.
func (mk *MasterKey) Decrypt(ciphertext []byte) ([]byte, error) {
	return DecryptAESGCM(mk.encryptionKey, ciphertext)
}

// SignJWT creates a signed JWT access token.
func (mk *MasterKey) SignJWT(claims JWTClaims, ttl time.Duration) (string, error) {
	return SignJWT(claims, mk.jwtSigningKey, ttl)
}

// VerifyJWT validates a JWT and returns the claims.
func (mk *MasterKey) VerifyJWT(token string) (*JWTClaims, error) {
	return VerifyJWT(token, mk.jwtSigningKey)
}
