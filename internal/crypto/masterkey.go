package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// MasterKey holds three derived 32-byte keys for HMAC, AES-GCM encryption, and JWT signing.
type MasterKey struct {
	HMACKey       []byte
	EncryptionKey []byte
	JWTSigningKey []byte
}

// NewMasterKey derives a MasterKey from a hex-encoded master key string.
// The hex string must be at least 64 characters (32 bytes) long.
// Keys are derived via HKDF-SHA256 with a nil salt.
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
		HMACKey:       hmacKey,
		EncryptionKey: encKey,
		JWTSigningKey: jwtKey,
	}, nil
}
