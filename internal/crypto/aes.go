package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

const (
	aesNonceSize = 12
	// aeadOverhead is the GCM authentication tag size (in bytes). Used
	// to validate envelope length before attempting Open.
	aeadOverhead = 16
)

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: creating AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: creating GCM: %w", err)
	}
	return gcm, nil
}

// EncryptAESGCM encrypts plaintext with AES-256-GCM and a random
// 12-byte nonce, binding the ciphertext to the given associated data.
// Output: [12-byte nonce] || [ciphertext+tag].
//
// AAD MUST match at decrypt time. Use the per-purpose helpers in
// aad.go to construct AAD strings — never pass nil. Binding the
// ciphertext to a (entity, purpose) AAD prevents an attacker with DB
// write access from swapping encrypted columns between rows or
// purposes; GCM auth fails on a mismatched AAD.
//
// key must be 32 bytes.
func EncryptAESGCM(key, plaintext, aad []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aesNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("crypto: failed to generate nonce: %w", err)
	}
	return aead.Seal(nonce, nonce, plaintext, aad), nil
}

// DecryptAESGCM decrypts ciphertext from EncryptAESGCM. AAD must
// match the encrypt-time value. AAD mismatch and tampering both
// surface as the same GCM auth-tag failure (intentional — callers
// cannot distinguish "wrong AAD" from "ciphertext modified", which
// is what closes the swap-defense gap).
//
// key must be 32 bytes.
func DecryptAESGCM(key, ciphertext, aad []byte) ([]byte, error) {
	if len(ciphertext) < aesNonceSize+aeadOverhead {
		return nil, fmt.Errorf("crypto: ciphertext too short")
	}
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	nonce := ciphertext[:aesNonceSize]
	data := ciphertext[aesNonceSize:]
	plaintext, err := aead.Open(nil, nonce, data, aad)
	if err != nil {
		return nil, fmt.Errorf("crypto: decryption failed: %w", err)
	}
	return plaintext, nil
}

// decryptLegacyNoAAD reads pre-AAD-migration ciphertexts that were
// written without associated data. PRIVATE to the package — used only
// by the one-shot startup migration in cmd/server/migrate_aad.go to
// port legacy blobs to the AAD-required format.
//
// Production code MUST always use DecryptAESGCM with the correct AAD.
// The wire format is otherwise byte-compatible: [nonce] || [ct+tag].
func decryptLegacyNoAAD(key, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < aesNonceSize+aeadOverhead {
		return nil, fmt.Errorf("crypto: legacy ciphertext too short")
	}
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	nonce := ciphertext[:aesNonceSize]
	data := ciphertext[aesNonceSize:]
	return aead.Open(nil, nonce, data, nil)
}
