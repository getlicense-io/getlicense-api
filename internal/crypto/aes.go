package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

const aesNonceSize = 12

// aeadOverhead is the GCM authentication tag size (in bytes). Used to
// validate envelope length before attempting Open.
const aeadOverhead = 16

// envelopeV2Magic is the first byte of a v2 (with-AAD) ciphertext.
//
// v1 ciphertexts (produced by EncryptAESGCM) start with a uniformly-
// random 12-byte nonce, so the magic byte may collide with a real
// nonce ~1/256 of the time. The decrypt path handles this by falling
// back from a v2 attempt to a v1 attempt when the v2 GCM open fails
// AND the first byte happens to be the magic value (see DecryptAuto
// on MasterKey).
const envelopeV2Magic byte = 0x02

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

// EncryptAESGCM encrypts plaintext using AES-256-GCM with a random 12-byte nonce.
// The output format is: [12-byte nonce] || [ciphertext+tag].
// key must be 32 bytes.
//
// This is the v1 (no-AAD) envelope. New encryption sites SHOULD use
// EncryptAESGCMWithAAD so ciphertexts are bound to (entity, purpose)
// and cannot be swapped between rows by an attacker with DB write
// access. EncryptAESGCM is retained for backward compatibility with
// existing v1 ciphertexts on disk.
func EncryptAESGCM(key, plaintext []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aesNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("crypto: failed to generate nonce: %w", err)
	}

	ciphertext := aead.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// DecryptAESGCM decrypts ciphertext that was produced by EncryptAESGCM.
// The input format is: [12-byte nonce] || [ciphertext+tag].
// key must be 32 bytes.
//
// This is the v1 (no-AAD) decrypt. To decrypt v2 envelopes use
// DecryptAESGCMWithAAD; to handle either format transparently use
// MasterKey.DecryptAuto.
func DecryptAESGCM(key, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < aesNonceSize {
		return nil, fmt.Errorf("crypto: ciphertext too short")
	}

	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}

	nonce := ciphertext[:aesNonceSize]
	data := ciphertext[aesNonceSize:]

	plaintext, err := aead.Open(nil, nonce, data, nil)
	if err != nil {
		return nil, fmt.Errorf("crypto: decryption failed: %w", err)
	}

	return plaintext, nil
}

// EncryptAESGCMWithAAD encrypts plaintext using AES-256-GCM with a
// random 12-byte nonce and the given associated data. The output
// format is: [v2 magic byte 0x02] || [12-byte nonce] || [ciphertext+tag].
//
// AAD MUST be the same value at decrypt time. Use distinct AAD per
// (entity, purpose) tuple — e.g. "webhook_endpoint:UUID:signing_secret"
// — so swapping ciphertexts between rows or purposes fails GCM auth.
//
// key must be 32 bytes. AAD may be empty (use EncryptAESGCM instead
// in that case — passing nil here works but the v2 envelope is
// unnecessary overhead for the no-AAD path).
func EncryptAESGCMWithAAD(key, plaintext, aad []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aesNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("crypto: failed to generate nonce: %w", err)
	}
	out := make([]byte, 1, 1+aesNonceSize+len(plaintext)+aead.Overhead())
	out[0] = envelopeV2Magic
	out = append(out, nonce...)
	out = aead.Seal(out, nonce, plaintext, aad)
	return out, nil
}

// DecryptAESGCMWithAAD decrypts a v2 envelope (produced by
// EncryptAESGCMWithAAD) using the given associated data. AAD MUST
// match the value used at encrypt time.
//
// Returns an error on malformed envelopes or AAD mismatch — both
// fail the GCM auth tag check and cannot be distinguished from
// "ciphertext was tampered with."
func DecryptAESGCMWithAAD(key, envelope, aad []byte) ([]byte, error) {
	if len(envelope) < 1+aesNonceSize+aeadOverhead {
		return nil, fmt.Errorf("crypto: envelope too short for v2 AAD format")
	}
	if envelope[0] != envelopeV2Magic {
		return nil, fmt.Errorf("crypto: v2 magic byte expected, got 0x%02x", envelope[0])
	}
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	nonce := envelope[1 : 1+aesNonceSize]
	data := envelope[1+aesNonceSize:]
	plaintext, err := aead.Open(nil, nonce, data, aad)
	if err != nil {
		return nil, fmt.Errorf("crypto: v2 decryption failed: %w", err)
	}
	return plaintext, nil
}
