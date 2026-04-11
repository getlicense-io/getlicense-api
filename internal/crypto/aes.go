package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

const aesNonceSize = 12

// EncryptAESGCM encrypts plaintext using AES-256-GCM with a random 12-byte nonce.
// The output format is: [12-byte nonce] || [ciphertext+tag].
// key must be 32 bytes.
func EncryptAESGCM(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to create AES cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to create GCM: %w", err)
	}

	nonce := make([]byte, aesNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("crypto: failed to generate nonce: %w", err)
	}

	ciphertext := aead.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// DecryptAESGCM decrypts ciphertext that was produced by EncryptAESGCM.
// The input format is: [12-byte nonce] || [ciphertext+tag].
// key must be 32 bytes.
func DecryptAESGCM(key, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < aesNonceSize {
		return nil, fmt.Errorf("crypto: ciphertext too short")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to create AES cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to create GCM: %w", err)
	}

	nonce := ciphertext[:aesNonceSize]
	data := ciphertext[aesNonceSize:]

	plaintext, err := aead.Open(nil, nonce, data, nil)
	if err != nil {
		return nil, fmt.Errorf("crypto: decryption failed: %w", err)
	}

	return plaintext, nil
}
