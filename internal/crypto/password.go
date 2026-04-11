package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	argon2Time    = 1
	argon2Memory  = 64 * 1024
	argon2Threads = 4
	argon2KeyLen  = 32
	argon2SaltLen = 16
)

// HashPassword hashes a password using Argon2id and returns an encoded string
// in the format: $argon2id$v=19$m=65536,t=1,p=4$<salt>$<hash>
func HashPassword(password string) (string, error) {
	salt := make([]byte, argon2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("crypto: failed to generate salt: %w", err)
	}

	hash := argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)

	saltB64 := base64.RawStdEncoding.EncodeToString(salt)
	hashB64 := base64.RawStdEncoding.EncodeToString(hash)

	encoded := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argon2Memory, argon2Time, argon2Threads, saltB64, hashB64)

	return encoded, nil
}

// VerifyPassword checks a password against an Argon2id-encoded hash.
// Returns true if the password matches. Uses constant-time comparison.
func VerifyPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	// Expected parts after split: ["", "argon2id", "v=19", "m=65536,t=1,p=4", "<salt>", "<hash>"]
	if len(parts) != 6 {
		return false
	}
	if parts[1] != "argon2id" {
		return false
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	expectedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}

	actualHash := argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)

	return subtle.ConstantTimeCompare(actualHash, expectedHash) == 1
}
