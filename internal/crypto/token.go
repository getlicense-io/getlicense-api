package crypto

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/getlicense-io/getlicense-api/internal/core"
)

const tokenPrefix = "gl1"

// TokenPayload holds the claims embedded in a license token.
type TokenPayload struct {
	Version   int                `json:"v"`
	ProductID string             `json:"pid"`
	LicenseID string             `json:"lid"`
	Status    core.LicenseStatus `json:"status"`
	IssuedAt  int64              `json:"iat"`
	ExpiresAt *int64             `json:"exp,omitempty"`
	// Validation staleness tolerance in seconds. The SDK caches a validate
	// response for this long before re-checking the server.
	TTL int `json:"ttl"`
}

// SignToken marshals the payload as JSON, base64url-encodes it (no padding),
// signs the encoded string with the Ed25519 private key, and returns a token
// in the form: gl1.<payload_b64>.<sig_b64>
func SignToken(payload TokenPayload, priv ed25519.PrivateKey) (string, error) {
	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("crypto: failed to marshal token payload: %w", err)
	}

	payloadB64 := base64.RawURLEncoding.EncodeToString(jsonBytes)
	sig := Ed25519Sign(priv, []byte(payloadB64))
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	return tokenPrefix + "." + payloadB64 + "." + sigB64, nil
}

// VerifyToken parses and verifies a gl1 license token.
// It checks the prefix, verifies the Ed25519 signature, then decodes the payload.
func VerifyToken(token string, pub ed25519.PublicKey) (*TokenPayload, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("crypto: invalid token format: expected 3 parts, got %d", len(parts))
	}

	if parts[0] != tokenPrefix {
		return nil, fmt.Errorf("crypto: invalid token prefix: expected %q, got %q", tokenPrefix, parts[0])
	}

	payloadB64 := parts[1]
	sigB64 := parts[2]

	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to decode token signature: %w", err)
	}

	if !Ed25519Verify(pub, []byte(payloadB64), sig) {
		return nil, fmt.Errorf("crypto: token signature verification failed")
	}

	jsonBytes, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to decode token payload: %w", err)
	}

	var payload TokenPayload
	if err := json.Unmarshal(jsonBytes, &payload); err != nil {
		return nil, fmt.Errorf("crypto: failed to unmarshal token payload: %w", err)
	}

	return &payload, nil
}
