package crypto

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

const leaseTokenPrefix = "gl2"

// LeaseTokenPayload is the claim set carried by a signed lease token.
// Format follows the same gl1 license-token convention: short field
// names for compact JSON, base64url-encoded payload, Ed25519 signature
// over the encoded payload.
//
// Spec: docs/superpowers/specs/2026-04-15-l2-checkout-design.md §Lease Token Format.
type LeaseTokenPayload struct {
	Version int `json:"v"`

	// License + policy + product context
	LicenseID      string `json:"lid"`
	ProductID      string `json:"pid"`
	PolicyID       string `json:"plid"`
	LicenseStatus  string `json:"lst"`
	LicenseExpires int64  `json:"lex,omitempty"` // 0 for perpetual

	// Machine context
	MachineID   string `json:"mid"`
	Fingerprint string `json:"fp"`

	// Lease state
	LeaseIssuedAt   int64 `json:"liat"`
	LeaseExpiresAt  int64 `json:"lex2"`
	RequiresCheckin bool  `json:"rqc"`
	GraceSec        int   `json:"gs"`

	// Entitlements (L3 populates; L2 ships an empty array slot)
	Entitlements []string `json:"ent"`

	// Standard claims
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
	JTI       string `json:"jti"`
}

// SignLeaseToken marshals the payload, base64url-encodes it, signs the
// encoded string with the product's Ed25519 private key, and returns
// gl2.<payload_b64>.<sig_b64>.
func SignLeaseToken(payload LeaseTokenPayload, priv ed25519.PrivateKey) (string, error) {
	if payload.Entitlements == nil {
		payload.Entitlements = []string{}
	}
	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("crypto: failed to marshal lease token payload: %w", err)
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(jsonBytes)
	sig := Ed25519Sign(priv, []byte(payloadB64))
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	return leaseTokenPrefix + "." + payloadB64 + "." + sigB64, nil
}

// VerifyLeaseToken parses, verifies the signature, and decodes a gl2 lease token.
func VerifyLeaseToken(token string, pub ed25519.PublicKey) (*LeaseTokenPayload, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("crypto: invalid lease token format: expected 3 parts, got %d", len(parts))
	}
	if parts[0] != leaseTokenPrefix {
		return nil, fmt.Errorf("crypto: invalid lease token prefix: expected %q, got %q", leaseTokenPrefix, parts[0])
	}
	payloadB64 := parts[1]
	sigB64 := parts[2]
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to decode lease signature: %w", err)
	}
	if !Ed25519Verify(pub, []byte(payloadB64), sig) {
		return nil, fmt.Errorf("crypto: lease signature verification failed")
	}
	jsonBytes, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to decode lease payload: %w", err)
	}
	var payload LeaseTokenPayload
	if err := json.Unmarshal(jsonBytes, &payload); err != nil {
		return nil, fmt.Errorf("crypto: failed to unmarshal lease payload: %w", err)
	}
	return &payload, nil
}
