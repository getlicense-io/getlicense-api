package crypto

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func makeTestPayload() TokenPayload {
	return TokenPayload{
		Version:   1,
		ProductID: "prod-123",
		LicenseID: "lic-456",
		Status:    "active",
		IssuedAt:  1700000000,
	}
}

func TestSignVerifyToken_Roundtrip(t *testing.T) {
	pub, priv, err := GenerateEd25519Keypair()
	if err != nil {
		t.Fatal(err)
	}

	payload := makeTestPayload()
	token, err := SignToken(payload, priv)
	if err != nil {
		t.Fatalf("SignToken error: %v", err)
	}

	if !strings.HasPrefix(token, "gl1.") {
		t.Errorf("token missing gl1. prefix: %q", token)
	}

	got, err := VerifyToken(token, pub)
	if err != nil {
		t.Fatalf("VerifyToken error: %v", err)
	}

	if got.ProductID != payload.ProductID {
		t.Errorf("ProductID: got %q, want %q", got.ProductID, payload.ProductID)
	}
	if got.LicenseID != payload.LicenseID {
		t.Errorf("LicenseID: got %q, want %q", got.LicenseID, payload.LicenseID)
	}
	if got.Version != payload.Version {
		t.Errorf("Version: got %d, want %d", got.Version, payload.Version)
	}
	if got.Status != payload.Status {
		t.Errorf("Status: got %q, want %q", got.Status, payload.Status)
	}
}

func TestVerifyToken_InvalidPrefix(t *testing.T) {
	pub, priv, err := GenerateEd25519Keypair()
	if err != nil {
		t.Fatal(err)
	}

	payload := makeTestPayload()
	token, err := SignToken(payload, priv)
	if err != nil {
		t.Fatal(err)
	}

	// Replace the prefix
	badToken := "gl2" + token[3:]
	_, err = VerifyToken(badToken, pub)
	if err == nil {
		t.Error("VerifyToken: expected error for invalid prefix, got nil")
	}
}

func TestVerifyToken_TamperedPayload(t *testing.T) {
	pub, priv, err := GenerateEd25519Keypair()
	if err != nil {
		t.Fatal(err)
	}

	payload := makeTestPayload()
	token, err := SignToken(payload, priv)
	if err != nil {
		t.Fatal(err)
	}

	// Tamper with payload part (middle segment)
	parts := strings.Split(token, ".")
	// Flip a character in the base64 payload
	b := []byte(parts[1])
	b[len(b)-1] ^= 1
	parts[1] = string(b)
	tampered := strings.Join(parts, ".")

	_, err = VerifyToken(tampered, pub)
	if err == nil {
		t.Error("VerifyToken: expected error for tampered payload, got nil")
	}
}

func TestVerifyToken_WrongKey(t *testing.T) {
	_, priv, err := GenerateEd25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	wrongPub, _, err := GenerateEd25519Keypair()
	if err != nil {
		t.Fatal(err)
	}

	payload := makeTestPayload()
	token, err := SignToken(payload, priv)
	if err != nil {
		t.Fatal(err)
	}

	_, err = VerifyToken(token, wrongPub)
	if err == nil {
		t.Error("VerifyToken: expected error for wrong key, got nil")
	}
}

func TestVerifyToken_InvalidFormat(t *testing.T) {
	pub, _, err := GenerateEd25519Keypair()
	if err != nil {
		t.Fatal(err)
	}

	_, err = VerifyToken("notavalidtoken", pub)
	if err == nil {
		t.Error("VerifyToken: expected error for invalid format, got nil")
	}
}

func TestSignVerifyToken_TTLRoundtrip(t *testing.T) {
	pub, priv, err := GenerateEd25519Keypair()
	if err != nil {
		t.Fatal(err)
	}

	payload := makeTestPayload()
	payload.TTL = 3600

	token, err := SignToken(payload, priv)
	if err != nil {
		t.Fatalf("SignToken error: %v", err)
	}

	got, err := VerifyToken(token, pub)
	if err != nil {
		t.Fatalf("VerifyToken error: %v", err)
	}
	if got.TTL != 3600 {
		t.Errorf("TTL: got %d, want 3600", got.TTL)
	}
}

// Old tokens minted before P3 have no "ttl" claim. They must still
// verify cleanly against the current decoder. Unmarshal gives TTL=0,
// which SDKs treat as "server didn't signal TTL, fall back to per-call
// validation" — matches pre-P3 behaviour.
func TestVerifyToken_BackwardsCompatMissingTTL(t *testing.T) {
	pub, priv, err := GenerateEd25519Keypair()
	if err != nil {
		t.Fatal(err)
	}

	// Hand-build an old-shape payload (no TTL field) to simulate a token
	// minted by a pre-P3 server.
	legacy := struct {
		V      int    `json:"v"`
		PID    string `json:"pid"`
		LID    string `json:"lid"`
		Status string `json:"status"`
		IAT    int64  `json:"iat"`
	}{
		V: 1, PID: "prod-1", LID: "lic-1", Status: "active", IAT: 1700000000,
	}
	jsonBytes, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(jsonBytes)
	sig := Ed25519Sign(priv, []byte(payloadB64))
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	legacyToken := "gl1." + payloadB64 + "." + sigB64

	got, err := VerifyToken(legacyToken, pub)
	if err != nil {
		t.Fatalf("VerifyToken legacy: %v", err)
	}
	if got.TTL != 0 {
		t.Errorf("legacy token TTL = %d, want 0", got.TTL)
	}
	if got.ProductID != "prod-1" {
		t.Errorf("legacy token ProductID = %q, want prod-1", got.ProductID)
	}
}
