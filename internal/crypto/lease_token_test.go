package crypto_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/getlicense-io/getlicense-api/internal/crypto"
)

func TestLeaseToken_RoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload := crypto.LeaseTokenPayload{
		Version:         1,
		LicenseID:       "lic_1",
		ProductID:       "prod_1",
		PolicyID:        "pol_1",
		MachineID:       "mach_1",
		Fingerprint:     "fp-sha256",
		LicenseStatus:   "active",
		LicenseExpires:  0,
		LeaseIssuedAt:   1700000000,
		LeaseExpiresAt:  1700000600,
		RequiresCheckin: true,
		GraceSec:        3600,
		Entitlements:    []string{},
		IssuedAt:        1700000000,
		ExpiresAt:       1700000600,
		JTI:             "abcdef0123456789",
	}
	token, err := crypto.SignLeaseToken(payload, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if len(token) < 10 || token[:4] != "gl2." {
		t.Errorf("token does not start with gl2.: %q", token)
	}
	got, err := crypto.VerifyLeaseToken(token, pub)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	wantJSON, _ := json.Marshal(payload)
	gotJSON, _ := json.Marshal(got)
	if string(wantJSON) != string(gotJSON) {
		t.Errorf("payload mismatch:\nwant %s\n got %s", wantJSON, gotJSON)
	}
}

func TestLeaseToken_TamperedSignatureFails(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	payload := crypto.LeaseTokenPayload{LicenseID: "lic_1", LeaseExpiresAt: 1700000600, ExpiresAt: 1700000600}
	token, _ := crypto.SignLeaseToken(payload, priv)
	// Flip a byte in the middle of the signature (not the last char,
	// which can be a no-op due to base64url padding bit alignment).
	b := []byte(token)
	b[len(b)-5] ^= 0xFF
	tampered := string(b)
	if _, err := crypto.VerifyLeaseToken(tampered, pub); err == nil {
		t.Error("verify accepted tampered signature")
	}
}

func TestLeaseToken_WrongPubKeyFails(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	payload := crypto.LeaseTokenPayload{LicenseID: "lic_1", LeaseExpiresAt: 1700000600, ExpiresAt: 1700000600}
	token, _ := crypto.SignLeaseToken(payload, priv)
	if _, err := crypto.VerifyLeaseToken(token, otherPub); err == nil {
		t.Error("verify accepted wrong public key")
	}
}

func TestLeaseToken_WrongPrefixFails(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	payload := crypto.LeaseTokenPayload{LicenseID: "lic_1", LeaseExpiresAt: 1700000600, ExpiresAt: 1700000600}
	token, _ := crypto.SignLeaseToken(payload, priv)
	wrong := "gl1" + token[3:]
	if _, err := crypto.VerifyLeaseToken(wrong, pub); err == nil {
		t.Error("verify accepted gl1 prefix")
	}
}

// TestGenerateLeaseTokenVector is a one-shot generator for the SDK test
// vector. Run with `go test -run TestGenerateLeaseTokenVector ./internal/crypto/`
// after any change to LeaseTokenPayload to regenerate the vector.
func TestGenerateLeaseTokenVector(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping vector generation in short mode")
	}
	// Deterministic seed for reproducibility.
	seed := bytes.Repeat([]byte{0x42}, 32)
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	payload := crypto.LeaseTokenPayload{
		Version:         1,
		LicenseID:       "01000000-0000-7000-8000-000000000001",
		ProductID:       "01000000-0000-7000-8000-000000000002",
		PolicyID:        "01000000-0000-7000-8000-000000000003",
		LicenseStatus:   "active",
		LicenseExpires:  1735689600,
		MachineID:       "01000000-0000-7000-8000-000000000004",
		Fingerprint:     "fp-sha256-test-vector",
		LeaseIssuedAt:   1700000000,
		LeaseExpiresAt:  1700003600,
		RequiresCheckin: true,
		GraceSec:        3600,
		Entitlements:    []string{},
		IssuedAt:        1700000000,
		ExpiresAt:       1700003600,
		JTI:             "fixed16bytehex01",
	}
	token, err := crypto.SignLeaseToken(payload, priv)
	if err != nil {
		t.Fatal(err)
	}

	vector := map[string]any{
		"description":      "Deterministic lease token vector for SDK verifiers",
		"public_key_hex":   hex.EncodeToString(pub),
		"private_seed_hex": hex.EncodeToString(seed),
		"signed_token":     token,
		"decoded_payload":  payload,
	}
	data, _ := json.MarshalIndent(vector, "", "  ")
	// Path relative to the crypto package (../../testdata/)
	if err := os.WriteFile("../../testdata/lease_token_vector.json", data, 0644); err != nil {
		t.Fatal(err)
	}
	t.Logf("vector written to testdata/lease_token_vector.json")
}
