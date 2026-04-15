package crypto_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
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
	tampered := token[:len(token)-1] + "A"
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
