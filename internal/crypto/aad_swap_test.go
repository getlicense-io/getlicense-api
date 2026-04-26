package crypto_test

import (
	"testing"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/crypto"
)

// These tests are the regression guards for PR-C's swap-defense
// invariant: a ciphertext encrypted under one entity's AAD must NOT
// decrypt cleanly when the wrong entity's AAD is supplied. They
// directly exercise the AAD helpers used at every encrypt/decrypt
// site in the repo, so a drift in the AAD format string surfaces
// here before it surfaces as a webhook-delivery failure in e2e.

func newTestMK(t *testing.T) *crypto.MasterKey {
	t.Helper()
	mk, err := crypto.NewMasterKey("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("NewMasterKey: %v", err)
	}
	return mk
}

func TestWebhookSigningSecret_DecryptFailsIfMovedToOtherEndpoint(t *testing.T) {
	mk := newTestMK(t)
	endpointA := core.NewWebhookEndpointID()
	endpointB := core.NewWebhookEndpointID()

	plaintext := []byte("super-secret-hmac-key")
	ct, err := mk.Encrypt(plaintext, crypto.WebhookSigningSecretAAD(endpointA))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Sanity: correct AAD round-trips.
	got, err := mk.Decrypt(ct, crypto.WebhookSigningSecretAAD(endpointA))
	if err != nil {
		t.Fatalf("decrypt with correct AAD: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("plaintext mismatch: got %q, want %q", got, plaintext)
	}

	// Attack: paste this ciphertext into endpointB's row. Decrypt
	// MUST fail GCM auth.
	if _, err := mk.Decrypt(ct, crypto.WebhookSigningSecretAAD(endpointB)); err == nil {
		t.Fatal("decrypt with endpointB's AAD succeeded; ciphertext is not bound to endpointA")
	}
}

func TestTOTPSecret_DecryptFailsIfMovedToOtherIdentity(t *testing.T) {
	mk := newTestMK(t)
	identityA := core.NewIdentityID()
	identityB := core.NewIdentityID()

	plaintext := []byte("base32totpsecret==")
	ct, err := mk.Encrypt(plaintext, crypto.TOTPSecretAAD(identityA))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	if got, err := mk.Decrypt(ct, crypto.TOTPSecretAAD(identityA)); err != nil {
		t.Fatalf("decrypt with correct AAD: %v", err)
	} else if string(got) != string(plaintext) {
		t.Fatalf("plaintext mismatch: got %q, want %q", got, plaintext)
	}

	if _, err := mk.Decrypt(ct, crypto.TOTPSecretAAD(identityB)); err == nil {
		t.Fatal("decrypt with identityB's AAD succeeded; TOTP ciphertext is not bound to identityA")
	}
}

func TestProductPrivateKey_DecryptFailsIfMovedToOtherProduct(t *testing.T) {
	mk := newTestMK(t)
	productA := core.NewProductID()
	productB := core.NewProductID()

	// Use a 64-byte buffer to mimic an Ed25519 private key shape.
	plaintext := make([]byte, 64)
	for i := range plaintext {
		plaintext[i] = byte(i)
	}

	ct, err := mk.Encrypt(plaintext, crypto.ProductPrivateKeyAAD(productA))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	if got, err := mk.Decrypt(ct, crypto.ProductPrivateKeyAAD(productA)); err != nil {
		t.Fatalf("decrypt with correct AAD: %v", err)
	} else if string(got) != string(plaintext) {
		t.Fatal("plaintext mismatch")
	}

	if _, err := mk.Decrypt(ct, crypto.ProductPrivateKeyAAD(productB)); err == nil {
		t.Fatal("decrypt with productB's AAD succeeded; private-key ciphertext is not bound to productA")
	}
}

// TestPurposeMismatch_DecryptFails verifies that ciphertexts cannot
// be moved across purposes within the same id namespace either —
// a webhook endpoint's signing secret pasted into a TOTP row (or
// vice versa, with matching uuid bytes) must still fail GCM auth.
//
// The attack model: an attacker who controls DB writes might try
// to use one column's ciphertext to satisfy another column. AAD
// purpose suffixes ("signing_secret" vs "totp_secret" vs
// "private_key") prevent this even when the underlying UUID bytes
// happen to collide.
func TestPurposeMismatch_DecryptFails(t *testing.T) {
	mk := newTestMK(t)

	// Reuse the same 16 random bytes as the id for two different
	// entity types. A real-world collision is astronomically
	// unlikely, but this proves the purpose suffix is what closes
	// the gap.
	rawID := core.NewWebhookEndpointID()
	wid := rawID
	idstr := rawID.String()

	plaintext := []byte("payload-bytes")
	ct, err := mk.Encrypt(plaintext, crypto.WebhookSigningSecretAAD(wid))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Hand-built TOTP AAD using the same id string. Fails because
	// the purpose suffix differs.
	wrongPurposeAAD := []byte("identity:" + idstr + ":totp_secret")
	if _, err := mk.Decrypt(ct, wrongPurposeAAD); err == nil {
		t.Fatal("decrypt with wrong-purpose AAD succeeded; purpose suffix does not bind ciphertext")
	}
}
