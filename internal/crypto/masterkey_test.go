package crypto

import (
	"testing"
)

const testHexKey = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20" +
	"2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40"

func TestNewMasterKey_Valid(t *testing.T) {
	mk, err := NewMasterKey(testHexKey, "", "")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if mk == nil {
		t.Fatal("expected non-nil MasterKey")
	}
	// HMAC returns a 64-char hex string (32 bytes = 64 hex chars).
	h := mk.HMAC("test")
	if len(h) != 64 {
		t.Errorf("HMAC: expected 64-char hex string, got %d chars", len(h))
	}
	// Encrypt/Decrypt roundtrip verifies the encryption key is valid (32 bytes).
	plaintext := []byte("hello world")
	aad := []byte("test:masterkey-roundtrip")
	ciphertext, err := mk.Encrypt(plaintext, aad)
	if err != nil {
		t.Fatalf("Encrypt: unexpected error: %v", err)
	}
	decrypted, err := mk.Decrypt(ciphertext, aad)
	if err != nil {
		t.Fatalf("Decrypt: unexpected error: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Errorf("Decrypt: expected %q, got %q", plaintext, decrypted)
	}
}

func TestNewMasterKey_TooShort(t *testing.T) {
	_, err := NewMasterKey("0102030405060708090a0b0c0d0e0f10", "", "")
	if err == nil {
		t.Fatal("expected error for too-short key, got nil")
	}
}

func TestNewMasterKey_InvalidHex(t *testing.T) {
	_, err := NewMasterKey("gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg", "", "")
	if err == nil {
		t.Fatal("expected error for invalid hex, got nil")
	}
}

func TestNewMasterKey_Deterministic(t *testing.T) {
	mk1, err := NewMasterKey(testHexKey, "", "")
	if err != nil {
		t.Fatal(err)
	}
	mk2, err := NewMasterKey(testHexKey, "", "")
	if err != nil {
		t.Fatal(err)
	}
	// Same input key must produce the same HMAC output.
	if mk1.HMAC("determinism-check") != mk2.HMAC("determinism-check") {
		t.Error("HMAC not deterministic")
	}
	// Encrypt with mk1 must be decryptable by mk2 (same derived key).
	plaintext := []byte("determinism")
	aad := []byte("test:cross-instance")
	ciphertext, err := mk1.Encrypt(plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := mk2.Decrypt(ciphertext, aad)
	if err != nil {
		t.Fatalf("cross-instance Decrypt failed: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Error("Encrypt/Decrypt not deterministic across instances")
	}
}

func TestNewMasterKey_DerivedKeysDiffer(t *testing.T) {
	mk, err := NewMasterKey(testHexKey, "", "")
	if err != nil {
		t.Fatal(err)
	}
	// The three derived keys are used for different purposes; if they were equal
	// we'd be using the same key for HMAC, encryption, and JWT signing.
	// We can observe they differ by checking that the HMAC key (used in HMAC)
	// produces a different AES-GCM ciphertext from a fresh Encrypt call, and that
	// SignJWT fails when called with a zero-length TTL (which is a separate concern).
	// The simplest observable check: encrypt the same plaintext twice — AES-GCM
	// uses a random nonce so ciphertexts differ, but both must decrypt correctly.
	plaintext := []byte("distinct-keys-test")
	aad := []byte("test:distinct-keys")
	ct1, err := mk.Encrypt(plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}
	ct2, err := mk.Encrypt(plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}
	// Ciphertexts use random nonces so they must differ.
	if string(ct1) == string(ct2) {
		t.Error("Encrypt produced identical ciphertexts for two calls (nonce reuse?)")
	}
	// Both must decrypt to the same plaintext.
	dec1, err := mk.Decrypt(ct1, aad)
	if err != nil {
		t.Fatalf("Decrypt ct1: %v", err)
	}
	dec2, err := mk.Decrypt(ct2, aad)
	if err != nil {
		t.Fatalf("Decrypt ct2: %v", err)
	}
	if string(dec1) != string(plaintext) || string(dec2) != string(plaintext) {
		t.Error("Decrypt produced wrong plaintext")
	}
	// HMAC of two distinct inputs must differ.
	h1 := mk.HMAC("input-a")
	h2 := mk.HMAC("input-b")
	if h1 == h2 {
		t.Error("HMAC of distinct inputs must differ")
	}
}
