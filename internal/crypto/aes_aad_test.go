package crypto

import (
	"bytes"
	"testing"
)

// AAD is mandatory at every encrypt and decrypt site (PR-C refinement).
// These tests cover the AES-GCM primitives directly; the per-purpose
// swap-defense tests live in aad_swap_test.go.

func TestEncryptAESGCM_AADRoundtrip(t *testing.T) {
	plaintext := []byte("the secret payload")
	aad := []byte("webhook_endpoint:abc123:signing_secret")

	ct, err := EncryptAESGCM(testAESKey, plaintext, aad)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	pt, err := DecryptAESGCM(testAESKey, ct, aad)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("roundtrip mismatch: got %q, want %q", pt, plaintext)
	}
}

func TestDecryptAESGCM_WrongAADFails(t *testing.T) {
	plaintext := []byte("the secret payload")
	aad := []byte("webhook_endpoint:abc123:signing_secret")
	wrongAAD := []byte("webhook_endpoint:DIFFERENT:signing_secret")

	ct, err := EncryptAESGCM(testAESKey, plaintext, aad)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	if _, err := DecryptAESGCM(testAESKey, ct, wrongAAD); err == nil {
		t.Fatal("decrypt with wrong AAD should fail, got nil error")
	}
}

func TestDecryptAESGCM_NilAADAfterAADBoundEncryptFails(t *testing.T) {
	// A ciphertext bound to non-empty AAD must not decrypt with nil
	// AAD. This is the regression guard that prevents reintroducing a
	// "no-AAD shortcut" by accident.
	plaintext := []byte("aad-bound payload")
	ct, err := EncryptAESGCM(testAESKey, plaintext, []byte("some-aad"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecryptAESGCM(testAESKey, ct, nil); err == nil {
		t.Fatal("decrypt with nil AAD should fail, got nil error")
	}
}

func TestMasterKey_EncryptDecryptRoundtrip(t *testing.T) {
	mk := newTestMasterKey(t)
	plaintext := []byte("masterkey roundtrip")
	aad := []byte("identity:i1:totp_secret")

	ct, err := mk.Encrypt(plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := mk.Decrypt(ct, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("roundtrip mismatch: got %q, want %q", pt, plaintext)
	}
}

func TestMasterKey_DecryptRejectsWrongAAD(t *testing.T) {
	mk := newTestMasterKey(t)
	plaintext := []byte("aad-bound")

	ct, err := mk.Encrypt(plaintext, []byte("right-aad"))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := mk.Decrypt(ct, []byte("wrong-aad")); err == nil {
		t.Fatal("Decrypt with wrong AAD should fail, got nil")
	}
}

// TestMasterKey_DecryptLegacyNoAAD covers the migration-only path used
// by cmd/server/migrate_aad.go to port pre-AAD ciphertexts.
func TestMasterKey_DecryptLegacyNoAAD(t *testing.T) {
	mk := newTestMasterKey(t)
	plaintext := []byte("legacy blob")

	// Synthesize a pre-AAD ciphertext via the package-private helper
	// (calling the new Encrypt with nil AAD produces a byte-compatible
	// envelope with the pre-AAD format).
	ct, err := EncryptAESGCM(mk.encryptionKey, plaintext, nil)
	if err != nil {
		t.Fatal(err)
	}

	got, err := mk.DecryptLegacyNoAAD(ct)
	if err != nil {
		t.Fatalf("DecryptLegacyNoAAD: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext mismatch: got %q, want %q", got, plaintext)
	}
}

// TestMigrationFlow simulates the startup migration: read a legacy
// ciphertext with DecryptLegacyNoAAD, re-encrypt with the AAD-required
// path, and verify it round-trips with the proper Decrypt + AAD.
func TestMigrationFlow_LegacyToAAD(t *testing.T) {
	mk := newTestMasterKey(t)
	plaintext := []byte("port me forward")
	aad := []byte("webhook_endpoint:legacy-id:signing_secret")

	// Pre-AAD ciphertext sitting on disk.
	legacy, err := EncryptAESGCM(mk.encryptionKey, plaintext, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Migrate.
	got, err := mk.DecryptLegacyNoAAD(legacy)
	if err != nil {
		t.Fatalf("legacy decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("legacy plaintext mismatch: got %q, want %q", got, plaintext)
	}
	migrated, err := mk.Encrypt(got, aad)
	if err != nil {
		t.Fatalf("re-encrypt with AAD: %v", err)
	}

	// Read post-migration with the proper AAD.
	final, err := mk.Decrypt(migrated, aad)
	if err != nil {
		t.Fatalf("post-migration decrypt: %v", err)
	}
	if !bytes.Equal(final, plaintext) {
		t.Fatalf("post-migration plaintext mismatch: got %q, want %q", final, plaintext)
	}
	// Wrong AAD must still fail post-migration.
	if _, err := mk.Decrypt(migrated, []byte("other-aad")); err == nil {
		t.Fatal("post-migration decrypt with wrong AAD should fail")
	}
}

// newTestMasterKey returns a MasterKey usable in unit tests. The hex
// string is exactly 64 chars (32 bytes) of a deterministic value so
// runs are reproducible.
func newTestMasterKey(t *testing.T) *MasterKey {
	t.Helper()
	const hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	mk, err := NewMasterKey(hex)
	if err != nil {
		t.Fatalf("NewMasterKey: %v", err)
	}
	return mk
}
