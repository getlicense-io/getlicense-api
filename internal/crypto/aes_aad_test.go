package crypto

import (
	"bytes"
	"testing"
)

func TestEncryptAESGCMWithAAD_Roundtrip(t *testing.T) {
	plaintext := []byte("the secret payload")
	aad := []byte("webhook_endpoint:abc123:signing_secret")

	ct, err := EncryptAESGCMWithAAD(testAESKey, plaintext, aad)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if ct[0] != envelopeV2Magic {
		t.Fatalf("envelope[0]: got 0x%02x, want 0x%02x", ct[0], envelopeV2Magic)
	}

	pt, err := DecryptAESGCMWithAAD(testAESKey, ct, aad)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("roundtrip mismatch: got %q, want %q", pt, plaintext)
	}
}

func TestEncryptAESGCMWithAAD_WrongAADFails(t *testing.T) {
	plaintext := []byte("the secret payload")
	aad := []byte("webhook_endpoint:abc123:signing_secret")
	wrongAAD := []byte("webhook_endpoint:DIFFERENT:signing_secret")

	ct, err := EncryptAESGCMWithAAD(testAESKey, plaintext, aad)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	if _, err := DecryptAESGCMWithAAD(testAESKey, ct, wrongAAD); err == nil {
		t.Fatal("decrypt with wrong AAD should fail, got nil error")
	}
}

func TestEncryptAESGCMWithAAD_DifferentEachTime(t *testing.T) {
	plaintext := []byte("same plaintext")
	aad := []byte("identity:i1:totp_secret")
	ct1, err := EncryptAESGCMWithAAD(testAESKey, plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}
	ct2, err := EncryptAESGCMWithAAD(testAESKey, plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(ct1, ct2) {
		t.Error("EncryptAESGCMWithAAD: same input produced same ciphertext (nonce not random)")
	}
}

func TestDecryptAESGCMWithAAD_RejectsV1Envelope(t *testing.T) {
	// A v1 envelope (no magic byte, just nonce||ct||tag) cannot be
	// decrypted by the v2 path. Verify the path rejects when the
	// first byte is not the v2 magic.
	plaintext := []byte("v1 plaintext")
	v1ct, err := EncryptAESGCM(testAESKey, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	// Force the first byte to be NOT the v2 magic so we can test
	// the magic-byte rejection branch deterministically.
	if v1ct[0] == envelopeV2Magic {
		v1ct[0] = 0x00
	}
	if _, err := DecryptAESGCMWithAAD(testAESKey, v1ct, nil); err == nil {
		t.Fatal("v2 decrypt of v1 envelope should fail, got nil error")
	}
}

func TestDecryptAESGCMWithAAD_TooShort(t *testing.T) {
	short := []byte{envelopeV2Magic, 0x00, 0x01}
	if _, err := DecryptAESGCMWithAAD(testAESKey, short, nil); err == nil {
		t.Fatal("v2 decrypt of too-short envelope should fail, got nil error")
	}
}

func TestEncryptAESGCMWithAAD_OutputLength(t *testing.T) {
	plaintext := []byte("hello world")
	aad := []byte("identity:i1:totp_secret")
	ct, err := EncryptAESGCMWithAAD(testAESKey, plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}
	// Expected: 1 (magic) + 12 (nonce) + len(plaintext) + 16 (GCM tag)
	expected := 1 + 12 + len(plaintext) + 16
	if len(ct) != expected {
		t.Errorf("output length: got %d, want %d", len(ct), expected)
	}
}

func TestDecryptAESGCMWithAAD_TamperedCiphertext(t *testing.T) {
	plaintext := []byte("hello world")
	aad := []byte("aad")
	ct, err := EncryptAESGCMWithAAD(testAESKey, plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}
	tampered := make([]byte, len(ct))
	copy(tampered, ct)
	tampered[len(tampered)-1] ^= 0xff
	if _, err := DecryptAESGCMWithAAD(testAESKey, tampered, aad); err == nil {
		t.Fatal("tampered ciphertext should fail GCM auth, got nil error")
	}
}

// TestMasterKeyDecryptAuto_HandlesV1Envelope verifies that v1 blobs
// (legacy, no AAD) decrypt cleanly through DecryptAuto when the
// supplied AAD is whatever caller wants — DecryptAuto must IGNORE
// AAD on the v1 path.
func TestMasterKeyDecryptAuto_HandlesV1Envelope(t *testing.T) {
	mk := newTestMasterKey(t)
	plaintext := []byte("v1 legacy blob")

	v1ct, err := mk.Encrypt(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	// Force first byte off magic so we don't accidentally hit the
	// v2-attempt-then-fall-back branch (covered by another test).
	if v1ct[0] == envelopeV2Magic {
		v1ct[0] = 0x00
	}

	pt, err := mk.DecryptAuto(v1ct, []byte("aad-ignored-on-v1"))
	if err != nil {
		t.Fatalf("DecryptAuto on v1: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("v1 plaintext mismatch: got %q, want %q", pt, plaintext)
	}
}

func TestMasterKeyDecryptAuto_HandlesV2Envelope(t *testing.T) {
	mk := newTestMasterKey(t)
	plaintext := []byte("v2 with aad")
	aad := []byte("product:p1:private_key")

	v2ct, err := mk.EncryptWithAAD(plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}

	pt, err := mk.DecryptAuto(v2ct, aad)
	if err != nil {
		t.Fatalf("DecryptAuto on v2: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("v2 plaintext mismatch: got %q, want %q", pt, plaintext)
	}
}

func TestMasterKeyDecryptAuto_RejectsV2WithWrongAAD(t *testing.T) {
	mk := newTestMasterKey(t)
	plaintext := []byte("v2 with aad")

	v2ct, err := mk.EncryptWithAAD(plaintext, []byte("right-aad"))
	if err != nil {
		t.Fatal(err)
	}

	// Wrong AAD: v2 path fails. First byte IS the v2 magic so the
	// v1 fallback IS attempted — but the v1 Open will also fail
	// because the bytes are not a valid v1 envelope (the data layout
	// is different). DecryptAuto must return an error.
	if _, err := mk.DecryptAuto(v2ct, []byte("wrong-aad")); err == nil {
		t.Fatal("DecryptAuto with wrong AAD on v2 should fail, got nil")
	}
}

// TestMasterKeyDecryptAuto_FallsBackForV1NonceWithMagicByte synthesizes
// a v1 ciphertext whose first byte (the start of the random nonce)
// happens to equal the v2 magic byte 0x02. ~1/256 of fresh v1 reads
// hit this case in production. DecryptAuto's v2-attempt-then-v1-
// fallback branch must recover the plaintext.
func TestMasterKeyDecryptAuto_FallsBackForV1NonceWithMagicByte(t *testing.T) {
	mk := newTestMasterKey(t)
	plaintext := []byte("collision case payload")

	// Generate v1 ciphertexts until we get one whose first byte
	// equals the v2 magic. Cap iterations so a pathological RNG
	// can't hang the test.
	const maxAttempts = 1000
	var v1ct []byte
	for i := 0; i < maxAttempts; i++ {
		ct, err := mk.Encrypt(plaintext)
		if err != nil {
			t.Fatal(err)
		}
		if ct[0] == envelopeV2Magic {
			v1ct = ct
			break
		}
	}
	if v1ct == nil {
		t.Skipf("no v1 ciphertext starting with 0x02 in %d attempts; rerun", maxAttempts)
	}

	// AAD is irrelevant — v1 must decrypt regardless.
	pt, err := mk.DecryptAuto(v1ct, []byte("any-aad-here"))
	if err != nil {
		t.Fatalf("v1 fallback failed for nonce starting with magic byte: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("v1 fallback plaintext mismatch: got %q, want %q", pt, plaintext)
	}
}

func TestMasterKeyEncryptWithAAD_RoundtripViaWithAAD(t *testing.T) {
	mk := newTestMasterKey(t)
	plaintext := []byte("masterkey roundtrip")
	aad := []byte("identity:i1:totp_secret")

	ct, err := mk.EncryptWithAAD(plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := mk.DecryptWithAAD(ct, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("roundtrip mismatch: got %q, want %q", pt, plaintext)
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
