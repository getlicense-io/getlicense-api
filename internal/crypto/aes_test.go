package crypto

import (
	"bytes"
	"testing"
)

var testAESKey = []byte("test-aes-key-32-bytes-long!!!!!!") // exactly 32 bytes

func TestEncryptDecryptAESGCM_Roundtrip(t *testing.T) {
	plaintext := []byte("hello, world! this is a secret message.")
	aad := []byte("test:roundtrip")
	ciphertext, err := EncryptAESGCM(testAESKey, plaintext, aad)
	if err != nil {
		t.Fatalf("EncryptAESGCM error: %v", err)
	}

	decrypted, err := DecryptAESGCM(testAESKey, ciphertext, aad)
	if err != nil {
		t.Fatalf("DecryptAESGCM error: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("roundtrip failed: got %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptAESGCM_DifferentEachTime(t *testing.T) {
	plaintext := []byte("same plaintext")
	aad := []byte("test:nonce-randomness")
	ct1, err := EncryptAESGCM(testAESKey, plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}
	ct2, err := EncryptAESGCM(testAESKey, plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(ct1, ct2) {
		t.Error("EncryptAESGCM: same plaintext+AAD produced same ciphertext (nonce not random)")
	}
}

func TestDecryptAESGCM_WrongKey(t *testing.T) {
	plaintext := []byte("hello world")
	aad := []byte("test:wrong-key")
	ct, err := EncryptAESGCM(testAESKey, plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}

	wrongKey := []byte("wrong-aes-key-32-bytes-long!!!!!")
	_, err = DecryptAESGCM(wrongKey, ct, aad)
	if err == nil {
		t.Error("DecryptAESGCM: expected error for wrong key, got nil")
	}
}

func TestDecryptAESGCM_TamperedCiphertext(t *testing.T) {
	plaintext := []byte("hello world")
	aad := []byte("test:tamper")
	ct, err := EncryptAESGCM(testAESKey, plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}

	// Tamper with the last byte of ciphertext.
	tampered := make([]byte, len(ct))
	copy(tampered, ct)
	tampered[len(tampered)-1] ^= 0xff

	_, err = DecryptAESGCM(testAESKey, tampered, aad)
	if err == nil {
		t.Error("DecryptAESGCM: expected error for tampered ciphertext, got nil")
	}
}

func TestEncryptAESGCM_OutputLength(t *testing.T) {
	plaintext := []byte("hello world")
	aad := []byte("test:length")
	ct, err := EncryptAESGCM(testAESKey, plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}
	// Expected: 12 (nonce) + len(plaintext) + 16 (GCM tag).
	expected := 12 + len(plaintext) + 16
	if len(ct) != expected {
		t.Errorf("output length: got %d, want %d", len(ct), expected)
	}
}

func TestDecryptAESGCM_TooShort(t *testing.T) {
	short := []byte{0x00, 0x01, 0x02}
	if _, err := DecryptAESGCM(testAESKey, short, nil); err == nil {
		t.Error("DecryptAESGCM: expected error for too-short ciphertext, got nil")
	}
}
