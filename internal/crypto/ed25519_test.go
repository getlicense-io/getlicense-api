package crypto

import (
	"crypto/ed25519"
	"testing"
)

func TestGenerateEd25519Keypair_KeySizes(t *testing.T) {
	pub, priv, err := GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("GenerateEd25519Keypair error: %v", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Errorf("public key size: got %d, want %d", len(pub), ed25519.PublicKeySize)
	}
	if len(priv) != ed25519.PrivateKeySize {
		t.Errorf("private key size: got %d, want %d", len(priv), ed25519.PrivateKeySize)
	}
}

func TestEd25519SignVerify(t *testing.T) {
	pub, priv, err := GenerateEd25519Keypair()
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("sign this message")
	sig := Ed25519Sign(priv, message)

	if !Ed25519Verify(pub, message, sig) {
		t.Error("Ed25519Verify: valid signature rejected")
	}
}

func TestEd25519Verify_TamperedMessage(t *testing.T) {
	pub, priv, err := GenerateEd25519Keypair()
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("sign this message")
	sig := Ed25519Sign(priv, message)

	tampered := []byte("sign THIS message")
	if Ed25519Verify(pub, tampered, sig) {
		t.Error("Ed25519Verify: tampered message accepted")
	}
}

func TestEd25519Verify_WrongKey(t *testing.T) {
	_, priv, err := GenerateEd25519Keypair()
	if err != nil {
		t.Fatal(err)
	}

	wrongPub, _, err := GenerateEd25519Keypair()
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("sign this message")
	sig := Ed25519Sign(priv, message)

	if Ed25519Verify(wrongPub, message, sig) {
		t.Error("Ed25519Verify: wrong public key accepted")
	}
}

func TestEncodeDecodePublicKey_Roundtrip(t *testing.T) {
	pub, _, err := GenerateEd25519Keypair()
	if err != nil {
		t.Fatal(err)
	}

	encoded := EncodePublicKey(pub)
	decoded, err := DecodePublicKey(encoded)
	if err != nil {
		t.Fatalf("DecodePublicKey error: %v", err)
	}

	if !pub.Equal(decoded) {
		t.Error("EncodePublicKey/DecodePublicKey roundtrip: keys differ")
	}
}

func TestDecodePublicKey_Invalid(t *testing.T) {
	_, err := DecodePublicKey("not-a-valid-key!!!")
	if err == nil {
		t.Error("DecodePublicKey: expected error for invalid input, got nil")
	}
}
