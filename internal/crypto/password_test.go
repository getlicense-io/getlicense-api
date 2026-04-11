package crypto

import (
	"strings"
	"testing"
)

func TestHashVerifyPassword_Roundtrip(t *testing.T) {
	password := "correct-horse-battery-staple"
	encoded, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword error: %v", err)
	}

	if !strings.HasPrefix(encoded, "$argon2id$") {
		t.Errorf("encoded hash missing argon2id prefix: %q", encoded)
	}

	if !VerifyPassword(encoded, password) {
		t.Error("VerifyPassword: correct password rejected")
	}
}

func TestVerifyPassword_WrongPassword(t *testing.T) {
	encoded, err := HashPassword("correct-password")
	if err != nil {
		t.Fatal(err)
	}

	if VerifyPassword(encoded, "wrong-password") {
		t.Error("VerifyPassword: wrong password accepted")
	}
}

func TestHashPassword_UniqueHashes(t *testing.T) {
	password := "same-password"
	h1, err := HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	if h1 == h2 {
		t.Error("HashPassword: same password produced identical hashes (salt not random)")
	}
}

func TestHashPassword_Format(t *testing.T) {
	encoded, err := HashPassword("testpassword")
	if err != nil {
		t.Fatal(err)
	}

	// Expected: $argon2id$v=19$m=65536,t=1,p=4$<salt>$<hash>
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 {
		t.Fatalf("expected 6 parts (split by $), got %d: %q", len(parts), encoded)
	}
	if parts[1] != "argon2id" {
		t.Errorf("expected argon2id, got %q", parts[1])
	}
	if parts[2] != "v=19" {
		t.Errorf("expected v=19, got %q", parts[2])
	}
	if parts[3] != "m=65536,t=1,p=4" {
		t.Errorf("expected m=65536,t=1,p=4, got %q", parts[3])
	}
}
