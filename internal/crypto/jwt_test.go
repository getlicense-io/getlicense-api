package crypto

import (
	"testing"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
)

func makeTestJWTClaims() JWTClaims {
	return JWTClaims{
		UserID:    core.NewUserID(),
		AccountID: core.NewAccountID(),
		Role:      core.UserRoleAdmin,
	}
}

var testJWTKey = []byte("test-jwt-signing-key-32-bytes!!!")

func TestSignVerifyJWT_Roundtrip(t *testing.T) {
	claims := makeTestJWTClaims()

	token, err := SignJWT(claims, testJWTKey, time.Hour)
	if err != nil {
		t.Fatalf("SignJWT error: %v", err)
	}

	got, err := VerifyJWT(token, testJWTKey)
	if err != nil {
		t.Fatalf("VerifyJWT error: %v", err)
	}

	if got.UserID.String() != claims.UserID.String() {
		t.Errorf("UserID: got %q, want %q", got.UserID.String(), claims.UserID.String())
	}
	if got.AccountID.String() != claims.AccountID.String() {
		t.Errorf("AccountID: got %q, want %q", got.AccountID.String(), claims.AccountID.String())
	}
	if got.Role != claims.Role {
		t.Errorf("Role: got %q, want %q", got.Role, claims.Role)
	}
}

func TestVerifyJWT_ExpiredToken(t *testing.T) {
	claims := makeTestJWTClaims()

	// Sign with a negative TTL (already expired)
	token, err := SignJWT(claims, testJWTKey, -time.Second)
	if err != nil {
		t.Fatalf("SignJWT error: %v", err)
	}

	_, err = VerifyJWT(token, testJWTKey)
	if err == nil {
		t.Error("VerifyJWT: expected error for expired token, got nil")
	}
}

func TestVerifyJWT_WrongKey(t *testing.T) {
	claims := makeTestJWTClaims()

	token, err := SignJWT(claims, testJWTKey, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	wrongKey := []byte("wrong-jwt-signing-key-32-bytes!!")
	_, err = VerifyJWT(token, wrongKey)
	if err == nil {
		t.Error("VerifyJWT: expected error for wrong key, got nil")
	}
}
