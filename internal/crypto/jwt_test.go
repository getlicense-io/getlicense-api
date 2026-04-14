package crypto

import (
	"testing"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
)

func makeTestJWTClaims() JWTClaims {
	return JWTClaims{
		IdentityID:      core.NewIdentityID(),
		ActingAccountID: core.NewAccountID(),
		MembershipID:    core.NewMembershipID(),
		RoleSlug:        "admin",
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

	if got.IdentityID.String() != claims.IdentityID.String() {
		t.Errorf("IdentityID: got %q, want %q", got.IdentityID.String(), claims.IdentityID.String())
	}
	if got.ActingAccountID.String() != claims.ActingAccountID.String() {
		t.Errorf("ActingAccountID: got %q, want %q", got.ActingAccountID.String(), claims.ActingAccountID.String())
	}
	if got.MembershipID.String() != claims.MembershipID.String() {
		t.Errorf("MembershipID: got %q, want %q", got.MembershipID.String(), claims.MembershipID.String())
	}
	if got.RoleSlug != claims.RoleSlug {
		t.Errorf("RoleSlug: got %q, want %q", got.RoleSlug, claims.RoleSlug)
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
