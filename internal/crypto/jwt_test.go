package crypto

import (
	"testing"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/golang-jwt/jwt/v5"
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

// TestVerifyJWT_RejectsHS512 ensures the verification path pins to
// HS256 exactly. A token signed with HS512 (same HMAC family) using
// the same key MUST be rejected — otherwise an attacker who can
// influence the alg header could downgrade verification semantics.
func TestVerifyJWT_RejectsHS512(t *testing.T) {
	now := time.Now()
	c := jwtCustomClaims{
		ActingAccountID: core.NewAccountID().String(),
		MembershipID:    core.NewMembershipID().String(),
		RoleSlug:        "admin",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   core.NewIdentityID().String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, c)
	signed, err := token.SignedString(testJWTKey)
	if err != nil {
		t.Fatalf("sign HS512: %v", err)
	}

	_, err = VerifyJWT(signed, testJWTKey)
	if err == nil {
		t.Error("VerifyJWT: expected error for HS512-signed token, got nil")
	}
}

// TestVerifyJWT_RejectsAlgNone ensures the "alg: none" downgrade
// attack is rejected. Without explicit method pinning the jwt
// library refuses "none" by default, but pinning HS256 also closes
// any future regression path.
func TestVerifyJWT_RejectsAlgNone(t *testing.T) {
	now := time.Now()
	c := jwtCustomClaims{
		ActingAccountID: core.NewAccountID().String(),
		MembershipID:    core.NewMembershipID().String(),
		RoleSlug:        "admin",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   core.NewIdentityID().String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodNone, c)
	signed, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign none: %v", err)
	}

	_, err = VerifyJWT(signed, testJWTKey)
	if err == nil {
		t.Error("VerifyJWT: expected error for alg=none token, got nil")
	}
}
