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

// TestSignJWT_EmitsStandardClaims confirms iss/aud/nbf/iat/exp/sub are
// all present on a freshly-signed token. Decode without verification
// since we just want the claims surface, not the signature check.
func TestSignJWT_EmitsStandardClaims(t *testing.T) {
	claims := makeTestJWTClaims()
	signed, err := SignJWT(claims, testJWTKey, time.Hour)
	if err != nil {
		t.Fatalf("SignJWT error: %v", err)
	}

	parsed, _, err := jwt.NewParser().ParseUnverified(signed, &jwtCustomClaims{})
	if err != nil {
		t.Fatalf("parse unverified: %v", err)
	}
	c, ok := parsed.Claims.(*jwtCustomClaims)
	if !ok {
		t.Fatal("claims not jwtCustomClaims")
	}
	if c.Issuer != JWTIssuer {
		t.Errorf("Issuer: got %q, want %q", c.Issuer, JWTIssuer)
	}
	if len(c.Audience) != 1 || c.Audience[0] != JWTAudience {
		t.Errorf("Audience: got %v, want [%q]", c.Audience, JWTAudience)
	}
	if c.NotBefore == nil {
		t.Error("NotBefore: missing")
	}
	if c.IssuedAt == nil {
		t.Error("IssuedAt: missing")
	}
	if c.ExpiresAt == nil {
		t.Error("ExpiresAt: missing")
	}
	if c.Subject != claims.IdentityID.String() {
		t.Errorf("Subject: got %q, want %q", c.Subject, claims.IdentityID.String())
	}
}

// TestVerifyJWT_RejectsWrongIssuer ensures a token minted by some
// other system that happens to share our signing key gets rejected
// at the iss check.
func TestVerifyJWT_RejectsWrongIssuer(t *testing.T) {
	now := time.Now()
	c := jwtCustomClaims{
		ActingAccountID: core.NewAccountID().String(),
		MembershipID:    core.NewMembershipID().String(),
		RoleSlug:        "admin",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "some-other-service",
			Audience:  jwt.ClaimStrings{JWTAudience},
			Subject:   core.NewIdentityID().String(),
			NotBefore: jwt.NewNumericDate(now.Add(-time.Second)),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	signed, err := token.SignedString(testJWTKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := VerifyJWT(signed, testJWTKey); err == nil {
		t.Error("VerifyJWT: expected error for wrong issuer, got nil")
	}
}

// TestVerifyJWT_RejectsWrongAudience ensures a token minted for a
// different audience (same issuer + key, e.g. an internal admin
// tool) cannot be presented to this API.
func TestVerifyJWT_RejectsWrongAudience(t *testing.T) {
	now := time.Now()
	c := jwtCustomClaims{
		ActingAccountID: core.NewAccountID().String(),
		MembershipID:    core.NewMembershipID().String(),
		RoleSlug:        "admin",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    JWTIssuer,
			Audience:  jwt.ClaimStrings{"internal-admin-tool"},
			Subject:   core.NewIdentityID().String(),
			NotBefore: jwt.NewNumericDate(now.Add(-time.Second)),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	signed, err := token.SignedString(testJWTKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := VerifyJWT(signed, testJWTKey); err == nil {
		t.Error("VerifyJWT: expected error for wrong audience, got nil")
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
