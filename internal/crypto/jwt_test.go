package crypto

import (
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

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

// testRegistry returns a JWTKeyRegistry running in implicit mode with
// testJWTKey as the HKDF-derived key. Every signed token embeds
// kid=v0 (ImplicitDefaultKID).
func testRegistry(t *testing.T) *JWTKeyRegistry {
	t.Helper()
	reg, err := NewJWTKeyRegistryFromConfig("", "", testJWTKey)
	if err != nil {
		t.Fatalf("testRegistry: %v", err)
	}
	return reg
}

func TestSignVerifyJWT_Roundtrip(t *testing.T) {
	claims := makeTestJWTClaims()
	reg := testRegistry(t)

	token, err := SignJWT(claims, reg, time.Hour)
	if err != nil {
		t.Fatalf("SignJWT error: %v", err)
	}

	got, err := VerifyJWT(token, reg)
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
	reg := testRegistry(t)

	// Sign with a negative TTL (already expired)
	token, err := SignJWT(claims, reg, -time.Second)
	if err != nil {
		t.Fatalf("SignJWT error: %v", err)
	}

	_, err = VerifyJWT(token, reg)
	if err == nil {
		t.Error("VerifyJWT: expected error for expired token, got nil")
	}
}

func TestVerifyJWT_WrongKey(t *testing.T) {
	claims := makeTestJWTClaims()
	reg := testRegistry(t)

	token, err := SignJWT(claims, reg, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	wrongReg, err := NewJWTKeyRegistryFromConfig("", "", []byte("wrong-jwt-signing-key-32-bytes!!"))
	if err != nil {
		t.Fatalf("wrongReg: %v", err)
	}
	_, err = VerifyJWT(token, wrongReg)
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

	_, err = VerifyJWT(signed, testRegistry(t))
	if err == nil {
		t.Error("VerifyJWT: expected error for HS512-signed token, got nil")
	}
}

// TestSignJWT_EmitsStandardClaims confirms iss/aud/nbf/iat/exp/sub/jti
// are all present on a freshly-signed token. Decode without
// verification since we just want the claims surface, not the
// signature check.
func TestSignJWT_EmitsStandardClaims(t *testing.T) {
	claims := makeTestJWTClaims()
	signed, err := SignJWT(claims, testRegistry(t), time.Hour)
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
	if c.ID == "" {
		t.Error("ID (jti): missing — every signed JWT must carry a jti claim for revocation routing")
	}
	if _, perr := core.ParseJTI(c.ID); perr != nil {
		t.Errorf("ID (jti): got %q, not a parseable JTI: %v", c.ID, perr)
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
	if _, err := VerifyJWT(signed, testRegistry(t)); err == nil {
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
	if _, err := VerifyJWT(signed, testRegistry(t)); err == nil {
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

	_, err = VerifyJWT(signed, testRegistry(t))
	if err == nil {
		t.Error("VerifyJWT: expected error for alg=none token, got nil")
	}
}

// TestSignJWT_EmbedsKidInHeader_WhenRegistryHasMultipleKeys verifies
// that the kid header is set to the registry's current id, so
// verifiers under rotation can route to the right key.
func TestSignJWT_EmbedsKidInHeader_WhenRegistryHasMultipleKeys(t *testing.T) {
	v1Hex := strings.Repeat("aa", 32)
	v2Hex := strings.Repeat("bb", 32)
	reg, err := NewJWTKeyRegistryFromConfig("v1:"+v1Hex+",v2:"+v2Hex, "v2", testJWTKey)
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	signed, err := SignJWT(makeTestJWTClaims(), reg, time.Hour)
	if err != nil {
		t.Fatalf("SignJWT: %v", err)
	}
	parsed, _, err := jwt.NewParser().ParseUnverified(signed, &jwtCustomClaims{})
	if err != nil {
		t.Fatalf("parse unverified: %v", err)
	}
	if parsed.Header["kid"] != "v2" {
		t.Errorf("kid header: got %v, want %q", parsed.Header["kid"], "v2")
	}
}

// TestVerifyJWT_LooksUpKidFromHeader confirms the verifier picks the
// key matching the kid header — a token signed under v1 must verify
// against v1's bytes even when v2 is current.
func TestVerifyJWT_LooksUpKidFromHeader(t *testing.T) {
	v1Hex := strings.Repeat("aa", 32)
	v2Hex := strings.Repeat("bb", 32)
	regV1Current, err := NewJWTKeyRegistryFromConfig("v1:"+v1Hex+",v2:"+v2Hex, "v1", testJWTKey)
	if err != nil {
		t.Fatalf("regV1Current: %v", err)
	}
	regV2Current, err := NewJWTKeyRegistryFromConfig("v1:"+v1Hex+",v2:"+v2Hex, "v2", testJWTKey)
	if err != nil {
		t.Fatalf("regV2Current: %v", err)
	}
	// Token minted under v1 must verify under a registry where v2 is
	// the current kid (v1 is still in the lookup map).
	signed, err := SignJWT(makeTestJWTClaims(), regV1Current, time.Hour)
	if err != nil {
		t.Fatalf("SignJWT: %v", err)
	}
	if _, err := VerifyJWT(signed, regV2Current); err != nil {
		t.Errorf("VerifyJWT under v2-current registry should accept v1-signed token: %v", err)
	}
}

// TestVerifyJWT_RejectsTokenWithoutKid confirms a token minted with no
// kid JOSE header is rejected. There is no fallback path — every signed
// JWT must carry a kid the registry knows.
func TestVerifyJWT_RejectsTokenWithoutKid(t *testing.T) {
	now := time.Now()
	c := jwtCustomClaims{
		ActingAccountID: core.NewAccountID().String(),
		MembershipID:    core.NewMembershipID().String(),
		RoleSlug:        "admin",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    JWTIssuer,
			Audience:  jwt.ClaimStrings{JWTAudience},
			Subject:   core.NewIdentityID().String(),
			NotBefore: jwt.NewNumericDate(now.Add(-time.Second)),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			ID:        core.NewJTI().String(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	// IMPORTANT: do NOT set token.Header["kid"]. The verifier must
	// reject this token — there is no kid-absent fallback.
	if _, ok := token.Header["kid"]; ok {
		t.Fatal("test setup error: expected no kid header on bare jwt.NewWithClaims output")
	}
	signed, err := token.SignedString(testJWTKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := VerifyJWT(signed, testRegistry(t)); err == nil {
		t.Error("VerifyJWT: expected error for kid-less token, got nil")
	}
}

// TestVerifyJWT_RejectsTokenWithoutJTI confirms a token minted without
// a jti claim is rejected. The revocation middleware needs jti to be
// present on every token.
func TestVerifyJWT_RejectsTokenWithoutJTI(t *testing.T) {
	now := time.Now()
	c := jwtCustomClaims{
		ActingAccountID: core.NewAccountID().String(),
		MembershipID:    core.NewMembershipID().String(),
		RoleSlug:        "admin",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    JWTIssuer,
			Audience:  jwt.ClaimStrings{JWTAudience},
			Subject:   core.NewIdentityID().String(),
			NotBefore: jwt.NewNumericDate(now.Add(-time.Second)),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			// ID intentionally omitted (zero string)
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	token.Header["kid"] = ImplicitDefaultKID
	signed, err := token.SignedString(testJWTKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := VerifyJWT(signed, testRegistry(t)); err == nil {
		t.Error("VerifyJWT: expected error for jti-less token, got nil")
	}
}

// TestVerifyJWT_RejectsUnknownKid verifies that a token with a kid
// header that doesn't match any registry entry is rejected — never
// silently fall back to a default key on an unknown kid.
func TestVerifyJWT_RejectsUnknownKid(t *testing.T) {
	v1Hex := strings.Repeat("aa", 32)
	reg, err := NewJWTKeyRegistryFromConfig("v1:"+v1Hex, "v1", testJWTKey)
	if err != nil {
		t.Fatalf("reg: %v", err)
	}
	now := time.Now()
	c := jwtCustomClaims{
		ActingAccountID: core.NewAccountID().String(),
		MembershipID:    core.NewMembershipID().String(),
		RoleSlug:        "admin",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    JWTIssuer,
			Audience:  jwt.ClaimStrings{JWTAudience},
			Subject:   core.NewIdentityID().String(),
			NotBefore: jwt.NewNumericDate(now.Add(-time.Second)),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			ID:        core.NewJTI().String(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	token.Header["kid"] = "v999"
	signed, err := token.SignedString(testJWTKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := VerifyJWT(signed, reg); err == nil {
		t.Error("VerifyJWT: expected error for unknown kid, got nil")
	}
}

// TestSignJWT_EmbedsRandomJTI confirms two consecutive signs produce
// distinct jti values.
func TestSignJWT_EmbedsRandomJTI(t *testing.T) {
	reg := testRegistry(t)
	a, err := SignJWT(makeTestJWTClaims(), reg, time.Hour)
	if err != nil {
		t.Fatalf("sign a: %v", err)
	}
	b, err := SignJWT(makeTestJWTClaims(), reg, time.Hour)
	if err != nil {
		t.Fatalf("sign b: %v", err)
	}
	parseJTI := func(token string) string {
		t.Helper()
		parsed, _, err := jwt.NewParser().ParseUnverified(token, &jwtCustomClaims{})
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		c := parsed.Claims.(*jwtCustomClaims)
		return c.ID
	}
	jtiA, jtiB := parseJTI(a), parseJTI(b)
	if jtiA == "" || jtiB == "" {
		t.Fatalf("expected both jtis populated, got %q / %q", jtiA, jtiB)
	}
	if jtiA == jtiB {
		t.Errorf("expected distinct jtis, both = %q", jtiA)
	}
}

// TestVerifyJWT_ExtractsJTIAndIAT confirms the verifier surfaces jti
// + iat + exp on the returned claims so the middleware can perform
// revocation and session-invalidation checks.
func TestVerifyJWT_ExtractsJTIAndIAT(t *testing.T) {
	reg := testRegistry(t)
	signed, err := SignJWT(makeTestJWTClaims(), reg, time.Hour)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	got, err := VerifyJWT(signed, reg)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	var zero core.JTI
	if got.JTI == zero {
		t.Error("JTI: expected non-zero, got zero")
	}
	if got.IssuedAt.IsZero() {
		t.Error("IssuedAt: expected non-zero, got zero")
	}
	if got.ExpiresAt.IsZero() {
		t.Error("ExpiresAt: expected non-zero, got zero")
	}
	if !got.ExpiresAt.After(got.IssuedAt) {
		t.Errorf("ExpiresAt (%v) should be after IssuedAt (%v)", got.ExpiresAt, got.IssuedAt)
	}
}
