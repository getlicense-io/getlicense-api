package crypto

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/getlicense-io/getlicense-api/internal/core"
)

// JWTIssuer is the canonical iss claim value emitted on every JWT.
// Verifiers reject tokens with a different iss to prevent
// cross-service token reuse — a token minted by some other system
// that happens to share the signing key cannot pass this check.
const JWTIssuer = "getlicense-api"

// JWTAudience is the canonical aud claim value emitted on every JWT.
// Verifiers reject tokens whose aud doesn't match — a token minted
// for a different audience (e.g. an internal admin tool with the
// same issuer) cannot be presented to this API.
const JWTAudience = "getlicense-api"

// jwtNotBeforeSkew gives clients a small buffer for clock skew when
// the token is issued. nbf = now - skew so a request that arrives
// at the same instant as issuance doesn't bounce.
const jwtNotBeforeSkew = 1 * time.Second

// jwtKidHeader is the JOSE header name carrying the signing-key
// identifier. The verifier reads it to look up the matching key in
// the registry. Every signed JWT MUST have a non-empty kid header —
// the verifier rejects tokens without one.
const jwtKidHeader = "kid"

// JWTClaims holds the application-specific claims for an access token.
// The three-ID request model means every JWT names an Identity, the
// AccountMembership it is currently acting through, and (by implication
// from the membership) the acting account. The role slug is advisory
// — middleware always re-resolves role + permissions from the DB per
// request, so a stolen JWT cannot elevate itself.
//
// JTI / IssuedAt / ExpiresAt are populated by VerifyJWT for the
// middleware's revocation checks. SignJWT generates a fresh random JTI
// when claims.JTI is the zero value, otherwise honors the caller-
// provided value (used by tests to bind a known jti to a token).
type JWTClaims struct {
	IdentityID      core.IdentityID   `json:"sub"`
	ActingAccountID core.AccountID    `json:"acting_account"`
	MembershipID    core.MembershipID `json:"mid"`
	RoleSlug        string            `json:"role"`
	JTI             core.JTI          `json:"jti"`
	IssuedAt        time.Time         `json:"-"`
	ExpiresAt       time.Time         `json:"-"`
}

type jwtCustomClaims struct {
	ActingAccountID string `json:"acting_account"`
	MembershipID    string `json:"mid"`
	RoleSlug        string `json:"role"`
	jwt.RegisteredClaims
}

// SignJWT creates a signed HMAC-SHA256 JWT token with the given claims and TTL.
//
// Standard claims emitted alongside the custom payload:
//   - iss=getlicense-api (cross-service token-reuse protection)
//   - aud=getlicense-api (cross-audience reuse protection)
//   - nbf=now-1s (clock-skew tolerant not-before)
//   - iat=now / exp=now+ttl
//   - sub=identityID
//   - jti=random-uuid (or claims.JTI if non-zero) for per-token revocation
//
// JOSE header:
//   - alg=HS256 (pinned, verified at parse time)
//   - kid=registry.Current() so verifiers can route to the right key
//     under multi-key rotation
func SignJWT(claims JWTClaims, registry *JWTKeyRegistry, ttl time.Duration) (string, error) {
	if registry == nil {
		return "", fmt.Errorf("crypto: SignJWT requires a non-nil JWTKeyRegistry")
	}
	jti := claims.JTI
	var zero core.JTI
	if jti == zero {
		jti = core.NewJTI()
	}
	now := time.Now()
	c := jwtCustomClaims{
		ActingAccountID: claims.ActingAccountID.String(),
		MembershipID:    claims.MembershipID.String(),
		RoleSlug:        claims.RoleSlug,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    JWTIssuer,
			Audience:  jwt.ClaimStrings{JWTAudience},
			Subject:   claims.IdentityID.String(),
			NotBefore: jwt.NewNumericDate(now.Add(-jwtNotBeforeSkew)),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			ID:        jti.String(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	token.Header[jwtKidHeader] = registry.Current()
	signed, err := token.SignedString(registry.CurrentKey())
	if err != nil {
		return "", fmt.Errorf("crypto: failed to sign JWT: %w", err)
	}
	return signed, nil
}

// VerifyJWT parses and validates a signed JWT token, returning the application claims.
//
// Signing method is pinned to exactly HS256 (matches SignJWT). Pinning
// the exact method — not just the HMAC family — closes algorithm-
// substitution attacks where an attacker swaps in HS512 / HS384 (or
// the famous "alg: none") to bypass verification with a different key
// model than the server expects.
//
// Standard claims enforced:
//   - iss must equal JWTIssuer
//   - aud must include JWTAudience
//   - nbf / exp / iat — validated by the jwt library's default checks
//   - jti must be a parseable, non-empty UUID — used by the revocation
//     middleware. Tokens without a jti are rejected.
//
// Key selection:
//   - The kid JOSE header is REQUIRED. The verifier looks the value up
//     in the registry; unknown or missing kids are rejected. There is
//     no fallback path — every signed JWT carries a kid.
//
// Populated on the returned JWTClaims:
//   - JTI from the jti claim (used by the revocation middleware)
//   - IssuedAt from the iat claim (used by the session-invalidation check)
//   - ExpiresAt from the exp claim (used by Logout to scope the
//     revocation row's TTL to the token's natural lifetime)
func VerifyJWT(tokenStr string, registry *JWTKeyRegistry) (*JWTClaims, error) {
	if registry == nil {
		return nil, fmt.Errorf("crypto: VerifyJWT requires a non-nil JWTKeyRegistry")
	}
	token, err := jwt.ParseWithClaims(tokenStr, &jwtCustomClaims{}, func(t *jwt.Token) (interface{}, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("crypto: unexpected signing method: %v", t.Header["alg"])
		}
		raw, ok := t.Header[jwtKidHeader]
		if !ok {
			return nil, fmt.Errorf("crypto: JWT missing required kid header")
		}
		kid, ok := raw.(string)
		if !ok || kid == "" {
			return nil, fmt.Errorf("crypto: JWT kid header is not a non-empty string")
		}
		key, lerr := registry.Lookup(kid)
		if lerr != nil {
			return nil, lerr
		}
		return key, nil
	},
		jwt.WithIssuer(JWTIssuer),
		jwt.WithAudience(JWTAudience),
	)
	if err != nil {
		return nil, fmt.Errorf("crypto: JWT verification failed: %w", err)
	}
	c, ok := token.Claims.(*jwtCustomClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("crypto: invalid JWT claims")
	}
	identityID, err := core.ParseIdentityID(c.Subject)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to parse identity ID: %w", err)
	}
	acting, err := core.ParseAccountID(c.ActingAccountID)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to parse acting account ID: %w", err)
	}
	mid, err := core.ParseMembershipID(c.MembershipID)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to parse membership ID: %w", err)
	}
	if c.ID == "" {
		return nil, fmt.Errorf("crypto: JWT missing required jti claim")
	}
	jti, perr := core.ParseJTI(c.ID)
	if perr != nil {
		return nil, fmt.Errorf("crypto: invalid jti claim: %w", perr)
	}
	out := &JWTClaims{
		IdentityID:      identityID,
		ActingAccountID: acting,
		MembershipID:    mid,
		RoleSlug:        c.RoleSlug,
		JTI:             jti,
	}
	if c.IssuedAt != nil {
		out.IssuedAt = c.IssuedAt.Time
	}
	if c.ExpiresAt != nil {
		out.ExpiresAt = c.ExpiresAt.Time
	}
	return out, nil
}
