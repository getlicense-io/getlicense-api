package crypto

import (
	"fmt"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/golang-jwt/jwt/v5"
)

// JWTClaims holds the application-specific claims for an access token.
// The three-ID request model means every JWT names an Identity, the
// AccountMembership it is currently acting through, and (by implication
// from the membership) the acting account. The role slug is advisory
// — middleware always re-resolves role + permissions from the DB per
// request, so a stolen JWT cannot elevate itself.
type JWTClaims struct {
	IdentityID      core.IdentityID   `json:"sub"`
	ActingAccountID core.AccountID    `json:"acting_account"`
	MembershipID    core.MembershipID `json:"mid"`
	RoleSlug        string            `json:"role"`
}

type jwtCustomClaims struct {
	ActingAccountID string `json:"acting_account"`
	MembershipID    string `json:"mid"`
	RoleSlug        string `json:"role"`
	jwt.RegisteredClaims
}

// SignJWT creates a signed HMAC-SHA256 JWT token with the given claims and TTL.
func SignJWT(claims JWTClaims, signingKey []byte, ttl time.Duration) (string, error) {
	now := time.Now()
	c := jwtCustomClaims{
		ActingAccountID: claims.ActingAccountID.String(),
		MembershipID:    claims.MembershipID.String(),
		RoleSlug:        claims.RoleSlug,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   claims.IdentityID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	signed, err := token.SignedString(signingKey)
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
func VerifyJWT(tokenStr string, signingKey []byte) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &jwtCustomClaims{}, func(t *jwt.Token) (interface{}, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("crypto: unexpected signing method: %v", t.Header["alg"])
		}
		return signingKey, nil
	})
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
	return &JWTClaims{
		IdentityID:      identityID,
		ActingAccountID: acting,
		MembershipID:    mid,
		RoleSlug:        c.RoleSlug,
	}, nil
}
