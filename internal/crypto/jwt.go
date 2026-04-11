package crypto

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/getlicense-io/getlicense-api/internal/core"
)

// JWTClaims holds the application-specific claims for an access token.
type JWTClaims struct {
	UserID    core.UserID    `json:"sub"`
	AccountID core.AccountID `json:"account_id"`
	Role      core.UserRole  `json:"role"`
}

// jwtCustomClaims is the internal claims struct passed to the JWT library.
type jwtCustomClaims struct {
	AccountID string        `json:"account_id"`
	Role      core.UserRole `json:"role"`
	jwt.RegisteredClaims
}

// SignJWT creates a signed HMAC-SHA256 JWT token with the given claims and TTL.
func SignJWT(claims JWTClaims, signingKey []byte, ttl time.Duration) (string, error) {
	now := time.Now()
	c := jwtCustomClaims{
		AccountID: claims.AccountID.String(),
		Role:      claims.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   claims.UserID.String(),
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
func VerifyJWT(tokenStr string, signingKey []byte) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &jwtCustomClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
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

	userID, err := core.ParseUserID(c.Subject)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to parse user ID from JWT: %w", err)
	}

	accountID, err := core.ParseAccountID(c.AccountID)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to parse account ID from JWT: %w", err)
	}

	return &JWTClaims{
		UserID:    userID,
		AccountID: accountID,
		Role:      c.Role,
	}, nil
}
