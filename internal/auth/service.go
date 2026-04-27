package auth

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/crypto"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/getlicense-io/getlicense-api/internal/identity"
)

const (
	accessTokenTTL  = 15 * time.Minute
	refreshTokenTTL = 7 * 24 * time.Hour
)

const pendingLoginTTL = 5 * time.Minute

type PendingTokenStore interface {
	Put(ctx context.Context, token string, id core.IdentityID) error
	Take(ctx context.Context, token string) (core.IdentityID, bool, error)
	Close() error
}

// Service handles identity authentication, account switching, and API key management.
type Service struct {
	txManager      domain.TxManager
	accounts       domain.AccountRepository
	identities     domain.IdentityRepository
	memberships    domain.AccountMembershipRepository
	roles          domain.RoleRepository
	apiKeys        domain.APIKeyRepository
	refreshTkns    domain.RefreshTokenRepository
	environments   domain.EnvironmentRepository
	products       domain.ProductRepository
	jwtRevocations domain.JWTRevocationRepository
	masterKey      *crypto.MasterKey

	identitySvc *identity.Service // used for TOTP verification in LoginStep2
	pending     PendingTokenStore // short-lived pending-token store for two-step login

	// dummyPasswordHash is a pre-computed Argon2id hash that never
	// matches any real password. Login runs VerifyPassword against
	// this hash when the identity lookup misses so the response time
	// does not leak whether an email is registered. F-002.
	dummyPasswordHash string
}

func NewService(
	txManager domain.TxManager,
	accounts domain.AccountRepository,
	identities domain.IdentityRepository,
	memberships domain.AccountMembershipRepository,
	roles domain.RoleRepository,
	apiKeys domain.APIKeyRepository,
	refreshTkns domain.RefreshTokenRepository,
	environments domain.EnvironmentRepository,
	products domain.ProductRepository,
	jwtRevocations domain.JWTRevocationRepository,
	masterKey *crypto.MasterKey,
	identitySvc *identity.Service,
	pendingStores ...PendingTokenStore,
) *Service {
	// Compute the dummy hash once at construction so the hot path
	// stays O(1) verify. A failure here means the Argon2 parameters
	// are broken and the process cannot start — panic is appropriate.
	dummyHash, err := crypto.HashPassword("no-real-password-will-ever-match-this")
	if err != nil {
		panic("auth: failed to generate dummy password hash: " + err.Error())
	}
	pending := PendingTokenStore(newMemoryPendingTokenStore())
	if len(pendingStores) > 0 && pendingStores[0] != nil {
		pending = pendingStores[0]
	}
	return &Service{
		txManager:         txManager,
		accounts:          accounts,
		identities:        identities,
		memberships:       memberships,
		roles:             roles,
		apiKeys:           apiKeys,
		refreshTkns:       refreshTkns,
		environments:      environments,
		products:          products,
		jwtRevocations:    jwtRevocations,
		masterKey:         masterKey,
		identitySvc:       identitySvc,
		pending:           pending,
		dummyPasswordHash: dummyHash,
	}
}

// --- Lifecycle ---

// Close releases background or external pending-token resources.
func (s *Service) Close() {
	if s.pending != nil {
		_ = s.pending.Close()
	}
}

// --- Private helpers ---

func (s *Service) signAccessToken(identityID core.IdentityID, accountID core.AccountID, membershipID core.MembershipID, roleSlug string) (string, error) {
	token, err := s.masterKey.SignJWT(crypto.JWTClaims{
		IdentityID:      identityID,
		ActingAccountID: accountID,
		MembershipID:    membershipID,
		RoleSlug:        roleSlug,
	}, accessTokenTTL)
	if err != nil {
		return "", core.NewAppError(core.ErrInternalError, "Failed to sign access token")
	}
	return token, nil
}

func (s *Service) createRefreshToken(ctx context.Context, identityID core.IdentityID) (string, error) {
	raw, err := crypto.GenerateRefreshToken()
	if err != nil {
		return "", core.NewAppError(core.ErrInternalError, "Failed to generate refresh token")
	}
	id, err := uuid.NewV7()
	if err != nil {
		return "", core.NewAppError(core.ErrInternalError, "Failed to generate token ID")
	}
	rt := &domain.RefreshToken{
		ID:         id.String(),
		IdentityID: identityID,
		TokenHash:  s.masterKey.HMAC(raw),
		ExpiresAt:  time.Now().UTC().Add(refreshTokenTTL),
	}
	if err := s.refreshTkns.Create(ctx, rt); err != nil {
		return "", err
	}
	return raw, nil
}

// createAPIKeyRecord generates a new API key and persists it. Internal
// helper shared by signup (account_wide, no product, never expires) and
// the CreateAPIKey path (scope/product/expiresAt forwarded from the
// request).
func (s *Service) createAPIKeyRecord(
	ctx context.Context,
	accountID core.AccountID,
	env core.Environment,
	scope core.APIKeyScope,
	productID *core.ProductID,
	label *string,
	expiresAt *time.Time,
	createdByIdentityID *core.IdentityID,
	createdByAPIKeyID *core.APIKeyID,
	permissions []string,
	ipAllowlist []string,
) (*domain.APIKey, string, error) {
	rawKey, prefix, err := crypto.GenerateAPIKey(env)
	if err != nil {
		return nil, "", core.NewAppError(core.ErrInternalError, "Failed to generate API key")
	}
	apiKey := &domain.APIKey{
		ID:                  core.NewAPIKeyID(),
		AccountID:           accountID,
		ProductID:           productID,
		Prefix:              prefix,
		KeyHash:             s.masterKey.HMAC(rawKey),
		Scope:               scope,
		Label:               label,
		Environment:         env,
		ExpiresAt:           expiresAt,
		CreatedAt:           time.Now().UTC(),
		CreatedByIdentityID: createdByIdentityID,
		CreatedByAPIKeyID:   createdByAPIKeyID,
		Permissions:         permissions,
		IPAllowlist:         ipAllowlist,
	}
	if err := s.apiKeys.Create(ctx, apiKey); err != nil {
		return nil, "", err
	}
	return apiKey, rawKey, nil
}

var (
	reNonAlphanumHyphen = regexp.MustCompile(`[^a-z0-9-]+`)
	reMultiHyphen       = regexp.MustCompile(`-{2,}`)
)

func slugify(name string) string {
	s := strings.ToLower(name)
	s = strings.ReplaceAll(s, " ", "-")
	s = reNonAlphanumHyphen.ReplaceAllString(s, "")
	s = reMultiHyphen.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	return s
}
