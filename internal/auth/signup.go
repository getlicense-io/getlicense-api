package auth

import (
	"context"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/crypto"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/getlicense-io/getlicense-api/internal/environment"
	"github.com/getlicense-io/getlicense-api/internal/rbac"
)

// --- Signup ---

// Signup creates a global identity, a new account, an owner membership,
// default environments, and an initial live API key in one transaction.
func (s *Service) Signup(ctx context.Context, req SignupRequest) (*SignupResult, error) {
	passwordHash, err := crypto.HashPassword(req.Password)
	if err != nil {
		return nil, core.NewAppError(core.ErrInternalError, "Failed to hash password")
	}

	// Signup runs before the tenant exists — the new account row is
	// created inside this tx. Use WithSystemContext (not WithTx) so the
	// tenant-scoped tables touched here (account_memberships,
	// environments, api_keys, roles) bypass RLS explicitly. Migration
	// 034 retired the implicit IS NULL bypass; bare-pool / WithTx calls
	// would now fail-closed on the empty-string uuid cast.
	var result *SignupResult
	err = s.txManager.WithSystemContext(ctx, func(ctx context.Context) error {
		existing, err := s.identities.GetByEmail(ctx, req.Email)
		if err != nil {
			return err
		}
		if existing != nil {
			return core.NewAppError(core.ErrEmailAlreadyExists, "An identity with that email already exists")
		}

		now := time.Now().UTC()

		identity := &domain.Identity{
			ID:           core.NewIdentityID(),
			Email:        req.Email,
			PasswordHash: passwordHash,
			CreatedAt:    now,
			UpdatedAt:    now,
		}
		if err := s.identities.Create(ctx, identity); err != nil {
			return err
		}

		account := &domain.Account{
			ID:        core.NewAccountID(),
			Name:      req.AccountName,
			Slug:      slugify(req.AccountName),
			CreatedAt: now,
		}
		if err := s.accounts.Create(ctx, account); err != nil {
			return err
		}

		ownerRole, err := s.roles.GetBySlug(ctx, nil, rbac.RoleSlugOwner)
		if err != nil {
			return err
		}
		if ownerRole == nil {
			return core.NewAppError(core.ErrInternalError, "Missing owner role preset")
		}

		membership := &domain.AccountMembership{
			ID:         core.NewMembershipID(),
			AccountID:  account.ID,
			IdentityID: identity.ID,
			RoleID:     ownerRole.ID,
			Status:     domain.MembershipStatusActive,
			JoinedAt:   now,
			CreatedAt:  now,
			UpdatedAt:  now,
		}
		if err := s.memberships.Create(ctx, membership); err != nil {
			return err
		}

		for _, env := range environment.DefaultEnvironments(account.ID, now) {
			if err := s.environments.Create(ctx, env); err != nil {
				return err
			}
		}

		_, rawKey, err := s.createAPIKeyRecord(ctx, account.ID, core.EnvironmentLive, core.APIKeyScopeAccountWide, nil, nil, nil, &identity.ID, nil, nil, nil)
		if err != nil {
			return err
		}

		accessToken, err := s.signAccessToken(identity.ID, account.ID, membership.ID, ownerRole.Slug)
		if err != nil {
			return err
		}
		rawRefresh, err := s.createRefreshToken(ctx, identity.ID)
		if err != nil {
			return err
		}

		result = &SignupResult{
			Identity: identity,
			Account:  account,
			Membership: MembershipSummary{
				MembershipID: membership.ID,
				Account:      AccountSummary{ID: account.ID, Name: account.Name, Slug: account.Slug},
				RoleSlug:     ownerRole.Slug,
				RoleName:     ownerRole.Name,
			},
			APIKey:       rawKey,
			AccessToken:  accessToken,
			RefreshToken: rawRefresh,
			ExpiresIn:    int(accessTokenTTL.Seconds()),
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}
