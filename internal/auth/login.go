package auth

import (
	"context"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/crypto"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

// --- Login ---

// Login verifies password and returns either a full token pair (for
// identities without TOTP) or a short-lived pending token requiring a
// second-factor TOTP submission via LoginStep2.
//
// F-002: when the identity lookup misses, we still run VerifyPassword
// against a cached dummy hash so the response time does not leak
// whether an email is registered. Without this, the unknown-email
// path short-circuits before Argon2 runs, creating a ~20ms timing
// delta that an attacker can use to enumerate valid identities.
func (s *Service) Login(ctx context.Context, req LoginRequest) (*LoginStep1, error) {
	ident, err := s.identities.GetByEmail(ctx, req.Email)
	if err != nil {
		return nil, err
	}
	if ident == nil {
		// Constant-time guard: burn a verify against the dummy hash
		// so the unknown-email path takes roughly the same time as
		// a wrong-password attempt on an existing identity. The
		// return value is always false and intentionally ignored.
		_ = crypto.VerifyPassword(s.dummyPasswordHash, req.Password)
		return nil, core.NewAppError(core.ErrAuthenticationRequired, "Invalid email or password")
	}
	if !crypto.VerifyPassword(ident.PasswordHash, req.Password) {
		return nil, core.NewAppError(core.ErrAuthenticationRequired, "Invalid email or password")
	}

	if ident.TOTPEnabled() {
		raw, err := crypto.GenerateRefreshToken()
		if err != nil {
			return nil, core.NewAppError(core.ErrInternalError, "Failed to generate pending token")
		}
		if err := s.pending.Put(ctx, raw, ident.ID); err != nil {
			return nil, core.NewAppError(core.ErrInternalError, "Failed to store pending token")
		}
		return &LoginStep1{NeedsTOTP: true, PendingToken: raw}, nil
	}

	var result *LoginResult
	if err := s.txManager.WithSystemContext(ctx, func(ctx context.Context) error {
		built, berr := s.buildLoginResult(ctx, ident, nil)
		if berr != nil {
			return berr
		}
		result = built
		return nil
	}); err != nil {
		return nil, err
	}
	return &LoginStep1{LoginResult: result}, nil
}

// LoginStep2 verifies a TOTP code (or a single-use recovery code)
// against a pending token from Login and, on success, returns the
// full token pair. The pending token is consumed on first attempt
// (success or failure) to prevent replay.
//
// F-012: accepting recovery codes here is what makes them real.
// Without this fallback, the codes returned at activation time are
// unusable and a user who loses their authenticator is locked out.
func (s *Service) LoginStep2(ctx context.Context, req LoginStep2Request) (*LoginResult, error) {
	identityID, ok, err := s.pending.Take(ctx, req.PendingToken)
	if err != nil {
		return nil, core.NewAppError(core.ErrInternalError, "Failed to consume pending token")
	}
	if !ok {
		return nil, core.NewAppError(core.ErrAuthenticationRequired, "Invalid or expired pending token")
	}
	identity, err := s.identitySvc.VerifyTOTPOrRecovery(ctx, identityID, req.Code)
	if err != nil {
		return nil, err
	}
	var result *LoginResult
	if err := s.txManager.WithSystemContext(ctx, func(ctx context.Context) error {
		built, berr := s.buildLoginResult(ctx, identity, nil)
		if berr != nil {
			return berr
		}
		result = built
		return nil
	}); err != nil {
		return nil, err
	}
	return result, nil
}

// buildLoginResult loads memberships and returns the fully-formed
// LoginResult (with tokens). When activeMembership is nil (default for
// signup / login / refresh) the oldest-joined membership is used.
// Switch passes an explicit membership so callers can select a specific
// acting account; without that, any multi-account identity would
// silently fall back to memberships[0] regardless of the requested
// target.
func (s *Service) buildLoginResult(ctx context.Context, identity *domain.Identity, activeMembership *domain.AccountMembership) (*LoginResult, error) {
	memberships, err := s.memberships.ListByIdentity(ctx, identity.ID)
	if err != nil {
		return nil, err
	}
	if len(memberships) == 0 {
		return nil, core.NewAppError(core.ErrAuthenticationRequired, "Identity has no active memberships")
	}

	active := memberships[0]
	if activeMembership != nil {
		active = *activeMembership
	}
	account, err := s.accounts.GetByID(ctx, active.AccountID)
	if err != nil {
		return nil, err
	}
	if account == nil {
		return nil, core.NewAppError(core.ErrAccountNotFound, "Default account missing")
	}

	summaries, err := s.hydrateMembershipSummaries(ctx, memberships)
	if err != nil {
		return nil, err
	}

	role, err := s.roles.GetByID(ctx, active.RoleID)
	if err != nil || role == nil {
		return nil, core.NewAppError(core.ErrInternalError, "Role missing for default membership")
	}

	accessToken, err := s.signAccessToken(identity.ID, account.ID, active.ID, role.Slug)
	if err != nil {
		return nil, err
	}
	rawRefresh, err := s.createRefreshToken(ctx, identity.ID)
	if err != nil {
		return nil, err
	}

	return &LoginResult{
		AccessToken:    accessToken,
		RefreshToken:   rawRefresh,
		TokenType:      "Bearer",
		ExpiresIn:      int(accessTokenTTL.Seconds()),
		Identity:       identity,
		Memberships:    summaries,
		CurrentAccount: AccountSummary{ID: account.ID, Name: account.Name, Slug: account.Slug},
	}, nil
}

func (s *Service) hydrateMembershipSummaries(ctx context.Context, memberships []domain.AccountMembership) ([]MembershipSummary, error) {
	out := make([]MembershipSummary, 0, len(memberships))
	for _, m := range memberships {
		account, err := s.accounts.GetByID(ctx, m.AccountID)
		if err != nil || account == nil {
			continue
		}
		role, err := s.roles.GetByID(ctx, m.RoleID)
		if err != nil || role == nil {
			continue
		}
		out = append(out, MembershipSummary{
			MembershipID: m.ID,
			Account:      AccountSummary{ID: account.ID, Name: account.Name, Slug: account.Slug},
			RoleSlug:     role.Slug,
			RoleName:     role.Name,
		})
	}
	return out, nil
}

// --- Switch ---

// Switch reissues a JWT pair scoped to a specific membership for the
// caller's identity. The membership must belong to the authenticated
// identity and be active. Callers identify the membership directly
// (not the account) so the switch is unambiguous across tables where
// a single identity could hold multiple memberships in the same
// account over time.
func (s *Service) Switch(ctx context.Context, identityID core.IdentityID, membershipID core.MembershipID) (*LoginResult, error) {
	// Switch reads memberships and roles across accounts (the caller can
	// pivot to any of their memberships), so RLS bypass is required.
	// Use WithSystemContext for an explicit, fail-closed bypass under
	// migration 034.
	var result *LoginResult
	if err := s.txManager.WithSystemContext(ctx, func(ctx context.Context) error {
		membership, err := s.memberships.GetByID(ctx, membershipID)
		if err != nil {
			return err
		}
		if membership == nil || membership.IdentityID != identityID || membership.Status != domain.MembershipStatusActive {
			return core.NewAppError(core.ErrPermissionDenied, "No active membership with that ID")
		}
		identity, err := s.identities.GetByID(ctx, identityID)
		if err != nil || identity == nil {
			return core.NewAppError(core.ErrIdentityNotFound, "Identity not found")
		}
		built, berr := s.buildLoginResult(ctx, identity, membership)
		if berr != nil {
			return berr
		}
		result = built
		return nil
	}); err != nil {
		return nil, err
	}
	return result, nil
}

// --- Refresh ---

// Refresh exchanges a refresh token for a new auth token pair. The
// old token is consumed atomically so concurrent refresh attempts
// with the same token cannot both succeed (rotation race fix). The
// Consume + identity lookup + new token mint all run in the same tx
// so a downstream failure rolls back the DELETE and the caller is
// not locked out.
func (s *Service) Refresh(ctx context.Context, refreshToken string) (*LoginResult, error) {
	tokenHash := s.masterKey.HMAC(refreshToken)

	// Refresh runs before the request can carry tenant context — the
	// caller supplies only an opaque refresh token, and the identity /
	// membership lookups inside buildLoginResult span the global
	// account_memberships and roles tables. Use WithSystemContext so
	// RLS bypass is explicit (PR-B / migration 034).
	var result *LoginResult
	err := s.txManager.WithSystemContext(ctx, func(ctx context.Context) error {
		identityID, cerr := s.refreshTkns.Consume(ctx, tokenHash)
		if cerr != nil {
			return cerr
		}
		var zero core.IdentityID
		if identityID == zero {
			return core.NewAppError(core.ErrAuthenticationRequired, "Invalid or expired refresh token")
		}

		identity, ierr := s.identities.GetByID(ctx, identityID)
		if ierr != nil {
			return ierr
		}
		if identity == nil {
			return core.NewAppError(core.ErrAuthenticationRequired, "Identity not found")
		}

		built, berr := s.buildLoginResult(ctx, identity, nil)
		if berr != nil {
			return berr
		}
		result = built
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// --- Logout ---

// Logout revokes the access token (jti) and deletes the matching
// refresh token. The access JWT's jti is added to revoked_jtis with
// expires_at scoped to the token's natural exp so the row is GC'd by
// the background sweep once the token can't validate anyway. The
// access-token revocation is a no-op when jti / expiry are zero (e.g.
// callers that bypass the auth middleware in tests); the refresh-token
// delete still runs.
func (s *Service) Logout(
	ctx context.Context,
	refreshToken string,
	jti core.JTI,
	identityID core.IdentityID,
	jwtExpiry time.Time,
) error {
	var zeroJTI core.JTI
	if jti != zeroJTI && !jwtExpiry.IsZero() {
		if err := s.jwtRevocations.RevokeJTI(ctx, jti, identityID, jwtExpiry, "logout"); err != nil {
			return err
		}
	}
	tokenHash := s.masterKey.HMAC(refreshToken)
	return s.refreshTkns.DeleteByHash(ctx, tokenHash)
}

// LogoutAll bulk-revokes every active session for the given identity
// by setting the per-identity session-invalidation cutoff and
// deleting every refresh token. Verifier rejects any JWT whose iat
// is strictly before the cutoff. Wrapped in WithSystemContext because
// the invalidation table is cross-tenant and the refresh-token delete
// needs an explicit RLS bypass under migration 034.
//
// JWT iat granularity is one second (RFC 7519 NumericDate, default
// jwt.TimePrecision). To guarantee a clean cut between "tokens that
// existed at logout-all time" and "tokens minted after", the cutoff
// is rounded UP to the next second boundary AND we block until that
// instant before returning. This way:
//   - every token issued before LogoutAll (iat ≤ current second) has
//     iat strictly less than the cutoff (next second) → revoked.
//   - every token minted after LogoutAll returns has iat ≥ next second
//     = cutoff → not strictly before → valid.
//
// The wait is at most one second, capped by the request context.
func (s *Service) LogoutAll(ctx context.Context, identityID core.IdentityID) error {
	now := time.Now().UTC()
	cutoff := now.Truncate(time.Second).Add(time.Second)
	if err := s.txManager.WithSystemContext(ctx, func(ctx context.Context) error {
		if err := s.jwtRevocations.SetSessionInvalidation(ctx, identityID, cutoff); err != nil {
			return err
		}
		return s.refreshTkns.DeleteByIdentityID(ctx, identityID)
	}); err != nil {
		return err
	}
	wait := time.Until(cutoff)
	if wait > 0 {
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// --- Me ---

func (s *Service) GetMe(ctx context.Context, identityID core.IdentityID, actingAccountID core.AccountID) (*MeResult, error) {
	// GetMe lists every membership the caller holds across accounts —
	// each account is a different RLS tenant. Use WithSystemContext so
	// the cross-tenant read is an explicit, fail-closed bypass under
	// migration 034.
	var result *MeResult
	if err := s.txManager.WithSystemContext(ctx, func(ctx context.Context) error {
		identity, err := s.identities.GetByID(ctx, identityID)
		if err != nil || identity == nil {
			return core.NewAppError(core.ErrIdentityNotFound, "Identity not found")
		}
		memberships, err := s.memberships.ListByIdentity(ctx, identityID)
		if err != nil {
			return err
		}

		var current AccountSummary
		var currentRole *domain.Role
		for _, m := range memberships {
			if m.AccountID != actingAccountID {
				continue
			}
			account, aerr := s.accounts.GetByID(ctx, m.AccountID)
			if aerr != nil || account == nil {
				continue
			}
			current = AccountSummary{ID: account.ID, Name: account.Name, Slug: account.Slug}
			role, rerr := s.roles.GetByID(ctx, m.RoleID)
			if rerr == nil {
				currentRole = role
			}
			break
		}

		summaries, err := s.hydrateMembershipSummaries(ctx, memberships)
		if err != nil {
			return err
		}

		result = &MeResult{
			Identity:       identity,
			CurrentAccount: current,
			CurrentRole:    currentRole,
			Memberships:    summaries,
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return result, nil
}
