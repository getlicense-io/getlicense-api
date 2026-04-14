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
	"github.com/getlicense-io/getlicense-api/internal/environment"
)

const (
	accessTokenTTL  = 15 * time.Minute
	refreshTokenTTL = 7 * 24 * time.Hour
)

// Service handles identity authentication, account switching, and API key management.
type Service struct {
	txManager    domain.TxManager
	accounts     domain.AccountRepository
	identities   domain.IdentityRepository
	memberships  domain.AccountMembershipRepository
	roles        domain.RoleRepository
	apiKeys      domain.APIKeyRepository
	refreshTkns  domain.RefreshTokenRepository
	environments domain.EnvironmentRepository
	masterKey    *crypto.MasterKey
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
	masterKey *crypto.MasterKey,
) *Service {
	return &Service{
		txManager:    txManager,
		accounts:     accounts,
		identities:   identities,
		memberships:  memberships,
		roles:        roles,
		apiKeys:      apiKeys,
		refreshTkns:  refreshTkns,
		environments: environments,
		masterKey:    masterKey,
	}
}

// --- Request / response types ---

type SignupRequest struct {
	AccountName string `json:"account_name" validate:"required,min=1,max=100"`
	Email       string `json:"email" validate:"required,email"`
	Password    string `json:"password" validate:"required,min=8"`
}

type AccountSummary struct {
	ID   core.AccountID `json:"id"`
	Name string         `json:"name"`
	Slug string         `json:"slug"`
}

type MembershipSummary struct {
	MembershipID core.MembershipID `json:"membership_id"`
	Account      AccountSummary    `json:"account"`
	RoleSlug     string            `json:"role_slug"`
	RoleName     string            `json:"role_name"`
}

type SignupResult struct {
	Identity     *domain.Identity  `json:"identity"`
	Account      *domain.Account   `json:"account"`
	Membership   MembershipSummary `json:"membership"`
	APIKey       string            `json:"api_key"`
	AccessToken  string            `json:"access_token"`
	RefreshToken string            `json:"refresh_token"`
	ExpiresIn    int               `json:"expires_in"`
}

type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type LoginResult struct {
	AccessToken    string              `json:"access_token"`
	RefreshToken   string              `json:"refresh_token"`
	TokenType      string              `json:"token_type"`
	ExpiresIn      int                 `json:"expires_in"`
	Identity       *domain.Identity    `json:"identity"`
	Memberships    []MembershipSummary `json:"memberships"`
	CurrentAccount AccountSummary      `json:"current_account"`
}

type SwitchRequest struct {
	AccountID core.AccountID `json:"account_id" validate:"required"`
}

type MeResult struct {
	Identity       *domain.Identity    `json:"identity"`
	CurrentAccount AccountSummary      `json:"current_account"`
	CurrentRole    *domain.Role        `json:"current_role"`
	Memberships    []MembershipSummary `json:"memberships"`
}

type CreateAPIKeyRequest struct {
	Label       *string `json:"label"`
	Environment string  `json:"environment" validate:"required"`
}

type CreateAPIKeyResult struct {
	APIKey *domain.APIKey `json:"api_key"`
	RawKey string         `json:"raw_key"`
}

// --- Signup ---

// Signup creates a global identity, a new account, an owner membership,
// default environments, and an initial live API key in one transaction.
func (s *Service) Signup(ctx context.Context, req SignupRequest) (*SignupResult, error) {
	passwordHash, err := crypto.HashPassword(req.Password)
	if err != nil {
		return nil, core.NewAppError(core.ErrInternalError, "Failed to hash password")
	}

	var result *SignupResult
	err = s.txManager.WithTx(ctx, func(ctx context.Context) error {
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
			if strings.Contains(err.Error(), "accounts_slug_key") {
				return core.NewAppError(core.ErrAccountAlreadyExists, "An account with that name already exists")
			}
			return err
		}

		ownerRole, err := s.roles.GetBySlug(ctx, nil, "owner")
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

		_, rawKey, err := s.createAPIKeyRecord(ctx, account.ID, core.EnvironmentLive, nil)
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

// --- Login ---

// Login verifies password and returns a token pair plus the identity's
// memberships. TOTP two-step verification is not yet implemented; when
// it lands, identities with TOTP enabled will receive a pending-token
// response and must follow up with the second-factor code. For now,
// Login always returns the full token pair on successful password
// verification.
func (s *Service) Login(ctx context.Context, req LoginRequest) (*LoginResult, error) {
	identity, err := s.identities.GetByEmail(ctx, req.Email)
	if err != nil {
		return nil, err
	}
	if identity == nil || !crypto.VerifyPassword(identity.PasswordHash, req.Password) {
		return nil, core.NewAppError(core.ErrAuthenticationRequired, "Invalid email or password")
	}
	return s.buildLoginResult(ctx, identity)
}

// buildLoginResult loads memberships, picks the oldest-joined as the
// default acting account, and returns the fully-formed LoginResult
// (with tokens).
func (s *Service) buildLoginResult(ctx context.Context, identity *domain.Identity) (*LoginResult, error) {
	memberships, err := s.memberships.ListByIdentity(ctx, identity.ID)
	if err != nil {
		return nil, err
	}
	if len(memberships) == 0 {
		return nil, core.NewAppError(core.ErrAuthenticationRequired, "Identity has no active memberships")
	}

	active := memberships[0]
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

// Switch reissues a JWT pair pointing at a different acting account
// for the same identity. The identity must have an active membership
// in the target account.
func (s *Service) Switch(ctx context.Context, identityID core.IdentityID, accountID core.AccountID) (*LoginResult, error) {
	membership, err := s.memberships.GetByIdentityAndAccount(ctx, identityID, accountID)
	if err != nil {
		return nil, err
	}
	if membership == nil || membership.Status != domain.MembershipStatusActive {
		return nil, core.NewAppError(core.ErrPermissionDenied, "No active membership in that account")
	}
	identity, err := s.identities.GetByID(ctx, identityID)
	if err != nil || identity == nil {
		return nil, core.NewAppError(core.ErrIdentityNotFound, "Identity not found")
	}
	return s.buildLoginResult(ctx, identity)
}

// --- Refresh ---

func (s *Service) Refresh(ctx context.Context, refreshToken string) (*LoginResult, error) {
	tokenHash := s.masterKey.HMAC(refreshToken)
	stored, err := s.refreshTkns.GetByHash(ctx, tokenHash)
	if err != nil {
		return nil, err
	}
	if stored == nil || time.Now().UTC().After(stored.ExpiresAt) {
		return nil, core.NewAppError(core.ErrAuthenticationRequired, "Invalid or expired refresh token")
	}

	identity, err := s.identities.GetByID(ctx, stored.IdentityID)
	if err != nil || identity == nil {
		return nil, core.NewAppError(core.ErrAuthenticationRequired, "Identity not found")
	}

	var result *LoginResult
	err = s.txManager.WithTx(ctx, func(ctx context.Context) error {
		if err := s.refreshTkns.DeleteByHash(ctx, tokenHash); err != nil {
			return err
		}
		built, err := s.buildLoginResult(ctx, identity)
		if err != nil {
			return err
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

func (s *Service) Logout(ctx context.Context, refreshToken string) error {
	tokenHash := s.masterKey.HMAC(refreshToken)
	return s.refreshTkns.DeleteByHash(ctx, tokenHash)
}

// --- Me ---

func (s *Service) GetMe(ctx context.Context, identityID core.IdentityID, actingAccountID core.AccountID) (*MeResult, error) {
	identity, err := s.identities.GetByID(ctx, identityID)
	if err != nil || identity == nil {
		return nil, core.NewAppError(core.ErrIdentityNotFound, "Identity not found")
	}
	memberships, err := s.memberships.ListByIdentity(ctx, identityID)
	if err != nil {
		return nil, err
	}

	var current AccountSummary
	var currentRole *domain.Role
	for _, m := range memberships {
		if m.AccountID != actingAccountID {
			continue
		}
		account, err := s.accounts.GetByID(ctx, m.AccountID)
		if err != nil || account == nil {
			continue
		}
		current = AccountSummary{ID: account.ID, Name: account.Name, Slug: account.Slug}
		role, err := s.roles.GetByID(ctx, m.RoleID)
		if err == nil {
			currentRole = role
		}
		break
	}

	summaries, err := s.hydrateMembershipSummaries(ctx, memberships)
	if err != nil {
		return nil, err
	}

	return &MeResult{
		Identity:       identity,
		CurrentAccount: current,
		CurrentRole:    currentRole,
		Memberships:    summaries,
	}, nil
}

// --- API keys ---

func (s *Service) CreateAPIKey(ctx context.Context, targetAccountID core.AccountID, env core.Environment, req CreateAPIKeyRequest) (*CreateAPIKeyResult, error) {
	reqEnv, err := core.ParseEnvironment(req.Environment)
	if err != nil {
		return nil, core.NewAppError(core.ErrValidationError, "Invalid environment slug")
	}
	var result *CreateAPIKeyResult
	err = s.txManager.WithTargetAccount(ctx, targetAccountID, env, func(ctx context.Context) error {
		apiKey, rawKey, err := s.createAPIKeyRecord(ctx, targetAccountID, reqEnv, req.Label)
		if err != nil {
			return err
		}
		result = &CreateAPIKeyResult{APIKey: apiKey, RawKey: rawKey}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (s *Service) ListAPIKeys(ctx context.Context, targetAccountID core.AccountID, env core.Environment, limit, offset int) ([]domain.APIKey, int, error) {
	var keys []domain.APIKey
	var total int
	err := s.txManager.WithTargetAccount(ctx, targetAccountID, env, func(ctx context.Context) error {
		var err error
		keys, total, err = s.apiKeys.ListByAccount(ctx, env, limit, offset)
		return err
	})
	if err != nil {
		return nil, 0, err
	}
	return keys, total, nil
}

func (s *Service) DeleteAPIKey(ctx context.Context, targetAccountID core.AccountID, env core.Environment, id core.APIKeyID) error {
	return s.txManager.WithTargetAccount(ctx, targetAccountID, env, func(ctx context.Context) error {
		return s.apiKeys.Delete(ctx, id)
	})
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

func (s *Service) createAPIKeyRecord(ctx context.Context, accountID core.AccountID, env core.Environment, label *string) (*domain.APIKey, string, error) {
	rawKey, prefix, err := crypto.GenerateAPIKey(env)
	if err != nil {
		return nil, "", core.NewAppError(core.ErrInternalError, "Failed to generate API key")
	}
	apiKey := &domain.APIKey{
		ID:          core.NewAPIKeyID(),
		AccountID:   accountID,
		Prefix:      prefix,
		KeyHash:     s.masterKey.HMAC(rawKey),
		Scope:       core.APIKeyScopeAccountWide,
		Label:       label,
		Environment: env,
		CreatedAt:   time.Now().UTC(),
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
