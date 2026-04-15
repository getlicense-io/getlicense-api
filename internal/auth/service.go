package auth

import (
	"context"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/crypto"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/getlicense-io/getlicense-api/internal/environment"
	"github.com/getlicense-io/getlicense-api/internal/identity"
	"github.com/getlicense-io/getlicense-api/internal/rbac"
)

const (
	accessTokenTTL  = 15 * time.Minute
	refreshTokenTTL = 7 * 24 * time.Hour
)

// pendingLogin holds the short-lived state between password verification
// and TOTP code entry. In-memory only — not persisted. Lost on restart.
type pendingLogin struct {
	identityID core.IdentityID
	expiresAt  time.Time
}

// pendingStore is a TTL-bounded map of pending-token → identity. Used
// by the two-step login flow. This is a single-instance design; a
// multi-instance deployment must swap this for Redis or equivalent.
type pendingStore struct {
	mu   sync.Mutex
	m    map[string]pendingLogin
	done chan struct{}
}

func newPendingStore() *pendingStore {
	ps := &pendingStore{
		m:    map[string]pendingLogin{},
		done: make(chan struct{}),
	}
	go ps.sweepLoop()
	return ps
}

// Close stops the sweep goroutine. Safe to call multiple times.
// Production callers don't need to — the Service is a process
// singleton. Tests call Close via t.Cleanup to avoid goroutine leaks
// between test functions.
func (p *pendingStore) Close() {
	select {
	case <-p.done:
		// already closed
	default:
		close(p.done)
	}
}

// sweepLoop runs once a minute and removes expired pending entries so
// the map size is bounded by the rate of pending-token creation × TTL,
// not by the lifetime of the process.
func (p *pendingStore) sweepLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-p.done:
			return
		case <-ticker.C:
			p.sweepExpired(time.Now().UTC())
		}
	}
}

// sweepExpired removes entries whose expiresAt is in the past.
// Exposed as a method so tests can drive a deterministic sweep
// without waiting for the ticker.
func (p *pendingStore) sweepExpired(now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for tok, pl := range p.m {
		if now.After(pl.expiresAt) {
			delete(p.m, tok)
		}
	}
}

func (p *pendingStore) put(token string, id core.IdentityID) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.m[token] = pendingLogin{identityID: id, expiresAt: time.Now().UTC().Add(5 * time.Minute)}
}

// take returns the identity for a valid non-expired token and removes
// it from the store. Returns (zero, false) if the token is missing or
// expired.
func (p *pendingStore) take(token string) (core.IdentityID, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	pl, ok := p.m[token]
	if !ok || time.Now().UTC().After(pl.expiresAt) {
		delete(p.m, token)
		return core.IdentityID{}, false
	}
	delete(p.m, token)
	return pl.identityID, true
}

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

	identitySvc *identity.Service // used for TOTP verification in LoginStep2
	pending     *pendingStore     // short-lived pending-token store for two-step login
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
	identitySvc *identity.Service,
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
		identitySvc:  identitySvc,
		pending:      newPendingStore(),
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

// LoginStep1 is the response to POST /v1/auth/login. If the identity
// has TOTP enabled, NeedsTOTP is true and PendingToken holds a
// short-lived token the client must submit along with a TOTP code to
// POST /v1/auth/login/totp. Otherwise LoginResult is populated with
// the full token pair and the client is logged in.
type LoginStep1 struct {
	*LoginResult        // populated when !NeedsTOTP
	NeedsTOTP    bool   `json:"needs_totp,omitempty"`
	PendingToken string `json:"pending_token,omitempty"`
}

// LoginStep2Request carries the TOTP code from the client after
// LoginStep1 returned NeedsTOTP=true.
type LoginStep2Request struct {
	PendingToken string `json:"pending_token" validate:"required"`
	Code         string `json:"code" validate:"required"`
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

// Login verifies password and returns either a full token pair (for
// identities without TOTP) or a short-lived pending token requiring a
// second-factor TOTP submission via LoginStep2.
func (s *Service) Login(ctx context.Context, req LoginRequest) (*LoginStep1, error) {
	ident, err := s.identities.GetByEmail(ctx, req.Email)
	if err != nil {
		return nil, err
	}
	if ident == nil || !crypto.VerifyPassword(ident.PasswordHash, req.Password) {
		return nil, core.NewAppError(core.ErrAuthenticationRequired, "Invalid email or password")
	}

	if ident.TOTPEnabled() {
		raw, err := crypto.GenerateRefreshToken()
		if err != nil {
			return nil, core.NewAppError(core.ErrInternalError, "Failed to generate pending token")
		}
		s.pending.put(raw, ident.ID)
		return &LoginStep1{NeedsTOTP: true, PendingToken: raw}, nil
	}

	result, err := s.buildLoginResult(ctx, ident)
	if err != nil {
		return nil, err
	}
	return &LoginStep1{LoginResult: result}, nil
}

// LoginStep2 verifies a TOTP code against a pending token from Login
// and, on success, returns the full token pair. The pending token is
// consumed on first attempt (success or failure) to prevent replay.
func (s *Service) LoginStep2(ctx context.Context, req LoginStep2Request) (*LoginResult, error) {
	identityID, ok := s.pending.take(req.PendingToken)
	if !ok {
		return nil, core.NewAppError(core.ErrAuthenticationRequired, "Invalid or expired pending token")
	}
	identity, err := s.identitySvc.VerifyTOTP(ctx, identityID, req.Code)
	if err != nil {
		return nil, err
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

func (s *Service) ListAPIKeys(ctx context.Context, targetAccountID core.AccountID, env core.Environment, cursor core.Cursor, limit int) ([]domain.APIKey, bool, error) {
	var keys []domain.APIKey
	var hasMore bool
	err := s.txManager.WithTargetAccount(ctx, targetAccountID, env, func(ctx context.Context) error {
		var err error
		keys, hasMore, err = s.apiKeys.ListByAccount(ctx, env, cursor, limit)
		return err
	})
	if err != nil {
		return nil, false, err
	}
	return keys, hasMore, nil
}

func (s *Service) DeleteAPIKey(ctx context.Context, targetAccountID core.AccountID, env core.Environment, id core.APIKeyID) error {
	return s.txManager.WithTargetAccount(ctx, targetAccountID, env, func(ctx context.Context) error {
		return s.apiKeys.Delete(ctx, id)
	})
}

// --- Lifecycle ---

// Close releases any background resources (currently just the pending
// store sweep goroutine). Production callers don't need to call this
// — the Service is a process singleton. Tests call it via t.Cleanup.
func (s *Service) Close() {
	if s.pending != nil {
		s.pending.Close()
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
