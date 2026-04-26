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
	pending     *pendingStore     // short-lived pending-token store for two-step login

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
) *Service {
	// Compute the dummy hash once at construction so the hot path
	// stays O(1) verify. A failure here means the Argon2 parameters
	// are broken and the process cannot start — panic is appropriate.
	dummyHash, err := crypto.HashPassword("no-real-password-will-ever-match-this")
	if err != nil {
		panic("auth: failed to generate dummy password hash: " + err.Error())
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
		pending:           newPendingStore(),
		dummyPasswordHash: dummyHash,
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
	MembershipID core.MembershipID `json:"membership_id" validate:"required"`
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
	// Scope defaults to core.APIKeyScopeAccountWide when empty.
	Scope core.APIKeyScope `json:"scope,omitempty"`
	// ProductID is required when Scope=core.APIKeyScopeProduct,
	// MUST be nil otherwise. Service-level validation enforces this.
	ProductID *core.ProductID `json:"product_id,omitempty"`
	// ExpiresAt, if non-nil, sets the API key's expiration timestamp.
	// The middleware rejects requests authenticated with an expired
	// key. Must be in the future at creation time (422 otherwise).
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
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

		_, rawKey, err := s.createAPIKeyRecord(ctx, account.ID, core.EnvironmentLive, core.APIKeyScopeAccountWide, nil, nil, nil)
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
		s.pending.put(raw, ident.ID)
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
	identityID, ok := s.pending.take(req.PendingToken)
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

// --- API keys ---

// CreateAPIKey mints a new API key for the target account. Scope defaults
// to account_wide; product-scoped keys must additionally include a
// product_id belonging to the target account (not a different tenant —
// RLS-filtered to prevent existence leaks across accounts).
func (s *Service) CreateAPIKey(ctx context.Context, targetAccountID core.AccountID, env core.Environment, req CreateAPIKeyRequest) (*CreateAPIKeyResult, error) {
	reqEnv, err := core.ParseEnvironment(req.Environment)
	if err != nil {
		return nil, core.NewAppError(core.ErrValidationError, "Invalid environment slug")
	}

	if req.ExpiresAt != nil && !req.ExpiresAt.After(time.Now().UTC()) {
		return nil, core.NewAppError(core.ErrValidationError,
			"expires_at must be in the future")
	}

	scope := req.Scope
	if scope == "" {
		scope = core.APIKeyScopeAccountWide
	}
	switch scope {
	case core.APIKeyScopeAccountWide:
		if req.ProductID != nil {
			return nil, core.NewAppError(core.ErrValidationError,
				"product_id must be omitted when scope is account_wide")
		}
	case core.APIKeyScopeProduct:
		if req.ProductID == nil {
			return nil, core.NewAppError(core.ErrValidationError,
				"product_id is required when scope is product")
		}
	default:
		return nil, core.NewAppError(core.ErrValidationError,
			"scope must be 'account_wide' or 'product'")
	}

	var result *CreateAPIKeyResult
	err = s.txManager.WithTargetAccount(ctx, targetAccountID, env, func(ctx context.Context) error {
		if scope == core.APIKeyScopeProduct {
			// Product existence check runs inside the target-account tx
			// so RLS filters rows to THIS tenant. A product belonging to
			// another tenant resolves to nil here; collapsed to 404 so
			// the caller cannot probe product existence across accounts.
			prod, perr := s.products.GetByID(ctx, *req.ProductID)
			if perr != nil {
				return perr
			}
			if prod == nil {
				return core.NewAppError(core.ErrProductNotFound, "Product not found")
			}
		}
		apiKey, rawKey, cerr := s.createAPIKeyRecord(ctx, targetAccountID, reqEnv, scope, req.ProductID, req.Label, req.ExpiresAt)
		if cerr != nil {
			return cerr
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
) (*domain.APIKey, string, error) {
	rawKey, prefix, err := crypto.GenerateAPIKey(env)
	if err != nil {
		return nil, "", core.NewAppError(core.ErrInternalError, "Failed to generate API key")
	}
	apiKey := &domain.APIKey{
		ID:          core.NewAPIKeyID(),
		AccountID:   accountID,
		ProductID:   productID,
		Prefix:      prefix,
		KeyHash:     s.masterKey.HMAC(rawKey),
		Scope:       scope,
		Label:       label,
		Environment: env,
		ExpiresAt:   expiresAt,
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
