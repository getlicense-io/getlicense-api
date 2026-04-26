package middleware

import (
	"context"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/crypto"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

// systemLookup runs a single read against an RLS-enabled table without
// any tenant context, using TxManager.WithSystemContext so the RLS
// bypass is explicit (PR-B / migration 034). Used by RequireAuth where
// the caller's tenant is not yet known — the API key hash and the JWT
// membership lookup both have to find their row across all tenants.
//
// One short tx per lookup, not a bundled tx across the whole request.
// These are single-statement reads; holding a tx across an entire
// request would burn pool capacity for no benefit.

const localsKeyAuth = "auth"

// authCtxKey is the unexported key for storing AuthContext on the
// request's context.Context. Used by middleware.EnforceProductScope
// (added in Task 10) and any future helper that needs auth from a
// service layer that only has context.Context.
type authCtxKey struct{}

// AuthFromGoContext reads an AuthContext stashed by RequireAuth on
// the request's standard context.Context. Returns nil when not
// authenticated, or when called outside a RequireAuth-wrapped route.
func AuthFromGoContext(ctx context.Context) *AuthContext {
	v := ctx.Value(authCtxKey{})
	if v == nil {
		return nil
	}
	a, _ := v.(*AuthContext)
	return a
}

// WithAuthForTest seeds an AuthContext into a context.Context under
// the same key the production middleware uses. Intended ONLY for
// service-layer tests that need to exercise AuthFromGoContext-backed
// helpers (e.g. middleware.EnforceProductScope) without spinning up
// a full Fiber request. Never call from non-test code.
func WithAuthForTest(ctx context.Context, auth *AuthContext) context.Context {
	return context.WithValue(ctx, authCtxKey{}, auth)
}

// HeaderEnvironment lets JWT-authenticated clients (e.g. the dashboard)
// opt into a specific environment per request. API key auth ignores it
// — the API key's own environment is authoritative there.
const HeaderEnvironment = "X-Environment"

// ActorKind distinguishes how the caller authenticated.
type ActorKind string

const (
	ActorKindIdentity ActorKind = "identity" // JWT auth
	ActorKindAPIKey   ActorKind = "api_key"  // API key auth
)

// AuthContext carries the three-ID model plus actor metadata for one
// request. Populated by RequireAuth and optionally mutated by the
// grant routing middleware (on /v1/grants/:id/... routes) to switch
// the target account from the acting account to the grantor.
//
// In every standard route, TargetAccountID == ActingAccountID. They
// diverge ONLY inside grant routes. Handlers that scope DB writes to
// a tenant (e.g. license.Create) must use TargetAccountID. Audit logs
// and rate-limit keys use ActingAccountID so grantee usage bills the
// grantee, not the grantor.
//
// Reachable from two places:
//   - c.Locals(localsKeyAuth) via AuthFromContext(c) — handler code path
//   - ctx.Value(authCtxKey{}) via AuthFromGoContext(ctx) — service code path,
//     consumed by middleware.EnforceProductScope
type AuthContext struct {
	ActorKind ActorKind

	// Identity-only fields (nil for API key auth)
	IdentityID   *core.IdentityID
	MembershipID *core.MembershipID

	// API key-only field (nil for identity auth)
	APIKeyID *core.APIKeyID

	// Product-scope fields, populated by resolveAPIKey ONLY.
	// APIKeyScope is "" for identity auth. APIKeyProductID is non-nil
	// only when ActorKind=APIKey AND APIKeyScope=core.APIKeyScopeProduct.
	// Identity callers and account-wide-key callers never trigger the
	// product-scope gate in downstream services.
	APIKeyScope     core.APIKeyScope
	APIKeyProductID *core.ProductID

	// Shared — every authenticated request has these.
	ActingAccountID core.AccountID
	TargetAccountID core.AccountID
	Environment     core.Environment
	Role            *domain.Role

	// Populated only by the grant routing middleware inside
	// /v1/grants/:id/... routes; nil for every other route.
	GrantID *core.GrantID

	// JWT-only metadata (populated by resolveJWT). Zero-valued for
	// API-key auth. Used by /v1/auth/logout to revoke the access JWT
	// for the remainder of its natural lifetime — the revocation row's
	// expires_at is set to JWTExpiresAt so the row is GC'd by the
	// background sweep once the token can no longer validate anyway.
	JTI          core.JTI
	JWTIssuedAt  time.Time
	JWTExpiresAt time.Time
}

// IsAPIKey reports whether this request was authenticated with an API
// key (as opposed to an identity JWT). Handlers that require identity
// auth (e.g. /auth/me, /auth/switch) use this to reject API-key callers.
func (a *AuthContext) IsAPIKey() bool {
	return a.ActorKind == ActorKindAPIKey
}

// AuthFromContext pulls the AuthContext stored during RequireAuth.
// Returns nil if authentication has not been performed.
func AuthFromContext(c fiber.Ctx) *AuthContext {
	v := c.Locals(localsKeyAuth)
	if v == nil {
		return nil
	}
	a, ok := v.(*AuthContext)
	if !ok {
		return nil
	}
	return a
}

// Dependencies bundles the repos RequireAuth needs to resolve a JWT
// into a full AuthContext. Identity JWTs require a membership + role
// lookup per request so permission checks run against DB-authoritative
// data, not claim-provided data.
type Dependencies struct {
	APIKeys     domain.APIKeyRepository
	Memberships domain.AccountMembershipRepository
	MasterKey   *crypto.MasterKey

	// TxManager is used to wrap the API key hash lookup and the JWT
	// membership lookup in WithSystemContext. Both read RLS-enabled
	// tables before the caller's tenant is known. PR-B (migration 034)
	// removed the implicit IS NULL bypass; the explicit
	// app.system_context GUC is required for these lookups to succeed.
	TxManager domain.TxManager

	// AdminRole is the preset "admin" role loaded once at startup and
	// reused by every API key authentication. Eliminates a DB round-trip
	// per API key request since the preset never changes at runtime.
	AdminRole *domain.Role

	// JWTRevocations powers the per-request revocation check on JWT
	// auth (jti present in revoked_jtis OR iat < min_iat for the
	// identity). Optional — when nil, the revocation check is skipped
	// (used by tests that don't care about revocation). Production
	// MUST set this; serve.go wires it unconditionally.
	JWTRevocations domain.JWTRevocationRepository
}

// RequireAuth returns middleware that validates either an API key or a
// JWT bearer token and populates AuthContext. It does NOT check
// permissions — handlers do that via rbac.Require.
func RequireAuth(deps Dependencies) fiber.Handler {
	return func(c fiber.Ctx) error {
		header := c.Get("Authorization")
		if header == "" {
			return core.NewAppError(core.ErrAuthenticationRequired, "Missing Authorization header")
		}
		token := strings.TrimPrefix(header, "Bearer ")
		if token == header {
			return core.NewAppError(core.ErrAuthenticationRequired, "Invalid Authorization header format")
		}
		if strings.HasPrefix(token, core.APIKeyPrefixLive) || strings.HasPrefix(token, core.APIKeyPrefixTest) {
			return resolveAPIKey(c, deps, token)
		}
		return resolveJWT(c, deps, token)
	}
}

func resolveAPIKey(c fiber.Ctx, deps Dependencies, token string) error {
	keyHash := deps.MasterKey.HMAC(token)
	// API key lookup runs across all tenants — the caller has presented
	// a hash and we need to find the row before we know which tenant
	// they belong to. Wrap in WithSystemContext for an explicit RLS
	// bypass under migration 034.
	var apiKey *domain.APIKey
	lookupErr := deps.TxManager.WithSystemContext(c.Context(), func(ctx context.Context) error {
		k, err := deps.APIKeys.GetByHash(ctx, keyHash)
		if err != nil {
			return err
		}
		apiKey = k
		return nil
	})
	if lookupErr != nil || apiKey == nil {
		return core.NewAppError(core.ErrInvalidAPIKey, "Invalid API key")
	}

	// Reject expired keys with a distinct message so debugging can
	// differentiate "this key never existed / wrong hash" (above) from
	// "this key was issued and has since expired" (here). Both surface
	// the same ErrInvalidAPIKey code (401) so callers cannot probe.
	if apiKey.ExpiresAt != nil && time.Now().UTC().After(*apiKey.ExpiresAt) {
		return core.NewAppError(core.ErrInvalidAPIKey, "API key expired")
	}

	if deps.AdminRole == nil {
		return core.NewAppError(core.ErrInternalError, "Missing admin role preset")
	}

	apiKeyID := apiKey.ID
	auth := &AuthContext{
		ActorKind:       ActorKindAPIKey,
		APIKeyID:        &apiKeyID,
		APIKeyScope:     apiKey.Scope,
		APIKeyProductID: apiKey.ProductID,
		ActingAccountID: apiKey.AccountID,
		TargetAccountID: apiKey.AccountID,
		Environment:     apiKey.Environment,
		Role:            deps.AdminRole,
	}
	c.Locals(localsKeyAuth, auth)
	c.SetContext(context.WithValue(c.Context(), authCtxKey{}, auth))
	return c.Next()
}

func resolveJWT(c fiber.Ctx, deps Dependencies, token string) error {
	claims, err := deps.MasterKey.VerifyJWT(token)
	if err != nil {
		return core.NewAppError(core.ErrAuthenticationRequired, "Invalid or expired token")
	}

	// Per-request revocation check. Both lookups are cheap (PK index +
	// optional second index lookup) and run BEFORE the membership +
	// role lookup so revoked tokens short-circuit. The revocation
	// tables are NOT RLS-scoped (cross-tenant by design — see
	// migration 035), so they read straight through the pool without
	// WithSystemContext. JWTRevocations is optional in the
	// Dependencies struct so unit tests that don't care about
	// revocation can leave it nil; production wires it unconditionally
	// (serve.go).
	if deps.JWTRevocations != nil {
		revoked, rerr := deps.JWTRevocations.IsJTIRevoked(c.Context(), claims.JTI)
		if rerr != nil {
			return core.NewAppError(core.ErrInternalError, "Revocation check failed")
		}
		if revoked {
			return core.NewAppError(core.ErrAuthenticationRequired, "Token revoked")
		}
		minIAT, merr := deps.JWTRevocations.GetSessionMinIAT(c.Context(), claims.IdentityID)
		if merr != nil {
			return core.NewAppError(core.ErrInternalError, "Session check failed")
		}
		if minIAT != nil && claims.IssuedAt.Before(*minIAT) {
			return core.NewAppError(core.ErrAuthenticationRequired, "Session invalidated")
		}
	}

	// Re-resolve membership + role from DB every request in one query.
	// Users can't forge elevated permissions even with a stolen JWT —
	// the role comes from the DB, not the claim.
	//
	// account_memberships is RLS-enabled; the caller's tenant context
	// is exactly what this lookup is establishing, so we wrap in
	// WithSystemContext for an explicit bypass (PR-B / migration 034).
	var (
		membership *domain.AccountMembership
		role       *domain.Role
	)
	if err := deps.TxManager.WithSystemContext(c.Context(), func(ctx context.Context) error {
		m, r, lerr := deps.Memberships.GetByIDWithRole(ctx, claims.MembershipID)
		if lerr != nil {
			return lerr
		}
		membership, role = m, r
		return nil
	}); err != nil {
		return core.NewAppError(core.ErrAuthenticationRequired, "Membership lookup failed")
	}
	if membership == nil || role == nil || membership.Status != domain.MembershipStatusActive {
		return core.NewAppError(core.ErrAuthenticationRequired, "Membership not found or inactive")
	}
	if membership.IdentityID != claims.IdentityID || membership.AccountID != claims.ActingAccountID {
		return core.NewAppError(core.ErrAuthenticationRequired, "Membership mismatch")
	}

	environment := core.EnvironmentLive
	if raw := c.Get(HeaderEnvironment); raw != "" {
		parsed, perr := core.ParseEnvironment(raw)
		if perr != nil {
			return core.NewAppError(core.ErrValidationError, "Invalid X-Environment header")
		}
		environment = parsed
	}

	identityID := claims.IdentityID
	membershipID := claims.MembershipID
	auth := &AuthContext{
		ActorKind:       ActorKindIdentity,
		IdentityID:      &identityID,
		MembershipID:    &membershipID,
		ActingAccountID: claims.ActingAccountID,
		TargetAccountID: claims.ActingAccountID,
		Environment:     environment,
		Role:            role,
		JTI:             claims.JTI,
		JWTIssuedAt:     claims.IssuedAt,
		JWTExpiresAt:    claims.ExpiresAt,
	}
	c.Locals(localsKeyAuth, auth)
	c.SetContext(context.WithValue(c.Context(), authCtxKey{}, auth))
	return c.Next()
}
