package domain

import (
	"context"
	"encoding/json"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
)

type AccountRepository interface {
	Create(ctx context.Context, account *Account) error
	GetByID(ctx context.Context, id core.AccountID) (*Account, error)
	GetBySlug(ctx context.Context, slug string) (*Account, error)
	// GetIfAccessible returns the target account only when the caller
	// has a visibility relationship: a membership on the target account
	// under the caller's identity, or a non-terminal grant between
	// caller and target in either direction. Returns (nil, nil) when
	// the caller has no such relationship — never leaks existence.
	// Runs outside tenant RLS; callers MUST NOT pin
	// app.current_account_id on the session.
	GetIfAccessible(
		ctx context.Context,
		targetID core.AccountID,
		callerAccountID core.AccountID,
		callerIdentityID core.IdentityID,
	) (*Account, error)
}

type EnvironmentRepository interface {
	Create(ctx context.Context, env *Environment) error
	ListByAccount(ctx context.Context) ([]Environment, error)
	GetBySlug(ctx context.Context, slug core.Environment) (*Environment, error)
	Delete(ctx context.Context, id core.EnvironmentID) error
	CountByAccount(ctx context.Context) (int, error)
}

// IdentityRepository manages global login records.
// Identities are not tenant-scoped; all methods run without RLS context.
type IdentityRepository interface {
	Create(ctx context.Context, identity *Identity) error
	GetByID(ctx context.Context, id core.IdentityID) (*Identity, error)
	GetByEmail(ctx context.Context, email string) (*Identity, error)
	Update(ctx context.Context, identity *Identity) error
	UpdatePassword(ctx context.Context, id core.IdentityID, passwordHash string) error
	UpdateTOTP(ctx context.Context, id core.IdentityID, secretEnc []byte, enabledAt *time.Time) error
}

// RecoveryCodeRepository persists per-identity TOTP recovery codes
// with row-per-code storage so single-use semantics can be enforced
// atomically via DELETE-RETURNING. Identities are global, so this
// repo runs without RLS context like IdentityRepository.
type RecoveryCodeRepository interface {
	// Insert writes a fresh batch of code hashes for an identity.
	// Called from ActivateTOTP after generating + hashing N codes.
	// Idempotent — duplicate (identity_id, code_hash) pairs are
	// silently ignored at the SQL level via ON CONFLICT DO NOTHING.
	Insert(ctx context.Context, identityID core.IdentityID, codeHashes []string) error
	// Consume atomically deletes the row matching
	// (identity_id, code_hash) when a row exists. Returns true on
	// hit, false on miss. Concurrent calls for the same code
	// produce exactly one true.
	Consume(ctx context.Context, identityID core.IdentityID, codeHash string) (bool, error)
	// DeleteAll removes all recovery codes for an identity. Used
	// by DisableTOTP and during identity teardown.
	DeleteAll(ctx context.Context, identityID core.IdentityID) error
	// Count returns the number of unconsumed recovery codes for an
	// identity. Used by tests.
	Count(ctx context.Context, identityID core.IdentityID) (int, error)
}

// RoleRepository reads preset and custom roles. Preset rows (account_id NULL)
// are visible to every tenant; custom rows are tenant-scoped via RLS.
type RoleRepository interface {
	GetByID(ctx context.Context, id core.RoleID) (*Role, error)
	GetBySlug(ctx context.Context, accountID *core.AccountID, slug string) (*Role, error)
	ListPresets(ctx context.Context) ([]Role, error)
	ListByAccount(ctx context.Context) ([]Role, error) // presets + custom for current tenant
}

// AccountMembershipRepository manages identity ↔ account joins.
type AccountMembershipRepository interface {
	Create(ctx context.Context, m *AccountMembership) error
	GetByID(ctx context.Context, id core.MembershipID) (*AccountMembership, error)
	// GetByIDWithRole loads a membership and its role in one round-trip.
	// Used by RequireAuth middleware to save a second DB query per JWT
	// request. Returns (nil, nil, nil) when no membership matches the ID.
	GetByIDWithRole(ctx context.Context, id core.MembershipID) (*AccountMembership, *Role, error)
	GetByIdentityAndAccount(ctx context.Context, identityID core.IdentityID, accountID core.AccountID) (*AccountMembership, error)
	ListByIdentity(ctx context.Context, identityID core.IdentityID) ([]AccountMembership, error)
	// ListByAccount returns a cursor-paginated page of memberships for
	// the current RLS-scoped account. The bool return is `hasMore` —
	// true when more rows exist beyond the returned slice.
	ListByAccount(ctx context.Context, cursor core.Cursor, limit int) ([]AccountMembership, bool, error)
	UpdateRole(ctx context.Context, id core.MembershipID, roleID core.RoleID) error
	UpdateStatus(ctx context.Context, id core.MembershipID, status MembershipStatus) error
	Delete(ctx context.Context, id core.MembershipID) error
	// CountOwners returns the number of active members holding the owner
	// role for the given account. Used to prevent removing the last
	// active owner. Suspended memberships are NOT counted.
	CountOwners(ctx context.Context, accountID core.AccountID) (int, error)
	// ListAccountWithDetails returns memberships in the current RLS
	// account, joined with their identity (id+email) and role
	// (id+slug+name). Used by the GET /v1/accounts/:id/members endpoint
	// for the dashboard team page.
	ListAccountWithDetails(
		ctx context.Context,
		cursor core.Cursor,
		limit int,
	) ([]MembershipDetail, bool, error)
}

type ProductRepository interface {
	Create(ctx context.Context, product *Product) error
	GetByID(ctx context.Context, id core.ProductID) (*Product, error)
	List(ctx context.Context, cursor core.Cursor, limit int) ([]Product, bool, error)
	Update(ctx context.Context, id core.ProductID, params UpdateProductParams) (*Product, error)
	Delete(ctx context.Context, id core.ProductID) error
	// Search returns products whose name or slug prefix-matches the query
	// (case-insensitive). Used by the global search endpoint.
	Search(ctx context.Context, query string, limit int) ([]Product, error)
}

// CustomerRepository persists end-user customer records. Account-scoped,
// environment-agnostic. Email comparisons are case-insensitive via a
// unique (account_id, lower(email)) index.
type CustomerRepository interface {
	Create(ctx context.Context, c *Customer) error
	Get(ctx context.Context, id core.CustomerID) (*Customer, error)
	GetByEmail(ctx context.Context, accountID core.AccountID, email string) (*Customer, error)
	List(ctx context.Context, accountID core.AccountID, filter CustomerListFilter, cursor core.Cursor, limit int) ([]Customer, bool, error)
	Update(ctx context.Context, c *Customer) error
	Delete(ctx context.Context, id core.CustomerID) error
	CountReferencingLicenses(ctx context.Context, id core.CustomerID) (int, error)

	// UpsertByEmail inserts a new customer row or returns the existing one
	// keyed on (account_id, lower(email)). On insert, createdByAccountID
	// is written to customers.created_by_account_id (may be nil). On
	// conflict, existing row is returned UNCHANGED — name and metadata
	// from the request are ignored (first-write-wins per spec §Upsert semantics).
	UpsertByEmail(ctx context.Context, accountID core.AccountID, email string, name *string, metadata json.RawMessage, createdByAccountID *core.AccountID) (*Customer, bool, error)
}

// CustomerListFilter is the narrow filter surface for customer list queries.
type CustomerListFilter struct {
	Email              string          // case-insensitive prefix match; empty = no filter
	Name               string          // case-insensitive prefix match; empty = no filter
	CreatedByAccountID *core.AccountID // nil = no filter
}

// EntitlementRepository manages the entitlements registry and its
// attachments to policies and licenses. Account-scoped, environment-agnostic.
type EntitlementRepository interface {
	Create(ctx context.Context, e *Entitlement) error
	Get(ctx context.Context, id core.EntitlementID) (*Entitlement, error)
	GetByCodes(ctx context.Context, accountID core.AccountID, codes []string) ([]Entitlement, error)
	List(ctx context.Context, accountID core.AccountID, codePrefix string, cursor core.Cursor, limit int) ([]Entitlement, bool, error)
	Update(ctx context.Context, e *Entitlement) error
	Delete(ctx context.Context, id core.EntitlementID) error

	AttachToPolicy(ctx context.Context, policyID core.PolicyID, entitlementIDs []core.EntitlementID) error
	DetachFromPolicy(ctx context.Context, policyID core.PolicyID, entitlementIDs []core.EntitlementID) error
	ReplacePolicyAttachments(ctx context.Context, policyID core.PolicyID, entitlementIDs []core.EntitlementID) error
	ListPolicyCodes(ctx context.Context, policyID core.PolicyID) ([]string, error)

	AttachToLicense(ctx context.Context, licenseID core.LicenseID, entitlementIDs []core.EntitlementID) error
	DetachFromLicense(ctx context.Context, licenseID core.LicenseID, entitlementIDs []core.EntitlementID) error
	ReplaceLicenseAttachments(ctx context.Context, licenseID core.LicenseID, entitlementIDs []core.EntitlementID) error
	ListLicenseCodes(ctx context.Context, licenseID core.LicenseID) ([]string, error)

	ResolveEffective(ctx context.Context, licenseID core.LicenseID) ([]string, error)
}

// PolicyRepository persists policies and resolves them for licensing.
type PolicyRepository interface {
	Create(ctx context.Context, p *Policy) error
	Get(ctx context.Context, id core.PolicyID) (*Policy, error)
	GetByProduct(ctx context.Context, productID core.ProductID, cursor core.Cursor, limit int) ([]Policy, bool, error)
	GetDefaultForProduct(ctx context.Context, productID core.ProductID) (*Policy, error)
	Update(ctx context.Context, p *Policy) error
	Delete(ctx context.Context, id core.PolicyID) error
	SetDefault(ctx context.Context, productID core.ProductID, policyID core.PolicyID) error
	ReassignLicensesFromPolicy(ctx context.Context, fromPolicyID, toPolicyID core.PolicyID) (int, error)
	CountReferencingLicenses(ctx context.Context, id core.PolicyID) (int, error)
}

// LicenseListFilters narrows a license listing. All fields are optional;
// a zero-valued struct means "no filter, return everything in this tenant".
// Dashboards use this to drive URL-driven filters that survive pagination.
type LicenseListFilters struct {
	// Status, if non-empty, restricts to licenses with that status.
	Status core.LicenseStatus
	// Q is a case-insensitive prefix/substring match. Matches are ORed
	// across `key_prefix` (prefix) and the referenced customer's name
	// and email (substring, joined via EXISTS subquery). Empty = no search.
	Q string
	// CustomerID, if non-nil, restricts to licenses owned by the given
	// customer. Powers GET /v1/customers/:id/licenses.
	CustomerID *core.CustomerID
	// ProductID, if non-nil, restricts to licenses owned by the given
	// product. Populated from the query string on GET /v1/licenses AND
	// auto-injected from AuthContext.APIKeyProductID for product-scoped
	// API keys. If BOTH are present, the handler returns 403 when they
	// disagree (caught before the repo is called). The dedicated
	// ListByProduct path uses its own productID arg — when that arg is
	// non-nil it takes precedence over this filter field.
	ProductID *core.ProductID
}

type LicenseRepository interface {
	Create(ctx context.Context, license *License) error
	BulkCreate(ctx context.Context, licenses []*License) error
	GetByID(ctx context.Context, id core.LicenseID) (*License, error)
	GetByIDForUpdate(ctx context.Context, id core.LicenseID) (*License, error)
	GetByKeyHash(ctx context.Context, keyHash string) (*License, error)
	List(ctx context.Context, filters LicenseListFilters, cursor core.Cursor, limit int) ([]License, bool, error)
	ListByProduct(ctx context.Context, productID core.ProductID, filters LicenseListFilters, cursor core.Cursor, limit int) ([]License, bool, error)
	// Update persists mutable license fields (policy_id, overrides,
	// customer_id, first_activated_at, expires_at) and refreshes
	// updated_at. Status transitions go through UpdateStatus to
	// preserve the from/to state check.
	Update(ctx context.Context, license *License) error
	UpdateStatus(ctx context.Context, id core.LicenseID, from core.LicenseStatus, to core.LicenseStatus) (time.Time, error)
	CountByProduct(ctx context.Context, productID core.ProductID) (int, error)
	// CountsByProductStatus returns a per-status breakdown of every
	// license belonging to the given product in the current RLS env.
	CountsByProductStatus(ctx context.Context, productID core.ProductID) (LicenseStatusCounts, error)
	// BulkRevokeByProduct atomically revokes every active or suspended
	// license for the given product in the current RLS env. Returns
	// the number of rows affected.
	BulkRevokeByProduct(ctx context.Context, productID core.ProductID) (int, error)
	// HasBlocking reports whether any active or suspended license
	// exists in the current RLS tenant+environment context. Used to
	// gate environment deletion without a full COUNT.
	HasBlocking(ctx context.Context) (bool, error)
	ExpireActive(ctx context.Context) ([]License, error)
}

type MachineRepository interface {
	// Get / read paths
	GetByID(ctx context.Context, id core.MachineID) (*Machine, error)
	GetByFingerprint(ctx context.Context, licenseID core.LicenseID, fingerprint string) (*Machine, error)

	// Counting (alive = active|stale; dead is excluded)
	CountAliveByLicense(ctx context.Context, licenseID core.LicenseID) (int, error)

	// Activation paths
	UpsertActivation(ctx context.Context, m *Machine) error
	RenewLease(ctx context.Context, m *Machine) error

	// Hard delete (Deactivate endpoint)
	DeleteByFingerprint(ctx context.Context, licenseID core.LicenseID, fingerprint string) error

	// Background sweep
	MarkStaleExpired(ctx context.Context) (int, error)
	MarkDeadExpired(ctx context.Context) (int, error)

	// Search returns machines whose fingerprint or hostname prefix-matches
	// the query (case-insensitive). Used by the global search endpoint.
	Search(ctx context.Context, query string, limit int) ([]Machine, error)

	// ListByLicense returns machines for licenseID in the current RLS
	// context, cursor-paginated. statusFilter is optional ("" means no
	// filter). Used by GET /v1/licenses/:id/machines.
	ListByLicense(
		ctx context.Context,
		licenseID core.LicenseID,
		statusFilter string,
		cursor core.Cursor,
		limit int,
	) ([]Machine, bool, error)
}

type APIKeyRepository interface {
	Create(ctx context.Context, key *APIKey) error
	GetByHash(ctx context.Context, keyHash string) (*APIKey, error)
	// ListByAccount returns API keys for the current RLS account,
	// scoped to the given environment. The env filter is applied at
	// the SQL level rather than via RLS because the api_keys RLS
	// policy intentionally does not filter by environment (a live
	// key is allowed to create/delete a test key).
	ListByAccount(ctx context.Context, env core.Environment, cursor core.Cursor, limit int) ([]APIKey, bool, error)
	Delete(ctx context.Context, id core.APIKeyID) error
}

type WebhookRepository interface {
	CreateEndpoint(ctx context.Context, ep *WebhookEndpoint) error
	GetEndpointByID(ctx context.Context, id core.WebhookEndpointID) (*WebhookEndpoint, error)
	ListEndpoints(ctx context.Context, cursor core.Cursor, limit int) ([]WebhookEndpoint, bool, error)
	DeleteEndpoint(ctx context.Context, id core.WebhookEndpointID) error
	GetActiveEndpointsByEvent(ctx context.Context, eventType core.EventType) ([]WebhookEndpoint, error)

	// RotateSigningSecret replaces the encrypted signing secret on the
	// endpoint with the supplied ciphertext. Returns
	// ErrWebhookEndpointNotFound when no row matched. Caller MUST run
	// inside a tenant tx so RLS scopes the UPDATE to the right
	// account+environment.
	RotateSigningSecret(ctx context.Context, id core.WebhookEndpointID, encrypted []byte) error

	CreateEvent(ctx context.Context, event *WebhookEvent) error
	UpdateEventStatus(ctx context.Context, id core.WebhookEventID, status core.DeliveryStatus, attempts int, responseStatus *int, responseBody *string, responseBodyTruncated bool, responseHeaders json.RawMessage, nextRetryAt *time.Time) error
	GetEventByID(ctx context.Context, id core.WebhookEventID) (*WebhookEvent, error)
	ListEventsByEndpoint(ctx context.Context, endpointID core.WebhookEndpointID, filter WebhookDeliveryFilter, cursor core.Cursor, limit int) ([]WebhookEvent, bool, error)

	// --- Outbox / worker pool (PR-3.1) ---
	//
	// Workers run WITHOUT tenant context — the webhook_events RLS
	// policy allows this via the standard NULLIF escape hatch.

	// ClaimNext atomically claims the next pending webhook event and
	// returns it. Returns (nil, nil) when the queue is empty. The
	// caller MUST call MarkDelivered, MarkFailedRetry, or
	// MarkFailedFinal to release the claim — otherwise it expires
	// after claim_expires_at and the row becomes reclaimable by the
	// next worker.
	ClaimNext(ctx context.Context, claimToken core.WebhookClaimToken, claimExpiresAt time.Time) (*WebhookEvent, error)

	// ReleaseStaleClaims clears claim_token on rows whose
	// claim_expires_at has passed. Returns the number of rows
	// released. Run once at startup AND periodically by the worker
	// pool's stale-claim sweeper.
	ReleaseStaleClaims(ctx context.Context) (int, error)

	// MarkDelivered records a successful delivery and clears the claim.
	// Returns the affected rowcount; 0 means another worker reclaimed
	// the row before the caller could record the outcome (claim was
	// lost — caller should log and skip without erroring). Caller
	// MUST pass the same claim token it received from ClaimNext so
	// the WHERE-clause predicate refuses overwrites by stale workers.
	MarkDelivered(ctx context.Context, id core.WebhookEventID, claimToken core.WebhookClaimToken, attempts int, result DeliveryResult) (int64, error)

	// MarkFailedRetry records a failed attempt with retry pending.
	// nextRetryAt is when the worker may re-claim this row. Same
	// claim_token gate + (int64, error) return semantics as
	// MarkDelivered.
	MarkFailedRetry(ctx context.Context, id core.WebhookEventID, claimToken core.WebhookClaimToken, attempts int, result DeliveryResult, nextRetryAt time.Time) (int64, error)

	// MarkFailedFinal records a permanent failure (retries exhausted
	// or unrecoverable HTTP status). Same claim_token gate +
	// (int64, error) return semantics as MarkDelivered.
	MarkFailedFinal(ctx context.Context, id core.WebhookEventID, claimToken core.WebhookClaimToken, attempts int, result DeliveryResult) (int64, error)

	// GetDispatcherCheckpoint returns the singleton dispatcher
	// checkpoint row. LastDomainEventID is nil on a fresh install
	// (treat as zero — process from the beginning).
	GetDispatcherCheckpoint(ctx context.Context) (*WebhookDispatcherCheckpoint, error)

	// UpdateDispatcherCheckpoint advances the singleton checkpoint
	// after the dispatcher fans out a batch to the outbox.
	UpdateDispatcherCheckpoint(ctx context.Context, lastDomainEventID core.DomainEventID) error
}

type RefreshTokenRepository interface {
	Create(ctx context.Context, token *RefreshToken) error
	GetByHash(ctx context.Context, tokenHash string) (*RefreshToken, error)
	DeleteByHash(ctx context.Context, tokenHash string) error
	DeleteByIdentityID(ctx context.Context, identityID core.IdentityID) error
	// Consume atomically removes the refresh token if it exists and is
	// unexpired, returning the owning identity_id. Returns (zero ID, nil)
	// on miss. Used by auth.Service.Refresh to close the rotation race
	// inherent in any read-then-delete approach.
	Consume(ctx context.Context, tokenHash string) (core.IdentityID, error)
}

// JWTRevocationRepository manages cross-tenant JWT revocation state.
//
// Two collaborating mechanisms:
//
//  1. revoked_jtis — per-token revocation. POST /v1/auth/logout calls
//     RevokeJTI to mark the access token's jti dead until its natural
//     exp. Verifier middleware rejects via IsJTIRevoked on every JWT
//     auth request.
//
//  2. identity_session_invalidations — bulk revocation. POST
//     /v1/auth/logout-all calls SetSessionInvalidation(now) so every
//     JWT issued before now fails verification. Captures "log me out
//     everywhere" without enumerating jtis.
//
// Both tables are NOT RLS-scoped — they're checked before any tenant
// context exists in the request lifecycle. Background sweep deletes
// revoked_jtis past their expires_at (the row is dead weight once the
// token can't validate anyway).
type JWTRevocationRepository interface {
	// RevokeJTI marks a single jti revoked until expiresAt. Idempotent
	// — concurrent revokes of the same jti are no-ops via ON CONFLICT.
	RevokeJTI(ctx context.Context, jti core.JTI, identityID core.IdentityID, expiresAt time.Time, reason string) error
	// IsJTIRevoked reports whether the jti is in the revocation table
	// AND not yet past expires_at. Past-exp rows are ignored (they are
	// swept by the background loop but the WHERE clause provides safety
	// even before the sweep runs).
	IsJTIRevoked(ctx context.Context, jti core.JTI) (bool, error)
	// SweepExpired deletes rows whose expires_at has passed. Returns
	// the number of rows deleted. Called by the background loop.
	SweepExpired(ctx context.Context) (int, error)
	// SetSessionInvalidation upserts the per-identity session-invalidation
	// cutoff. Tokens with iat < minIAT are rejected at verify time.
	SetSessionInvalidation(ctx context.Context, identityID core.IdentityID, minIAT time.Time) error
	// GetSessionMinIAT returns the per-identity session-invalidation
	// cutoff, or nil if the identity has never invalidated all sessions.
	GetSessionMinIAT(ctx context.Context, identityID core.IdentityID) (*time.Time, error)
}

// InvitationRepository manages invitation tokens for both membership
// and grant kinds. Most methods are RLS-scoped via created_by_account_id.
// GetByTokenHash is a cross-tenant lookup — the unauthenticated
// invitation lookup endpoint uses it before any tenant context exists.
type InvitationRepository interface {
	Create(ctx context.Context, inv *Invitation) error
	// GetByID returns the invitation with the given id. The returned row
	// has CreatedByAccount populated via JOIN and Status computed from
	// (accepted_at, expires_at, now).
	GetByID(ctx context.Context, id core.InvitationID) (*Invitation, error)
	// GetByTokenHash runs without RLS context. Used by the public
	// lookup endpoint to preview an invitation from its token alone.
	GetByTokenHash(ctx context.Context, tokenHash string) (*Invitation, error)
	// ListByAccount returns cursor-paginated invitations for the current
	// RLS-scoped account with optional kind + status filters. Rows
	// include CreatedByAccount via JOIN and a computed Status field.
	ListByAccount(ctx context.Context, filter InvitationListFilter, cursor core.Cursor, limit int) ([]Invitation, bool, error)
	MarkAccepted(ctx context.Context, id core.InvitationID, acceptedAt time.Time) error
	// UpdateTokenHash rotates the invitation's token hash. Used by
	// POST /v1/invitations/:id/resend to invalidate the previous token.
	UpdateTokenHash(ctx context.Context, id core.InvitationID, tokenHash string) error
	Delete(ctx context.Context, id core.InvitationID) error
	// HasActiveGrantInvitation returns true when a pending-unexpired
	// grant-kind invitation already exists for the given
	// (account, lower(email), product) triple. Used by the duplicate
	// guard before creating a new grant invitation.
	HasActiveGrantInvitation(
		ctx context.Context,
		accountID core.AccountID,
		emailLower string,
		productID core.ProductID,
	) (bool, error)
}

// InvitationListFilter narrows an invitation listing. Zero-valued
// struct means "no filter". Status is computed at query time from
// (accepted_at, expires_at, now) — see domain.ComputeInvitationStatus.
type InvitationListFilter struct {
	// Kind, if non-nil, restricts to invitations of a single kind.
	Kind *InvitationKind
	// Status, if non-empty, filters to invitations whose computed status
	// is any of the given values. Accepts a subset of
	// {"pending", "accepted", "expired"}. Nil/empty = no status filter.
	Status []string
	// CreatedByIdentityID, if non-nil, restricts results to invitations
	// created by the given identity. Used by GET /v1/accounts/:id/invitations
	// to show low-privilege callers ONLY their own outgoing invitations
	// when they lack the kind-specific permission for full visibility.
	CreatedByIdentityID *core.IdentityID
}

// GrantRepository manages capability grant records. RLS is enforced on
// both grantor_account_id and grantee_account_id columns so both sides
// of a grant relationship can read the row.
//
// ListByGrantor and ListByGrantee both require a WithTargetAccount
// context — the account filter is pulled from the GUC rather than
// passed as a parameter to avoid ID duplication.
type GrantRepository interface {
	Create(ctx context.Context, grant *Grant) error
	GetByID(ctx context.Context, id core.GrantID) (*Grant, error)

	// ListByGrantor returns grants where the current RLS account is the
	// grantor, with optional filters. Passing zero values for all filter
	// parameters reproduces the old unfiltered behavior.
	ListByGrantor(ctx context.Context, filter GrantListFilter, cursor core.Cursor, limit int) ([]Grant, bool, error)
	// ListByGrantee returns grants where the current RLS account is the
	// grantee, with optional filters. Passing zero values for all filter
	// parameters reproduces the old unfiltered behavior.
	ListByGrantee(ctx context.Context, filter GrantListFilter, cursor core.Cursor, limit int) ([]Grant, bool, error)

	UpdateStatus(ctx context.Context, id core.GrantID, status GrantStatus) error

	// Update applies a partial update. Only fields whose pointer is
	// non-nil on UpdateGrantParams are persisted.
	Update(ctx context.Context, id core.GrantID, params UpdateGrantParams) error

	// MarkAccepted atomically sets status=active, accepted_at, and
	// updated_at in one statement. Used by Service.Accept.
	MarkAccepted(ctx context.Context, id core.GrantID, acceptedAt time.Time) error

	// CountLicensesInPeriod counts licenses attributed to the grant
	// created on or after `since`. Pass time.Time{} for an all-time count.
	// Used by CheckLicenseCreateConstraints for quota enforcement.
	CountLicensesInPeriod(ctx context.Context, grantID core.GrantID, since time.Time) (int, error)

	// GetUsage returns all three grant-usage counters in a single query.
	// `since` bounds the "this month" bucket; all-time total and distinct
	// customer count ignore it. Used by Service.Get to populate the usage
	// field on GET /v1/grants/:id in one round trip.
	GetUsage(ctx context.Context, grantID core.GrantID, since time.Time) (GrantUsage, error)

	// ListExpirable returns grants whose expires_at has passed and whose
	// status is still non-terminal. Used by the background expire_grants
	// job. Must be called without tenant context (RLS bypass via NULLIF).
	ListExpirable(ctx context.Context, now time.Time, limit int) ([]Grant, error)

	// HasActiveGrantForProductEmail returns true when a non-terminal
	// grant (status in pending/active/suspended) already exists for the
	// given (grantor, lower(grantee_email), product) triple. The email
	// is sourced from the originating invitation row via JOIN on
	// invitation_id — directly-issued grants (no invitation) are not
	// matched. Used by the duplicate guard before creating a new grant
	// invitation.
	HasActiveGrantForProductEmail(
		ctx context.Context,
		grantorAccountID core.AccountID,
		granteeEmailLower string,
		productID core.ProductID,
	) (bool, error)
}

// GrantListFilter is the optional filter set for grant list queries.
// Zero values mean "no filter on this field."
type GrantListFilter struct {
	// ProductID, if non-nil, restricts to grants for a single product.
	ProductID *core.ProductID
	// GrantorAccountID, if non-nil, restricts grantee-side listings to
	// grants issued by this grantor. Ignored by the grantor-side list.
	GrantorAccountID *core.AccountID
	// GranteeAccountID, if non-nil, restricts grantor-side listings to
	// grants issued to this grantee. Ignored by the grantee-side list.
	GranteeAccountID *core.AccountID
	// Statuses, if non-empty, filters to grants whose status is any of
	// the given values (OR-combined).
	Statuses []GrantStatus
	// IncludeTerminal, when false (the default), excludes grants in
	// revoked / left / expired status. Set true to include them.
	IncludeTerminal bool
}

// UpdateGrantParams is the partial-update shape for PATCH grant.
// Pointer-nil means "don't touch this column." Pointer-non-nil
// with inner nil (e.g., *ExpiresAt with value nil) means "set to NULL."
type UpdateGrantParams struct {
	// Capabilities, when non-nil, replaces the capability set.
	Capabilities *[]GrantCapability
	// Constraints, when non-nil, replaces the constraints JSON blob.
	Constraints *json.RawMessage
	// ExpiresAt uses double pointer semantics: outer nil = no change;
	// inner nil = clear to NULL; inner non-nil = set to that time.
	ExpiresAt **time.Time
	// Label uses double pointer semantics: outer nil = no change;
	// inner nil = clear to NULL; inner non-nil = set to that string.
	Label **string
	// Metadata, when non-nil, replaces the metadata JSON blob.
	Metadata *json.RawMessage
}

// DomainEventRepository defines the persistence interface for domain events.
type DomainEventRepository interface {
	Create(ctx context.Context, e *DomainEvent) error
	Get(ctx context.Context, id core.DomainEventID) (*DomainEvent, error)
	List(ctx context.Context, filter DomainEventFilter, cursor core.Cursor, limit int) ([]DomainEvent, bool, error)
	// CountFiltered returns the number of events matching the given filter.
	// Used by the CSV export handler to enforce a pre-flight row cap before
	// streaming. Runs under the current RLS tenant context.
	CountFiltered(ctx context.Context, filter DomainEventFilter) (int64, error)
	// ListSince returns up to `limit` domain events with id > afterID,
	// ordered by id ASC. Runs WITHOUT RLS context (background job) so
	// it reads ALL events across all tenants.
	ListSince(ctx context.Context, afterID core.DomainEventID, limit int) ([]DomainEvent, error)
}
