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
	UpdateTOTP(ctx context.Context, id core.IdentityID, secretEnc []byte, enabledAt *time.Time, recoveryEnc []byte) error
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
	CreateEvent(ctx context.Context, event *WebhookEvent) error
	UpdateEventStatus(ctx context.Context, id core.WebhookEventID, status core.DeliveryStatus, attempts int, responseStatus *int, responseBody *string, responseBodyTruncated bool, responseHeaders json.RawMessage, nextRetryAt *time.Time) error
	GetEventByID(ctx context.Context, id core.WebhookEventID) (*WebhookEvent, error)
	ListEventsByEndpoint(ctx context.Context, endpointID core.WebhookEndpointID, filter WebhookDeliveryFilter, cursor core.Cursor, limit int) ([]WebhookEvent, bool, error)
}

type RefreshTokenRepository interface {
	Create(ctx context.Context, token *RefreshToken) error
	GetByHash(ctx context.Context, tokenHash string) (*RefreshToken, error)
	DeleteByHash(ctx context.Context, tokenHash string) error
	DeleteByIdentityID(ctx context.Context, identityID core.IdentityID) error
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
	CountLicensesInPeriod(ctx context.Context, grantID core.GrantID, since time.Time) (int, error)
	// CountLicensesTotal returns the all-time license count for the grant.
	CountLicensesTotal(ctx context.Context, grantID core.GrantID) (int, error)
	// CountDistinctCustomers returns the distinct customer count across
	// all licenses issued under the grant.
	CountDistinctCustomers(ctx context.Context, grantID core.GrantID) (int, error)

	// ListExpirable returns grants whose expires_at has passed and whose
	// status is still non-terminal. Used by the background expire_grants
	// job. Must be called without tenant context (RLS bypass via NULLIF).
	ListExpirable(ctx context.Context, now time.Time, limit int) ([]Grant, error)
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
	// ListSince returns up to `limit` domain events with id > afterID,
	// ordered by id ASC. Runs WITHOUT RLS context (background job) so
	// it reads ALL events across all tenants.
	ListSince(ctx context.Context, afterID core.DomainEventID, limit int) ([]DomainEvent, error)
}
