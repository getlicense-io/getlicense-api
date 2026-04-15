package domain

import (
	"context"
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
	// ListByAccountPage returns a cursor-paginated page of environments for
	// the current RLS-scoped account. Environments are capped at 5 per
	// account so hasMore is always false in practice; the method exists for
	// API shape consistency with all other list endpoints.
	ListByAccountPage(ctx context.Context, cursor core.Cursor, limit int) ([]Environment, bool, error)
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
	List(ctx context.Context, limit, offset int) ([]Product, int, error)
	// ListPage returns a cursor-paginated page of products for the current
	// RLS-scoped account. The bool return is hasMore.
	ListPage(ctx context.Context, cursor core.Cursor, limit int) ([]Product, bool, error)
	Update(ctx context.Context, id core.ProductID, params UpdateProductParams) (*Product, error)
	Delete(ctx context.Context, id core.ProductID) error
}

// LicenseListFilters narrows a license listing. All fields are optional;
// a zero-valued struct means "no filter, return everything in this tenant".
// Dashboards use this to drive URL-driven filters that survive pagination.
type LicenseListFilters struct {
	// Status, if non-empty, restricts to licenses with that status.
	Status core.LicenseStatus
	// Type, if non-empty, restricts to licenses of that type.
	Type core.LicenseType
	// Q is a case-insensitive prefix/substring match. Matches are ORed
	// across `key_prefix` (prefix), `licensee_name` (substring) and
	// `licensee_email` (substring). Empty = no search.
	Q string
}

type LicenseRepository interface {
	Create(ctx context.Context, license *License) error
	BulkCreate(ctx context.Context, licenses []*License) error
	GetByID(ctx context.Context, id core.LicenseID) (*License, error)
	GetByIDForUpdate(ctx context.Context, id core.LicenseID) (*License, error)
	GetByKeyHash(ctx context.Context, keyHash string) (*License, error)
	List(ctx context.Context, filters LicenseListFilters, limit, offset int) ([]License, int, error)
	// ListPage returns a cursor-paginated page of licenses for the current
	// RLS-scoped tenant, optionally narrowed by filters.
	ListPage(ctx context.Context, filters LicenseListFilters, cursor core.Cursor, limit int) ([]License, bool, error)
	// ListByProduct returns a paginated slice of licenses scoped to a
	// single product within the current RLS env, plus the total count.
	// Used by the dashboard's product detail page so it never has to
	// fetch the global licenses list and filter client-side.
	ListByProduct(ctx context.Context, productID core.ProductID, filters LicenseListFilters, limit, offset int) ([]License, int, error)
	// ListPageByProduct returns a cursor-paginated page of licenses scoped
	// to a single product within the current RLS env.
	ListPageByProduct(ctx context.Context, productID core.ProductID, filters LicenseListFilters, cursor core.Cursor, limit int) ([]License, bool, error)
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
	Create(ctx context.Context, machine *Machine) error
	GetByFingerprint(ctx context.Context, licenseID core.LicenseID, fingerprint string) (*Machine, error)
	CountByLicense(ctx context.Context, licenseID core.LicenseID) (int, error)
	DeleteByFingerprint(ctx context.Context, licenseID core.LicenseID, fingerprint string) error
	UpdateHeartbeat(ctx context.Context, licenseID core.LicenseID, fingerprint string) (*Machine, error)
	DeactivateStale(ctx context.Context) (int, error)
}

type APIKeyRepository interface {
	Create(ctx context.Context, key *APIKey) error
	GetByHash(ctx context.Context, keyHash string) (*APIKey, error)
	// ListByAccount returns API keys for the current RLS account,
	// scoped to the given environment. The env filter is applied at
	// the SQL level rather than via RLS because the api_keys RLS
	// policy intentionally does not filter by environment (a live
	// key is allowed to create/delete a test key).
	ListByAccount(ctx context.Context, env core.Environment, limit, offset int) ([]APIKey, int, error)
	// ListPageByAccount returns a cursor-paginated page of API keys for
	// the current RLS account, scoped to the given environment.
	ListPageByAccount(ctx context.Context, env core.Environment, cursor core.Cursor, limit int) ([]APIKey, bool, error)
	Delete(ctx context.Context, id core.APIKeyID) error
}

type WebhookRepository interface {
	CreateEndpoint(ctx context.Context, ep *WebhookEndpoint) error
	ListEndpoints(ctx context.Context, limit, offset int) ([]WebhookEndpoint, int, error)
	// ListPageEndpoints returns a cursor-paginated page of webhook endpoints
	// for the current RLS-scoped account and environment.
	ListPageEndpoints(ctx context.Context, cursor core.Cursor, limit int) ([]WebhookEndpoint, bool, error)
	DeleteEndpoint(ctx context.Context, id core.WebhookEndpointID) error
	GetActiveEndpointsByEvent(ctx context.Context, eventType core.EventType) ([]WebhookEndpoint, error)
	CreateEvent(ctx context.Context, event *WebhookEvent) error
	UpdateEventStatus(ctx context.Context, id core.WebhookEventID, status core.DeliveryStatus, attempts int, responseStatus *int) error
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
	GetByID(ctx context.Context, id core.InvitationID) (*Invitation, error)
	// GetByTokenHash runs without RLS context. Used by the public
	// lookup endpoint to preview an invitation from its token alone.
	GetByTokenHash(ctx context.Context, tokenHash string) (*Invitation, error)
	ListByAccount(ctx context.Context, cursor core.Cursor, limit int) ([]Invitation, bool, error)
	MarkAccepted(ctx context.Context, id core.InvitationID, acceptedAt time.Time) error
	Delete(ctx context.Context, id core.InvitationID) error
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
	// ListByGrantor returns cursor-paginated grants where the current
	// RLS-scoped account is the grantor (issuer).
	ListByGrantor(ctx context.Context, cursor core.Cursor, limit int) ([]Grant, bool, error)
	// ListByGrantee returns cursor-paginated grants where the current
	// RLS-scoped account is the grantee (recipient).
	ListByGrantee(ctx context.Context, cursor core.Cursor, limit int) ([]Grant, bool, error)
	UpdateStatus(ctx context.Context, id core.GrantID, status GrantStatus) error
	// MarkAccepted atomically sets status=active, accepted_at, and
	// updated_at in one statement. Used by Service.Accept.
	MarkAccepted(ctx context.Context, id core.GrantID, acceptedAt time.Time) error
	// CountLicensesInPeriod counts licenses attributed to the grant
	// created on or after `since`. Pass time.Time{} for an all-time count.
	CountLicensesInPeriod(ctx context.Context, grantID core.GrantID, since time.Time) (int, error)
}
