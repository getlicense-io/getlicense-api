package rbac

// Permission is a flat colon-separated string in "<resource>:<verb>" form.
// The authoritative set lives here; every check site must reference a
// constant — no string literals in handlers or services.
type Permission = string

const (
	// License lifecycle
	LicenseCreate  Permission = "license:create"
	LicenseRead    Permission = "license:read"
	LicenseUpdate  Permission = "license:update"
	LicenseSuspend Permission = "license:suspend"
	LicenseRevoke  Permission = "license:revoke"

	// Machines
	MachineRead       Permission = "machine:read"
	MachineDeactivate Permission = "machine:deactivate"

	// Products
	ProductCreate Permission = "product:create"
	ProductRead   Permission = "product:read"
	ProductUpdate Permission = "product:update"
	ProductDelete Permission = "product:delete"

	// Policies — L1 policy CRUD. Migration 020_policies.sql seeds these
	// onto the owner/admin/developer preset roles (all three) and onto
	// operator (read only). read_only gets none.
	PolicyRead   Permission = "policy:read"
	PolicyWrite  Permission = "policy:write"
	PolicyDelete Permission = "policy:delete"

	// Customers — L4 customer CRUD. Migration 021_customers.sql seeds these
	// onto the owner/admin/developer preset roles (all three) and onto
	// operator (read only). read_only gets none.
	CustomerRead   Permission = "customer:read"
	CustomerWrite  Permission = "customer:write"
	CustomerDelete Permission = "customer:delete"

	// Entitlements — L3 entitlement registry CRUD. Migration
	// 023_entitlements.sql seeds these onto the owner/admin/developer
	// preset roles (all three) and onto operator (read only).
	EntitlementRead   Permission = "entitlement:read"
	EntitlementWrite  Permission = "entitlement:write"
	EntitlementDelete Permission = "entitlement:delete"

	// API keys
	APIKeyCreate Permission = "apikey:create"
	APIKeyRead   Permission = "apikey:read"
	APIKeyRevoke Permission = "apikey:revoke"

	// Webhooks
	WebhookCreate Permission = "webhook:create"
	WebhookRead   Permission = "webhook:read"
	WebhookUpdate Permission = "webhook:update"
	WebhookDelete Permission = "webhook:delete"

	// Environments
	EnvironmentCreate Permission = "environment:create"
	EnvironmentRead   Permission = "environment:read"
	EnvironmentDelete Permission = "environment:delete"

	// User/membership management
	UserInvite     Permission = "user:invite"
	UserRemove     Permission = "user:remove"
	UserChangeRole Permission = "user:change_role"
	UserList       Permission = "user:list"

	// Grants
	GrantIssue  Permission = "grant:issue"
	GrantRevoke Permission = "grant:revoke"
	GrantAccept Permission = "grant:accept"
	GrantUse    Permission = "grant:use"
	GrantUpdate Permission = "grant:update" // sharing v2

	// Observability
	MetricsRead Permission = "metrics:read"
	EventsRead  Permission = "events:read"

	// Billing + account
	BillingRead   Permission = "billing:read"
	BillingManage Permission = "billing:manage"
	AccountUpdate Permission = "account:update"
	AccountDelete Permission = "account:delete"
)

// Role slugs of the preset roles seeded by migration 016. Production
// code that looks up a preset by slug must use these constants rather
// than raw string literals.
const (
	RoleSlugOwner     = "owner"
	RoleSlugAdmin     = "admin"
	RoleSlugDeveloper = "developer"
	RoleSlugOperator  = "operator"
	RoleSlugReadOnly  = "read_only"
)

// All returns the full set of known permissions in a stable order. Used
// only by tests that enumerate permissions (e.g. the migration 016 seed
// assertion test). Runtime authorization checks call individual
// constants directly.
func All() []Permission {
	return []Permission{
		LicenseCreate, LicenseRead, LicenseUpdate, LicenseSuspend, LicenseRevoke,
		MachineRead, MachineDeactivate,
		ProductCreate, ProductRead, ProductUpdate, ProductDelete,
		PolicyRead, PolicyWrite, PolicyDelete,
		CustomerRead, CustomerWrite, CustomerDelete,
		EntitlementRead, EntitlementWrite, EntitlementDelete,
		APIKeyCreate, APIKeyRead, APIKeyRevoke,
		WebhookCreate, WebhookRead, WebhookUpdate, WebhookDelete,
		EnvironmentCreate, EnvironmentRead, EnvironmentDelete,
		UserInvite, UserRemove, UserChangeRole, UserList,
		GrantIssue, GrantRevoke, GrantAccept, GrantUse, GrantUpdate,
		MetricsRead, EventsRead,
		BillingRead, BillingManage,
		AccountUpdate, AccountDelete,
	}
}

// IsKnown reports whether perm is part of the authoritative permission set.
func IsKnown(perm Permission) bool {
	for _, known := range All() {
		if perm == known {
			return true
		}
	}
	return false
}
