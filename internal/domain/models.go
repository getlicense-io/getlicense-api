package domain

import (
	"encoding/json"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
)

// Account represents a tenant organization in the system.
type Account struct {
	ID        core.AccountID `json:"id"`
	Name      string         `json:"name"`
	Slug      string         `json:"slug"`
	CreatedAt time.Time      `json:"created_at"`
}

// Environment represents a per-account data partition (e.g. "live",
// "test", or a user-defined slug like "staging"). The slug is the
// stable identifier used by all tenant-scoped rows (licenses, API
// keys, webhook endpoints, etc.) via RLS. The remaining fields are
// presentation metadata — name, description, icon, color — surfaced
// in the dashboard account switcher.
type Environment struct {
	ID          core.EnvironmentID `json:"id"`
	AccountID   core.AccountID     `json:"account_id"`
	Slug        core.Environment   `json:"slug"`
	Name        string             `json:"name"`
	Description string             `json:"description"`
	Icon        string             `json:"icon"`
	Color       string             `json:"color"`
	Position    int                `json:"position"`
	CreatedAt   time.Time          `json:"created_at"`
	UpdatedAt   time.Time          `json:"updated_at"`
}

// Identity represents a global login record. One row per human,
// identified by email. Identities join to accounts via AccountMembership.
type Identity struct {
	ID               core.IdentityID `json:"id"`
	Email            string          `json:"email"`
	PasswordHash     string          `json:"-"`
	TOTPSecretEnc    []byte          `json:"-"`
	TOTPEnabledAt    *time.Time      `json:"totp_enabled_at,omitempty"`
	RecoveryCodesEnc []byte          `json:"-"`
	CreatedAt        time.Time       `json:"created_at"`
	UpdatedAt        time.Time       `json:"updated_at"`
}

// TOTPEnabled reports whether this identity has 2FA active.
func (i *Identity) TOTPEnabled() bool {
	return i.TOTPEnabledAt != nil
}

// MembershipStatus is the state of an account membership.
type MembershipStatus string

const (
	MembershipStatusActive    MembershipStatus = "active"
	MembershipStatusSuspended MembershipStatus = "suspended"
)

// Role represents a named bundle of flat permission strings.
// account_id NULL = system preset visible to every account.
type Role struct {
	ID          core.RoleID     `json:"id"`
	AccountID   *core.AccountID `json:"account_id,omitempty"`
	Slug        string          `json:"slug"`
	Name        string          `json:"name"`
	Permissions []string        `json:"permissions"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

// InvitationKind is the discriminator between membership invites
// (join an account with a role) and grant invites (receive a
// capability grant on the inviter's account via grant.Service).
type InvitationKind string

const (
	InvitationKindMembership InvitationKind = "membership"
	InvitationKindGrant      InvitationKind = "grant"
)

// Invitation represents a pending invitation token. Both kinds share
// the same table, token mechanism, and accept flow — the `kind`
// column selects which branch the service takes on accept.
type Invitation struct {
	ID        core.InvitationID `json:"id"`
	Kind      InvitationKind    `json:"kind"`
	Email     string            `json:"email"`
	TokenHash string            `json:"-"`

	// Populated for kind=membership
	AccountID *core.AccountID `json:"account_id,omitempty"`
	RoleID    *core.RoleID    `json:"role_id,omitempty"`

	// GrantDraft is a raw JSON blob interpreted at accept time by the
	// invitation service as a grant.IssueRequest. Populated only for
	// kind=grant invitations.
	GrantDraft json.RawMessage `json:"grant_draft,omitempty"`

	// Attribution
	CreatedByIdentityID core.IdentityID `json:"created_by_identity_id"`
	CreatedByAccountID  core.AccountID  `json:"created_by_account_id"`

	ExpiresAt  time.Time  `json:"expires_at"`
	AcceptedAt *time.Time `json:"accepted_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

// AccountMembership joins an identity to an account with a role.
type AccountMembership struct {
	ID                  core.MembershipID `json:"id"`
	AccountID           core.AccountID    `json:"account_id"`
	IdentityID          core.IdentityID   `json:"identity_id"`
	RoleID              core.RoleID       `json:"role_id"`
	Status              MembershipStatus  `json:"status"`
	InvitedByIdentityID *core.IdentityID  `json:"invited_by_identity_id,omitempty"`
	JoinedAt            time.Time         `json:"joined_at"`
	CreatedAt           time.Time         `json:"created_at"`
	UpdatedAt           time.Time         `json:"updated_at"`
}

// Customer represents an end-user of the vendor's licensed software.
// Account-scoped, environment-agnostic. Never called "users".
// No login in v1 — the portal is explicit v2 (see FEATURES.md §6).
type Customer struct {
	ID                 core.CustomerID `json:"id"`
	AccountID          core.AccountID  `json:"account_id"`
	Email              string          `json:"email"`
	Name               *string         `json:"name,omitempty"`
	Metadata           json.RawMessage `json:"metadata,omitempty"`
	CreatedByAccountID *core.AccountID `json:"created_by_account_id,omitempty"`
	CreatedAt          time.Time       `json:"created_at"`
	UpdatedAt          time.Time       `json:"updated_at"`
}

// Product represents a licensable software product.
type Product struct {
	ID            core.ProductID  `json:"id"`
	AccountID     core.AccountID  `json:"account_id"`
	Name          string          `json:"name"`
	Slug          string          `json:"slug"`
	PublicKey     string          `json:"public_key"`
	PrivateKeyEnc []byte          `json:"-"`
	Metadata      json.RawMessage `json:"metadata,omitempty"`
	CreatedAt     time.Time       `json:"created_at"`
}

// Policy owns all license lifecycle configuration. Every license references
// exactly one policy. Effective values are resolved lazily via policy.Resolve
// so policy updates cascade to referencing licenses. See internal/policy/resolve.go.
type Policy struct {
	ID        core.PolicyID  `json:"id"`
	AccountID core.AccountID `json:"account_id"`
	ProductID core.ProductID `json:"product_id"`
	Name      string         `json:"name"`
	IsDefault bool           `json:"is_default"`

	// Lifecycle
	DurationSeconds    *int                    `json:"duration_seconds,omitempty"`
	ExpirationStrategy core.ExpirationStrategy `json:"expiration_strategy"`
	ExpirationBasis    core.ExpirationBasis    `json:"expiration_basis"`

	// Machine constraints
	MaxMachines *int `json:"max_machines,omitempty"`
	MaxSeats    *int `json:"max_seats,omitempty"`
	Floating    bool `json:"floating"`
	Strict      bool `json:"strict"`

	// Checkout (L2)
	RequireCheckout        bool `json:"require_checkout"`
	CheckoutIntervalSec    int  `json:"checkout_interval_sec"`
	MaxCheckoutDurationSec int  `json:"max_checkout_duration_sec"`

	// Components (L5 scaffold)
	ComponentMatchingStrategy core.ComponentMatchingStrategy `json:"component_matching_strategy"`

	Metadata  json.RawMessage `json:"metadata,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

// LicenseOverrides holds sparse per-license overrides for quantitative
// policy fields. Nil pointers mean "inherit from policy". Only quantitative
// fields are overridable; behavioral flags (Floating, Strict, ExpirationStrategy,
// RequireCheckout, etc.) are policy-only. See spec §Cascade Scope.
type LicenseOverrides struct {
	MaxMachines            *int `json:"max_machines,omitempty"`
	MaxSeats               *int `json:"max_seats,omitempty"`
	CheckoutIntervalSec    *int `json:"checkout_interval_sec,omitempty"`
	MaxCheckoutDurationSec *int `json:"max_checkout_duration_sec,omitempty"`
}

// License represents a license granted to an end user for a product.
type License struct {
	ID               core.LicenseID     `json:"id"`
	AccountID        core.AccountID     `json:"account_id"`
	ProductID        core.ProductID     `json:"product_id"`
	PolicyID         core.PolicyID      `json:"policy_id"`
	CustomerID       core.CustomerID    `json:"customer_id"`
	Overrides        LicenseOverrides   `json:"overrides"`
	KeyPrefix        string             `json:"key_prefix"`
	KeyHash          string             `json:"-"`
	Token            string             `json:"token"`
	Status           core.LicenseStatus `json:"status"`
	ExpiresAt        *time.Time         `json:"expires_at,omitempty"`
	FirstActivatedAt *time.Time         `json:"first_activated_at,omitempty"`
	CreatedAt        time.Time          `json:"created_at"`
	UpdatedAt        time.Time          `json:"updated_at"`
	Environment      core.Environment   `json:"environment"`

	// Attribution — set at creation time; never mutated after insert.
	// GrantID is nil for direct (non-grant) license creation.
	GrantID             *core.GrantID    `json:"grant_id,omitempty"`
	CreatedByAccountID  core.AccountID   `json:"created_by_account_id"`
	CreatedByIdentityID *core.IdentityID `json:"created_by_identity_id,omitempty"`
}

// Machine represents an activated machine for a license.
type Machine struct {
	ID          core.MachineID   `json:"id"`
	AccountID   core.AccountID   `json:"account_id"`
	LicenseID   core.LicenseID   `json:"license_id"`
	Fingerprint string           `json:"fingerprint"`
	Hostname    *string          `json:"hostname,omitempty"`
	Metadata    json.RawMessage  `json:"metadata,omitempty"`
	LastSeenAt  *time.Time       `json:"last_seen_at,omitempty"`
	CreatedAt   time.Time        `json:"created_at"`
	Environment core.Environment `json:"environment"`
}

// APIKey represents an API key used to authenticate requests.
type APIKey struct {
	ID          core.APIKeyID    `json:"id"`
	AccountID   core.AccountID   `json:"account_id"`
	ProductID   *core.ProductID  `json:"product_id,omitempty"`
	Prefix      string           `json:"prefix"`
	KeyHash     string           `json:"-"`
	Scope       core.APIKeyScope `json:"scope"`
	Label       *string          `json:"label,omitempty"`
	Environment core.Environment `json:"environment"`
	ExpiresAt   *time.Time       `json:"expires_at,omitempty"`
	CreatedAt   time.Time        `json:"created_at"`
}

// WebhookEndpoint represents a registered webhook destination.
type WebhookEndpoint struct {
	ID            core.WebhookEndpointID `json:"id"`
	AccountID     core.AccountID         `json:"account_id"`
	URL           string                 `json:"url"`
	Events        []core.EventType       `json:"events"`
	SigningSecret string                 `json:"-"`
	Active        bool                   `json:"active"`
	CreatedAt     time.Time              `json:"created_at"`
	Environment   core.Environment       `json:"environment"`
}

// WebhookEvent represents a single delivery attempt of a webhook.
type WebhookEvent struct {
	ID              core.WebhookEventID    `json:"id"`
	AccountID       core.AccountID         `json:"account_id"`
	EndpointID      core.WebhookEndpointID `json:"endpoint_id"`
	EventType       core.EventType         `json:"event_type"`
	Payload         json.RawMessage        `json:"payload,omitempty"`
	Status          core.DeliveryStatus    `json:"status"`
	Attempts        int                    `json:"attempts"`
	LastAttemptedAt *time.Time             `json:"last_attempted_at,omitempty"`
	ResponseStatus  *int                   `json:"response_status,omitempty"`
	CreatedAt       time.Time              `json:"created_at"`
	Environment     core.Environment       `json:"environment"`
}

// RefreshToken represents a long-lived token used to obtain new access
// tokens. All fields are excluded from JSON — this type is never sent
// over the wire.
type RefreshToken struct {
	ID         string          `json:"-"`
	IdentityID core.IdentityID `json:"-"`
	TokenHash  string          `json:"-"`
	ExpiresAt  time.Time       `json:"-"`
}

// LicenseStatusCounts holds a per-status license breakdown for a
// given scope (e.g. one product in one environment). Returned by the
// product license-counts endpoint so dashboards can render accurate
// blocking counters without paging through every row.
type LicenseStatusCounts struct {
	Active    int `json:"active"`
	Suspended int `json:"suspended"`
	Revoked   int `json:"revoked"`
	Expired   int `json:"expired"`
	Inactive  int `json:"inactive"`
	Total     int `json:"total"`
}

// UpdateProductParams holds optional fields for a product update.
type UpdateProductParams struct {
	Name     *string          `json:"name,omitempty"`
	Metadata *json.RawMessage `json:"metadata,omitempty"`
}

// GrantStatus is the lifecycle state of a grant.
type GrantStatus string

const (
	GrantStatusPending   GrantStatus = "pending"
	GrantStatusActive    GrantStatus = "active"
	GrantStatusSuspended GrantStatus = "suspended"
	GrantStatusRevoked   GrantStatus = "revoked"
)

// GrantCapability is a typed permission token the grantee may exercise
// on the grantor's behalf.
type GrantCapability string

const (
	GrantCapLicenseCreate     GrantCapability = "LICENSE_CREATE"
	GrantCapLicenseRead       GrantCapability = "LICENSE_READ"
	GrantCapLicenseUpdate     GrantCapability = "LICENSE_UPDATE"
	GrantCapLicenseSuspend    GrantCapability = "LICENSE_SUSPEND"
	GrantCapLicenseRevoke     GrantCapability = "LICENSE_REVOKE"
	GrantCapMachineRead       GrantCapability = "MACHINE_READ"
	GrantCapMachineDeactivate GrantCapability = "MACHINE_DEACTIVATE"
)

// allGrantCapabilities is the set of valid GrantCapability values.
// Used by grant.Service.Issue to reject unknown strings at issuance
// time rather than storing garbage that will fail RequireCapability
// at runtime. F-003.
var allGrantCapabilities = map[GrantCapability]struct{}{
	GrantCapLicenseCreate:     {},
	GrantCapLicenseRead:       {},
	GrantCapLicenseUpdate:     {},
	GrantCapLicenseSuspend:    {},
	GrantCapLicenseRevoke:     {},
	GrantCapMachineRead:       {},
	GrantCapMachineDeactivate: {},
}

// IsValidGrantCapability reports whether c is a known capability.
func IsValidGrantCapability(c GrantCapability) bool {
	_, ok := allGrantCapabilities[c]
	return ok
}

// GrantConstraints is the typed shape of Grant.Constraints after
// JSON unmarshal. All fields are optional; zero values mean "no
// constraint of this kind".
type GrantConstraints struct {
	MaxLicensesTotal        int      `json:"max_licenses_total,omitempty"`
	MaxLicensesPerMonth     int      `json:"max_licenses_per_month,omitempty"`
	AllowedPolicyIDs        []string `json:"allowed_policy_ids,omitempty"`
	AllowedEntitlementCodes []string `json:"allowed_entitlement_codes,omitempty"`
	CustomerEmailPattern    string   `json:"customer_email_pattern,omitempty"`
}

// Grant represents a delegated-capability record. The grantor account
// issues the grant; the grantee account exercises it.
type Grant struct {
	ID               core.GrantID       `json:"id"`
	GrantorAccountID core.AccountID     `json:"grantor_account_id"`
	GranteeAccountID core.AccountID     `json:"grantee_account_id"`
	ProductID        core.ProductID     `json:"product_id"`
	Status           GrantStatus        `json:"status"`
	Capabilities     []GrantCapability  `json:"capabilities"`
	Constraints      json.RawMessage    `json:"constraints,omitempty"`
	InvitationID     *core.InvitationID `json:"invitation_id,omitempty"`
	ExpiresAt        *time.Time         `json:"expires_at,omitempty"`
	AcceptedAt       *time.Time         `json:"accepted_at,omitempty"`
	CreatedAt        time.Time          `json:"created_at"`
	UpdatedAt        time.Time          `json:"updated_at"`
}
