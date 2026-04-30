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

// AccountSummary is the public, minimal shape of an account used to embed
// counterparty identity in Grant / Customer / Invitation responses. Exactly
// three fields — never includes created_at, member counts, email, or any
// other account state. Constructed only via toAccountSummary() helper in
// the handler layer so the invariant is enforced in one place.
type AccountSummary struct {
	ID   core.AccountID `json:"id"`
	Name string         `json:"name"`
	Slug string         `json:"slug"`
}

// ProductSummary is the public, minimal shape of a product used to embed
// product identity in Grant responses. Exactly three fields — never
// includes account_id, public_key, metadata, or any other product state.
// Materialized via ProductRepository.GetSummariesByIDs run under
// WithSystemContext so cross-tenant reads (grantee viewing a grantor's
// product) succeed without exposing the full product row.
type ProductSummary struct {
	ID   core.ProductID `json:"id"`
	Name string         `json:"name"`
	Slug string         `json:"slug"`
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
	ID            core.IdentityID `json:"id"`
	Email         string          `json:"email"`
	PasswordHash  string          `json:"-"`
	TOTPSecretEnc []byte          `json:"-"`
	TOTPEnabledAt *time.Time      `json:"totp_enabled_at,omitempty"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
}

// TOTPEnabled reports whether this identity has 2FA active.
func (i *Identity) TOTPEnabled() bool {
	return i.TOTPEnabledAt != nil
}

// RecoveryCode is one row in the recovery_codes table — a single
// HMAC of a TOTP recovery code generated at ActivateTOTP time. The
// plaintext is hashed (HMAC) before storage; the hash matches what
// the consume path computes from the user-supplied code at verify
// time. Atomic DELETE-RETURNING enforces single-use semantics under
// concurrency, and the hash comparison happens server-side via
// index lookup (so no in-memory string comparison can leak timing
// information).
//
// CreatedAt is for audit; UsedAt remains nil while the row is
// alive (DELETE on successful consume — see PR-4.5 spec).
type RecoveryCode struct {
	ID         core.RecoveryCodeID
	IdentityID core.IdentityID
	CodeHash   string
	CreatedAt  time.Time
	UsedAt     *time.Time
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

	// Sharing v2 additions. Status is computed at serialization time
	// (pending | accepted | expired) — never stored. CreatedByAccount is
	// populated via JOIN on reads.
	Status           string          `json:"status"`
	CreatedByAccount *AccountSummary `json:"created_by_account,omitempty"`
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

// MembershipDetail is the joined view returned by
// AccountMembershipRepository.ListAccountWithDetails. It carries the
// minimal identity + role fields needed by the team page; secrets
// (password_hash, totp_secret, etc.) are deliberately excluded.
type MembershipDetail struct {
	MembershipID        core.MembershipID  `json:"membership_id"`
	Identity            MembershipIdentity `json:"identity"`
	Role                MembershipRole     `json:"role"`
	JoinedAt            time.Time          `json:"joined_at"`
	InvitedByIdentityID *core.IdentityID   `json:"invited_by_identity_id"`
	CreatedAt           time.Time          `json:"-"` // cursor seed only
}

// MembershipIdentity is the minimal identity payload exposed by the
// team-page list endpoint. ALL OTHER identity fields (password_hash,
// totp_*, refresh tokens, etc.) are intentionally absent.
type MembershipIdentity struct {
	ID    core.IdentityID `json:"id"`
	Email string          `json:"email"`
}

// MembershipRole is the minimal role payload used in MembershipDetail.
type MembershipRole struct {
	ID   core.RoleID `json:"id"`
	Slug string      `json:"slug"`
	Name string      `json:"name"`
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

	// Sharing v2 addition. Populated via LEFT JOIN on reads when
	// created_by_account_id is not null. Lets the dashboard badge
	// partner-sourced customers without an N+1 lookup.
	CreatedByAccount *AccountSummary `json:"created_by_account,omitempty"`
}

// Entitlement represents a named feature/capability in the entitlements
// registry. Account-scoped, environment-agnostic. The Code is immutable
// after creation and serves as the stable identifier in lease tokens and
// validate responses.
type Entitlement struct {
	ID        core.EntitlementID `json:"id"`
	AccountID core.AccountID     `json:"account_id"`
	Code      string             `json:"code"`
	Name      string             `json:"name"`
	Metadata  json.RawMessage    `json:"metadata,omitempty"`
	CreatedAt time.Time          `json:"created_at"`
	UpdatedAt time.Time          `json:"updated_at"`
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

	// Runtime SDK staleness tolerance. Null = inherit server default.
	ValidationTTLSec *int `json:"validation_ttl_sec,omitempty"`

	// Machine constraints
	MaxMachines *int `json:"max_machines,omitempty"`
	MaxSeats    *int `json:"max_seats,omitempty"`
	Floating    bool `json:"floating"`
	Strict      bool `json:"strict"`

	// Checkout (L2)
	RequireCheckout        bool `json:"require_checkout"`
	CheckoutIntervalSec    int  `json:"checkout_interval_sec"`
	MaxCheckoutDurationSec int  `json:"max_checkout_duration_sec"`
	CheckoutGraceSec       int  `json:"checkout_grace_sec"`

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
	ValidationTTLSec       *int `json:"validation_ttl_sec,omitempty"`
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
	ID             core.MachineID     `json:"id"`
	AccountID      core.AccountID     `json:"account_id"`
	LicenseID      core.LicenseID     `json:"license_id"`
	Fingerprint    string             `json:"fingerprint"`
	Hostname       *string            `json:"hostname,omitempty"`
	Metadata       json.RawMessage    `json:"metadata,omitempty"`
	LeaseIssuedAt  time.Time          `json:"lease_issued_at"`
	LeaseExpiresAt time.Time          `json:"lease_expires_at"`
	LastCheckinAt  time.Time          `json:"last_checkin_at"`
	Status         core.MachineStatus `json:"status"`
	Environment    core.Environment   `json:"environment"`
	CreatedAt      time.Time          `json:"created_at"`
}

// APIKey represents an API key used to authenticate requests.
type APIKey struct {
	ID                    core.APIKeyID    `json:"id"`
	AccountID             core.AccountID   `json:"account_id"`
	ProductID             *core.ProductID  `json:"product_id,omitempty"`
	Prefix                string           `json:"prefix"`
	KeyHash               string           `json:"-"`
	Scope                 core.APIKeyScope `json:"scope"`
	Label                 *string          `json:"label,omitempty"`
	Environment           core.Environment `json:"environment"`
	ExpiresAt             *time.Time       `json:"expires_at,omitempty"`
	CreatedAt             time.Time        `json:"created_at"`
	LastUsedAt            *time.Time       `json:"last_used_at,omitempty"`
	LastUsedIP            *string          `json:"last_used_ip,omitempty"`
	LastUsedUserAgentHash *string          `json:"last_used_user_agent_hash,omitempty"`
	CreatedByIdentityID   *core.IdentityID `json:"created_by_identity_id,omitempty"`
	CreatedByAPIKeyID     *core.APIKeyID   `json:"created_by_api_key_id,omitempty"`
	RevokedAt             *time.Time       `json:"revoked_at,omitempty"`
	RevokedByIdentityID   *core.IdentityID `json:"revoked_by_identity_id,omitempty"`
	RevokedReason         *string          `json:"revoked_reason,omitempty"`
	Permissions           []string         `json:"permissions"`
	IPAllowlist           []string         `json:"ip_allowlist"`
}

// WebhookEndpoint represents a registered webhook destination.
//
// SigningSecretEncrypted holds the AES-GCM-encrypted HMAC signing
// key (PR-3.2 — see migration 033). The plaintext is generated at
// endpoint creation, returned to the caller ONCE in the create
// response, and never persisted in the clear. Webhook delivery code
// (internal/webhook/deliver.go) decrypts via crypto.MasterKey
// immediately before HMAC-signing each outbound payload. To rotate
// the secret, POST /v1/webhooks/:id/rotate-signing-secret.
//
// The field is `json:"-"` so the encrypted bytes never appear in
// any API response — the only legitimate exposure of the secret is
// the plaintext returned by the create + rotate handlers.
type WebhookEndpoint struct {
	ID                             core.WebhookEndpointID `json:"id"`
	AccountID                      core.AccountID         `json:"account_id"`
	URL                            string                 `json:"url"`
	Events                         []core.EventType       `json:"events"`
	SigningSecretEncrypted         []byte                 `json:"-"`
	PreviousSigningSecretEncrypted []byte                 `json:"-"`
	PreviousSigningSecretExpiresAt *time.Time             `json:"previous_signing_secret_expires_at,omitempty"`
	Active                         bool                   `json:"active"`
	CreatedAt                      time.Time              `json:"created_at"`
	Environment                    core.Environment       `json:"environment"`
}

// WebhookEvent represents a single delivery attempt of a webhook.
type WebhookEvent struct {
	ID                    core.WebhookEventID    `json:"id"`
	AccountID             core.AccountID         `json:"account_id"`
	EndpointID            core.WebhookEndpointID `json:"endpoint_id"`
	EventType             core.EventType         `json:"event_type"`
	Payload               json.RawMessage        `json:"payload,omitempty"`
	Status                core.DeliveryStatus    `json:"status"`
	Attempts              int                    `json:"attempts"`
	LastAttemptedAt       *time.Time             `json:"last_attempted_at,omitempty"`
	ResponseStatus        *int                   `json:"response_status,omitempty"`
	DomainEventID         core.DomainEventID     `json:"domain_event_id"`
	ResponseBody          *string                `json:"response_body,omitempty"`
	ResponseBodyTruncated bool                   `json:"response_body_truncated"`
	ResponseHeaders       json.RawMessage        `json:"response_headers,omitempty"`
	NextRetryAt           *time.Time             `json:"next_retry_at,omitempty"`
	CreatedAt             time.Time              `json:"created_at"`
	Environment           core.Environment       `json:"environment"`

	// ClaimToken + ClaimExpiresAt are write-side fields used by the
	// outbox worker pool (see internal/webhook/worker.go) and the
	// Service.Redeliver path. NULL means the row is unclaimed and
	// eligible for the next polling ClaimNext. json:"-" keeps them
	// out of API responses — they are internal infrastructure state.
	ClaimToken     *core.WebhookClaimToken `json:"-"`
	ClaimExpiresAt *time.Time              `json:"-"`
}

// WebhookDeliveryFilter holds optional filter criteria for listing deliveries.
type WebhookDeliveryFilter struct {
	EventType core.EventType
	Status    core.DeliveryStatus
}

// DeliveryResult captures the HTTP response details from a single
// webhook POST attempt. Promoted from webhook.deliveryResult so the
// worker pool (internal/webhook) can hand outcomes back to the
// repository (internal/db) without webhook depending on db. Field
// names mirror webhook_events column names so the repo can copy
// straight through into sqlc params.
//
// ResponseStatus is nil when no HTTP response was received (network
// error, DNS failure, timeout). ResponseBody is nil when the body
// was empty or unreadable; ResponseBodyTruncated is true when the
// body exceeded the 2 KiB cap and was sliced. ResponseHeaders is
// the raw JSON-marshalled header map (single value per key) or nil
// when the response had no headers.
type DeliveryResult struct {
	ResponseStatus        *int
	ResponseBody          *string
	ResponseBodyTruncated bool
	ResponseHeaders       json.RawMessage
}

// WebhookDispatcherCheckpoint is the singleton row that records the
// last domain_event_id the background dispatcher fanned out to the
// outbox. LastDomainEventID is nil on a fresh install (treat as zero
// — process from the beginning).
type WebhookDispatcherCheckpoint struct {
	LastDomainEventID *core.DomainEventID
	UpdatedAt         time.Time
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

// MachineStatusCounts mirrors LicenseStatusCounts for machine status
// aggregation. Used by analytics.Service.Snapshot to surface the
// active/stale/dead breakdown without paging through every row.
type MachineStatusCounts struct {
	Active int `json:"active"`
	Stale  int `json:"stale"`
	Dead   int `json:"dead"`
	Total  int `json:"total"`
}

// DailyEventCount holds one row of an analytics time-series bucket:
// the calendar date (UTC, ISO-8601 yyyy-mm-dd) and the event count.
type DailyEventCount struct {
	Date  string `json:"date"`
	Count int    `json:"count"`
}

// UpdateProductParams holds optional fields for a product update.
type UpdateProductParams struct {
	Name     *string          `json:"name,omitempty"`
	Metadata *json.RawMessage `json:"metadata,omitempty"`
}

// ChannelStatus is the lifecycle state of a channel. Channel-level
// status is stored as a real column on the channels table, separate
// from the underlying grants' statuses.
type ChannelStatus string

const (
	ChannelStatusDraft     ChannelStatus = "draft"
	ChannelStatusPending   ChannelStatus = "pending"
	ChannelStatusActive    ChannelStatus = "active"
	ChannelStatusSuspended ChannelStatus = "suspended"
	ChannelStatusClosed    ChannelStatus = "closed"
)

// ChannelProductStatus is the wire-level status name for a channel
// product. It's a serialization of grant.status — see channel.projector.
type ChannelProductStatus string

const (
	ChannelProductStatusActive ChannelProductStatus = "active"
	ChannelProductStatusPaused ChannelProductStatus = "paused"
	ChannelProductStatusClosed ChannelProductStatus = "closed"
)

// GrantStatus is the lifecycle state of a grant.
type GrantStatus string

const (
	GrantStatusPending   GrantStatus = "pending"
	GrantStatusActive    GrantStatus = "active"
	GrantStatusSuspended GrantStatus = "suspended"
	GrantStatusRevoked   GrantStatus = "revoked"
	GrantStatusLeft      GrantStatus = "left"
	GrantStatusExpired   GrantStatus = "expired"
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
	// L4: customer capabilities. CUSTOMER_CREATE is required by the
	// grant-scoped license create handler when the request carries an
	// inline `customer` block (inserts a new customers row under the
	// grantor). CUSTOMER_READ is required when attaching an existing
	// `customer_id`, and when listing customers via the grant-scoped
	// list endpoint.
	GrantCapCustomerCreate GrantCapability = "CUSTOMER_CREATE"
	GrantCapCustomerRead   GrantCapability = "CUSTOMER_READ"
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
	GrantCapCustomerCreate:    {},
	GrantCapCustomerRead:      {},
}

// IsValidGrantCapability reports whether c is a known capability.
func IsValidGrantCapability(c GrantCapability) bool {
	_, ok := allGrantCapabilities[c]
	return ok
}

// allGrantStatuses is the set of valid GrantStatus values. Used by
// the HTTP handler to reject unknown status filter values before
// opening a tx; mirrors the IsValidGrantCapability pattern above.
var allGrantStatuses = map[GrantStatus]struct{}{
	GrantStatusPending:   {},
	GrantStatusActive:    {},
	GrantStatusSuspended: {},
	GrantStatusRevoked:   {},
	GrantStatusLeft:      {},
	GrantStatusExpired:   {},
}

// IsValidGrantStatus reports whether s is a known grant status.
func IsValidGrantStatus(s GrantStatus) bool {
	_, ok := allGrantStatuses[s]
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

// GrantUsage is the computed aggregate surfaced on single-grant GET only.
// Never returned on list responses — the 50 × 3 count matrix is too costly.
type GrantUsage struct {
	LicensesTotal     int `json:"licenses_total"`
	LicensesThisMonth int `json:"licenses_this_month"`
	CustomersTotal    int `json:"customers_total"`
}

// ChannelSummary is the {id, name} embed used on Grant responses and
// InvitationLookup. Always JOIN-populated, never N+1.
type ChannelSummary struct {
	ID   core.ChannelID `json:"id"`
	Name string         `json:"name"`
}

// ChannelStats is the count payload included on single-GET channel
// responses, never on list responses.
type ChannelStats struct {
	ProductsTotal     int64 `json:"products_total"`
	ProductsActive    int64 `json:"products_active"`
	LicensesTotal     int64 `json:"licenses_total"`
	LicensesThisMonth int64 `json:"licenses_this_month"`
	CustomersTotal    int64 `json:"customers_total"`
}

// Channel is a named, lifecycle-tracked partnership between a vendor
// account and a partner account. Wraps one or more Grants under one
// envelope. Account-scoped, env-agnostic.
type Channel struct {
	ID                core.ChannelID  `json:"id"`
	VendorAccountID   core.AccountID  `json:"vendor_account_id"`
	PartnerAccountID  *core.AccountID `json:"partner_account_id"` // nullable while status=draft
	Name              string          `json:"name"`
	Description       *string         `json:"description"`
	Status            ChannelStatus   `json:"status"`
	DraftFirstProduct json.RawMessage `json:"-"` // server-internal during draft state
	CreatedAt         time.Time       `json:"created_at"`
	UpdatedAt         time.Time       `json:"updated_at"`
	ClosedAt          *time.Time      `json:"closed_at"`

	// Embeds populated by JOIN on read paths
	VendorAccount  *AccountSummary `json:"vendor_account,omitempty"`
	PartnerAccount *AccountSummary `json:"partner_account,omitempty"`

	// Optional, only populated on single-GET via channel.Service.Get
	Stats *ChannelStats `json:"stats,omitempty"`
}

// ChannelProduct is the serialization of a grants row when projected
// inside a channel. Same identity space as Grant — id == grants.id.
type ChannelProduct struct {
	ID           core.GrantID         `json:"id"`
	ChannelID    core.ChannelID       `json:"channel_id"`
	ProductID    core.ProductID       `json:"product_id"`
	Status       ChannelProductStatus `json:"status"`
	Capabilities []GrantCapability    `json:"capabilities"`
	Constraints  json.RawMessage      `json:"constraints,omitempty"`
	Product      *ProductSummary      `json:"product,omitempty"`
	CreatedAt    time.Time            `json:"created_at"`
	UpdatedAt    time.Time            `json:"updated_at"`
	Usage        *GrantUsage          `json:"usage,omitempty"`
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

	// ChannelID is the FK to the channel this grant belongs to. Set on
	// Create and populated on all read paths. NOT NULL in the DB after
	// migration 038. json:"-" keeps it out of API responses — callers see
	// the richer Channel embed below.
	ChannelID core.ChannelID `json:"-"`

	// Sharing v2 additions.
	Label    *string         `json:"label,omitempty"`
	Metadata json.RawMessage `json:"metadata,omitempty"`

	// Populated on read paths via JOIN. Nil on the Create / Issue path.
	GrantorAccount *AccountSummary `json:"grantor_account,omitempty"`
	GranteeAccount *AccountSummary `json:"grantee_account,omitempty"`

	// Populated on read paths (Get / ListByGrantor / ListByGrantee) via a
	// post-fetch fan-out under WithSystemContext so grantees can see
	// product identity without grantor-tenant RLS blocking the read.
	// Nil on the Create / Issue path.
	Product *ProductSummary `json:"product,omitempty"`

	// Channel is the {id, name} envelope this grant lives under. JOIN-
	// populated on every read path after the channels v1 migration. Never
	// nil after migration 038 has run.
	Channel *ChannelSummary `json:"channel,omitempty"`

	// Populated only by Get (single-grant read); always nil on list.
	Usage *GrantUsage `json:"usage,omitempty"`
}

// DomainEvent represents a persisted domain event with three-ID
// attribution. Events are append-only — written synchronously inside
// the mutation tx by audit.Writer and never updated afterwards.
type DomainEvent struct {
	ID              core.DomainEventID `json:"id"`
	AccountID       core.AccountID     `json:"account_id"`
	Environment     core.Environment   `json:"environment"`
	EventType       core.EventType     `json:"event_type"`
	ResourceType    string             `json:"resource_type"`
	ResourceID      *string            `json:"resource_id,omitempty"`
	ActingAccountID *core.AccountID    `json:"acting_account_id,omitempty"`
	IdentityID      *core.IdentityID   `json:"identity_id,omitempty"`
	ActorLabel      string             `json:"actor_label"`
	ActorKind       core.ActorKind     `json:"actor_kind"`
	APIKeyID        *core.APIKeyID     `json:"api_key_id,omitempty"`
	GrantID         *core.GrantID      `json:"grant_id,omitempty"`
	RequestID       *string            `json:"request_id,omitempty"`
	IPAddress       *string            `json:"ip_address,omitempty"`
	Payload         json.RawMessage    `json:"payload"`
	CreatedAt       time.Time          `json:"created_at"`
}

// DomainEventFilter holds optional filter criteria for listing domain events.
type DomainEventFilter struct {
	ResourceType string
	ResourceID   string
	EventType    core.EventType
	IdentityID   *core.IdentityID
	GrantID      *core.GrantID
	From         *time.Time
	To           *time.Time
	// RestrictToLicenseProductID, if non-nil, restricts the result
	// set to events about licenses belonging to the given product
	// AND drops events for other resource types (grant.*, invitation.*,
	// webhook.*, etc). Auto-injected from AuthContext.APIKeyProductID
	// for product-scoped API keys. Never user-set — the client cannot
	// pass this via query string.
	RestrictToLicenseProductID *core.ProductID
}

// ComputeInvitationStatus returns the serialized status value for an
// invitation row given a reference time. Repositories set this field
// before returning rows to the service layer.
func ComputeInvitationStatus(acceptedAt *time.Time, expiresAt time.Time, now time.Time) string {
	if acceptedAt != nil {
		return "accepted"
	}
	if now.After(expiresAt) {
		return "expired"
	}
	return "pending"
}
