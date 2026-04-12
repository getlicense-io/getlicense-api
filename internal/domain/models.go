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

// User represents an authenticated user within an account.
type User struct {
	ID           core.UserID    `json:"id"`
	AccountID    core.AccountID `json:"account_id"`
	Email        string         `json:"email"`
	PasswordHash string         `json:"-"`
	Role         core.UserRole  `json:"role"`
	CreatedAt    time.Time      `json:"created_at"`
}

// Product represents a licensable software product.
type Product struct {
	ID            core.ProductID  `json:"id"`
	AccountID     core.AccountID  `json:"account_id"`
	Name          string          `json:"name"`
	Slug          string          `json:"slug"`
	PublicKey     string          `json:"public_key"`
	PrivateKeyEnc []byte          `json:"-"`
	ValidationTTL int             `json:"validation_ttl"`
	GracePeriod   int             `json:"grace_period"`
	Metadata         json.RawMessage `json:"metadata,omitempty"`
	HeartbeatTimeout *int            `json:"heartbeat_timeout,omitempty"`
	CreatedAt        time.Time       `json:"created_at"`
}

// License represents a license granted to an end user for a product.
type License struct {
	ID            core.LicenseID  `json:"id"`
	AccountID     core.AccountID  `json:"account_id"`
	ProductID     core.ProductID  `json:"product_id"`
	KeyPrefix     string          `json:"key_prefix"`
	KeyHash       string          `json:"-"`
	Token         string          `json:"token"`
	LicenseType   core.LicenseType   `json:"license_type"`
	Status        core.LicenseStatus `json:"status"`
	MaxMachines   *int            `json:"max_machines,omitempty"`
	MaxSeats      *int            `json:"max_seats,omitempty"`
	Entitlements  json.RawMessage `json:"entitlements,omitempty"`
	LicenseeName  *string         `json:"licensee_name,omitempty"`
	LicenseeEmail *string         `json:"licensee_email,omitempty"`
	ExpiresAt     *time.Time      `json:"expires_at,omitempty"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
	Environment   core.Environment   `json:"environment"`
}

// Machine represents an activated machine for a license.
type Machine struct {
	ID          core.MachineID  `json:"id"`
	AccountID   core.AccountID  `json:"account_id"`
	LicenseID   core.LicenseID  `json:"license_id"`
	Fingerprint string          `json:"fingerprint"`
	Hostname    *string         `json:"hostname,omitempty"`
	Metadata    json.RawMessage `json:"metadata,omitempty"`
	LastSeenAt  *time.Time      `json:"last_seen_at,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
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

// RefreshToken represents a long-lived token used to obtain new access tokens.
// All fields are excluded from JSON — this type is never sent over the wire.
type RefreshToken struct {
	ID        string         `json:"-"`
	UserID    core.UserID    `json:"-"`
	AccountID core.AccountID `json:"-"`
	TokenHash string         `json:"-"`
	ExpiresAt time.Time      `json:"-"`
}

// Pagination holds metadata for paginated list responses.
type Pagination struct {
	Limit  int `json:"limit"`
	Offset int `json:"offset"`
	Total  int `json:"total"`
}

// ListResponse is a generic wrapper for paginated lists of domain objects.
type ListResponse[T any] struct {
	Data       []T        `json:"data"`
	Pagination Pagination `json:"pagination"`
}

// UpdateProductParams holds optional fields for a product update.
type UpdateProductParams struct {
	Name             *string          `json:"name,omitempty"`
	ValidationTTL    *int             `json:"validation_ttl,omitempty"`
	GracePeriod      *int             `json:"grace_period,omitempty"`
	Metadata         *json.RawMessage `json:"metadata,omitempty"`
	HeartbeatTimeout *int             `json:"heartbeat_timeout,omitempty"`
}
