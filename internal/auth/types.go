package auth

import (
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

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
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	Permissions []string   `json:"permissions,omitempty"`
	IPAllowlist []string   `json:"ip_allowlist,omitempty"`
}

type CreateAPIKeyResult struct {
	APIKey *domain.APIKey `json:"api_key"`
	RawKey string         `json:"raw_key"`
}
