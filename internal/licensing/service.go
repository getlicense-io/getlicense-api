package licensing

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"regexp"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/audit"
	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/crypto"
	"github.com/getlicense-io/getlicense-api/internal/customer"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/getlicense-io/getlicense-api/internal/entitlement"
	"github.com/getlicense-io/getlicense-api/internal/policy"
	"github.com/getlicense-io/getlicense-api/internal/server/middleware"
)

type Service struct {
	txManager               domain.TxManager
	licenses                domain.LicenseRepository
	products                domain.ProductRepository
	machines                domain.MachineRepository
	policies                domain.PolicyRepository
	customers               *customer.Service
	entitlements            *entitlement.Service
	masterKey               *crypto.MasterKey
	audit                   *audit.Writer
	defaultValidationTTLSec int
}

func NewService(
	txManager domain.TxManager,
	licenses domain.LicenseRepository,
	products domain.ProductRepository,
	machines domain.MachineRepository,
	policies domain.PolicyRepository,
	customers *customer.Service,
	entitlements *entitlement.Service,
	masterKey *crypto.MasterKey,
	auditWriter *audit.Writer,
	defaultValidationTTLSec int,
) *Service {
	return &Service{
		txManager:               txManager,
		licenses:                licenses,
		products:                products,
		machines:                machines,
		policies:                policies,
		customers:               customers,
		entitlements:            entitlements,
		masterKey:               masterKey,
		audit:                   auditWriter,
		defaultValidationTTLSec: defaultValidationTTLSec,
	}
}

// CreateRequest describes a new license. License lifecycle configuration
// comes from the referenced policy (or the product's default policy if
// PolicyID is nil); the request carries the customer reference, per-license
// overrides, and an optional explicit expires_at override.
type CreateRequest struct {
	// PolicyID pins the license to a specific policy. Nil falls back
	// to the product's default policy.
	PolicyID *core.PolicyID `json:"policy_id,omitempty"`

	// Overrides holds sparse per-license overrides for quantitative
	// policy fields. Nil pointers inherit from the policy.
	Overrides domain.LicenseOverrides `json:"overrides,omitempty"`

	// CustomerID attaches the license to an existing customer. Mutually
	// exclusive with Customer — exactly one must be provided.
	CustomerID *core.CustomerID `json:"customer_id,omitempty"`

	// Customer creates or upserts a customer row in the target account
	// keyed on (account_id, lower(email)). Mutually exclusive with CustomerID.
	Customer *CustomerInlineRequest `json:"customer,omitempty"`

	// ExpiresAt lets the caller stamp an explicit expiry. When nil,
	// the service computes it from the resolved policy duration for
	// FROM_CREATION basis; FROM_FIRST_ACTIVATION leaves it nil until
	// the first machine activation.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`

	// Entitlements is an optional list of entitlement codes to attach
	// to this license at creation time (add-only). Codes must exist in
	// the account's entitlement registry.
	Entitlements []string `json:"entitlements,omitempty"`
}

// CustomerInlineRequest is the shape used when a license is created
// with an inline customer rather than a pre-existing customer_id.
// The service upserts by (account_id, lower(email)) — first write wins
// for name and metadata on conflicts.
type CustomerInlineRequest struct {
	Email    string          `json:"email"`
	Name     *string         `json:"name,omitempty"`
	Metadata json.RawMessage `json:"metadata,omitempty"`
}

// CreateOptions carries attribution metadata for license creation.
// For direct creation (dashboard or API key) all fields default to
// the acting account. For grant-routed creation the caller sets
// GrantID and CreatedByAccountID to the grantee's account.
type CreateOptions struct {
	// GrantID links this license to the originating grant. Nil for
	// direct (non-grant) creation.
	GrantID *core.GrantID

	// CreatedByAccountID is the account that triggered the creation.
	// Required — equals accountID for direct creation, grantee account
	// for grant-routed creation.
	CreatedByAccountID core.AccountID

	// CreatedByIdentityID is the identity (human) that triggered
	// the creation. Nil when created via API key.
	CreatedByIdentityID *core.IdentityID

	// AllowedPolicyIDs is the grant-scoped allowlist derived from
	// GrantConstraints.AllowedPolicyIDs. Nil or empty means no policy
	// allowlist is enforced. When populated, the effective policy ID
	// (explicit or resolved default) must be a member or Create
	// rejects with ErrGrantPolicyNotAllowed.
	AllowedPolicyIDs []core.PolicyID

	// CustomerEmailPattern is the grant-scoped constraint from
	// GrantConstraints.CustomerEmailPattern. Empty means no constraint.
	// When populated, Create validates the resolved customer's email
	// against the pattern (simple "@domain" / "*.suffix.tld" forms).
	// Violations return ErrGrantConstraintViolated.
	CustomerEmailPattern string

	// AllowedEntitlementCodes is the grant-scoped allowlist derived
	// from GrantConstraints.AllowedEntitlementCodes. Nil or empty means
	// no entitlement allowlist is enforced. When populated, every
	// inline entitlement code on CreateRequest must be a member or
	// Create rejects with ErrGrantEntitlementNotAllowed.
	AllowedEntitlementCodes []string

	// Attribution carries the caller's identity for domain event
	// recording. Populated by the handler from AuthContext.
	Attribution audit.Attribution
}

type CreateResult struct {
	License    *domain.License `json:"license"`
	LicenseKey string          `json:"license_key"`
}

type BulkCreateRequest struct {
	Licenses []CreateRequest `json:"licenses" validate:"required,min=1,max=100,dive"`
}

type BulkCreateResult struct {
	Results []CreateResult `json:"results"`
}

type ValidateResult struct {
	Valid        bool            `json:"valid"`
	License      *domain.License `json:"license"`
	Entitlements []string        `json:"entitlements"`
	// Mirror of the token's `ttl` claim. Exposed so callers can decode
	// the response without verifying the token (debug / proxy use cases).
	// Authoritative for SDK caching decisions only after token verification.
	ValidationTTLSec int `json:"validation_ttl_sec"`
}

type ActivateRequest struct {
	Fingerprint string           `json:"fingerprint" validate:"required"`
	Hostname    *string          `json:"hostname"`
	Metadata    *json.RawMessage `json:"metadata"`
}

type DeactivateRequest struct {
	Fingerprint string `json:"fingerprint" validate:"required"`
}

// ActivateResult is returned from Activate. The lease token is the
// signed gl2 string; LeaseClaims is the decoded payload so callers
// don't have to verify their own token to inspect it.
type ActivateResult struct {
	Machine     *domain.Machine          `json:"machine"`
	LeaseToken  string                   `json:"lease_token"`
	LeaseClaims crypto.LeaseTokenPayload `json:"lease_claims"`
}

// CheckinResult is the return shape from Checkin — a refreshed lease.
type CheckinResult struct {
	Machine     *domain.Machine          `json:"machine"`
	LeaseToken  string                   `json:"lease_token"`
	LeaseClaims crypto.LeaseTokenPayload `json:"lease_claims"`
}

// UpdateRequest is the PATCH /v1/licenses/:id body. All fields are
// optional; only non-nil pointers are applied. Overrides replaces the
// entire LicenseOverrides struct (whole-struct replace); ExpiresAt is
// **time.Time so callers can explicitly set expires_at to null for a
// perpetual license by passing a non-nil outer pointer to a nil inner
// pointer. CustomerID reassigns the license to a different customer
// under the same account.
type UpdateRequest struct {
	Overrides  *domain.LicenseOverrides `json:"overrides,omitempty"`
	ExpiresAt  **time.Time              `json:"expires_at,omitempty"`
	CustomerID *core.CustomerID         `json:"customer_id,omitempty"`
}

// --- Private helpers ---

// fingerprintRegex enforces the Activate/Checkin fingerprint format:
// 1-256 characters from the URL-safe base64 alphabet plus `-` and `_`.
// The upper bound stays consistent with MaxFingerprintLength in keygen.go.
var fingerprintRegex = regexp.MustCompile(`^[A-Za-z0-9+/=_\-]{1,256}$`)

// isValidFingerprint reports whether s matches the L2 fingerprint regex.
// Used by Activate and Checkin. ValidateFingerprint (in keygen.go) is
// the older non-regex variant kept for Deactivate's looser semantics.
func isValidFingerprint(s string) bool {
	return fingerprintRegex.MatchString(s)
}

// validateOverrideTTL enforces the same 60..2_592_000 bound the policy
// service applies to policies, so override-only writes can't bypass the
// rule. Returns nil when ValidationTTLSec is nil (inherit).
func validateOverrideTTL(o domain.LicenseOverrides) error {
	if o.ValidationTTLSec == nil {
		return nil
	}
	v := *o.ValidationTTLSec
	if v < 60 || v > 2_592_000 {
		return core.NewAppError(core.ErrPolicyInvalidTTL, "overrides.validation_ttl_sec must be between 60 and 2592000")
	}
	return nil
}

// decryptProductPrivateKey loads the product row and decrypts its
// encrypted Ed25519 signing key. Used by Activate and Checkin to sign
// gl2 lease tokens. Consolidates the product-fetch-then-decrypt pattern
// that was previously inlined in buildLicense / BulkCreate.
func (s *Service) decryptProductPrivateKey(ctx context.Context, productID core.ProductID) (ed25519.PrivateKey, error) {
	product, err := s.products.GetByID(ctx, productID)
	if err != nil {
		return nil, err
	}
	if product == nil {
		return nil, core.NewAppError(core.ErrProductNotFound, "Product not found")
	}
	// PR-C: AAD binds the ciphertext to (product, private_key).
	privBytes, err := s.masterKey.Decrypt(product.PrivateKeyEnc, crypto.ProductPrivateKeyAAD(product.ID))
	if err != nil {
		return nil, core.NewAppError(core.ErrInternalError, "Failed to decrypt product private key")
	}
	return ed25519.PrivateKey(privBytes), nil
}

// effectiveValidationTTL returns the per-license effective TTL seconds:
// override > policy > server default. Never returns zero — the server
// default is applied when neither policy nor override set the field.
func (s *Service) effectiveValidationTTL(eff policy.Effective) int {
	if eff.ValidationTTLSec != nil {
		return *eff.ValidationTTLSec
	}
	return s.defaultValidationTTLSec
}

// requireLicense fetches a license by ID and returns ErrLicenseNotFound if missing.
// Also enforces the product-scope gate so a product-scoped API key can't read
// a license outside its bound product; identity callers and account-wide API
// keys pass through unchanged.
func (s *Service) requireLicense(ctx context.Context, id core.LicenseID) (*domain.License, error) {
	license, err := s.licenses.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if license == nil {
		return nil, core.NewAppError(core.ErrLicenseNotFound, "License not found")
	}
	if err := middleware.EnforceProductScope(ctx, license.ProductID); err != nil {
		return nil, err
	}
	return license, nil
}
