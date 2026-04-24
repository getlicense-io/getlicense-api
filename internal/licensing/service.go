package licensing

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"regexp"
	"slices"
	"time"

	"log/slog"

	"github.com/getlicense-io/getlicense-api/internal/audit"
	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/crypto"
	"github.com/getlicense-io/getlicense-api/internal/customer"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/getlicense-io/getlicense-api/internal/entitlement"
	"github.com/getlicense-io/getlicense-api/internal/policy"
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

func (s *Service) Create(ctx context.Context, accountID core.AccountID, env core.Environment, productID core.ProductID, req CreateRequest, opts CreateOptions) (*CreateResult, error) {
	// Pre-generate values outside the transaction to minimize connection hold time.
	fullKey, prefix, err := GenerateLicenseKey()
	if err != nil {
		return nil, core.NewAppError(core.ErrInternalError, "Failed to generate license key")
	}
	licenseID := core.NewLicenseID()
	now := time.Now().UTC()
	keyHash := s.masterKey.HMAC(fullKey)

	emailPatternRe, err := compileCustomerEmailPattern(opts.CustomerEmailPattern)
	if err != nil {
		return nil, err
	}

	if err := validateOverrideTTL(req.Overrides); err != nil {
		return nil, err
	}

	var result *CreateResult

	err = s.txManager.WithTargetAccount(ctx, accountID, env, func(ctx context.Context) error {
		product, err := s.products.GetByID(ctx, productID)
		if err != nil {
			return err
		}
		if product == nil {
			return core.NewAppError(core.ErrProductNotFound, "Product not found")
		}

		p, err := s.resolvePolicyForCreate(ctx, productID, req.PolicyID)
		if err != nil {
			return err
		}

		if err := checkPolicyAllowed(p.ID, opts.AllowedPolicyIDs); err != nil {
			return err
		}

		customerID, customerEmail, err := s.resolveCustomerForCreate(ctx, accountID, req, opts)
		if err != nil {
			return err
		}
		if err := checkCustomerEmailPattern(emailPatternRe, customerEmail); err != nil {
			return err
		}

		privKeyBytes, err := s.masterKey.Decrypt(product.PrivateKeyEnc)
		if err != nil {
			return core.NewAppError(core.ErrInternalError, "Failed to decrypt product private key")
		}

		license, err := s.buildLicense(req, p, customerID, licenseID, prefix, keyHash, now, accountID, productID, ed25519.PrivateKey(privKeyBytes), env)
		if err != nil {
			return err
		}

		// Apply attribution after buildLicense so the builder stays
		// focused on key/token generation only.
		license.GrantID = opts.GrantID
		license.CreatedByAccountID = opts.CreatedByAccountID
		license.CreatedByIdentityID = opts.CreatedByIdentityID

		if err := s.licenses.Create(ctx, license); err != nil {
			return err
		}

		if len(req.Entitlements) > 0 {
			if len(opts.AllowedEntitlementCodes) > 0 {
				for _, code := range req.Entitlements {
					if !slices.Contains(opts.AllowedEntitlementCodes, code) {
						return core.NewAppError(core.ErrGrantEntitlementNotAllowed, "entitlement code not allowed by grant: "+code)
					}
				}
			}
			if err := s.entitlements.AttachToLicense(ctx, license.ID, req.Entitlements, accountID); err != nil {
				return err
			}
		}

		result = &CreateResult{License: license, LicenseKey: fullKey}

		if s.audit != nil {
			payload, _ := json.Marshal(result.License)
			if err := s.audit.Record(ctx, audit.EventFrom(opts.Attribution, core.EventTypeLicenseCreated, "license", result.License.ID.String(), payload)); err != nil {
				slog.Error("audit: failed to record event", "event", core.EventTypeLicenseCreated, "error", err)
			}
		}
		return nil
	})
	return result, err
}

// resolvePolicyForCreate loads either the caller-specified policy or the
// product's default. It validates that an explicit policy belongs to the
// target product and translates repo (nil, nil) no-match into typed
// AppError responses.
func (s *Service) resolvePolicyForCreate(ctx context.Context, productID core.ProductID, policyID *core.PolicyID) (*domain.Policy, error) {
	if policyID != nil {
		p, err := s.policies.Get(ctx, *policyID)
		if err != nil {
			return nil, err
		}
		if p == nil {
			return nil, core.NewAppError(core.ErrPolicyNotFound, "policy not found")
		}
		if p.ProductID != productID {
			return nil, core.NewAppError(core.ErrPolicyProductMismatch, "policy belongs to a different product")
		}
		return p, nil
	}
	p, err := s.policies.GetDefaultForProduct(ctx, productID)
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, core.NewAppError(core.ErrPolicyNotFound, "no default policy for product")
	}
	return p, nil
}

// checkPolicyAllowed enforces a grant-scoped allowlist against the
// effective policy ID. An empty or nil allowlist means no constraint
// (direct / non-grant creation and grants that omit AllowedPolicyIDs).
// A non-empty allowlist that does not contain the resolved ID returns
// ErrGrantPolicyNotAllowed.
func checkPolicyAllowed(effective core.PolicyID, allowed []core.PolicyID) error {
	if len(allowed) == 0 {
		return nil
	}
	for _, id := range allowed {
		if id == effective {
			return nil
		}
	}
	return core.NewAppError(core.ErrGrantPolicyNotAllowed, "policy not allowed by grant")
}

// resolveCustomerForCreate handles the customer_id vs. inline customer
// dispatch for license creation. Exactly one of req.CustomerID or
// req.Customer must be set; both or neither returns a typed AppError.
// On the inline path the customer is upserted by (account_id, lower(email))
// inside the caller's tx so the license insert sees it. Returns the
// resolved customer ID plus the customer's normalized email (for
// CustomerEmailPattern enforcement by the caller).
func (s *Service) resolveCustomerForCreate(
	ctx context.Context,
	accountID core.AccountID,
	req CreateRequest,
	opts CreateOptions,
) (core.CustomerID, string, error) {
	switch {
	case req.CustomerID != nil && req.Customer != nil:
		return core.CustomerID{}, "", core.NewAppError(core.ErrCustomerAmbiguous, "provide exactly one of customer_id or customer")
	case req.CustomerID == nil && req.Customer == nil:
		return core.CustomerID{}, "", core.NewAppError(core.ErrCustomerRequired, "customer_id or customer is required")
	case req.CustomerID != nil:
		c, err := s.customers.Get(ctx, *req.CustomerID)
		if err != nil {
			return core.CustomerID{}, "", err
		}
		// Belt-and-braces: RLS should have already filtered, but the
		// explicit account check keeps the error code stable.
		if c.AccountID != accountID {
			return core.CustomerID{}, "", core.NewAppError(core.ErrCustomerNotFound, "customer not found")
		}
		return c.ID, c.Email, nil
	default:
		// Inline upsert path. For grant-scoped inline creates the grantee
		// account is stamped on the new customer row so the grantor can
		// filter their customer list by "created under grant X".
		var createdBy *core.AccountID
		if opts.GrantID != nil && opts.CreatedByAccountID != accountID {
			cb := opts.CreatedByAccountID
			createdBy = &cb
		}
		c, err := s.customers.UpsertForLicense(ctx, accountID, customer.UpsertRequest{
			Email:              req.Customer.Email,
			Name:               req.Customer.Name,
			Metadata:           req.Customer.Metadata,
			CreatedByAccountID: createdBy,
		})
		if err != nil {
			return core.CustomerID{}, "", err
		}
		return c.ID, c.Email, nil
	}
}

// compileCustomerEmailPattern wraps the grantor-supplied pattern in
// full-match anchors and compiles it. Unanchored patterns are a
// security footgun — "@acme\.com" without anchors silently allows
// "user@acme.com.evil.net". The "(?i)" flag makes the match
// case-insensitive; emails are already lowercased via
// customer.NormalizeEmail but explicit case-insensitivity guards
// against future changes. Invalid patterns return
// ErrGrantConstraintViolated since they are authored by the grantor
// at issuance time.
func compileCustomerEmailPattern(pattern string) (*regexp.Regexp, error) {
	if pattern == "" {
		return nil, nil
	}
	re, err := regexp.Compile("(?i)^(?:" + pattern + ")$")
	if err != nil {
		return nil, core.NewAppError(core.ErrGrantConstraintViolated, "invalid customer_email_pattern")
	}
	return re, nil
}

// checkCustomerEmailPattern matches the email against an
// already-compiled pattern. Returns nil if re is nil (no constraint)
// or the email matches.
func checkCustomerEmailPattern(re *regexp.Regexp, email string) error {
	if re == nil {
		return nil
	}
	if !re.MatchString(email) {
		return core.NewAppError(core.ErrGrantConstraintViolated, "customer email does not match allowed pattern")
	}
	return nil
}

func (s *Service) BulkCreate(ctx context.Context, accountID core.AccountID, env core.Environment, productID core.ProductID, req BulkCreateRequest, opts CreateOptions) (*BulkCreateResult, error) {
	// Pre-generate all keys, IDs, and HMACs outside the transaction.
	type pregenerated struct {
		fullKey   string
		prefix    string
		keyHash   string
		licenseID core.LicenseID
	}

	now := time.Now().UTC()
	pregens := make([]pregenerated, len(req.Licenses))
	for i := range req.Licenses {
		fullKey, prefix, err := GenerateLicenseKey()
		if err != nil {
			return nil, core.NewAppError(core.ErrInternalError, "Failed to generate license key")
		}
		pregens[i] = pregenerated{
			fullKey:   fullKey,
			prefix:    prefix,
			keyHash:   s.masterKey.HMAC(fullKey),
			licenseID: core.NewLicenseID(),
		}
	}

	emailPatternRe, err := compileCustomerEmailPattern(opts.CustomerEmailPattern)
	if err != nil {
		return nil, err
	}

	var results []CreateResult

	err = s.txManager.WithTargetAccount(ctx, accountID, env, func(ctx context.Context) error {
		product, err := s.products.GetByID(ctx, productID)
		if err != nil {
			return err
		}
		if product == nil {
			return core.NewAppError(core.ErrProductNotFound, "Product not found")
		}

		privKeyBytes, err := s.masterKey.Decrypt(product.PrivateKeyEnc)
		if err != nil {
			return core.NewAppError(core.ErrInternalError, "Failed to decrypt product private key")
		}
		privKey := ed25519.PrivateKey(privKeyBytes)

		allLicenses := make([]*domain.License, len(req.Licenses))
		results = make([]CreateResult, len(req.Licenses))

		// Cache resolved policies by ID so a bulk request that mixes an
		// explicit policy_id with default fallback hits the repo at most
		// twice regardless of batch size.
		policyCache := make(map[core.PolicyID]*domain.Policy)
		// Customer resolution is intentionally per-row — each row in the
		// batch may reference a distinct customer (via CustomerID or
		// inline Customer). Do not hoist resolution out of the loop;
		// heterogeneous batches are a supported use case.
		for i, lr := range req.Licenses {
			pg := pregens[i]
			var p *domain.Policy
			cacheKey := core.PolicyID{}
			if lr.PolicyID != nil {
				cacheKey = *lr.PolicyID
			}
			if cached, ok := policyCache[cacheKey]; ok {
				p = cached
			} else {
				p, err = s.resolvePolicyForCreate(ctx, productID, lr.PolicyID)
				if err != nil {
					return err
				}
				policyCache[cacheKey] = p
			}

			if err := checkPolicyAllowed(p.ID, opts.AllowedPolicyIDs); err != nil {
				return err
			}

			if err := validateOverrideTTL(lr.Overrides); err != nil {
				return err
			}

			customerID, customerEmail, err := s.resolveCustomerForCreate(ctx, accountID, lr, opts)
			if err != nil {
				return err
			}
			if err := checkCustomerEmailPattern(emailPatternRe, customerEmail); err != nil {
				return err
			}

			// Validate AllowedEntitlementCodes before the bulk insert so
			// we fail fast without a wasted DB round-trip.
			if len(lr.Entitlements) > 0 && len(opts.AllowedEntitlementCodes) > 0 {
				for _, code := range lr.Entitlements {
					if !slices.Contains(opts.AllowedEntitlementCodes, code) {
						return core.NewAppError(core.ErrGrantEntitlementNotAllowed, "entitlement code not allowed by grant: "+code)
					}
				}
			}

			license, err := s.buildLicense(lr, p, customerID, pg.licenseID, pg.prefix, pg.keyHash, now, accountID, productID, privKey, env)
			if err != nil {
				return err
			}
			license.GrantID = opts.GrantID
			license.CreatedByAccountID = opts.CreatedByAccountID
			license.CreatedByIdentityID = opts.CreatedByIdentityID
			allLicenses[i] = license
			results[i] = CreateResult{License: license, LicenseKey: pg.fullKey}
		}

		if err := s.licenses.BulkCreate(ctx, allLicenses); err != nil {
			return err
		}

		// Attach inline entitlements after the bulk insert so the
		// license_entitlements FK can resolve.
		for i, lr := range req.Licenses {
			if len(lr.Entitlements) > 0 {
				if err := s.entitlements.AttachToLicense(ctx, allLicenses[i].ID, lr.Entitlements, accountID); err != nil {
					return err
				}
			}
		}
		if s.audit != nil {
			for _, r := range results {
				payload, _ := json.Marshal(r.License)
				if err := s.audit.Record(ctx, audit.EventFrom(opts.Attribution, core.EventTypeLicenseCreated, "license", r.License.ID.String(), payload)); err != nil {
					slog.Error("audit: failed to record event", "event", core.EventTypeLicenseCreated, "error", err)
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &BulkCreateResult{Results: results}, nil
}

func (s *Service) List(ctx context.Context, accountID core.AccountID, env core.Environment, filters domain.LicenseListFilters, cursor core.Cursor, limit int) ([]domain.License, bool, error) {
	var licenses []domain.License
	var hasMore bool

	err := s.txManager.WithTargetAccount(ctx, accountID, env, func(ctx context.Context) error {
		var err error
		licenses, hasMore, err = s.licenses.List(ctx, filters, cursor, limit)
		return err
	})
	if err != nil {
		return nil, false, err
	}
	return licenses, hasMore, nil
}

// ListByProduct validates that the product exists in this tenant
// before returning so callers get a clean 404 instead of an empty
// page when they're holding a stale ID.
func (s *Service) ListByProduct(ctx context.Context, accountID core.AccountID, env core.Environment, productID core.ProductID, filters domain.LicenseListFilters, cursor core.Cursor, limit int) ([]domain.License, bool, error) {
	var licenses []domain.License
	var hasMore bool

	err := s.txManager.WithTargetAccount(ctx, accountID, env, func(ctx context.Context) error {
		product, err := s.products.GetByID(ctx, productID)
		if err != nil {
			return err
		}
		if product == nil {
			return core.NewAppError(core.ErrProductNotFound, "Product not found")
		}
		licenses, hasMore, err = s.licenses.ListByProduct(ctx, productID, filters, cursor, limit)
		return err
	})
	if err != nil {
		return nil, false, err
	}
	return licenses, hasMore, nil
}

// ListByCustomer returns licenses owned by the given customer, paginated.
// Runs under the target account's RLS context so the underlying repo
// query is naturally scoped to this tenant. Callers (the customer
// handler) should verify the customer exists separately so a 404
// surfaces before this list query runs.
func (s *Service) ListByCustomer(ctx context.Context, accountID core.AccountID, env core.Environment, customerID core.CustomerID, cursor core.Cursor, limit int) ([]domain.License, bool, error) {
	var licenses []domain.License
	var hasMore bool
	err := s.txManager.WithTargetAccount(ctx, accountID, env, func(ctx context.Context) error {
		filters := domain.LicenseListFilters{CustomerID: &customerID}
		var err error
		licenses, hasMore, err = s.licenses.List(ctx, filters, cursor, limit)
		return err
	})
	if err != nil {
		return nil, false, err
	}
	return licenses, hasMore, nil
}

// ListMachines returns machines for licenseID, cursor-paginated, with
// optional status filter and a grantee gate.
//
// statusFilter is validated against core.MachineStatus; an unknown
// value returns ErrValidationError (422). Empty string means "no
// filter".
//
// callerGrantID is the caller's GrantID when invoked from the
// /v1/grants/:grant_id/... routes (populated by ResolveGrant
// middleware), nil for vendor direct calls. When non-nil, the license
// MUST have been created under THAT grant — otherwise return 404 to
// avoid leaking the license's existence to a grantee asking about a
// license that isn't theirs.
func (s *Service) ListMachines(
	ctx context.Context,
	accountID core.AccountID,
	env core.Environment,
	licenseID core.LicenseID,
	statusFilter string,
	cursor core.Cursor,
	limit int,
	callerGrantID *core.GrantID,
) ([]domain.Machine, bool, error) {
	// Validate status BEFORE opening the tx. An unknown value is a
	// caller bug, not a data-access failure.
	if statusFilter != "" && !core.MachineStatus(statusFilter).IsValid() {
		return nil, false, core.NewAppError(core.ErrValidationError,
			"Invalid status filter; expected active|stale|dead")
	}

	var rows []domain.Machine
	var hasMore bool
	err := s.txManager.WithTargetAccount(ctx, accountID, env, func(ctx context.Context) error {
		lic, err := s.requireLicense(ctx, licenseID)
		if err != nil {
			return err
		}
		// Grantee gate: grantee caller may only see machines on
		// licenses created under THEIR grant. 404 (not 403) so we do
		// not leak the license's existence across grant boundaries.
		if callerGrantID != nil && (lic.GrantID == nil || *lic.GrantID != *callerGrantID) {
			return core.NewAppError(core.ErrLicenseNotFound, "License not found")
		}
		var e error
		rows, hasMore, e = s.machines.ListByLicense(ctx, licenseID, statusFilter, cursor, limit)
		return e
	})
	if err != nil {
		return nil, false, err
	}
	return rows, hasMore, nil
}

// CountsByProductStatus returns a per-status license breakdown for
// the given product within the current env. The dashboard uses this
// to render an accurate blocking count for the delete-product flow
// without having to fetch every license row.
func (s *Service) CountsByProductStatus(ctx context.Context, accountID core.AccountID, env core.Environment, productID core.ProductID) (domain.LicenseStatusCounts, error) {
	var counts domain.LicenseStatusCounts
	err := s.txManager.WithTargetAccount(ctx, accountID, env, func(ctx context.Context) error {
		product, err := s.products.GetByID(ctx, productID)
		if err != nil {
			return err
		}
		if product == nil {
			return core.NewAppError(core.ErrProductNotFound, "Product not found")
		}
		counts, err = s.licenses.CountsByProductStatus(ctx, productID)
		return err
	})
	if err != nil {
		return domain.LicenseStatusCounts{}, err
	}
	return counts, nil
}

// BulkRevokeForProduct atomically revokes every active or suspended
// license for the given product in the given env. Used by the
// dashboard to unblock product deletion when there are too many
// licenses to revoke individually through the bulk-action toolbar.
// Returns the number of licenses revoked.
func (s *Service) BulkRevokeForProduct(ctx context.Context, accountID core.AccountID, env core.Environment, productID core.ProductID) (int, error) {
	var count int
	err := s.txManager.WithTargetAccount(ctx, accountID, env, func(ctx context.Context) error {
		product, err := s.products.GetByID(ctx, productID)
		if err != nil {
			return err
		}
		if product == nil {
			return core.NewAppError(core.ErrProductNotFound, "Product not found")
		}
		count, err = s.licenses.BulkRevokeByProduct(ctx, productID)
		return err
	})
	if err != nil {
		return 0, err
	}
	// We deliberately do NOT fan out N license.revoked webhooks here.
	// A bulk cleanup would otherwise drown subscribers in events
	// without giving them anything actionable they couldn't get from
	// the count itself. If aggregate cleanup notifications become
	// useful we can introduce a single license.bulk_revoked event.
	return count, nil
}

func (s *Service) Get(ctx context.Context, accountID core.AccountID, env core.Environment, licenseID core.LicenseID) (*domain.License, error) {
	var result *domain.License

	err := s.txManager.WithTargetAccount(ctx, accountID, env, func(ctx context.Context) error {
		l, err := s.requireLicense(ctx, licenseID)
		if err != nil {
			return err
		}
		result = l
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (s *Service) Revoke(ctx context.Context, accountID core.AccountID, env core.Environment, licenseID core.LicenseID, attr audit.Attribution) error {
	_, err := s.transitionStatus(ctx, accountID, env, licenseID,
		func(st core.LicenseStatus) bool { return st.CanRevoke() },
		core.LicenseStatusRevoked,
		"License cannot be revoked from current status",
		attr, core.EventTypeLicenseRevoked,
	)
	return err
}

func (s *Service) Suspend(ctx context.Context, accountID core.AccountID, env core.Environment, licenseID core.LicenseID, attr audit.Attribution) (*domain.License, error) {
	return s.transitionStatus(ctx, accountID, env, licenseID,
		func(st core.LicenseStatus) bool { return st.CanSuspend() },
		core.LicenseStatusSuspended,
		"License cannot be suspended from current status",
		attr, core.EventTypeLicenseSuspended,
	)
}

func (s *Service) Reinstate(ctx context.Context, accountID core.AccountID, env core.Environment, licenseID core.LicenseID, attr audit.Attribution) (*domain.License, error) {
	return s.transitionStatus(ctx, accountID, env, licenseID,
		func(st core.LicenseStatus) bool { return st.CanReinstate() },
		core.LicenseStatusActive,
		"License cannot be reinstated from current status",
		attr, core.EventTypeLicenseReinstated,
	)
}

// Validate looks up a license by its raw key and checks status.
// No tenant context needed — this is a public endpoint.
func (s *Service) Validate(ctx context.Context, licenseKey string) (*ValidateResult, error) {
	keyHash := s.masterKey.HMAC(licenseKey)

	license, err := s.licenses.GetByKeyHash(ctx, keyHash)
	if err != nil {
		return nil, err
	}
	if license == nil {
		return nil, core.NewAppError(core.ErrInvalidLicenseKey, "Invalid license key")
	}

	// Status transitions that were applied via UpdateStatus (suspend,
	// revoke, background expire sweep) still surface their terminal
	// codes regardless of the policy's expiration strategy.
	switch license.Status {
	case core.LicenseStatusRevoked:
		return nil, core.NewAppError(core.ErrLicenseRevoked, "License has been revoked")
	case core.LicenseStatusSuspended:
		return nil, core.NewAppError(core.ErrLicenseSuspended, "License is suspended")
	case core.LicenseStatusInactive:
		return nil, core.NewAppError(core.ErrLicenseInactive, "License is inactive")
	case core.LicenseStatusExpired:
		return nil, core.NewAppError(core.ErrLicenseExpired, "License has expired")
	}

	p, err := s.policies.Get(ctx, license.PolicyID)
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, core.NewAppError(core.ErrPolicyNotFound, "policy not found")
	}
	eff := policy.Resolve(p, license.Overrides)
	if dec := policy.EvaluateExpiration(eff, license.ExpiresAt); !dec.Valid {
		return nil, core.NewAppError(dec.Code, "License has expired")
	}

	entCodes, err := s.entitlements.ResolveEffective(ctx, license.ID)
	if err != nil {
		return nil, err
	}

	// Re-mint the gl1 token with the current effective TTL so policy
	// updates cascade to existing licenses. The stored licenses.token
	// column is never updated by this path — only /v1/validate returns
	// a re-minted token. See CLAUDE.md § Validation TTL (P3).
	ttl := s.effectiveValidationTTL(eff)
	privKey, err := s.decryptProductPrivateKey(ctx, license.ProductID)
	if err != nil {
		return nil, err
	}
	payload := crypto.TokenPayload{
		Version:   1,
		ProductID: license.ProductID.String(),
		LicenseID: license.ID.String(),
		Status:    license.Status,
		IssuedAt:  time.Now().UTC().Unix(),
		TTL:       ttl,
	}
	if license.ExpiresAt != nil {
		ts := license.ExpiresAt.Unix()
		payload.ExpiresAt = &ts
	}
	fresh, err := crypto.SignToken(payload, privKey)
	if err != nil {
		return nil, core.NewAppError(core.ErrInternalError, "Failed to sign license token")
	}

	// Shallow-copy the license so swapping .Token doesn't mutate anything
	// a future caching layer might hold. The repo returns a fresh struct
	// per call today, but this keeps intent explicit.
	licenseOut := *license
	licenseOut.Token = fresh

	return &ValidateResult{
		Valid:            true,
		License:          &licenseOut,
		Entitlements:     entCodes,
		ValidationTTLSec: ttl,
	}, nil
}

// Activate registers a machine for a license and issues a signed gl2
// lease token. The request is idempotent per (license, fingerprint):
// re-activating the same fingerprint reuses the existing machine row
// and overwrites its hostname/metadata/lease state. Re-activating a
// dead fingerprint (lease grace window elapsed) resurrects it and
// resets status to active — the audit row is preserved. The max
// machines cap is enforced against CountAliveByLicense (active + stale)
// excluding the fingerprint being activated so an idempotent re-activate
// doesn't double-count.
func (s *Service) Activate(ctx context.Context, accountID core.AccountID, env core.Environment, licenseID core.LicenseID, req ActivateRequest, attr audit.Attribution) (*ActivateResult, error) {
	if !isValidFingerprint(req.Fingerprint) {
		return nil, core.NewAppError(core.ErrMachineInvalidFingerprint, "fingerprint must be 1-256 chars from [A-Za-z0-9+/=_-]")
	}

	var result *ActivateResult

	err := s.txManager.WithTargetAccount(ctx, accountID, env, func(ctx context.Context) error {
		license, err := s.licenses.GetByIDForUpdate(ctx, licenseID)
		if err != nil {
			return err
		}
		if license == nil {
			return core.NewAppError(core.ErrLicenseNotFound, "License not found")
		}

		// Terminal or hold statuses short-circuit before we even look at
		// the policy — they already represent an explicit operator or
		// scheduler decision that overrides the policy's expiration view.
		switch license.Status {
		case core.LicenseStatusRevoked:
			return core.NewAppError(core.ErrLicenseRevoked, "License has been revoked")
		case core.LicenseStatusSuspended:
			return core.NewAppError(core.ErrLicenseSuspended, "License is suspended")
		case core.LicenseStatusInactive:
			return core.NewAppError(core.ErrLicenseInactive, "License is inactive")
		case core.LicenseStatusExpired:
			return core.NewAppError(core.ErrLicenseExpired, "License has expired")
		}

		p, err := s.policies.Get(ctx, license.PolicyID)
		if err != nil {
			return err
		}
		if p == nil {
			return core.NewAppError(core.ErrPolicyNotFound, "policy not found")
		}
		eff := policy.Resolve(p, license.Overrides)

		// Policy-driven expiration decision. For REVOKE_ACCESS this
		// returns invalid; for MAINTAIN/RESTRICT_ACCESS callers decide
		// at validate time — activation still refuses past-expiry to
		// avoid minting new leases on a stale license.
		if dec := policy.EvaluateExpiration(eff, license.ExpiresAt); !dec.Valid {
			return core.NewAppError(dec.Code, "License has expired")
		}

		now := time.Now().UTC()

		// FROM_FIRST_ACTIVATION: stamp first_activated_at and (if a
		// duration is set) compute expires_at on first hit only. The
		// same tx persists the stamp so a concurrent retry sees it.
		if license.FirstActivatedAt == nil && p.ExpirationBasis == core.ExpirationBasisFromFirstActivation {
			license.FirstActivatedAt = &now
			if eff.DurationSeconds != nil {
				exp := now.Add(time.Duration(*eff.DurationSeconds) * time.Second)
				license.ExpiresAt = &exp
			}
			if err := s.licenses.Update(ctx, license); err != nil {
				return err
			}
		}

		// Check for an existing row for this (license, fingerprint).
		// A hit means either an idempotent re-activate or a resurrection
		// of a dead machine — both reuse the ID so the audit row is kept.
		existing, err := s.machines.GetByFingerprint(ctx, licenseID, req.Fingerprint)
		if err != nil {
			return err
		}

		// Enforce max_machines against alive (active+stale) rows, but
		// only when the activation is for a NEW fingerprint. An idempotent
		// re-activate or a resurrection of a dead machine under an
		// existing fingerprint never needs a cap check — the row either
		// already counts (active/stale) or is dead and doesn't.
		if eff.MaxMachines != nil && existing == nil {
			alive, err := s.machines.CountAliveByLicense(ctx, licenseID)
			if err != nil {
				return err
			}
			if alive >= *eff.MaxMachines {
				return core.NewAppError(core.ErrMachineLimitExceeded, "Machine limit exceeded")
			}
		}

		var metadata json.RawMessage
		if req.Metadata != nil {
			metadata = *req.Metadata
		}

		leaseExp := ComputeLeaseExpiresAt(eff, license.ExpiresAt, now)

		var machine *domain.Machine
		if existing != nil {
			machine = existing
			machine.Hostname = req.Hostname
			machine.Metadata = metadata
		} else {
			machine = &domain.Machine{
				ID:          core.NewMachineID(),
				AccountID:   accountID,
				LicenseID:   licenseID,
				Fingerprint: req.Fingerprint,
				Hostname:    req.Hostname,
				Metadata:    metadata,
				Environment: env,
				CreatedAt:   now,
			}
		}
		machine.LeaseIssuedAt = now
		machine.LeaseExpiresAt = leaseExp
		machine.LastCheckinAt = now
		machine.Status = core.MachineStatusActive

		if err := s.machines.UpsertActivation(ctx, machine); err != nil {
			return err
		}

		entCodes, err := s.entitlements.ResolveEffective(ctx, license.ID)
		if err != nil {
			return err
		}

		privKey, err := s.decryptProductPrivateKey(ctx, license.ProductID)
		if err != nil {
			return err
		}
		claims := BuildLeaseClaims(BuildLeaseClaimsInput{
			LicenseID:        license.ID,
			ProductID:        license.ProductID,
			PolicyID:         license.PolicyID,
			MachineID:        machine.ID,
			Fingerprint:      machine.Fingerprint,
			LicenseStatus:    license.Status,
			LicenseExpiresAt: license.ExpiresAt,
			LeaseIssuedAt:    machine.LeaseIssuedAt,
			LeaseExpiresAt:   machine.LeaseExpiresAt,
			Effective:        eff,
			Entitlements:     entCodes,
		})
		leaseToken, err := crypto.SignLeaseToken(claims, privKey)
		if err != nil {
			return core.NewAppError(core.ErrLeaseSignFailed, "failed to sign lease token")
		}

		result = &ActivateResult{
			Machine:     machine,
			LeaseToken:  leaseToken,
			LeaseClaims: claims,
		}

		if s.audit != nil {
			payload, _ := json.Marshal(map[string]any{
				"machine_id":       result.Machine.ID,
				"license_id":       result.Machine.LicenseID,
				"fingerprint":      result.Machine.Fingerprint,
				"lease_expires_at": result.Machine.LeaseExpiresAt,
			})
			if err := s.audit.Record(ctx, audit.EventFrom(attr, core.EventTypeMachineActivated, "machine", result.Machine.ID.String(), payload)); err != nil {
				slog.Error("audit: failed to record event", "event", core.EventTypeMachineActivated, "error", err)
			}
		}
		return nil
	})
	return result, err
}

// Checkin renews a machine's lease. Differs from Activate:
//   - Rejects if the machine is dead (caller must Activate to resurrect).
//   - Does NOT recheck max_machines (existing machines are already counted).
//   - Updates lease_issued_at + lease_expires_at + last_checkin_at and
//     transitions stale → active.
func (s *Service) Checkin(ctx context.Context, accountID core.AccountID, env core.Environment, licenseID core.LicenseID, fingerprint string, attr audit.Attribution) (*CheckinResult, error) {
	if !isValidFingerprint(fingerprint) {
		return nil, core.NewAppError(core.ErrMachineInvalidFingerprint, "fingerprint must be 1-256 chars from [A-Za-z0-9+/=_-]")
	}

	var result *CheckinResult

	err := s.txManager.WithTargetAccount(ctx, accountID, env, func(ctx context.Context) error {
		license, err := s.licenses.GetByIDForUpdate(ctx, licenseID)
		if err != nil {
			return err
		}
		if license == nil {
			return core.NewAppError(core.ErrLicenseNotFound, "License not found")
		}

		switch license.Status {
		case core.LicenseStatusRevoked:
			return core.NewAppError(core.ErrLicenseRevoked, "License has been revoked")
		case core.LicenseStatusSuspended:
			return core.NewAppError(core.ErrLicenseSuspended, "License is suspended")
		case core.LicenseStatusInactive:
			return core.NewAppError(core.ErrLicenseInactive, "License is inactive")
		case core.LicenseStatusExpired:
			return core.NewAppError(core.ErrLicenseExpired, "License has expired")
		}

		p, err := s.policies.Get(ctx, license.PolicyID)
		if err != nil {
			return err
		}
		if p == nil {
			return core.NewAppError(core.ErrPolicyNotFound, "policy not found")
		}
		eff := policy.Resolve(p, license.Overrides)

		if dec := policy.EvaluateExpiration(eff, license.ExpiresAt); !dec.Valid {
			return core.NewAppError(dec.Code, "License has expired")
		}

		machine, err := s.machines.GetByFingerprint(ctx, licenseID, fingerprint)
		if err != nil {
			return err
		}
		if machine == nil {
			return core.NewAppError(core.ErrMachineNotFound, "machine not found for license")
		}
		if machine.Status == core.MachineStatusDead {
			return core.NewAppError(core.ErrMachineDead, "machine is dead — re-activate to resurrect")
		}

		now := time.Now().UTC()
		machine.LeaseIssuedAt = now
		machine.LeaseExpiresAt = ComputeLeaseExpiresAt(eff, license.ExpiresAt, now)
		machine.LastCheckinAt = now
		machine.Status = core.MachineStatusActive

		if err := s.machines.RenewLease(ctx, machine); err != nil {
			return err
		}

		entCodes, err := s.entitlements.ResolveEffective(ctx, license.ID)
		if err != nil {
			return err
		}

		privKey, err := s.decryptProductPrivateKey(ctx, license.ProductID)
		if err != nil {
			return err
		}
		claims := BuildLeaseClaims(BuildLeaseClaimsInput{
			LicenseID:        license.ID,
			ProductID:        license.ProductID,
			PolicyID:         license.PolicyID,
			MachineID:        machine.ID,
			Fingerprint:      machine.Fingerprint,
			LicenseStatus:    license.Status,
			LicenseExpiresAt: license.ExpiresAt,
			LeaseIssuedAt:    machine.LeaseIssuedAt,
			LeaseExpiresAt:   machine.LeaseExpiresAt,
			Effective:        eff,
			Entitlements:     entCodes,
		})
		leaseToken, err := crypto.SignLeaseToken(claims, privKey)
		if err != nil {
			return core.NewAppError(core.ErrLeaseSignFailed, "failed to sign lease token")
		}

		result = &CheckinResult{
			Machine:     machine,
			LeaseToken:  leaseToken,
			LeaseClaims: claims,
		}

		if s.audit != nil {
			payload, _ := json.Marshal(map[string]any{
				"machine_id":       result.Machine.ID,
				"license_id":       result.Machine.LicenseID,
				"fingerprint":      result.Machine.Fingerprint,
				"lease_expires_at": result.Machine.LeaseExpiresAt,
			})
			if err := s.audit.Record(ctx, audit.EventFrom(attr, core.EventTypeMachineCheckedIn, "machine", result.Machine.ID.String(), payload)); err != nil {
				slog.Error("audit: failed to record event", "event", core.EventTypeMachineCheckedIn, "error", err)
			}
		}
		return nil
	})
	return result, err
}

// Update applies partial updates to the mutable fields of a license.
// Overrides replaces the entire LicenseOverrides struct when non-nil.
// ExpiresAt uses **time.Time so callers can distinguish "not set" from
// "explicitly cleared": an outer-nil pointer leaves the field alone; a
// non-nil outer pointer whose inner pointer is nil clears expires_at
// (perpetual license).
func (s *Service) Update(ctx context.Context, accountID core.AccountID, env core.Environment, licenseID core.LicenseID, req UpdateRequest) (*domain.License, error) {
	var result *domain.License
	err := s.txManager.WithTargetAccount(ctx, accountID, env, func(ctx context.Context) error {
		l, err := s.licenses.GetByIDForUpdate(ctx, licenseID)
		if err != nil {
			return err
		}
		if l == nil {
			return core.NewAppError(core.ErrLicenseNotFound, "License not found")
		}
		if req.Overrides != nil {
			if err := validateOverrideTTL(*req.Overrides); err != nil {
				return err
			}
		}
		if req.Overrides != nil {
			l.Overrides = *req.Overrides
		}
		if req.ExpiresAt != nil {
			l.ExpiresAt = *req.ExpiresAt
		}
		if req.CustomerID != nil {
			c, err := s.customers.Get(ctx, *req.CustomerID)
			if err != nil {
				return err
			}
			if c.AccountID != accountID {
				return core.NewAppError(core.ErrCustomerAccountMismatch, "customer belongs to a different account")
			}
			l.CustomerID = c.ID
		}
		if err := s.licenses.Update(ctx, l); err != nil {
			return err
		}
		result = l
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// Freeze snapshots the current effective quantitative values into the
// license's overrides so future policy changes no longer affect it.
// Only quantitative fields are frozen — behavioral flags (strict,
// floating, expiration_strategy, etc.) remain policy-driven.
func (s *Service) Freeze(ctx context.Context, accountID core.AccountID, env core.Environment, licenseID core.LicenseID) (*domain.License, error) {
	var result *domain.License
	err := s.txManager.WithTargetAccount(ctx, accountID, env, func(ctx context.Context) error {
		l, err := s.licenses.GetByIDForUpdate(ctx, licenseID)
		if err != nil {
			return err
		}
		if l == nil {
			return core.NewAppError(core.ErrLicenseNotFound, "License not found")
		}
		p, err := s.policies.Get(ctx, l.PolicyID)
		if err != nil {
			return err
		}
		if p == nil {
			return core.NewAppError(core.ErrPolicyNotFound, "policy not found")
		}
		eff := policy.Resolve(p, l.Overrides)

		// CheckoutIntervalSec and MaxCheckoutDurationSec are non-pointer
		// ints on policy.Effective; snapshot their values into local
		// vars so we can take addresses for the *int override fields.
		// policy.Resolve treats a non-nil *int override identically to
		// the raw policy value, so the round-trip preserves semantics.
		interval := eff.CheckoutIntervalSec
		maxDur := eff.MaxCheckoutDurationSec
		l.Overrides = domain.LicenseOverrides{
			MaxMachines:            eff.MaxMachines,
			MaxSeats:               eff.MaxSeats,
			CheckoutIntervalSec:    &interval,
			MaxCheckoutDurationSec: &maxDur,
		}
		if err := s.licenses.Update(ctx, l); err != nil {
			return err
		}
		result = l
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// AttachPolicy moves a license to a different policy, optionally
// clearing its per-license overrides so the new policy's values take
// effect unchanged. The new policy must belong to the same product.
func (s *Service) AttachPolicy(ctx context.Context, accountID core.AccountID, env core.Environment, licenseID core.LicenseID, newPolicyID core.PolicyID, clearOverrides bool) (*domain.License, error) {
	var result *domain.License
	err := s.txManager.WithTargetAccount(ctx, accountID, env, func(ctx context.Context) error {
		l, err := s.licenses.GetByIDForUpdate(ctx, licenseID)
		if err != nil {
			return err
		}
		if l == nil {
			return core.NewAppError(core.ErrLicenseNotFound, "License not found")
		}
		p, err := s.policies.Get(ctx, newPolicyID)
		if err != nil {
			return err
		}
		if p == nil {
			return core.NewAppError(core.ErrPolicyNotFound, "policy not found")
		}
		if p.ProductID != l.ProductID {
			return core.NewAppError(core.ErrPolicyProductMismatch, "policy belongs to a different product")
		}
		l.PolicyID = newPolicyID
		if clearOverrides {
			l.Overrides = domain.LicenseOverrides{}
		}
		if err := s.licenses.Update(ctx, l); err != nil {
			return err
		}
		result = l
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (s *Service) Deactivate(ctx context.Context, accountID core.AccountID, env core.Environment, licenseID core.LicenseID, req DeactivateRequest, attr audit.Attribution) error {
	if err := ValidateFingerprint(req.Fingerprint); err != nil {
		return err
	}

	return s.txManager.WithTargetAccount(ctx, accountID, env, func(ctx context.Context) error {
		if err := s.machines.DeleteByFingerprint(ctx, licenseID, req.Fingerprint); err != nil {
			return err
		}

		if s.audit != nil {
			payload, _ := json.Marshal(map[string]string{
				"license_id":  licenseID.String(),
				"fingerprint": req.Fingerprint,
			})
			if err := s.audit.Record(ctx, audit.EventFrom(attr, core.EventTypeMachineDeactivated, "machine", licenseID.String(), payload)); err != nil {
				slog.Error("audit: failed to record event", "event", core.EventTypeMachineDeactivated, "error", err)
			}
		}
		return nil
	})
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
	privBytes, err := s.masterKey.Decrypt(product.PrivateKeyEnc)
	if err != nil {
		return nil, core.NewAppError(core.ErrInternalError, "Failed to decrypt product private key")
	}
	return ed25519.PrivateKey(privBytes), nil
}

// buildLicense constructs a domain.License from pre-generated values, a
// CreateRequest, and the resolved policy. It computes expires_at from
// the effective duration (when the caller has not supplied one), signs
// the embedded license token, and returns the populated license. The
// Overrides carried on the request are persisted verbatim; all
// lifecycle configuration lives on the referenced policy. The caller
// passes the already-resolved customerID.
// effectiveValidationTTL returns the per-license effective TTL seconds:
// override > policy > server default. Never returns zero — the server
// default is applied when neither policy nor override set the field.
func (s *Service) effectiveValidationTTL(eff policy.Effective) int {
	if eff.ValidationTTLSec != nil {
		return *eff.ValidationTTLSec
	}
	return s.defaultValidationTTLSec
}

func (s *Service) buildLicense(
	req CreateRequest,
	p *domain.Policy,
	customerID core.CustomerID,
	licenseID core.LicenseID,
	prefix, keyHash string,
	now time.Time,
	accountID core.AccountID,
	productID core.ProductID,
	privKey ed25519.PrivateKey,
	env core.Environment,
) (*domain.License, error) {
	eff := policy.Resolve(p, req.Overrides)
	ttl := s.effectiveValidationTTL(eff)

	// Expires-at resolution:
	//   1. Caller-supplied ExpiresAt wins (explicit override).
	//   2. FROM_CREATION with a duration → stamp now + duration.
	//   3. Otherwise leave nil; FROM_FIRST_ACTIVATION stamps on activate.
	var expiresAt *time.Time
	if req.ExpiresAt != nil {
		exp := req.ExpiresAt.UTC()
		expiresAt = &exp
	} else if eff.DurationSeconds != nil && p.ExpirationBasis == core.ExpirationBasisFromCreation {
		exp := now.Add(time.Duration(*eff.DurationSeconds) * time.Second)
		expiresAt = &exp
	}

	payload := crypto.TokenPayload{
		Version:   1,
		ProductID: productID.String(),
		LicenseID: licenseID.String(),
		Status:    core.LicenseStatusActive,
		IssuedAt:  now.Unix(),
		TTL:       ttl,
	}
	if expiresAt != nil {
		ts := expiresAt.Unix()
		payload.ExpiresAt = &ts
	}

	token, err := crypto.SignToken(payload, privKey)
	if err != nil {
		return nil, core.NewAppError(core.ErrInternalError, "Failed to sign license token")
	}

	license := &domain.License{
		ID:          licenseID,
		AccountID:   accountID,
		ProductID:   productID,
		PolicyID:    p.ID,
		CustomerID:  customerID,
		Overrides:   req.Overrides,
		KeyPrefix:   prefix,
		KeyHash:     keyHash,
		Token:       token,
		Status:      core.LicenseStatusActive,
		ExpiresAt:   expiresAt,
		Environment: env,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	return license, nil
}

// requireLicense fetches a license by ID and returns ErrLicenseNotFound if missing.
func (s *Service) requireLicense(ctx context.Context, id core.LicenseID) (*domain.License, error) {
	license, err := s.licenses.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if license == nil {
		return nil, core.NewAppError(core.ErrLicenseNotFound, "License not found")
	}
	return license, nil
}

// transitionStatus is the shared implementation for Revoke, Suspend, and Reinstate.
// The audit record is written inside the tx so it shares the mutation's RLS context
// and is atomic with the status change.
func (s *Service) transitionStatus(
	ctx context.Context,
	accountID core.AccountID,
	env core.Environment,
	licenseID core.LicenseID,
	canTransition func(core.LicenseStatus) bool,
	target core.LicenseStatus,
	errMsg string,
	attr audit.Attribution,
	eventType core.EventType,
) (*domain.License, error) {
	var result *domain.License

	err := s.txManager.WithTargetAccount(ctx, accountID, env, func(ctx context.Context) error {
		license, err := s.requireLicense(ctx, licenseID)
		if err != nil {
			return err
		}
		if !canTransition(license.Status) {
			// F-015: emit a state-specific error code so clients can
			// distinguish "illegal transition" from generic validation.
			// The dashboard uses the code to decide whether to show a
			// form error (validation_error) or a state error (this).
			return core.NewAppError(licenseInvalidTransitionCode(license.Status), errMsg)
		}
		updatedAt, err := s.licenses.UpdateStatus(ctx, licenseID, license.Status, target)
		if err != nil {
			return err
		}
		license.Status = target
		license.UpdatedAt = updatedAt
		result = license

		if s.audit != nil {
			payload, _ := json.Marshal(result)
			if err := s.audit.Record(ctx, audit.EventFrom(attr, eventType, "license", result.ID.String(), payload)); err != nil {
				slog.Error("audit: failed to record event", "event", eventType, "error", err)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// licenseInvalidTransitionCode returns the typed error code for a
// refused state transition. When the current status has a dedicated
// code (revoked/suspended/expired/inactive) we use it so clients see
// license_revoked rather than the generic license_invalid_transition.
func licenseInvalidTransitionCode(current core.LicenseStatus) core.ErrorCode {
	switch current {
	case core.LicenseStatusRevoked:
		return core.ErrLicenseRevoked
	case core.LicenseStatusSuspended:
		return core.ErrLicenseSuspended
	case core.LicenseStatusExpired:
		return core.ErrLicenseExpired
	case core.LicenseStatusInactive:
		return core.ErrLicenseInactive
	default:
		return core.ErrLicenseInvalidTransition
	}
}
