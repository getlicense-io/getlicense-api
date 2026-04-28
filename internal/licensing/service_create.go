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
	"github.com/getlicense-io/getlicense-api/internal/policy"
	"github.com/getlicense-io/getlicense-api/internal/server/middleware"
)

func (s *Service) Create(ctx context.Context, accountID core.AccountID, env core.Environment, productID core.ProductID, req CreateRequest, opts CreateOptions) (*CreateResult, error) {
	// Product-scope gate runs pre-tx, pre-pregen: a product-scoped API
	// key calling for a different product short-circuits before we burn
	// a key+HMAC or pay for tenant RLS setup.
	if err := middleware.EnforceProductScope(ctx, productID); err != nil {
		return nil, err
	}
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

		// PR-C: AAD binds the ciphertext to (product, private_key).
		privKeyBytes, err := s.masterKey.Decrypt(product.PrivateKeyEnc, crypto.ProductPrivateKeyAAD(product.ID))
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
	// Product-scope gate runs pre-tx, pre-pregen: a product-scoped API
	// key calling for a different product short-circuits before we burn
	// keys+HMACs for N rows.
	if err := middleware.EnforceProductScope(ctx, productID); err != nil {
		return nil, err
	}
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

		// PR-C: AAD binds the ciphertext to (product, private_key).
		privKeyBytes, err := s.masterKey.Decrypt(product.PrivateKeyEnc, crypto.ProductPrivateKeyAAD(product.ID))
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
