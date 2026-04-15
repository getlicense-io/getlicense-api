package licensing

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"time"

	"log/slog"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/crypto"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/getlicense-io/getlicense-api/internal/policy"
)

type Service struct {
	txManager  domain.TxManager
	licenses   domain.LicenseRepository
	products   domain.ProductRepository
	machines   domain.MachineRepository
	policies   domain.PolicyRepository
	masterKey  *crypto.MasterKey
	webhookSvc domain.EventDispatcher
}

func NewService(
	txManager domain.TxManager,
	licenses domain.LicenseRepository,
	products domain.ProductRepository,
	machines domain.MachineRepository,
	policies domain.PolicyRepository,
	masterKey *crypto.MasterKey,
	webhookSvc domain.EventDispatcher,
) *Service {
	return &Service{
		txManager:  txManager,
		licenses:   licenses,
		products:   products,
		machines:   machines,
		policies:   policies,
		masterKey:  masterKey,
		webhookSvc: webhookSvc,
	}
}

// CreateRequest describes a new license. License lifecycle configuration
// comes from the referenced policy (or the product's default policy if
// PolicyID is nil); the request carries only per-license overrides plus
// the licensee metadata and an optional explicit expires_at override.
type CreateRequest struct {
	// PolicyID pins the license to a specific policy. Nil falls back
	// to the product's default policy.
	PolicyID *core.PolicyID `json:"policy_id,omitempty"`

	// Overrides holds sparse per-license overrides for quantitative
	// policy fields. Nil pointers inherit from the policy.
	Overrides domain.LicenseOverrides `json:"overrides,omitempty"`

	// LicenseeName / LicenseeEmail are free-form metadata on the
	// license. They live here until L4 customer records land.
	LicenseeName  *string `json:"licensee_name,omitempty"`
	LicenseeEmail *string `json:"licensee_email,omitempty"`

	// ExpiresAt lets the caller stamp an explicit expiry. When nil,
	// the service computes it from the resolved policy duration for
	// FROM_CREATION basis; FROM_FIRST_ACTIVATION leaves it nil until
	// the first machine activation.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
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
	Valid   bool            `json:"valid"`
	License *domain.License `json:"license"`
}

type ActivateRequest struct {
	Fingerprint string           `json:"fingerprint" validate:"required"`
	Hostname    *string          `json:"hostname"`
	Metadata    *json.RawMessage `json:"metadata"`
}

type DeactivateRequest struct {
	Fingerprint string `json:"fingerprint" validate:"required"`
}

type HeartbeatRequest struct {
	Fingerprint string `json:"fingerprint" validate:"required"`
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

		privKeyBytes, err := s.masterKey.Decrypt(product.PrivateKeyEnc)
		if err != nil {
			return core.NewAppError(core.ErrInternalError, "Failed to decrypt product private key")
		}

		license, err := buildLicense(req, p, licenseID, prefix, keyHash, now, accountID, productID, ed25519.PrivateKey(privKeyBytes), env)
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

		result = &CreateResult{License: license, LicenseKey: fullKey}
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.dispatchEvent(ctx, accountID, env, core.EventTypeLicenseCreated, result.License)
	return result, nil
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

	var results []CreateResult

	err := s.txManager.WithTargetAccount(ctx, accountID, env, func(ctx context.Context) error {
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

			license, err := buildLicense(lr, p, pg.licenseID, pg.prefix, pg.keyHash, now, accountID, productID, privKey, env)
			if err != nil {
				return err
			}
			license.GrantID = opts.GrantID
			license.CreatedByAccountID = opts.CreatedByAccountID
			license.CreatedByIdentityID = opts.CreatedByIdentityID
			allLicenses[i] = license
			results[i] = CreateResult{License: license, LicenseKey: pg.fullKey}
		}

		return s.licenses.BulkCreate(ctx, allLicenses)
	})
	if err != nil {
		return nil, err
	}
	for _, r := range results {
		s.dispatchEvent(ctx, accountID, env, core.EventTypeLicenseCreated, r.License)
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

func (s *Service) Revoke(ctx context.Context, accountID core.AccountID, env core.Environment, licenseID core.LicenseID) error {
	result, err := s.transitionStatus(ctx, accountID, env, licenseID,
		func(st core.LicenseStatus) bool { return st.CanRevoke() },
		core.LicenseStatusRevoked,
		"License cannot be revoked from current status",
	)
	if err != nil {
		return err
	}
	s.dispatchEvent(ctx, accountID, env, core.EventTypeLicenseRevoked, result)
	return nil
}

func (s *Service) Suspend(ctx context.Context, accountID core.AccountID, env core.Environment, licenseID core.LicenseID) (*domain.License, error) {
	result, err := s.transitionStatus(ctx, accountID, env, licenseID,
		func(st core.LicenseStatus) bool { return st.CanSuspend() },
		core.LicenseStatusSuspended,
		"License cannot be suspended from current status",
	)
	if err != nil {
		return nil, err
	}
	s.dispatchEvent(ctx, accountID, env, core.EventTypeLicenseSuspended, result)
	return result, nil
}

func (s *Service) Reinstate(ctx context.Context, accountID core.AccountID, env core.Environment, licenseID core.LicenseID) (*domain.License, error) {
	result, err := s.transitionStatus(ctx, accountID, env, licenseID,
		func(st core.LicenseStatus) bool { return st.CanReinstate() },
		core.LicenseStatusActive,
		"License cannot be reinstated from current status",
	)
	if err != nil {
		return nil, err
	}
	s.dispatchEvent(ctx, accountID, env, core.EventTypeLicenseReinstated, result)
	return result, nil
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

	return &ValidateResult{Valid: true, License: license}, nil
}

func (s *Service) Activate(ctx context.Context, accountID core.AccountID, env core.Environment, licenseID core.LicenseID, req ActivateRequest) (*domain.Machine, error) {
	if err := ValidateFingerprint(req.Fingerprint); err != nil {
		return nil, err
	}

	var result *domain.Machine

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

		existing, err := s.machines.GetByFingerprint(ctx, licenseID, req.Fingerprint)
		if err != nil {
			return err
		}
		if existing != nil {
			return core.NewAppError(core.ErrMachineAlreadyActivated, "Machine is already activated for this license")
		}

		if eff.MaxMachines != nil {
			count, err := s.machines.CountByLicense(ctx, licenseID)
			if err != nil {
				return err
			}
			if count >= *eff.MaxMachines {
				return core.NewAppError(core.ErrMachineLimitExceeded, "Machine limit exceeded")
			}
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

		var metadata json.RawMessage
		if req.Metadata != nil {
			metadata = *req.Metadata
		}

		machine := &domain.Machine{
			ID:          core.NewMachineID(),
			AccountID:   accountID,
			LicenseID:   licenseID,
			Fingerprint: req.Fingerprint,
			Hostname:    req.Hostname,
			Metadata:    metadata,
			Environment: env,
			CreatedAt:   now,
		}

		if err := s.machines.Create(ctx, machine); err != nil {
			return err
		}

		result = machine
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.dispatchEvent(ctx, accountID, env, core.EventTypeMachineActivated, result)
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

func (s *Service) Deactivate(ctx context.Context, accountID core.AccountID, env core.Environment, licenseID core.LicenseID, req DeactivateRequest) error {
	if err := ValidateFingerprint(req.Fingerprint); err != nil {
		return err
	}

	err := s.txManager.WithTargetAccount(ctx, accountID, env, func(ctx context.Context) error {
		return s.machines.DeleteByFingerprint(ctx, licenseID, req.Fingerprint)
	})
	if err != nil {
		return err
	}
	s.dispatchEvent(ctx, accountID, env, core.EventTypeMachineDeactivated, map[string]string{
		"license_id":  licenseID.String(),
		"fingerprint": req.Fingerprint,
	})
	return nil
}

func (s *Service) Heartbeat(ctx context.Context, accountID core.AccountID, env core.Environment, licenseID core.LicenseID, req HeartbeatRequest) (*domain.Machine, error) {
	if err := ValidateFingerprint(req.Fingerprint); err != nil {
		return nil, err
	}

	var result *domain.Machine

	err := s.txManager.WithTargetAccount(ctx, accountID, env, func(ctx context.Context) error {
		m, err := s.machines.UpdateHeartbeat(ctx, licenseID, req.Fingerprint)
		if err != nil {
			return err
		}
		result = m
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// --- Private helpers ---

func (s *Service) dispatchEvent(ctx context.Context, accountID core.AccountID, env core.Environment, eventType core.EventType, payload any) {
	if s.webhookSvc == nil {
		return
	}
	data, err := json.Marshal(payload)
	if err != nil {
		slog.Error("webhook: failed to marshal event payload", "event", eventType, "error", err)
		return
	}
	s.webhookSvc.Dispatch(ctx, accountID, env, eventType, data)
}

// buildLicense constructs a domain.License from pre-generated values, a
// CreateRequest, and the resolved policy. It computes expires_at from
// the effective duration (when the caller has not supplied one), signs
// the embedded license token, and returns the populated license. The
// Overrides carried on the request are persisted verbatim; all
// lifecycle configuration lives on the referenced policy.
func buildLicense(
	req CreateRequest,
	p *domain.Policy,
	licenseID core.LicenseID,
	prefix, keyHash string,
	now time.Time,
	accountID core.AccountID,
	productID core.ProductID,
	privKey ed25519.PrivateKey,
	env core.Environment,
) (*domain.License, error) {
	eff := policy.Resolve(p, req.Overrides)

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
		ID:            licenseID,
		AccountID:     accountID,
		ProductID:     productID,
		PolicyID:      p.ID,
		Overrides:     req.Overrides,
		KeyPrefix:     prefix,
		KeyHash:       keyHash,
		Token:         token,
		Status:        core.LicenseStatusActive,
		LicenseeName:  req.LicenseeName,
		LicenseeEmail: req.LicenseeEmail,
		ExpiresAt:     expiresAt,
		Environment:   env,
		CreatedAt:     now,
		UpdatedAt:     now,
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
func (s *Service) transitionStatus(
	ctx context.Context,
	accountID core.AccountID,
	env core.Environment,
	licenseID core.LicenseID,
	canTransition func(core.LicenseStatus) bool,
	target core.LicenseStatus,
	errMsg string,
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
