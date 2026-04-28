package licensing

import (
	"context"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/getlicense-io/getlicense-api/internal/policy"
	"github.com/getlicense-io/getlicense-api/internal/server/middleware"
)

// Update applies partial updates to the mutable fields of a license.
// Overrides replaces the entire LicenseOverrides struct when non-nil.
// ExpiresAt uses **time.Time so callers can distinguish "not set" from
// "explicitly cleared": an outer-nil pointer leaves the field alone; a
// non-nil outer pointer whose inner pointer is nil clears expires_at
// (perpetual license).
func (s *Service) Update(ctx context.Context, accountID core.AccountID, env core.Environment, licenseID core.LicenseID, req UpdateRequest) (*domain.License, error) {
	var result *domain.License
	err := s.txManager.WithTargetAccount(ctx, accountID, env, func(ctx context.Context) error {
		l, err := s.requireLicenseForUpdate(ctx, licenseID)
		if err != nil {
			return err
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
		l, err := s.requireLicenseForUpdate(ctx, licenseID)
		if err != nil {
			return err
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
		l, err := s.requireLicenseForUpdate(ctx, licenseID)
		if err != nil {
			return err
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

// requireLicenseForUpdate is the lock-taking sibling of requireLicense.
// Used by Activate, Checkin, Update, Freeze, AttachPolicy — any method
// that needs SELECT ... FOR UPDATE on the license row. Also runs the
// product-scope gate so a product-scoped API key can't mutate a license
// outside its scope.
func (s *Service) requireLicenseForUpdate(ctx context.Context, id core.LicenseID) (*domain.License, error) {
	license, err := s.licenses.GetByIDForUpdate(ctx, id)
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
