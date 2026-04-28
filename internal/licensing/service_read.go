package licensing

import (
	"context"
	"crypto/ed25519"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/crypto"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/getlicense-io/getlicense-api/internal/policy"
	"github.com/getlicense-io/getlicense-api/internal/server/middleware"
)

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
	// Product-scope gate runs pre-tx: a product-scoped API key calling
	// for a different product short-circuits before the tenant tx is
	// opened, mirroring the Create gate's placement.
	if err := middleware.EnforceProductScope(ctx, productID); err != nil {
		return nil, false, err
	}
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

// CountsByProductStatus returns a per-status license breakdown for
// the given product within the current env. The dashboard uses this
// to render an accurate blocking count for the delete-product flow
// without having to fetch every license row.
func (s *Service) CountsByProductStatus(ctx context.Context, accountID core.AccountID, env core.Environment, productID core.ProductID) (domain.LicenseStatusCounts, error) {
	// Product-scope gate runs pre-tx so a product-scoped API key cannot
	// even count licenses on a product it isn't bound to.
	if err := middleware.EnforceProductScope(ctx, productID); err != nil {
		return domain.LicenseStatusCounts{}, err
	}
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
	// Product-scope gate runs pre-tx: a product-scoped API key for
	// product A must not be able to bulk-revoke product B's licenses.
	if err := middleware.EnforceProductScope(ctx, productID); err != nil {
		return 0, err
	}
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

// Validate looks up a license by its raw key and checks status. This
// is a public endpoint — the caller is unauthenticated and has no
// tenant context. The hash lookup must read across tenants, so wrap
// in WithSystemContext (PR-B / migration 034) for an explicit RLS
// bypass. Once the license is resolved, downstream tenant-scoped reads
// run through the same system tx so policy / entitlement /
// product-key lookups all succeed.
func (s *Service) Validate(ctx context.Context, licenseKey string) (*ValidateResult, error) {
	keyHash := s.masterKey.HMAC(licenseKey)

	var (
		license  *domain.License
		p        *domain.Policy
		entCodes []string
		privKey  ed25519.PrivateKey
	)
	if err := s.txManager.WithSystemContext(ctx, func(ctx context.Context) error {
		l, err := s.licenses.GetByKeyHash(ctx, keyHash)
		if err != nil {
			return err
		}
		if l == nil {
			return core.NewAppError(core.ErrInvalidLicenseKey, "Invalid license key")
		}
		license = l

		// Status transitions that were applied via UpdateStatus (suspend,
		// revoke, background expire sweep) still surface their terminal
		// codes regardless of the policy's expiration strategy.
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

		pol, err := s.policies.Get(ctx, license.PolicyID)
		if err != nil {
			return err
		}
		if pol == nil {
			return core.NewAppError(core.ErrPolicyNotFound, "policy not found")
		}
		p = pol

		ent, err := s.entitlements.ResolveEffective(ctx, license.ID)
		if err != nil {
			return err
		}
		entCodes = ent

		pk, err := s.decryptProductPrivateKey(ctx, license.ProductID)
		if err != nil {
			return err
		}
		privKey = pk
		return nil
	}); err != nil {
		return nil, err
	}

	eff := policy.Resolve(p, license.Overrides)
	if dec := policy.EvaluateExpiration(eff, license.ExpiresAt); !dec.Valid {
		return nil, core.NewAppError(dec.Code, "License has expired")
	}

	// Re-mint the gl1 token with the current effective TTL so policy
	// updates cascade to existing licenses. The stored licenses.token
	// column is never updated by this path — only /v1/validate returns
	// a re-minted token. See CLAUDE.md § Validation TTL (P3).
	ttl := s.effectiveValidationTTL(eff)
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
