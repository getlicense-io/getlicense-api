package grant

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

// Service manages the capability grant lifecycle: issuance,
// acceptance, suspension, and revocation. HTTP routing lives in
// server/handler/grants.go; invitation-driven grant creation lives
// in invitation.Service.acceptGrant.
type Service struct {
	txManager domain.TxManager
	grants    domain.GrantRepository
	products  domain.ProductRepository
}

// NewService creates a new grant Service.
func NewService(
	txManager domain.TxManager,
	grants domain.GrantRepository,
	products domain.ProductRepository,
) *Service {
	return &Service{
		txManager: txManager,
		grants:    grants,
		products:  products,
	}
}

// IssueRequest is the body for issuing a new grant. The grantor
// specifies the grantee account, the product, the capabilities they
// are delegating, and an optional constraint blob.
type IssueRequest struct {
	GranteeAccountID core.AccountID          `json:"grantee_account_id"`
	ProductID        core.ProductID          `json:"product_id"`
	Capabilities     []domain.GrantCapability `json:"capabilities"`
	Constraints      json.RawMessage          `json:"constraints,omitempty"`
	InvitationID     *core.InvitationID       `json:"invitation_id,omitempty"`
	ExpiresAt        *time.Time               `json:"expires_at,omitempty"`
}

// Issue creates a new grant in the pending state. The grant becomes
// active only when the grantee calls Accept. Runs inside the grantor's
// tenant context so RLS scopes the insert correctly.
func (s *Service) Issue(
	ctx context.Context,
	grantorAccountID core.AccountID,
	env core.Environment,
	req IssueRequest,
) (*domain.Grant, error) {
	if grantorAccountID == req.GranteeAccountID {
		return nil, core.NewAppError(core.ErrValidationError, "Grantor and grantee must be different accounts")
	}
	if len(req.Capabilities) == 0 {
		return nil, core.NewAppError(core.ErrValidationError, "At least one capability is required")
	}
	// F-003: reject unknown capability strings at issuance time.
	// Without this check, arbitrary strings (e.g. "license.create"
	// dot-case, "TOTALLY_FAKE", even path-traversal payloads) were
	// stored as-is and only rejected at RequireCapability time —
	// grants appeared valid at creation but were permanently unusable.
	for _, c := range req.Capabilities {
		if !domain.IsValidGrantCapability(c) {
			return nil, core.NewAppError(core.ErrValidationError,
				"Unknown grant capability: "+string(c))
		}
	}

	now := time.Now().UTC()
	g := &domain.Grant{
		ID:               core.NewGrantID(),
		GrantorAccountID: grantorAccountID,
		GranteeAccountID: req.GranteeAccountID,
		ProductID:        req.ProductID,
		Status:           domain.GrantStatusPending,
		Capabilities:     req.Capabilities,
		Constraints:      req.Constraints,
		InvitationID:     req.InvitationID,
		ExpiresAt:        req.ExpiresAt,
		CreatedAt:        now,
		UpdatedAt:        now,
	}

	err := s.txManager.WithTargetAccount(ctx, grantorAccountID, env, func(ctx context.Context) error {
		product, err := s.products.GetByID(ctx, req.ProductID)
		if err != nil {
			return err
		}
		if product == nil || product.AccountID != grantorAccountID {
			return core.NewAppError(core.ErrProductNotFound, "Product not found in grantor account")
		}
		return s.grants.Create(ctx, g)
	})
	if err != nil {
		return nil, err
	}
	return g, nil
}

// Accept transitions a grant from pending → active. Must be called by
// the grantee. Runs inside the grantee's tenant context.
func (s *Service) Accept(
	ctx context.Context,
	granteeAccountID core.AccountID,
	env core.Environment,
	grantID core.GrantID,
) (*domain.Grant, error) {
	var g *domain.Grant

	err := s.txManager.WithTargetAccount(ctx, granteeAccountID, env, func(ctx context.Context) error {
		var err error
		g, err = s.grants.GetByID(ctx, grantID)
		if err != nil {
			return err
		}
		if g == nil {
			return core.NewAppError(core.ErrGrantNotFound, "Grant not found")
		}
		if g.GranteeAccountID != granteeAccountID {
			return core.NewAppError(core.ErrGrantNotFound, "Grant not found")
		}
		if g.Status != domain.GrantStatusPending {
			return core.NewAppError(core.ErrGrantNotActive, "Grant is not in pending state")
		}

		now := time.Now().UTC()
		if err := s.grants.MarkAccepted(ctx, grantID, now); err != nil {
			return err
		}
		g.Status = domain.GrantStatusActive
		g.AcceptedAt = &now
		g.UpdatedAt = now
		return nil
	})
	if err != nil {
		return nil, err
	}
	return g, nil
}

// Suspend temporarily suspends an active grant. Can be called by the
// grantor. Runs inside the grantor's tenant context.
func (s *Service) Suspend(
	ctx context.Context,
	grantorAccountID core.AccountID,
	env core.Environment,
	grantID core.GrantID,
) (*domain.Grant, error) {
	var g *domain.Grant

	err := s.txManager.WithTargetAccount(ctx, grantorAccountID, env, func(ctx context.Context) error {
		var err error
		g, err = s.grants.GetByID(ctx, grantID)
		if err != nil {
			return err
		}
		if g == nil {
			return core.NewAppError(core.ErrGrantNotFound, "Grant not found")
		}
		if g.GrantorAccountID != grantorAccountID {
			return core.NewAppError(core.ErrGrantNotFound, "Grant not found")
		}
		if g.Status != domain.GrantStatusActive {
			return core.NewAppError(core.ErrGrantNotActive, "Grant is not active")
		}

		if err := s.grants.UpdateStatus(ctx, grantID, domain.GrantStatusSuspended); err != nil {
			return err
		}
		g.Status = domain.GrantStatusSuspended
		g.UpdatedAt = time.Now().UTC()
		return nil
	})
	if err != nil {
		return nil, err
	}
	return g, nil
}

// Revoke permanently revokes a grant. Can be called by the grantor.
// A revoked grant cannot be reactivated. Runs inside the grantor's
// tenant context.
func (s *Service) Revoke(
	ctx context.Context,
	grantorAccountID core.AccountID,
	env core.Environment,
	grantID core.GrantID,
) (*domain.Grant, error) {
	var g *domain.Grant

	err := s.txManager.WithTargetAccount(ctx, grantorAccountID, env, func(ctx context.Context) error {
		var err error
		g, err = s.grants.GetByID(ctx, grantID)
		if err != nil {
			return err
		}
		if g == nil {
			return core.NewAppError(core.ErrGrantNotFound, "Grant not found")
		}
		if g.GrantorAccountID != grantorAccountID {
			return core.NewAppError(core.ErrGrantNotFound, "Grant not found")
		}
		if g.Status == domain.GrantStatusRevoked {
			return core.NewAppError(core.ErrValidationError, "Grant is already revoked")
		}

		if err := s.grants.UpdateStatus(ctx, grantID, domain.GrantStatusRevoked); err != nil {
			return err
		}
		g.Status = domain.GrantStatusRevoked
		g.UpdatedAt = time.Now().UTC()
		return nil
	})
	if err != nil {
		return nil, err
	}
	return g, nil
}

// Get returns a single grant by ID. Readable by both grantor and
// grantee via the dual-branch RLS policy.
func (s *Service) Get(
	ctx context.Context,
	accountID core.AccountID,
	env core.Environment,
	grantID core.GrantID,
) (*domain.Grant, error) {
	var g *domain.Grant

	err := s.txManager.WithTargetAccount(ctx, accountID, env, func(ctx context.Context) error {
		var err error
		g, err = s.grants.GetByID(ctx, grantID)
		if err != nil {
			return err
		}
		if g == nil {
			return core.NewAppError(core.ErrGrantNotFound, "Grant not found")
		}
		// Verify caller is either grantor or grantee.
		if g.GrantorAccountID != accountID && g.GranteeAccountID != accountID {
			return core.NewAppError(core.ErrGrantNotFound, "Grant not found")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return g, nil
}

// ListByGrantor returns cursor-paginated grants issued by accountID.
func (s *Service) ListByGrantor(
	ctx context.Context,
	accountID core.AccountID,
	env core.Environment,
	cursor core.Cursor,
	limit int,
) ([]domain.Grant, bool, error) {
	var grants []domain.Grant
	var hasMore bool

	err := s.txManager.WithTargetAccount(ctx, accountID, env, func(ctx context.Context) error {
		var err error
		grants, hasMore, err = s.grants.ListByGrantor(ctx, cursor, limit)
		return err
	})
	if err != nil {
		return nil, false, err
	}
	return grants, hasMore, nil
}

// ListByGrantee returns cursor-paginated grants received by accountID.
func (s *Service) ListByGrantee(
	ctx context.Context,
	accountID core.AccountID,
	env core.Environment,
	cursor core.Cursor,
	limit int,
) ([]domain.Grant, bool, error) {
	var grants []domain.Grant
	var hasMore bool

	err := s.txManager.WithTargetAccount(ctx, accountID, env, func(ctx context.Context) error {
		var err error
		grants, hasMore, err = s.grants.ListByGrantee(ctx, cursor, limit)
		return err
	})
	if err != nil {
		return nil, false, err
	}
	return grants, hasMore, nil
}

// RequireCapability checks that the grant is active and contains the
// requested capability. Returns ErrGrantNotActive or
// ErrGrantCapabilityDenied if either check fails. Used by the grant
// routing middleware to gate grantee operations.
func (s *Service) RequireCapability(g *domain.Grant, cap domain.GrantCapability) error {
	if g.Status != domain.GrantStatusActive {
		return core.NewAppError(core.ErrGrantNotActive, "Grant is not active")
	}
	if !slices.Contains(g.Capabilities, cap) {
		return core.NewAppError(core.ErrGrantCapabilityDenied, "Capability not granted")
	}
	return nil
}

// Resolve loads a grant and verifies the acting account is its
// grantee. Used by the grant routing middleware to validate a
// grant-scoped request before switching the RLS target to the
// grantor. The resolve tx is scoped to the acting (grantee) account
// so the grants RLS policy's grantee-match branch fires.
//
// EnvironmentLive is hardcoded because grants are account-scoped,
// not environment-scoped — the grants table has no environment
// column and the RLS policy does not filter on environment. Callers
// in any environment (live, test, custom) will resolve the same
// grant row.
func (s *Service) Resolve(ctx context.Context, grantID core.GrantID, actingAccountID core.AccountID) (*domain.Grant, error) {
	var grant *domain.Grant
	err := s.txManager.WithTargetAccount(ctx, actingAccountID, core.EnvironmentLive, func(ctx context.Context) error {
		g, err := s.grants.GetByID(ctx, grantID)
		if err != nil {
			return err
		}
		if g == nil {
			return core.NewAppError(core.ErrGrantNotFound, "Grant not found")
		}
		if g.GranteeAccountID != actingAccountID {
			return core.NewAppError(core.ErrPermissionDenied, "Grant is not held by acting account")
		}
		grant = g
		return nil
	})
	if err != nil {
		return nil, err
	}
	return grant, nil
}

// RequireActive returns ErrGrantNotActive if the grant is anything
// other than active, or has expired.
func (s *Service) RequireActive(g *domain.Grant) error {
	if g.Status != domain.GrantStatusActive {
		return core.NewAppError(core.ErrGrantNotActive, "Grant is "+string(g.Status))
	}
	if g.ExpiresAt != nil && time.Now().UTC().After(*g.ExpiresAt) {
		return core.NewAppError(core.ErrGrantNotActive, "Grant has expired")
	}
	return nil
}

// CheckLicenseCreateConstraints enforces the declarative constraints
// from the grant's JSON blob against the incoming operation. Must be
// called inside the grantor's tenant tx so the license count query
// is RLS-scoped correctly.
func (s *Service) CheckLicenseCreateConstraints(ctx context.Context, g *domain.Grant, licenseeEmail string) error {
	var constraints domain.GrantConstraints
	if len(g.Constraints) > 0 {
		if err := json.Unmarshal(g.Constraints, &constraints); err != nil {
			return core.NewAppError(core.ErrInternalError, "Malformed grant constraints")
		}
	}

	if constraints.MaxLicensesTotal > 0 {
		total, err := s.grants.CountLicensesInPeriod(ctx, g.ID, time.Time{})
		if err != nil {
			return err
		}
		if total >= constraints.MaxLicensesTotal {
			return core.NewAppError(core.ErrGrantConstraintViolated, "Grant total license quota exceeded")
		}
	}
	if constraints.MaxLicensesPerMonth > 0 {
		start := time.Now().UTC().AddDate(0, 0, -30)
		n, err := s.grants.CountLicensesInPeriod(ctx, g.ID, start)
		if err != nil {
			return err
		}
		if n >= constraints.MaxLicensesPerMonth {
			return core.NewAppError(core.ErrGrantConstraintViolated, "Grant monthly license quota exceeded")
		}
	}
	if pattern := constraints.LicenseeEmailPattern; pattern != "" {
		if !matchEmailPattern(licenseeEmail, pattern) {
			return core.NewAppError(core.ErrGrantConstraintViolated, "Licensee email does not match allowed pattern")
		}
	}
	return nil
}

// matchEmailPattern supports two simple forms:
//   - "@example.com"  → exact domain match
//   - "*.example.com" → domain suffix match (any subdomain)
func matchEmailPattern(email, pattern string) bool {
	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 {
		return false
	}
	domain := parts[1]
	if strings.HasPrefix(pattern, "@") {
		return "@"+domain == pattern
	}
	if strings.HasPrefix(pattern, "*.") && strings.HasSuffix(domain, pattern[1:]) {
		return true
	}
	return false
}
