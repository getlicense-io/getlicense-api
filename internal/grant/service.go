package grant

import (
	"context"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

// Service manages the grant lifecycle: issuance, acceptance,
// suspension, and revocation. It does not handle HTTP routing or
// invitation integration — those are wired in bundle 4b.
type Service struct {
	txManager domain.TxManager
	grants    domain.GrantRepository
}

// NewService creates a new grant Service.
func NewService(
	txManager domain.TxManager,
	grants domain.GrantRepository,
) *Service {
	return &Service{
		txManager: txManager,
		grants:    grants,
	}
}

// IssueRequest is the body for issuing a new grant. The grantor
// specifies the grantee account, the capabilities they are delegating,
// and an optional constraint blob.
type IssueRequest struct {
	GranteeAccountID core.AccountID          `json:"grantee_account_id"`
	Capabilities     []domain.GrantCapability `json:"capabilities"`
	Constraints      domain.GrantConstraints  `json:"constraints,omitempty"`
	InvitationID     *core.InvitationID       `json:"invitation_id,omitempty"`
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

	now := time.Now().UTC()
	g := &domain.Grant{
		ID:               core.NewGrantID(),
		GrantorAccountID: grantorAccountID,
		GranteeAccountID: req.GranteeAccountID,
		Status:           domain.GrantStatusPending,
		Capabilities:     req.Capabilities,
		Constraints:      req.Constraints,
		InvitationID:     req.InvitationID,
		Environment:      env,
		CreatedAt:        now,
		UpdatedAt:        now,
	}

	err := s.txManager.WithTargetAccount(ctx, grantorAccountID, env, func(ctx context.Context) error {
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
		if err := s.grants.UpdateStatus(ctx, grantID, domain.GrantStatusActive, now); err != nil {
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

		now := time.Now().UTC()
		if err := s.grants.UpdateStatus(ctx, grantID, domain.GrantStatusSuspended, now); err != nil {
			return err
		}
		g.Status = domain.GrantStatusSuspended
		g.SuspendedAt = &now
		g.UpdatedAt = now
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

		now := time.Now().UTC()
		if err := s.grants.UpdateStatus(ctx, grantID, domain.GrantStatusRevoked, now); err != nil {
			return err
		}
		g.Status = domain.GrantStatusRevoked
		g.RevokedAt = &now
		g.UpdatedAt = now
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
	for _, c := range g.Capabilities {
		if c == cap {
			return nil
		}
	}
	return core.NewAppError(core.ErrGrantCapabilityDenied, "Capability not granted")
}
