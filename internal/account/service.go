package account

import (
	"context"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

// Service is the read-only account lookup service used by
// GET /v1/accounts/:id to render counterparty summaries on sharing
// screens. It NEVER exposes full Account details — callers serialize
// the returned *domain.AccountSummary directly.
type Service struct {
	accounts domain.AccountRepository
}

// NewService constructs a Service backed by the given AccountRepository.
func NewService(accounts domain.AccountRepository) *Service {
	return &Service{accounts: accounts}
}

// GetSummary returns the AccountSummary for the target account when the
// caller is authorized to see it — i.e. they have a membership on the
// target account under callerIdentityID, or there is a non-terminal
// grant (pending/active/suspended) between callerAccountID and targetID
// in either direction.
//
// Every other case — including "account does not exist", "caller has
// no relationship", and "only terminal (revoked) grant history" —
// returns ErrAccountNotFound (404). This collapse is deliberate: the
// endpoint is called with untrusted AccountIDs, so distinguishing "no
// such account" from "forbidden" would leak existence.
//
// Note: the membership branch requires a non-zero callerIdentityID. For
// API-key callers (no identity), only the grant-counterparty branch can
// authorize; passing a zero IdentityID is safe because the uuid will
// match no real row.
func (s *Service) GetSummary(
	ctx context.Context,
	targetID core.AccountID,
	callerAccountID core.AccountID,
	callerIdentityID core.IdentityID,
) (*domain.AccountSummary, error) {
	acc, err := s.accounts.GetIfAccessible(ctx, targetID, callerAccountID, callerIdentityID)
	if err != nil {
		return nil, err
	}
	if acc == nil {
		return nil, core.NewAppError(core.ErrAccountNotFound, "Account not found")
	}
	return &domain.AccountSummary{
		ID:   acc.ID,
		Name: acc.Name,
		Slug: acc.Slug,
	}, nil
}
