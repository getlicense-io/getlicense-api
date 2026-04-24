// Package membership owns read-only enumeration of an account's members
// for the dashboard team page. The mutation surface (invite, remove,
// change_role) lives in the existing auth and invitation packages.
package membership

import (
	"context"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

// Service exposes the team-page enumeration of an account's
// memberships joined with their identity (id+email) and role
// (id+slug+name). Read-only.
type Service struct {
	tx   domain.TxManager
	memb domain.AccountMembershipRepository
}

// NewService constructs the service. Wired from main.go's composition
// root, mirroring the other internal/* services.
func NewService(tx domain.TxManager, memb domain.AccountMembershipRepository) *Service {
	return &Service{tx: tx, memb: memb}
}

// List returns memberships for accountID, cursor-paginated. The repo
// call runs inside WithTargetAccount so RLS scopes the query to the
// path account.
//
// Note on environment: account_memberships rows have no environment
// column (memberships are account-wide). WithTargetAccount writes both
// account_id and environment GUCs, but the membership RLS policy
// ignores the environment one — same as how invitations and grants
// work for account-wide reads.
func (s *Service) List(
	ctx context.Context,
	accountID core.AccountID,
	cursor core.Cursor,
	limit int,
) ([]domain.MembershipDetail, bool, error) {
	var rows []domain.MembershipDetail
	var hasMore bool
	err := s.tx.WithTargetAccount(ctx, accountID, core.EnvironmentLive, func(ctx context.Context) error {
		var e error
		rows, hasMore, e = s.memb.ListAccountWithDetails(ctx, cursor, limit)
		return e
	})
	return rows, hasMore, err
}
