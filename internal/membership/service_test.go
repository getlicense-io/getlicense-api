package membership_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/getlicense-io/getlicense-api/internal/membership"
)

// fakeRepo satisfies the subset of domain.AccountMembershipRepository
// that the membership service touches. Other methods stay nil-receivers
// because the service never calls them — keeps the test surface narrow.
type fakeRepo struct {
	rows    []domain.MembershipDetail
	hasMore bool
	err     error
	// captureCursor and captureLimit record what the service passed
	// through; lets us verify the service didn't transform the args.
	captureCursor core.Cursor
	captureLimit  int
}

// Implement the only method the service uses.
func (f *fakeRepo) ListAccountWithDetails(_ context.Context, cursor core.Cursor, limit int) ([]domain.MembershipDetail, bool, error) {
	f.captureCursor = cursor
	f.captureLimit = limit
	return f.rows, f.hasMore, f.err
}

// Stub the rest of the interface (not called by Service.List).
// Keep these as no-op returns rather than panics so accidental misuse
// produces a friendlier diagnostic if the service surface ever expands.
func (f *fakeRepo) Create(context.Context, *domain.AccountMembership) error { return nil }
func (f *fakeRepo) GetByID(context.Context, core.MembershipID) (*domain.AccountMembership, error) {
	return nil, nil
}
func (f *fakeRepo) GetByIDWithRole(context.Context, core.MembershipID) (*domain.AccountMembership, *domain.Role, error) {
	return nil, nil, nil
}
func (f *fakeRepo) GetByIdentityAndAccount(context.Context, core.IdentityID, core.AccountID) (*domain.AccountMembership, error) {
	return nil, nil
}
func (f *fakeRepo) ListByIdentity(context.Context, core.IdentityID) ([]domain.AccountMembership, error) {
	return nil, nil
}
func (f *fakeRepo) ListByAccount(context.Context, core.Cursor, int) ([]domain.AccountMembership, bool, error) {
	return nil, false, nil
}
func (f *fakeRepo) UpdateRole(context.Context, core.MembershipID, core.RoleID) error { return nil }
func (f *fakeRepo) UpdateStatus(context.Context, core.MembershipID, domain.MembershipStatus) error {
	return nil
}
func (f *fakeRepo) Delete(context.Context, core.MembershipID) error          { return nil }
func (f *fakeRepo) CountOwners(context.Context, core.AccountID) (int, error) { return 0, nil }

// fakeTx is the minimal TxManager that runs `fn` inline. It does NOT
// assert what accountID/env got passed; if a future test wants to check
// that, capture them on the struct.
type fakeTx struct{}

func (fakeTx) WithTargetAccount(ctx context.Context, _ core.AccountID, _ core.Environment, fn func(context.Context) error) error {
	return fn(ctx)
}
func (fakeTx) WithTx(ctx context.Context, fn func(context.Context) error) error { return fn(ctx) }

func TestService_List_PassesThroughRepoResults(t *testing.T) {
	rows := []domain.MembershipDetail{{
		MembershipID: core.NewMembershipID(),
		Identity:     domain.MembershipIdentity{ID: core.NewIdentityID(), Email: "a@example.com"},
		Role:         domain.MembershipRole{ID: core.NewRoleID(), Slug: "owner", Name: "Owner"},
	}}
	repo := &fakeRepo{rows: rows, hasMore: true}
	svc := membership.NewService(fakeTx{}, repo)

	accountID := core.NewAccountID()
	cursor := core.Cursor{}
	got, hasMore, err := svc.List(context.Background(), accountID, cursor, 50)

	require.NoError(t, err)
	assert.True(t, hasMore)
	assert.Equal(t, rows, got)
	assert.Equal(t, cursor, repo.captureCursor, "service must pass cursor through unchanged")
	assert.Equal(t, 50, repo.captureLimit, "service must pass limit through unchanged")
}

func TestService_List_PropagatesRepoError(t *testing.T) {
	repo := &fakeRepo{err: assert.AnError}
	svc := membership.NewService(fakeTx{}, repo)

	_, _, err := svc.List(context.Background(), core.NewAccountID(), core.Cursor{}, 50)
	assert.ErrorIs(t, err, assert.AnError)
}
