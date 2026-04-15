package invitation_test

import (
	"context"
	"errors"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

// --- fake TxManager ---

type fakeTxManager struct{}

func (fakeTxManager) WithTargetAccount(ctx context.Context, _ core.AccountID, _ core.Environment, fn func(context.Context) error) error {
	return fn(ctx)
}
func (fakeTxManager) WithTx(ctx context.Context, fn func(context.Context) error) error {
	return fn(ctx)
}

// --- fake InvitationRepository ---

type fakeInvitationRepo struct {
	byID   map[core.InvitationID]*domain.Invitation
	byHash map[string]*domain.Invitation
}

func newFakeInvitationRepo() *fakeInvitationRepo {
	return &fakeInvitationRepo{
		byID:   map[core.InvitationID]*domain.Invitation{},
		byHash: map[string]*domain.Invitation{},
	}
}

func (f *fakeInvitationRepo) Create(_ context.Context, inv *domain.Invitation) error {
	f.byID[inv.ID] = inv
	f.byHash[inv.TokenHash] = inv
	return nil
}

func (f *fakeInvitationRepo) GetByID(_ context.Context, id core.InvitationID) (*domain.Invitation, error) {
	return f.byID[id], nil
}

func (f *fakeInvitationRepo) GetByTokenHash(_ context.Context, hash string) (*domain.Invitation, error) {
	return f.byHash[hash], nil
}

func (f *fakeInvitationRepo) ListByAccount(_ context.Context, _ core.Cursor, _ int) ([]domain.Invitation, bool, error) {
	out := make([]domain.Invitation, 0, len(f.byID))
	for _, inv := range f.byID {
		out = append(out, *inv)
	}
	return out, false, nil
}

func (f *fakeInvitationRepo) MarkAccepted(_ context.Context, id core.InvitationID, acceptedAt time.Time) error {
	if inv, ok := f.byID[id]; ok {
		inv.AcceptedAt = &acceptedAt
	}
	return nil
}

func (f *fakeInvitationRepo) Delete(_ context.Context, id core.InvitationID) error {
	if inv, ok := f.byID[id]; ok {
		delete(f.byHash, inv.TokenHash)
	}
	delete(f.byID, id)
	return nil
}

// --- fake IdentityRepository ---

type fakeIdentityRepo struct {
	byID    map[core.IdentityID]*domain.Identity
	byEmail map[string]*domain.Identity
}

func newFakeIdentityRepo() *fakeIdentityRepo {
	return &fakeIdentityRepo{
		byID:    make(map[core.IdentityID]*domain.Identity),
		byEmail: make(map[string]*domain.Identity),
	}
}

func (r *fakeIdentityRepo) Create(_ context.Context, i *domain.Identity) error {
	r.byID[i.ID] = i
	r.byEmail[i.Email] = i
	return nil
}
func (r *fakeIdentityRepo) GetByID(_ context.Context, id core.IdentityID) (*domain.Identity, error) {
	return r.byID[id], nil
}
func (r *fakeIdentityRepo) GetByEmail(_ context.Context, email string) (*domain.Identity, error) {
	return r.byEmail[email], nil
}
func (r *fakeIdentityRepo) Update(_ context.Context, _ *domain.Identity) error {
	return errors.New("not implemented")
}
func (r *fakeIdentityRepo) UpdatePassword(_ context.Context, _ core.IdentityID, _ string) error {
	return errors.New("not implemented")
}
func (r *fakeIdentityRepo) UpdateTOTP(_ context.Context, _ core.IdentityID, _ []byte, _ *time.Time, _ []byte) error {
	return errors.New("not implemented")
}

// --- fake AccountMembershipRepository ---

type fakeMembershipRepo struct {
	byID                 map[core.MembershipID]*domain.AccountMembership
	byIdentity           map[core.IdentityID][]domain.AccountMembership
	byIdentityAndAccount map[[2]string]*domain.AccountMembership
}

func newFakeMembershipRepo() *fakeMembershipRepo {
	return &fakeMembershipRepo{
		byID:                 make(map[core.MembershipID]*domain.AccountMembership),
		byIdentity:           make(map[core.IdentityID][]domain.AccountMembership),
		byIdentityAndAccount: make(map[[2]string]*domain.AccountMembership),
	}
}

func (r *fakeMembershipRepo) Create(_ context.Context, m *domain.AccountMembership) error {
	r.byID[m.ID] = m
	r.byIdentity[m.IdentityID] = append(r.byIdentity[m.IdentityID], *m)
	key := [2]string{m.IdentityID.String(), m.AccountID.String()}
	r.byIdentityAndAccount[key] = m
	return nil
}
func (r *fakeMembershipRepo) GetByID(_ context.Context, id core.MembershipID) (*domain.AccountMembership, error) {
	return r.byID[id], nil
}
func (r *fakeMembershipRepo) GetByIDWithRole(_ context.Context, _ core.MembershipID) (*domain.AccountMembership, *domain.Role, error) {
	return nil, nil, errors.New("not implemented")
}
func (r *fakeMembershipRepo) GetByIdentityAndAccount(_ context.Context, identityID core.IdentityID, accountID core.AccountID) (*domain.AccountMembership, error) {
	key := [2]string{identityID.String(), accountID.String()}
	return r.byIdentityAndAccount[key], nil
}
func (r *fakeMembershipRepo) ListByIdentity(_ context.Context, identityID core.IdentityID) ([]domain.AccountMembership, error) {
	return r.byIdentity[identityID], nil
}
func (r *fakeMembershipRepo) ListByAccount(_ context.Context, _ core.Cursor, _ int) ([]domain.AccountMembership, bool, error) {
	return nil, false, errors.New("not implemented")
}
func (r *fakeMembershipRepo) UpdateRole(_ context.Context, _ core.MembershipID, _ core.RoleID) error {
	return errors.New("not implemented")
}
func (r *fakeMembershipRepo) UpdateStatus(_ context.Context, _ core.MembershipID, _ domain.MembershipStatus) error {
	return errors.New("not implemented")
}
func (r *fakeMembershipRepo) Delete(_ context.Context, _ core.MembershipID) error {
	return errors.New("not implemented")
}
func (r *fakeMembershipRepo) CountOwners(_ context.Context, _ core.AccountID) (int, error) {
	return 0, errors.New("not implemented")
}

// --- fake RoleRepository ---

type fakeRoleRepo struct {
	byID   map[core.RoleID]*domain.Role
	bySlug map[string]*domain.Role
}

func newFakeRoleRepo() *fakeRoleRepo {
	return &fakeRoleRepo{
		byID:   make(map[core.RoleID]*domain.Role),
		bySlug: make(map[string]*domain.Role),
	}
}

func (r *fakeRoleRepo) seed(role *domain.Role) {
	r.byID[role.ID] = role
	r.bySlug[role.Slug] = role
}

func (r *fakeRoleRepo) GetByID(_ context.Context, id core.RoleID) (*domain.Role, error) {
	return r.byID[id], nil
}
func (r *fakeRoleRepo) GetBySlug(_ context.Context, _ *core.AccountID, slug string) (*domain.Role, error) {
	return r.bySlug[slug], nil
}
func (r *fakeRoleRepo) ListPresets(_ context.Context) ([]domain.Role, error) {
	return nil, errors.New("not implemented")
}
func (r *fakeRoleRepo) ListByAccount(_ context.Context) ([]domain.Role, error) {
	return nil, errors.New("not implemented")
}

// --- fake AccountRepository ---

type fakeAccountRepo struct {
	byID   map[core.AccountID]*domain.Account
	bySlug map[string]*domain.Account
}

func newFakeAccountRepo() *fakeAccountRepo {
	return &fakeAccountRepo{
		byID:   make(map[core.AccountID]*domain.Account),
		bySlug: make(map[string]*domain.Account),
	}
}

func (r *fakeAccountRepo) seed(acct *domain.Account) {
	r.byID[acct.ID] = acct
	r.bySlug[acct.Slug] = acct
}

func (r *fakeAccountRepo) Create(_ context.Context, a *domain.Account) error {
	r.byID[a.ID] = a
	r.bySlug[a.Slug] = a
	return nil
}
func (r *fakeAccountRepo) GetByID(_ context.Context, id core.AccountID) (*domain.Account, error) {
	return r.byID[id], nil
}
func (r *fakeAccountRepo) GetBySlug(_ context.Context, slug string) (*domain.Account, error) {
	return r.bySlug[slug], nil
}

// --- fake Mailer ---

type fakeMailer struct {
	callCount int
	lastTo    string
	lastURL   string
}

func (m *fakeMailer) SendInvitation(_ context.Context, to string, _ domain.InvitationKind, acceptURL string, _ map[string]string) error {
	m.callCount++
	m.lastTo = to
	m.lastURL = acceptURL
	return nil
}
