package identity_test

import (
	"context"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

// fakeStore is an in-memory IdentityRepository for unit tests. It
// implements every method of domain.IdentityRepository so adding a
// new method to the interface will break the build here, not
// silently at runtime.
type fakeStore struct {
	byID    map[core.IdentityID]*domain.Identity
	byEmail map[string]core.IdentityID
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		byID:    map[core.IdentityID]*domain.Identity{},
		byEmail: map[string]core.IdentityID{},
	}
}

func (f *fakeStore) seedIdentity(id core.IdentityID, email string) *domain.Identity {
	now := time.Now().UTC()
	i := &domain.Identity{ID: id, Email: email, CreatedAt: now, UpdatedAt: now}
	f.byID[id] = i
	f.byEmail[email] = id
	return i
}

func (f *fakeStore) Create(_ context.Context, i *domain.Identity) error {
	f.byID[i.ID] = i
	f.byEmail[i.Email] = i.ID
	return nil
}

func (f *fakeStore) GetByID(_ context.Context, id core.IdentityID) (*domain.Identity, error) {
	return f.byID[id], nil
}

func (f *fakeStore) GetByEmail(_ context.Context, email string) (*domain.Identity, error) {
	id, ok := f.byEmail[email]
	if !ok {
		return nil, nil
	}
	return f.byID[id], nil
}

func (f *fakeStore) Update(_ context.Context, i *domain.Identity) error {
	f.byID[i.ID] = i
	return nil
}

func (f *fakeStore) UpdatePassword(_ context.Context, id core.IdentityID, hash string) error {
	if i, ok := f.byID[id]; ok {
		i.PasswordHash = hash
	}
	return nil
}

func (f *fakeStore) UpdateTOTP(_ context.Context, id core.IdentityID, secretEnc []byte, enabledAt *time.Time, recoveryEnc []byte) error {
	i, ok := f.byID[id]
	if !ok {
		return nil
	}
	i.TOTPSecretEnc = secretEnc
	i.TOTPEnabledAt = enabledAt
	i.RecoveryCodesEnc = recoveryEnc
	return nil
}
