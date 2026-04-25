package identity_test

import (
	"context"
	"sync"
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

// fakeRecoveryCodes is an in-memory RecoveryCodeRepository for unit
// tests. The map[identity][hash]→struct{} shape mirrors the (identity_id,
// code_hash) UNIQUE index in the real schema. The mutex models the
// row-level atomicity the production DELETE-RETURNING provides — each
// Consume is a single critical section so a unit test that fans out
// goroutines on the same code can still observe single-use semantics
// (the integration test in db/recovery_code_repo_test.go is the
// authoritative race coverage).
type fakeRecoveryCodes struct {
	mu sync.Mutex
	// rows maps identity → set of hashes. The inner set is a map
	// instead of a slice so Consume is O(1) and to match the unique
	// (identity_id, code_hash) constraint at the application layer.
	rows map[core.IdentityID]map[string]struct{}
}

func newFakeRecoveryCodes() *fakeRecoveryCodes {
	return &fakeRecoveryCodes{rows: map[core.IdentityID]map[string]struct{}{}}
}

func (f *fakeRecoveryCodes) Insert(_ context.Context, identityID core.IdentityID, codeHashes []string) error {
	if len(codeHashes) == 0 {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	set, ok := f.rows[identityID]
	if !ok {
		set = map[string]struct{}{}
		f.rows[identityID] = set
	}
	for _, h := range codeHashes {
		set[h] = struct{}{} // ON CONFLICT DO NOTHING — duplicate insert is a no-op.
	}
	return nil
}

func (f *fakeRecoveryCodes) Consume(_ context.Context, identityID core.IdentityID, codeHash string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	set, ok := f.rows[identityID]
	if !ok {
		return false, nil
	}
	if _, ok := set[codeHash]; !ok {
		return false, nil
	}
	delete(set, codeHash)
	return true, nil
}

func (f *fakeRecoveryCodes) DeleteAll(_ context.Context, identityID core.IdentityID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.rows, identityID)
	return nil
}

func (f *fakeRecoveryCodes) Count(_ context.Context, identityID core.IdentityID) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.rows[identityID]), nil
}
