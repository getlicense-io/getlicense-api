package identity_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/crypto"
	"github.com/getlicense-io/getlicense-api/internal/identity"
)

func newMasterKey(t *testing.T) *crypto.MasterKey {
	t.Helper()
	mk, err := crypto.NewMasterKey("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	require.NoError(t, err)
	return mk
}

// newSvc builds a service with both fakes and returns each so tests
// can assert against persistent state in either store.
func newSvc(t *testing.T) (*identity.Service, *fakeStore, *fakeRecoveryCodes, *crypto.MasterKey) {
	t.Helper()
	store := newFakeStore()
	rc := newFakeRecoveryCodes()
	mk := newMasterKey(t)
	svc := identity.NewService(store, rc, mk)
	return svc, store, rc, mk
}

func TestEnrollTOTP_StoresEncryptedSecretWithoutActivating(t *testing.T) {
	svc, store, rc, _ := newSvc(t)

	id := core.NewIdentityID()
	_ = store.seedIdentity(id, "user@example.com")

	secret, url, err := svc.EnrollTOTP(context.Background(), id)
	require.NoError(t, err)
	assert.NotEmpty(t, secret)
	assert.Contains(t, url, "otpauth://totp/")

	got, _ := store.GetByID(context.Background(), id)
	assert.NotNil(t, got.TOTPSecretEnc, "secret must be stored")
	assert.Nil(t, got.TOTPEnabledAt, "enrollment must NOT activate TOTP")
	assert.Nil(t, got.RecoveryCodesEnc, "recovery codes must not exist yet")
	n, err := rc.Count(context.Background(), id)
	require.NoError(t, err)
	assert.Equal(t, 0, n, "no recovery rows until activation")
}

func TestEnrollTOTP_FailsWhenAlreadyEnabled(t *testing.T) {
	svc, store, _, _ := newSvc(t)

	id := core.NewIdentityID()
	_ = store.seedIdentity(id, "user@example.com")
	_, _, err := svc.EnrollTOTP(context.Background(), id)
	require.NoError(t, err)

	// Simulate activation by setting TOTPEnabledAt directly.
	got, _ := store.GetByID(context.Background(), id)
	now := nowPtr()
	got.TOTPEnabledAt = now

	_, _, err = svc.EnrollTOTP(context.Background(), id)
	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrTOTPAlreadyEnabled, appErr.Code)
}

func TestActivateTOTP_RequiresValidCode(t *testing.T) {
	svc, store, rc, mk := newSvc(t)

	id := core.NewIdentityID()
	_ = store.seedIdentity(id, "user@example.com")
	_, _, err := svc.EnrollTOTP(context.Background(), id)
	require.NoError(t, err)

	// Wrong code is rejected.
	_, err = svc.ActivateTOTP(context.Background(), id, "000000")
	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrTOTPInvalid, appErr.Code)

	// Valid code succeeds and returns 10 recovery codes.
	got, _ := store.GetByID(context.Background(), id)
	secretBytes, err := mk.Decrypt(got.TOTPSecretEnc, crypto.TOTPSecretAAD(id))
	require.NoError(t, err)
	code, err := crypto.TOTPCodeForTest(string(secretBytes))
	require.NoError(t, err)

	recovery, err := svc.ActivateTOTP(context.Background(), id, code)
	require.NoError(t, err)
	assert.Len(t, recovery, 10)

	got, _ = store.GetByID(context.Background(), id)
	assert.NotNil(t, got.TOTPEnabledAt)
	// PR-4.5: new enrollments write per-row to recovery_codes, NOT to
	// the legacy encrypted blob. The blob stays nil; the per-row count
	// is exactly the number of generated codes.
	assert.Nil(t, got.RecoveryCodesEnc, "new enrollments must not write to legacy blob")
	n, err := rc.Count(context.Background(), id)
	require.NoError(t, err)
	assert.Equal(t, 10, n)
}

func TestVerifyTOTP_AcceptsCurrentCode(t *testing.T) {
	svc, store, _, mk := newSvc(t)

	id := core.NewIdentityID()
	_ = store.seedIdentity(id, "user@example.com")
	_, _, _ = svc.EnrollTOTP(context.Background(), id)

	// Activate.
	got, _ := store.GetByID(context.Background(), id)
	secretBytes, _ := mk.Decrypt(got.TOTPSecretEnc, crypto.TOTPSecretAAD(id))
	code, _ := crypto.TOTPCodeForTest(string(secretBytes))
	_, err := svc.ActivateTOTP(context.Background(), id, code)
	require.NoError(t, err)

	// Verify with a fresh code for the current window.
	freshCode, _ := crypto.TOTPCodeForTest(string(secretBytes))
	got, err = svc.VerifyTOTP(context.Background(), id, freshCode)
	require.NoError(t, err)
	assert.NotNil(t, got)
	assert.Equal(t, id, got.ID)
}

func TestVerifyTOTP_RejectsWrongCode(t *testing.T) {
	svc, store, _, mk := newSvc(t)

	id := core.NewIdentityID()
	_ = store.seedIdentity(id, "user@example.com")
	_, _, _ = svc.EnrollTOTP(context.Background(), id)

	got, _ := store.GetByID(context.Background(), id)
	secretBytes, _ := mk.Decrypt(got.TOTPSecretEnc, crypto.TOTPSecretAAD(id))
	code, _ := crypto.TOTPCodeForTest(string(secretBytes))
	_, err := svc.ActivateTOTP(context.Background(), id, code)
	require.NoError(t, err)

	got, err = svc.VerifyTOTP(context.Background(), id, "000000")
	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrTOTPInvalid, appErr.Code)
	assert.Nil(t, got)
}

// F-012: recovery codes must actually work as a fallback during
// login step 2, consumed single-use so a replayed code is refused.
func TestVerifyTOTPOrRecovery_AcceptsRecoveryCode(t *testing.T) {
	svc, store, rc, mk := newSvc(t)

	id := core.NewIdentityID()
	_ = store.seedIdentity(id, "user@example.com")
	_, _, _ = svc.EnrollTOTP(context.Background(), id)
	got, _ := store.GetByID(context.Background(), id)
	secretBytes, _ := mk.Decrypt(got.TOTPSecretEnc, crypto.TOTPSecretAAD(id))
	code, _ := crypto.TOTPCodeForTest(string(secretBytes))
	recovery, err := svc.ActivateTOTP(context.Background(), id, code)
	require.NoError(t, err)
	require.Len(t, recovery, 10)

	// Use the first recovery code as the step2 code.
	got, err = svc.VerifyTOTPOrRecovery(context.Background(), id, recovery[0])
	require.NoError(t, err)
	assert.Equal(t, id, got.ID)

	// PR-4.5: consume must DELETE the row. Count drops from 10 → 9.
	n, err := rc.Count(context.Background(), id)
	require.NoError(t, err)
	assert.Equal(t, 9, n)

	// Reusing the same recovery code must now fail (single-use).
	_, err = svc.VerifyTOTPOrRecovery(context.Background(), id, recovery[0])
	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrTOTPInvalid, appErr.Code)

	// A different unused recovery code still works.
	_, err = svc.VerifyTOTPOrRecovery(context.Background(), id, recovery[1])
	require.NoError(t, err)

	// A real TOTP code still works alongside the recovery path.
	fresh, _ := crypto.TOTPCodeForTest(string(secretBytes))
	_, err = svc.VerifyTOTPOrRecovery(context.Background(), id, fresh)
	require.NoError(t, err)
}

func TestVerifyTOTPOrRecovery_RejectsGarbage(t *testing.T) {
	svc, store, _, mk := newSvc(t)

	id := core.NewIdentityID()
	_ = store.seedIdentity(id, "user@example.com")
	_, _, _ = svc.EnrollTOTP(context.Background(), id)
	got, _ := store.GetByID(context.Background(), id)
	secretBytes, _ := mk.Decrypt(got.TOTPSecretEnc, crypto.TOTPSecretAAD(id))
	code, _ := crypto.TOTPCodeForTest(string(secretBytes))
	_, err := svc.ActivateTOTP(context.Background(), id, code)
	require.NoError(t, err)

	// Neither a TOTP match nor a recovery match — must refuse.
	_, err = svc.VerifyTOTPOrRecovery(context.Background(), id, "deadbeefdeadbeef")
	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrTOTPInvalid, appErr.Code)
}

// PR-4.5: fan out N goroutines that all try to consume the SAME
// recovery code. The fake's mutex models the row-level atomicity
// of DELETE-RETURNING — exactly one call must succeed; the rest
// must observe the single-use rejection. The integration test in
// db/recovery_code_repo_test.go is the authoritative DB-level
// race coverage; this one is the service-layer regression guard.
func TestVerifyTOTPOrRecovery_ConcurrentSameCode_OnlyOneSucceeds(t *testing.T) {
	svc, store, _, mk := newSvc(t)

	id := core.NewIdentityID()
	_ = store.seedIdentity(id, "user@example.com")
	_, _, _ = svc.EnrollTOTP(context.Background(), id)
	got, _ := store.GetByID(context.Background(), id)
	secretBytes, _ := mk.Decrypt(got.TOTPSecretEnc, crypto.TOTPSecretAAD(id))
	code, _ := crypto.TOTPCodeForTest(string(secretBytes))
	recovery, err := svc.ActivateTOTP(context.Background(), id, code)
	require.NoError(t, err)

	const goroutines = 8
	var (
		wg           sync.WaitGroup
		successCount atomic.Int32
		failCount    atomic.Int32
	)
	wg.Add(goroutines)
	start := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			<-start
			if _, err := svc.VerifyTOTPOrRecovery(context.Background(), id, recovery[0]); err == nil {
				successCount.Add(1)
			} else {
				failCount.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()

	assert.Equal(t, int32(1), successCount.Load(), "exactly one goroutine must consume the code")
	assert.Equal(t, int32(goroutines-1), failCount.Load(), "all other goroutines must be rejected")
}

func TestDisableTOTP_AcceptsRecoveryCode(t *testing.T) {
	svc, store, rc, mk := newSvc(t)

	id := core.NewIdentityID()
	_ = store.seedIdentity(id, "user@example.com")
	_, _, _ = svc.EnrollTOTP(context.Background(), id)
	got, _ := store.GetByID(context.Background(), id)
	secretBytes, _ := mk.Decrypt(got.TOTPSecretEnc, crypto.TOTPSecretAAD(id))
	code, _ := crypto.TOTPCodeForTest(string(secretBytes))
	recovery, err := svc.ActivateTOTP(context.Background(), id, code)
	require.NoError(t, err)

	// Disable using a recovery code instead of a TOTP code — the
	// "I lost my phone" recovery path.
	err = svc.DisableTOTP(context.Background(), id, recovery[0])
	require.NoError(t, err)

	got, _ = store.GetByID(context.Background(), id)
	assert.Nil(t, got.TOTPSecretEnc)
	assert.Nil(t, got.TOTPEnabledAt)
	assert.Nil(t, got.RecoveryCodesEnc)
	// PR-4.5: DisableTOTP must also wipe the new table.
	n, err := rc.Count(context.Background(), id)
	require.NoError(t, err)
	assert.Equal(t, 0, n, "all recovery_codes rows must be cleared")
}

func TestDisableTOTP_ClearsState(t *testing.T) {
	svc, store, rc, mk := newSvc(t)

	id := core.NewIdentityID()
	_ = store.seedIdentity(id, "user@example.com")
	_, _, _ = svc.EnrollTOTP(context.Background(), id)
	got, _ := store.GetByID(context.Background(), id)
	secretBytes, _ := mk.Decrypt(got.TOTPSecretEnc, crypto.TOTPSecretAAD(id))
	code, _ := crypto.TOTPCodeForTest(string(secretBytes))
	_, err := svc.ActivateTOTP(context.Background(), id, code)
	require.NoError(t, err)

	// Disable with a valid code.
	code2, _ := crypto.TOTPCodeForTest(string(secretBytes))
	err = svc.DisableTOTP(context.Background(), id, code2)
	require.NoError(t, err)

	got, _ = store.GetByID(context.Background(), id)
	assert.Nil(t, got.TOTPSecretEnc)
	assert.Nil(t, got.TOTPEnabledAt)
	assert.Nil(t, got.RecoveryCodesEnc)
	n, err := rc.Count(context.Background(), id)
	require.NoError(t, err)
	assert.Equal(t, 0, n)
}

func nowPtr() *time.Time {
	t := time.Now().UTC()
	return &t
}
