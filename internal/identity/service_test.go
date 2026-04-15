package identity_test

import (
	"context"
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

func TestEnrollTOTP_StoresEncryptedSecretWithoutActivating(t *testing.T) {
	store := newFakeStore()
	mk := newMasterKey(t)
	svc := identity.NewService(store, mk)

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
}

func TestEnrollTOTP_FailsWhenAlreadyEnabled(t *testing.T) {
	store := newFakeStore()
	mk := newMasterKey(t)
	svc := identity.NewService(store, mk)

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
	store := newFakeStore()
	mk := newMasterKey(t)
	svc := identity.NewService(store, mk)

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
	secretBytes, err := mk.Decrypt(got.TOTPSecretEnc)
	require.NoError(t, err)
	code, err := crypto.TOTPCodeForTest(string(secretBytes))
	require.NoError(t, err)

	recovery, err := svc.ActivateTOTP(context.Background(), id, code)
	require.NoError(t, err)
	assert.Len(t, recovery, 10)

	got, _ = store.GetByID(context.Background(), id)
	assert.NotNil(t, got.TOTPEnabledAt)
	assert.NotNil(t, got.RecoveryCodesEnc)
}

func TestVerifyTOTP_AcceptsCurrentCode(t *testing.T) {
	store := newFakeStore()
	mk := newMasterKey(t)
	svc := identity.NewService(store, mk)

	id := core.NewIdentityID()
	_ = store.seedIdentity(id, "user@example.com")
	_, _, _ = svc.EnrollTOTP(context.Background(), id)

	// Activate.
	got, _ := store.GetByID(context.Background(), id)
	secretBytes, _ := mk.Decrypt(got.TOTPSecretEnc)
	code, _ := crypto.TOTPCodeForTest(string(secretBytes))
	_, err := svc.ActivateTOTP(context.Background(), id, code)
	require.NoError(t, err)

	// Verify with a fresh code for the current window.
	freshCode, _ := crypto.TOTPCodeForTest(string(secretBytes))
	err = svc.VerifyTOTP(context.Background(), id, freshCode)
	require.NoError(t, err)
}

func TestVerifyTOTP_RejectsWrongCode(t *testing.T) {
	store := newFakeStore()
	mk := newMasterKey(t)
	svc := identity.NewService(store, mk)

	id := core.NewIdentityID()
	_ = store.seedIdentity(id, "user@example.com")
	_, _, _ = svc.EnrollTOTP(context.Background(), id)

	got, _ := store.GetByID(context.Background(), id)
	secretBytes, _ := mk.Decrypt(got.TOTPSecretEnc)
	code, _ := crypto.TOTPCodeForTest(string(secretBytes))
	_, err := svc.ActivateTOTP(context.Background(), id, code)
	require.NoError(t, err)

	err = svc.VerifyTOTP(context.Background(), id, "000000")
	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrTOTPInvalid, appErr.Code)
}

func TestDisableTOTP_ClearsState(t *testing.T) {
	store := newFakeStore()
	mk := newMasterKey(t)
	svc := identity.NewService(store, mk)

	id := core.NewIdentityID()
	_ = store.seedIdentity(id, "user@example.com")
	_, _, _ = svc.EnrollTOTP(context.Background(), id)
	got, _ := store.GetByID(context.Background(), id)
	secretBytes, _ := mk.Decrypt(got.TOTPSecretEnc)
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
}

func nowPtr() *time.Time {
	t := time.Now().UTC()
	return &t
}
