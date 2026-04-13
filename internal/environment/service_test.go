package environment

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

// --- mock TxManager: runs fn synchronously, ignores tenant context ---

type mockTxManager struct{}

func (m *mockTxManager) WithTenant(_ context.Context, _ core.AccountID, _ core.Environment, fn func(context.Context) error) error {
	return fn(context.Background())
}

func (m *mockTxManager) WithTx(_ context.Context, fn func(context.Context) error) error {
	return fn(context.Background())
}

// --- mock EnvironmentRepository ---

type mockEnvRepo struct {
	envs []*domain.Environment
}

func (r *mockEnvRepo) Create(_ context.Context, env *domain.Environment) error {
	r.envs = append(r.envs, env)
	return nil
}

func (r *mockEnvRepo) ListByAccount(_ context.Context) ([]domain.Environment, error) {
	out := make([]domain.Environment, 0, len(r.envs))
	for _, e := range r.envs {
		out = append(out, *e)
	}
	return out, nil
}

func (r *mockEnvRepo) GetBySlug(_ context.Context, slug core.Environment) (*domain.Environment, error) {
	for _, e := range r.envs {
		if e.Slug == slug {
			return e, nil
		}
	}
	return nil, nil
}

func (r *mockEnvRepo) Delete(_ context.Context, id core.EnvironmentID) error {
	filtered := r.envs[:0]
	for _, e := range r.envs {
		if e.ID != id {
			filtered = append(filtered, e)
		}
	}
	r.envs = filtered
	return nil
}

func (r *mockEnvRepo) CountByAccount(_ context.Context) (int, error) {
	return len(r.envs), nil
}

// --- mock LicenseRepository: only CountBlocking is used here ---

type mockLicenseRepo struct {
	blocking int
}

func (r *mockLicenseRepo) Create(_ context.Context, _ *domain.License) error { return nil }
func (r *mockLicenseRepo) BulkCreate(_ context.Context, _ []*domain.License) error {
	return nil
}
func (r *mockLicenseRepo) GetByID(_ context.Context, _ core.LicenseID) (*domain.License, error) {
	return nil, nil
}
func (r *mockLicenseRepo) GetByIDForUpdate(_ context.Context, _ core.LicenseID) (*domain.License, error) {
	return nil, nil
}
func (r *mockLicenseRepo) GetByKeyHash(_ context.Context, _ string) (*domain.License, error) {
	return nil, nil
}
func (r *mockLicenseRepo) List(_ context.Context, _, _ int) ([]domain.License, int, error) {
	return nil, 0, nil
}
func (r *mockLicenseRepo) UpdateStatus(_ context.Context, _ core.LicenseID, _ core.LicenseStatus, _ core.LicenseStatus) (time.Time, error) {
	return time.Time{}, nil
}
func (r *mockLicenseRepo) CountByProduct(_ context.Context, _ core.ProductID) (int, error) {
	return 0, nil
}
func (r *mockLicenseRepo) CountBlocking(_ context.Context) (int, error) {
	return r.blocking, nil
}
func (r *mockLicenseRepo) ExpireActive(_ context.Context) ([]domain.License, error) {
	return nil, nil
}

// --- tests ---

func newTestService() (*Service, *mockEnvRepo, *mockLicenseRepo) {
	envs := &mockEnvRepo{}
	licenses := &mockLicenseRepo{}
	return NewService(&mockTxManager{}, envs, licenses), envs, licenses
}

func TestSeedDefaults_CreatesLiveAndTest(t *testing.T) {
	svc, envs, _ := newTestService()
	accountID := core.NewAccountID()

	err := svc.SeedDefaults(context.Background(), accountID)
	require.NoError(t, err)

	require.Len(t, envs.envs, 2)
	assert.Equal(t, core.EnvironmentLive, envs.envs[0].Slug)
	assert.Equal(t, "Live", envs.envs[0].Name)
	assert.Equal(t, core.EnvironmentTest, envs.envs[1].Slug)
	assert.Equal(t, "Test", envs.envs[1].Name)
}

func TestCreate_RejectsInvalidSlug(t *testing.T) {
	svc, _, _ := newTestService()
	_, err := svc.Create(context.Background(), core.NewAccountID(), CreateRequest{
		Slug: "Bad Slug!",
		Name: "Bad",
	})
	require.Error(t, err)
	appErr, ok := err.(*core.AppError)
	require.True(t, ok)
	assert.Equal(t, core.ErrValidationError, appErr.Code)
}

func TestCreate_RejectsEmptyName(t *testing.T) {
	svc, _, _ := newTestService()
	_, err := svc.Create(context.Background(), core.NewAccountID(), CreateRequest{
		Slug: "staging",
		Name: "   ",
	})
	require.Error(t, err)
	appErr, ok := err.(*core.AppError)
	require.True(t, ok)
	assert.Equal(t, core.ErrValidationError, appErr.Code)
}

func TestCreate_EnforcesLimit(t *testing.T) {
	svc, envs, _ := newTestService()
	accountID := core.NewAccountID()
	require.NoError(t, svc.SeedDefaults(context.Background(), accountID))

	// Third environment: allowed.
	_, err := svc.Create(context.Background(), accountID, CreateRequest{
		Slug: "staging",
		Name: "Staging",
	})
	require.NoError(t, err)
	assert.Len(t, envs.envs, 3)

	// Fourth environment: blocked.
	_, err = svc.Create(context.Background(), accountID, CreateRequest{
		Slug: "preview",
		Name: "Preview",
	})
	require.Error(t, err)
	appErr, ok := err.(*core.AppError)
	require.True(t, ok)
	assert.Equal(t, core.ErrEnvironmentLimitReached, appErr.Code)
}

func TestCreate_RejectsDuplicateSlug(t *testing.T) {
	svc, _, _ := newTestService()
	accountID := core.NewAccountID()
	require.NoError(t, svc.SeedDefaults(context.Background(), accountID))

	_, err := svc.Create(context.Background(), accountID, CreateRequest{
		Slug: "live",
		Name: "Live 2",
	})
	require.Error(t, err)
	appErr, ok := err.(*core.AppError)
	require.True(t, ok)
	assert.Equal(t, core.ErrEnvironmentAlreadyExists, appErr.Code)
}

func TestDelete_RefusesLastEnvironment(t *testing.T) {
	svc, envs, _ := newTestService()
	accountID := core.NewAccountID()
	// Seed only one environment so the "last env" guard trips.
	envs.envs = append(envs.envs, &domain.Environment{
		ID:        core.NewEnvironmentID(),
		AccountID: accountID,
		Slug:      core.EnvironmentLive,
		Name:      "Live",
	})

	err := svc.Delete(context.Background(), accountID, envs.envs[0].ID)
	require.Error(t, err)
	appErr, ok := err.(*core.AppError)
	require.True(t, ok)
	assert.Equal(t, core.ErrLastEnvironment, appErr.Code)
}

func TestDelete_RefusesWhenBlockingLicenses(t *testing.T) {
	svc, envs, licenses := newTestService()
	accountID := core.NewAccountID()
	require.NoError(t, svc.SeedDefaults(context.Background(), accountID))
	licenses.blocking = 1

	err := svc.Delete(context.Background(), accountID, envs.envs[0].ID)
	require.Error(t, err)
	appErr, ok := err.(*core.AppError)
	require.True(t, ok)
	assert.Equal(t, core.ErrEnvironmentNotEmpty, appErr.Code)
}

func TestDelete_Success(t *testing.T) {
	svc, envs, _ := newTestService()
	accountID := core.NewAccountID()
	require.NoError(t, svc.SeedDefaults(context.Background(), accountID))
	targetID := envs.envs[1].ID // test

	err := svc.Delete(context.Background(), accountID, targetID)
	require.NoError(t, err)
	assert.Len(t, envs.envs, 1)
	assert.Equal(t, core.EnvironmentLive, envs.envs[0].Slug)
}
