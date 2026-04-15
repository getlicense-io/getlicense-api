package environment

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

// --- mock TxManager: runs fn synchronously, ignores tenant context ---

type mockTxManager struct{}

func (m *mockTxManager) WithTargetAccount(_ context.Context, _ core.AccountID, _ core.Environment, fn func(context.Context) error) error {
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
	for _, existing := range r.envs {
		if existing.AccountID == env.AccountID && existing.Slug == env.Slug {
			// Mirror pgx unique_violation so the service error mapping
			// is exercised.
			return &pgconn.PgError{Code: "23505"}
		}
	}
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

func (r *mockEnvRepo) ListByAccountPage(_ context.Context, _ core.Cursor, _ int) ([]domain.Environment, bool, error) {
	out := make([]domain.Environment, 0, len(r.envs))
	for _, e := range r.envs {
		out = append(out, *e)
	}
	return out, false, nil
}

func (r *mockEnvRepo) CountByAccount(_ context.Context) (int, error) {
	return len(r.envs), nil
}

// --- mock LicenseRepository: only HasBlocking is used here ---

type mockLicenseRepo struct {
	blocking bool
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
func (r *mockLicenseRepo) List(_ context.Context, _ domain.LicenseListFilters, _, _ int) ([]domain.License, int, error) {
	return nil, 0, nil
}
func (r *mockLicenseRepo) ListPage(_ context.Context, _ domain.LicenseListFilters, _ core.Cursor, _ int) ([]domain.License, bool, error) {
	return nil, false, nil
}
func (r *mockLicenseRepo) ListByProduct(_ context.Context, _ core.ProductID, _ domain.LicenseListFilters, _, _ int) ([]domain.License, int, error) {
	return nil, 0, nil
}
func (r *mockLicenseRepo) ListPageByProduct(_ context.Context, _ core.ProductID, _ domain.LicenseListFilters, _ core.Cursor, _ int) ([]domain.License, bool, error) {
	return nil, false, nil
}
func (r *mockLicenseRepo) UpdateStatus(_ context.Context, _ core.LicenseID, _ core.LicenseStatus, _ core.LicenseStatus) (time.Time, error) {
	return time.Time{}, nil
}
func (r *mockLicenseRepo) CountByProduct(_ context.Context, _ core.ProductID) (int, error) {
	return 0, nil
}

func (r *mockLicenseRepo) CountsByProductStatus(_ context.Context, _ core.ProductID) (domain.LicenseStatusCounts, error) {
	return domain.LicenseStatusCounts{}, nil
}

func (r *mockLicenseRepo) BulkRevokeByProduct(_ context.Context, _ core.ProductID) (int, error) {
	return 0, nil
}
func (r *mockLicenseRepo) HasBlocking(_ context.Context) (bool, error) {
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

// seedDefaults pre-populates the mock repo with the same two
// environments AuthService inserts at signup, so Delete/Create tests
// can start from a "fresh account" baseline.
func seedDefaults(t *testing.T, _ *Service, envs *mockEnvRepo, accountID core.AccountID) {
	t.Helper()
	envs.envs = append(envs.envs, DefaultEnvironments(accountID, time.Now().UTC())...)
}

func TestDefaultEnvironments_LiveAndTest(t *testing.T) {
	accountID := core.NewAccountID()
	envs := DefaultEnvironments(accountID, time.Now().UTC())

	require.Len(t, envs, 2)
	assert.Equal(t, core.EnvironmentLive, envs[0].Slug)
	assert.Equal(t, "Live", envs[0].Name)
	assert.Equal(t, core.EnvironmentTest, envs[1].Slug)
	assert.Equal(t, "Test", envs[1].Name)
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

func TestCreate_RejectsOverlongName(t *testing.T) {
	svc, _, _ := newTestService()
	longName := strings.Repeat("n", MaxEnvironmentNameLength+1)
	_, err := svc.Create(context.Background(), core.NewAccountID(), CreateRequest{
		Slug: "staging",
		Name: longName,
	})
	require.Error(t, err)
	appErr, ok := err.(*core.AppError)
	require.True(t, ok)
	assert.Equal(t, core.ErrValidationError, appErr.Code)
}

func TestCreate_RejectsOverlongDescription(t *testing.T) {
	svc, _, _ := newTestService()
	longDesc := strings.Repeat("d", MaxEnvironmentDescriptionLength+1)
	_, err := svc.Create(context.Background(), core.NewAccountID(), CreateRequest{
		Slug:        "staging",
		Name:        "Staging",
		Description: longDesc,
	})
	require.Error(t, err)
	appErr, ok := err.(*core.AppError)
	require.True(t, ok)
	assert.Equal(t, core.ErrValidationError, appErr.Code)
}

func TestCreate_EnforcesLimit(t *testing.T) {
	svc, envs, _ := newTestService()
	accountID := core.NewAccountID()
	seedDefaults(t, svc, envs, accountID)

	// Fill the cap: seeded live + test, plus 3 user-defined envs = 5.
	for _, slug := range []string{"staging", "qa", "preview"} {
		_, err := svc.Create(context.Background(), accountID, CreateRequest{
			Slug: slug,
			Name: slug,
		})
		require.NoError(t, err)
	}
	assert.Len(t, envs.envs, MaxEnvironmentsPerAccount)

	// One more: blocked.
	_, err := svc.Create(context.Background(), accountID, CreateRequest{
		Slug: "debug",
		Name: "Debug",
	})
	require.Error(t, err)
	appErr, ok := err.(*core.AppError)
	require.True(t, ok)
	assert.Equal(t, core.ErrEnvironmentLimitReached, appErr.Code)
}

func TestCreate_RejectsDuplicateSlug(t *testing.T) {
	svc, envs, _ := newTestService()
	accountID := core.NewAccountID()
	seedDefaults(t, svc, envs, accountID)

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
	seedDefaults(t, svc, envs, accountID)
	licenses.blocking = true

	err := svc.Delete(context.Background(), accountID, envs.envs[0].ID)
	require.Error(t, err)
	appErr, ok := err.(*core.AppError)
	require.True(t, ok)
	assert.Equal(t, core.ErrEnvironmentNotEmpty, appErr.Code)
}

func TestDelete_Success(t *testing.T) {
	svc, envs, _ := newTestService()
	accountID := core.NewAccountID()
	seedDefaults(t, svc, envs, accountID)
	targetID := envs.envs[1].ID // test

	err := svc.Delete(context.Background(), accountID, targetID)
	require.NoError(t, err)
	assert.Len(t, envs.envs, 1)
	assert.Equal(t, core.EnvironmentLive, envs.envs[0].Slug)
}
