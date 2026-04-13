// Package environment contains the business logic for per-account
// data partitions ("environments"). An environment is a named slug
// (e.g. "live", "test", "staging") plus presentation metadata that
// scopes licenses, machines, API keys, webhook endpoints, and
// webhook events via PostgreSQL row-level security.
//
// Every account is auto-seeded with "live" and "test" at signup and
// may create up to MaxEnvironmentsPerAccount total. Environments with
// outstanding active or suspended licenses cannot be deleted, and an
// account must always retain at least one environment.
package environment

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/jackc/pgx/v5/pgconn"
)

// MaxEnvironmentsPerAccount caps how many environments a single
// account may define. Chosen to match common real-world usage (live,
// test, staging) while keeping the UI — a flat dropdown — simple.
const MaxEnvironmentsPerAccount = 3

// Service owns environment lifecycle operations. It is used by HTTP
// handlers for list/create/delete, and by the auth service to seed
// the two default environments at signup.
type Service struct {
	txManager    domain.TxManager
	environments domain.EnvironmentRepository
	licenses     domain.LicenseRepository
}

// NewService constructs a new environment Service.
func NewService(
	txManager domain.TxManager,
	environments domain.EnvironmentRepository,
	licenses domain.LicenseRepository,
) *Service {
	return &Service{
		txManager:    txManager,
		environments: environments,
		licenses:     licenses,
	}
}

// CreateRequest is the payload accepted by POST /environments.
type CreateRequest struct {
	Slug        string `json:"slug" validate:"required"`
	Name        string `json:"name" validate:"required"`
	Description string `json:"description"`
	Icon        string `json:"icon"`
	Color       string `json:"color"`
}

// DefaultEnvironments returns the two environment rows auto-created
// at signup. Extracted so the auth service and the migration stay in
// sync without duplicating magic strings.
func DefaultEnvironments(accountID core.AccountID, now time.Time) []*domain.Environment {
	return []*domain.Environment{
		{
			ID:          core.NewEnvironmentID(),
			AccountID:   accountID,
			Slug:        core.EnvironmentLive,
			Name:        "Live",
			Description: "Production data",
			Icon:        "radio",
			Color:       "emerald",
			Position:    0,
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		{
			ID:          core.NewEnvironmentID(),
			AccountID:   accountID,
			Slug:        core.EnvironmentTest,
			Name:        "Test",
			Description: "Sandbox · safe to break",
			Icon:        "flask-conical",
			Color:       "amber",
			Position:    1,
			CreatedAt:   now,
			UpdatedAt:   now,
		},
	}
}

// SeedDefaults inserts the default "live" and "test" environments
// for a new account. Safe to call inside an existing transaction —
// the caller provides the ctx already bound to tenant context.
func (s *Service) SeedDefaults(ctx context.Context, accountID core.AccountID) error {
	for _, env := range DefaultEnvironments(accountID, time.Now().UTC()) {
		if err := s.environments.Create(ctx, env); err != nil {
			return err
		}
	}
	return nil
}

// List returns all environments for the account, ordered by position.
// The environments table is account-scoped only (not env-scoped), so
// the slug passed to WithTenant is just filler for the RLS GUC.
func (s *Service) List(ctx context.Context, accountID core.AccountID) ([]domain.Environment, error) {
	var result []domain.Environment
	err := s.txManager.WithTenant(ctx, accountID, core.EnvironmentLive, func(ctx context.Context) error {
		envs, err := s.environments.ListByAccount(ctx)
		if err != nil {
			return err
		}
		result = envs
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// Create validates the request, enforces the per-account cap and the
// unique-slug constraint, then inserts the row.
func (s *Service) Create(ctx context.Context, accountID core.AccountID, req CreateRequest) (*domain.Environment, error) {
	slug, err := core.ParseEnvironment(strings.TrimSpace(req.Slug))
	if err != nil {
		return nil, core.NewAppError(core.ErrValidationError, "Environment slug must be 1-32 characters: lowercase letters, digits, or hyphens, starting with a letter")
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return nil, core.NewAppError(core.ErrValidationError, "Environment name is required")
	}
	icon := strings.TrimSpace(req.Icon)
	if icon == "" {
		icon = "radio"
	}
	color := strings.TrimSpace(req.Color)
	if color == "" {
		color = "emerald"
	}

	var result *domain.Environment
	err = s.txManager.WithTenant(ctx, accountID, core.EnvironmentLive, func(ctx context.Context) error {
		// Check for duplicate slug before the count check — a
		// collision is the more actionable error message when both
		// conditions would fail simultaneously.
		existing, err := s.environments.GetBySlug(ctx, slug)
		if err != nil {
			return err
		}
		if existing != nil {
			return core.NewAppError(
				core.ErrEnvironmentAlreadyExists,
				"An environment with this slug already exists",
			)
		}

		count, err := s.environments.CountByAccount(ctx)
		if err != nil {
			return err
		}
		if count >= MaxEnvironmentsPerAccount {
			return core.NewAppError(
				core.ErrEnvironmentLimitReached,
				"Account already has the maximum number of environments",
			)
		}

		now := time.Now().UTC()
		env := &domain.Environment{
			ID:          core.NewEnvironmentID(),
			AccountID:   accountID,
			Slug:        slug,
			Name:        name,
			Description: strings.TrimSpace(req.Description),
			Icon:        icon,
			Color:       color,
			Position:    count, // append to the end
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		if err := s.environments.Create(ctx, env); err != nil {
			// 23505 = unique_violation: (account_id, slug) collision.
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				return core.NewAppError(
					core.ErrEnvironmentAlreadyExists,
					"An environment with this slug already exists",
				)
			}
			return err
		}
		result = env
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// Delete removes an environment by ID after verifying the account
// will still have at least one environment and no active/suspended
// licenses remain inside the target environment.
func (s *Service) Delete(ctx context.Context, accountID core.AccountID, envID core.EnvironmentID) error {
	// Step 1: look up the environment (account-scoped tenant context)
	// and check the remaining-environments invariant.
	var targetSlug core.Environment
	err := s.txManager.WithTenant(ctx, accountID, core.EnvironmentLive, func(ctx context.Context) error {
		envs, err := s.environments.ListByAccount(ctx)
		if err != nil {
			return err
		}
		if len(envs) <= 1 {
			return core.NewAppError(
				core.ErrLastEnvironment,
				"An account must have at least one environment",
			)
		}
		for _, e := range envs {
			if e.ID == envID {
				targetSlug = e.Slug
				return nil
			}
		}
		return core.NewAppError(core.ErrEnvironmentNotFound, "Environment not found")
	})
	if err != nil {
		return err
	}

	// Step 2: switch tenant context to the target environment and
	// count blocking licenses. Active/suspended licenses prevent
	// deletion — the user must revoke or expire them first.
	err = s.txManager.WithTenant(ctx, accountID, targetSlug, func(ctx context.Context) error {
		blocking, err := s.licenses.CountBlocking(ctx)
		if err != nil {
			return err
		}
		if blocking > 0 {
			return core.NewAppError(
				core.ErrEnvironmentNotEmpty,
				"Environment has active or suspended licenses. Revoke them before deleting the environment.",
			)
		}
		return nil
	})
	if err != nil {
		return err
	}

	// Step 3: delete the environment row.
	return s.txManager.WithTenant(ctx, accountID, core.EnvironmentLive, func(ctx context.Context) error {
		return s.environments.Delete(ctx, envID)
	})
}
