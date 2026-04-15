// Package environment owns per-account data partitions ("environments").
// Every account has at least one and at most MaxEnvironmentsPerAccount;
// "live" and "test" are auto-seeded at signup.
package environment

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/db"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

const MaxEnvironmentsPerAccount = 5

// Length bounds for free-text environment fields. Enforced server-side
// so a curl client can't bypass the dashboard's maxLength inputs.
const (
	MaxEnvironmentNameLength        = 32
	MaxEnvironmentDescriptionLength = 100
)

// Default icon/color pairs for the auto-seeded environments. Kept in
// sync with the migration's seed INSERT so drift is a single-file fix.
const (
	liveIcon  = "radio"
	liveColor = "emerald"
	testIcon  = "flask-conical"
	testColor = "amber"

	// Fallback visuals when a user-created environment omits icon/color.
	defaultIcon  = "radio"
	defaultColor = "emerald"
)

type Service struct {
	txManager    domain.TxManager
	environments domain.EnvironmentRepository
	licenses     domain.LicenseRepository
}

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

type CreateRequest struct {
	Slug        string `json:"slug" validate:"required"`
	Name        string `json:"name" validate:"required"`
	Description string `json:"description"`
	Icon        string `json:"icon"`
	Color       string `json:"color"`
}

// DefaultEnvironments returns the two environments auto-created at
// signup. The auth service calls this directly inside its signup
// transaction — see migrations/014_environments.sql for the parallel
// seed used for accounts that pre-date this table.
func DefaultEnvironments(accountID core.AccountID, now time.Time) []*domain.Environment {
	return []*domain.Environment{
		{
			ID:          core.NewEnvironmentID(),
			AccountID:   accountID,
			Slug:        core.EnvironmentLive,
			Name:        "Live",
			Description: "Production data",
			Icon:        liveIcon,
			Color:       liveColor,
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
			Icon:        testIcon,
			Color:       testColor,
			Position:    1,
			CreatedAt:   now,
			UpdatedAt:   now,
		},
	}
}

func (s *Service) List(ctx context.Context, accountID core.AccountID) ([]domain.Environment, error) {
	var result []domain.Environment
	// environments is account-scoped; the env slug passed to
	// WithTargetAccount is unused by RLS on this table (environments
	// are not partitioned by environment slug).
	err := s.txManager.WithTargetAccount(ctx, accountID, core.EnvironmentLive, func(ctx context.Context) error {
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

// ListPage returns a cursor-paginated page of environments for the given
// account. Environments are capped at 5 so hasMore is always false in
// practice; the method exists for API shape consistency.
func (s *Service) ListPage(ctx context.Context, accountID core.AccountID, cursor core.Cursor, limit int) ([]domain.Environment, bool, error) {
	var result []domain.Environment
	var hasMore bool
	err := s.txManager.WithTargetAccount(ctx, accountID, core.EnvironmentLive, func(ctx context.Context) error {
		var err error
		result, hasMore, err = s.environments.ListByAccountPage(ctx, cursor, limit)
		return err
	})
	if err != nil {
		return nil, false, err
	}
	return result, hasMore, nil
}

func (s *Service) Create(ctx context.Context, accountID core.AccountID, req CreateRequest) (*domain.Environment, error) {
	slug, err := core.ParseEnvironment(strings.TrimSpace(req.Slug))
	if err != nil {
		return nil, core.NewAppError(core.ErrValidationError, "Environment slug must be 1-32 characters: lowercase letters, digits, or hyphens, starting with a letter")
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return nil, core.NewAppError(core.ErrValidationError, "Environment name is required")
	}
	if len(name) > MaxEnvironmentNameLength {
		return nil, core.NewAppError(core.ErrValidationError, fmt.Sprintf("Environment name must be %d characters or fewer", MaxEnvironmentNameLength))
	}
	description := strings.TrimSpace(req.Description)
	if len(description) > MaxEnvironmentDescriptionLength {
		return nil, core.NewAppError(core.ErrValidationError, fmt.Sprintf("Environment description must be %d characters or fewer", MaxEnvironmentDescriptionLength))
	}

	icon := strings.TrimSpace(req.Icon)
	if icon == "" {
		icon = defaultIcon
	}
	color := strings.TrimSpace(req.Color)
	if color == "" {
		color = defaultColor
	}

	var result *domain.Environment
	err = s.txManager.WithTargetAccount(ctx, accountID, core.EnvironmentLive, func(ctx context.Context) error {
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
			Description: description,
			Icon:        icon,
			Color:       color,
			Position:    count,
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		if err := s.environments.Create(ctx, env); err != nil {
			if db.IsUniqueViolation(err, "") {
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

func (s *Service) Delete(ctx context.Context, accountID core.AccountID, envID core.EnvironmentID) error {
	// Step 1 (account-scoped tx): resolve the target slug and enforce
	// the "at least one env per account" invariant.
	var targetSlug core.Environment
	err := s.txManager.WithTargetAccount(ctx, accountID, core.EnvironmentLive, func(ctx context.Context) error {
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

	// Step 2 (target-env tx): license existence check + delete run in
	// one transaction under the target env's RLS GUC, so a concurrent
	// license insert cannot race with the delete.
	return s.txManager.WithTargetAccount(ctx, accountID, targetSlug, func(ctx context.Context) error {
		has, err := s.licenses.HasBlocking(ctx)
		if err != nil {
			return err
		}
		if has {
			return core.NewAppError(
				core.ErrEnvironmentNotEmpty,
				"Environment has active or suspended licenses. Revoke them before deleting the environment.",
			)
		}
		return s.environments.Delete(ctx, envID)
	})
}
