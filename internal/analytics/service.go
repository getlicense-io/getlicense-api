package analytics

import (
	"context"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

// Snapshot holds all KPI counts and daily event buckets for one account+env.
type Snapshot struct {
	Licenses  domain.LicenseStatusCounts `json:"licenses"`
	Machines  domain.MachineStatusCounts `json:"machines"`
	Customers CustomerStats              `json:"customers"`
	Grants    GrantStats                 `json:"grants"`
	Events    []domain.DailyEventCount   `json:"events_by_day"`
}

// CustomerStats holds total customer count.
type CustomerStats struct {
	Total int `json:"total"`
}

// GrantStats holds grant-related counts.
type GrantStats struct {
	ActiveGrants      int `json:"active_grants"`
	LicensesViaGrants int `json:"licenses_via_grants"`
}

// Service provides read-only aggregate analytics queries.
//
// Every aggregate runs inside a WithTargetAccount transaction so RLS
// scopes the read to the requested account+environment. PR-B
// (migration 034) made the implicit NULLIF IS NULL bypass explicit, so
// bare-pool reads on RLS-enabled tables now fail closed — every query
// here goes through txManager + a sqlc repo method.
type Service struct {
	tx           domain.TxManager
	licenses     domain.LicenseRepository
	machines     domain.MachineRepository
	customers    domain.CustomerRepository
	grants       domain.GrantRepository
	domainEvents domain.DomainEventRepository
}

// NewService creates a new analytics Service.
func NewService(
	tx domain.TxManager,
	licenses domain.LicenseRepository,
	machines domain.MachineRepository,
	customers domain.CustomerRepository,
	grants domain.GrantRepository,
	domainEvents domain.DomainEventRepository,
) *Service {
	return &Service{
		tx:           tx,
		licenses:     licenses,
		machines:     machines,
		customers:    customers,
		grants:       grants,
		domainEvents: domainEvents,
	}
}

// Snapshot returns KPI counts and daily event buckets for the given
// account+env. The four KPI sub-queries (licenses, machines, customers,
// grants) run in parallel via errgroup; daily event buckets run
// sequentially after the parallel batch so its tenant context is
// fresh.
func (s *Service) Snapshot(ctx context.Context, accountID core.AccountID, env core.Environment, from, to time.Time) (*Snapshot, error) {
	snap := &Snapshot{}

	g, gCtx := errgroup.WithContext(ctx)

	// 1. License stats — env-scoped via RLS.
	g.Go(func() error {
		return s.tx.WithTargetAccount(gCtx, accountID, env, func(ctx context.Context) error {
			counts, err := s.licenses.CountByStatus(ctx)
			if err != nil {
				return err
			}
			snap.Licenses = counts
			return nil
		})
	})

	// 2. Machine stats — env-scoped via RLS.
	g.Go(func() error {
		return s.tx.WithTargetAccount(gCtx, accountID, env, func(ctx context.Context) error {
			counts, err := s.machines.CountByStatus(ctx)
			if err != nil {
				return err
			}
			snap.Machines = counts
			return nil
		})
	})

	// 3. Customer count — account-scoped via RLS; customers are env-agnostic.
	g.Go(func() error {
		return s.tx.WithTargetAccount(gCtx, accountID, env, func(ctx context.Context) error {
			n, err := s.customers.Count(ctx)
			if err != nil {
				return err
			}
			snap.Customers.Total = n
			return nil
		})
	})

	// 4. Grant stats — explicit grantor filter (grants RLS includes
	//    both grantor and grantee sides; we want only "grants I issued").
	g.Go(func() error {
		return s.tx.WithTargetAccount(gCtx, accountID, env, func(ctx context.Context) error {
			activeGrants, err := s.grants.CountActiveByGrantor(ctx, accountID)
			if err != nil {
				return err
			}
			snap.Grants.ActiveGrants = activeGrants

			licensesViaGrants, err := s.licenses.CountIssuedByGrant(ctx)
			if err != nil {
				return err
			}
			snap.Grants.LicensesViaGrants = licensesViaGrants
			return nil
		})
	})

	if err := g.Wait(); err != nil {
		return nil, err
	}

	// 5. Daily event buckets — env-scoped via RLS; runs after the
	//    parallel batch so its tenant context is fresh.
	err := s.tx.WithTargetAccount(ctx, accountID, env, func(ctx context.Context) error {
		buckets, err := s.domainEvents.CountByDay(ctx, from, to)
		if err != nil {
			return err
		}
		snap.Events = buckets
		return nil
	})
	if err != nil {
		return nil, err
	}

	if snap.Events == nil {
		snap.Events = []domain.DailyEventCount{}
	}

	return snap, nil
}
