package analytics

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/sync/errgroup"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

// Snapshot holds all KPI counts and daily event buckets for one account+env.
type Snapshot struct {
	Licenses  domain.LicenseStatusCounts `json:"licenses"`
	Machines  MachineStats               `json:"machines"`
	Customers CustomerStats              `json:"customers"`
	Grants    GrantStats                  `json:"grants"`
	Events    []DailyBucket              `json:"events_by_day"`
}

// MachineStats holds machine counts grouped by status.
type MachineStats struct {
	Active int `json:"active"`
	Stale  int `json:"stale"`
	Dead   int `json:"dead"`
	Total  int `json:"total"`
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

// DailyBucket holds event count for a single day.
type DailyBucket struct {
	Date  string `json:"date"`
	Count int    `json:"count"`
}

// Service provides read-only aggregate analytics queries.
type Service struct {
	pool *pgxpool.Pool
}

// NewService creates a new analytics Service.
func NewService(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool}
}

// withRLS begins a transaction, sets the RLS session variables, runs fn, and commits.
func (s *Service) withRLS(ctx context.Context, accountID core.AccountID, env core.Environment, fn func(tx pgx.Tx) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("analytics: beginning tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	_, err = tx.Exec(ctx, "SELECT set_config('app.current_account_id', $1, true)", accountID.String())
	if err != nil {
		return fmt.Errorf("analytics: setting account context: %w", err)
	}
	_, err = tx.Exec(ctx, "SELECT set_config('app.current_environment', $1, true)", string(env))
	if err != nil {
		return fmt.Errorf("analytics: setting environment context: %w", err)
	}

	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Snapshot returns KPI counts and daily event buckets for the given account+env.
func (s *Service) Snapshot(ctx context.Context, accountID core.AccountID, env core.Environment, from, to time.Time) (*Snapshot, error) {
	snap := &Snapshot{}

	g, gCtx := errgroup.WithContext(ctx)

	// 1. License stats — env-scoped via RLS
	g.Go(func() error {
		return s.withRLS(gCtx, accountID, env, func(tx pgx.Tx) error {
			rows, err := tx.Query(gCtx, "SELECT status, COUNT(*) FROM licenses GROUP BY status")
			if err != nil {
				return fmt.Errorf("analytics: license stats: %w", err)
			}
			defer rows.Close()
			for rows.Next() {
				var status string
				var count int
				if err := rows.Scan(&status, &count); err != nil {
					return fmt.Errorf("analytics: scanning license row: %w", err)
				}
				switch core.LicenseStatus(status) {
				case core.LicenseStatusActive:
					snap.Licenses.Active = count
				case core.LicenseStatusSuspended:
					snap.Licenses.Suspended = count
				case core.LicenseStatusRevoked:
					snap.Licenses.Revoked = count
				case core.LicenseStatusExpired:
					snap.Licenses.Expired = count
				case core.LicenseStatusInactive:
					snap.Licenses.Inactive = count
				}
				snap.Licenses.Total += count
			}
			return rows.Err()
		})
	})

	// 2. Machine stats — env-scoped via RLS
	g.Go(func() error {
		return s.withRLS(gCtx, accountID, env, func(tx pgx.Tx) error {
			rows, err := tx.Query(gCtx, "SELECT status, COUNT(*) FROM machines GROUP BY status")
			if err != nil {
				return fmt.Errorf("analytics: machine stats: %w", err)
			}
			defer rows.Close()
			for rows.Next() {
				var status string
				var count int
				if err := rows.Scan(&status, &count); err != nil {
					return fmt.Errorf("analytics: scanning machine row: %w", err)
				}
				switch core.MachineStatus(status) {
				case core.MachineStatusActive:
					snap.Machines.Active = count
				case core.MachineStatusStale:
					snap.Machines.Stale = count
				case core.MachineStatusDead:
					snap.Machines.Dead = count
				}
				snap.Machines.Total += count
			}
			return rows.Err()
		})
	})

	// 3. Customer count — account-scoped only (no environment column)
	g.Go(func() error {
		return s.pool.QueryRow(gCtx,
			"SELECT COUNT(*) FROM customers WHERE account_id = $1",
			accountID.String(),
		).Scan(&snap.Customers.Total)
	})

	// 4. Grant stats — account-scoped only (no environment column)
	g.Go(func() error {
		err := s.pool.QueryRow(gCtx,
			"SELECT COUNT(*) FROM grants WHERE grantor_account_id = $1 AND status = 'active'",
			accountID.String(),
		).Scan(&snap.Grants.ActiveGrants)
		if err != nil {
			return fmt.Errorf("analytics: active grants: %w", err)
		}
		return s.pool.QueryRow(gCtx,
			"SELECT COUNT(*) FROM licenses WHERE account_id = $1 AND grant_id IS NOT NULL",
			accountID.String(),
		).Scan(&snap.Grants.LicensesViaGrants)
	})

	if err := g.Wait(); err != nil {
		return nil, err
	}

	// 5. Daily event buckets — env-scoped via RLS, runs after errgroup
	err := s.withRLS(ctx, accountID, env, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT date_trunc('day', created_at)::date AS date, COUNT(*)
			 FROM domain_events
			 WHERE created_at BETWEEN $1 AND $2
			 GROUP BY 1 ORDER BY 1`,
			from, to,
		)
		if err != nil {
			return fmt.Errorf("analytics: daily buckets: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var b DailyBucket
			var d time.Time
			if err := rows.Scan(&d, &b.Count); err != nil {
				return fmt.Errorf("analytics: scanning bucket: %w", err)
			}
			b.Date = d.Format("2006-01-02")
			snap.Events = append(snap.Events, b)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}

	if snap.Events == nil {
		snap.Events = []DailyBucket{}
	}

	return snap, nil
}
