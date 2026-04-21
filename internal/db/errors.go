package db

import (
	"errors"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// --- SQLSTATE codes we classify on ---
const (
	sqlstateUniqueViolation     = "23505"
	sqlstateForeignKeyViolation = "23503"
	sqlstateCheckViolation      = "23514"
)

// IsUniqueViolation reports whether err is a Postgres unique-constraint
// violation (SQLSTATE 23505) on the named constraint. Pass an empty
// constraint name to match any unique violation.
func IsUniqueViolation(err error, constraint string) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != sqlstateUniqueViolation {
		return false
	}
	return constraint == "" || pgErr.ConstraintName == constraint
}

// IsForeignKeyViolation reports whether err is a Postgres FK violation
// (SQLSTATE 23503) on the named constraint. Used by Delete handlers
// that rely on FK-RESTRICT instead of a pre-count guard.
func IsForeignKeyViolation(err error, constraint string) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != sqlstateForeignKeyViolation {
		return false
	}
	return constraint == "" || pgErr.ConstraintName == constraint
}

// IsCheckViolation reports whether err is a Postgres CHECK violation
// (SQLSTATE 23514) on the named constraint.
func IsCheckViolation(err error, constraint string) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != sqlstateCheckViolation {
		return false
	}
	return constraint == "" || pgErr.ConstraintName == constraint
}

// notFoundOrNil collapses the "GET → ErrNoRows → nil" pattern used by
// every idempotent lookup. Returns (nil, nil) on ErrNoRows, (&v, nil)
// on success, (nil, err) on other errors.
//
// Consumed by sqlc repo adapters landed in Tasks 3-19.
//
//nolint:unused // wired by upcoming sqlc adapter tasks
func notFoundOrNil[T any](v T, err error) (*T, error) {
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &v, nil
}

// notFoundErr maps pgx.ErrNoRows to a typed AppError for mandatory-row
// operations (UPDATE/DELETE WHERE id = $1 RETURNING ...). Other errors
// pass through unchanged.
//
// Consumed by sqlc repo adapters landed in Tasks 3-19.
//
//nolint:unused // wired by upcoming sqlc adapter tasks
func notFoundErr(err error, code core.ErrorCode, msg string) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return core.NewAppError(code, msg)
	}
	return err
}
