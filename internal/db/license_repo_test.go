package db

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// classifyStatusUpdateErr runs after UpdateLicenseStatusFromTo returns
// pgx.ErrNoRows and uses a follow-up LicenseExists query to distinguish
// "status mismatch" (row still there, caller should see a 422-ish
// validation error) from "license gone" (404-ish not-found). These
// tests drive a stub sqlcgen.DBTX to confirm the branching behaviour
// without round-tripping to Postgres. The happy-path and integration
// semantics are covered by the licensing package's e2e scenarios.

// stubDBTX is a sqlcgen.DBTX mock that forwards every QueryRow call to
// the configured row and captures the SQL for assertion. It is
// deliberately single-shot: classifyStatusUpdateErr makes exactly one
// QueryRow call (the LicenseExists probe).
type stubDBTX struct {
	row       pgx.Row
	lastQuery string
	lastArgs  []any
}

func (s *stubDBTX) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	panic("unexpected Exec call")
}

func (s *stubDBTX) Query(context.Context, string, ...any) (pgx.Rows, error) {
	panic("unexpected Query call")
}

func (s *stubDBTX) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	s.lastQuery = sql
	s.lastArgs = args
	return s.row
}

// stubBoolRow serves the scalar `EXISTS(...)` result the LicenseExists
// query scans into a *bool.
type stubBoolRow struct {
	value bool
	err   error
}

func (r stubBoolRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	exists, ok := dest[0].(*bool)
	if !ok {
		return errors.New("expected *bool destination")
	}
	*exists = r.value
	return nil
}

func TestClassifyStatusUpdateErr_StatusChangedReturnsValidationError(t *testing.T) {
	repo := NewLicenseRepo(nil)
	db := &stubDBTX{row: stubBoolRow{value: true}}
	id := core.NewLicenseID()

	err := repo.classifyStatusUpdateErr(context.Background(), db, id, pgx.ErrNoRows)
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrValidationError, appErr.Code)
	assert.Contains(t, appErr.Message, "status")
	assert.Contains(t, db.lastQuery, "SELECT EXISTS")
	require.Len(t, db.lastArgs, 1)
}

func TestClassifyStatusUpdateErr_MissingLicenseReturnsNotFound(t *testing.T) {
	repo := NewLicenseRepo(nil)
	db := &stubDBTX{row: stubBoolRow{value: false}}

	err := repo.classifyStatusUpdateErr(context.Background(), db, core.NewLicenseID(), pgx.ErrNoRows)
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrLicenseNotFound, appErr.Code)
}

func TestClassifyStatusUpdateErr_PassesThroughNonNoRowsError(t *testing.T) {
	repo := NewLicenseRepo(nil)
	// row is nil — if the stub is touched, it will panic. Any non-
	// ErrNoRows input must short-circuit before reaching QueryRow.
	db := &stubDBTX{}
	upstream := errors.New("connection reset")

	err := repo.classifyStatusUpdateErr(context.Background(), db, core.NewLicenseID(), upstream)
	require.Same(t, upstream, err)
	assert.Empty(t, db.lastQuery)
}
