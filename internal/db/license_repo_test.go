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

type stubQuerier struct {
	exists    bool
	queryErr  error
	lastQuery string
	lastArgs  []any
}

func (s *stubQuerier) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	panic("unexpected Exec call")
}

func (s *stubQuerier) Query(context.Context, string, ...any) (pgx.Rows, error) {
	panic("unexpected Query call")
}

func (s *stubQuerier) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	s.lastQuery = sql
	s.lastArgs = args
	return stubBoolRow{value: s.exists, err: s.queryErr}
}

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
		return errors.New("expected bool destination")
	}
	*exists = r.value
	return nil
}

func TestClassifyLicenseStatusUpdateError_StatusChangedReturnsValidationError(t *testing.T) {
	id := core.NewLicenseID()
	q := &stubQuerier{exists: true}

	err := classifyLicenseStatusUpdateError(context.Background(), q, id, pgx.ErrNoRows)
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrValidationError, appErr.Code)
	assert.Contains(t, appErr.Message, "status")
	assert.Contains(t, q.lastQuery, "SELECT EXISTS")
	require.Len(t, q.lastArgs, 1)
}

func TestClassifyLicenseStatusUpdateError_MissingLicenseReturnsNotFound(t *testing.T) {
	err := classifyLicenseStatusUpdateError(context.Background(), &stubQuerier{exists: false}, core.NewLicenseID(), pgx.ErrNoRows)
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrLicenseNotFound, appErr.Code)
}
