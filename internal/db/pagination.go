package db

import (
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/google/uuid"
)

// cursorParams extracts the two nullable cursor params from core.Cursor.
// Zero cursor (first page) → (nil, nil); otherwise pointers to the values.
// Every paginated sqlc query uses these as its cursor_ts / cursor_id
// sqlc.narg arguments.
func cursorParams(c core.Cursor) (*time.Time, *uuid.UUID) {
	if c.IsZero() {
		return nil, nil
	}
	ts := c.CreatedAt
	id := c.ID
	return &ts, &id
}

// sliceHasMore implements the limit+1 probe uniformly. Every paginated
// repo method fetches LIMIT limit+1 rows and passes the returned slice
// through this to drop the probe row and report has_more.
func sliceHasMore[T any](rows []T, limit int) ([]T, bool) {
	if len(rows) > limit {
		return rows[:limit], true
	}
	return rows, false
}
