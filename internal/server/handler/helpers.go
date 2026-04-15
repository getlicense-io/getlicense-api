package handler

import (
	"strconv"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/gofiber/fiber/v3"
)

const (
	defaultPageLimit = 50
	maxPageLimit     = 200
)

// cursorParams parses the `cursor` and `limit` query parameters.
//
// A missing `limit` parameter falls back to defaultPageLimit.
// An explicit `limit` that is outside [1, maxPageLimit] is rejected
// with ErrValidationError — F-007: previously such values silently
// reset to the default, which confused clients that deliberately
// probed the boundary. A missing cursor is treated as "first page".
// A malformed or field-incomplete cursor is rejected — F-006.
func cursorParams(c fiber.Ctx) (core.Cursor, int, error) {
	cursor, err := core.DecodeCursor(c.Query("cursor"))
	if err != nil {
		return core.Cursor{}, 0, core.NewAppError(core.ErrValidationError, "Invalid cursor")
	}
	limit := defaultPageLimit
	if raw := c.Query("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			return core.Cursor{}, 0, core.NewAppError(core.ErrValidationError, "Invalid limit")
		}
		if parsed < 1 || parsed > maxPageLimit {
			return core.Cursor{}, 0, core.NewAppError(core.ErrValidationError,
				"limit must be between 1 and 200")
		}
		limit = parsed
	}
	return cursor, limit, nil
}

func pageFromCursor[T any](items []T, hasMore bool, getCursor func(T) core.Cursor) core.Page[T] {
	page := core.Page[T]{Data: items, HasMore: hasMore}
	if hasMore && len(items) > 0 {
		c := core.EncodeCursor(getCursor(items[len(items)-1]))
		page.NextCursor = &c
	}
	return page
}
