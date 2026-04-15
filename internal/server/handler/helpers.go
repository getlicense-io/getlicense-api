package handler

import (
	"strconv"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/gofiber/fiber/v3"
)

// queryInt parses an integer query parameter, returning defaultValue on missing or invalid input.
func queryInt(c fiber.Ctx, key string, defaultValue int) int {
	s := c.Query(key)
	if s == "" {
		return defaultValue
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return defaultValue
	}
	return v
}

const (
	defaultPageLimit = 50
	maxPageLimit     = 200
)

// cursorParams parses the `cursor` and `limit` query parameters. An
// empty cursor returns the zero Cursor (first page). limit defaults
// to defaultPageLimit and is clamped to [1, maxPageLimit].
func cursorParams(c fiber.Ctx) (core.Cursor, int, error) {
	cursor, err := core.DecodeCursor(c.Query("cursor"))
	if err != nil {
		return core.Cursor{}, 0, core.NewAppError(core.ErrValidationError, "Invalid cursor")
	}
	limit := queryInt(c, "limit", defaultPageLimit)
	if limit < 1 {
		limit = defaultPageLimit
	}
	if limit > maxPageLimit {
		limit = maxPageLimit
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
