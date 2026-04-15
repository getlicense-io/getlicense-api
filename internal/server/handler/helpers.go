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

// cursorParams parses the `cursor` and `limit` query parameters. An
// empty cursor returns the zero Cursor (first page). limit is
// clamped to [1, 200] with a default of 50.
func cursorParams(c fiber.Ctx) (core.Cursor, int, error) {
	cursor, err := core.DecodeCursor(c.Query("cursor"))
	if err != nil {
		return core.Cursor{}, 0, core.NewAppError(core.ErrValidationError, "Invalid cursor")
	}
	limit := queryInt(c, "limit", 50)
	if limit < 1 || limit > 200 {
		limit = 50
	}
	return cursor, limit, nil
}

// pageFromCursor builds a core.Page[T] from a repo result. getCursor
// extracts (createdAt, id) from the last item — needed because Go
// generics can't reach into arbitrary struct fields.
func pageFromCursor[T any](items []T, hasMore bool, getCursor func(T) core.Cursor) core.Page[T] {
	page := core.Page[T]{Data: items, HasMore: hasMore}
	if hasMore && len(items) > 0 {
		c := core.EncodeCursor(getCursor(items[len(items)-1]))
		page.NextCursor = &c
	}
	return page
}
