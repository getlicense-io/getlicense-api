package handler

import (
	"strconv"

	"github.com/gofiber/fiber/v3"
)

// paginationParams extracts limit and offset query parameters with defaults and bounds.
func paginationParams(c fiber.Ctx) (limit, offset int) {
	limit = queryInt(c, "limit", 20)
	if limit < 1 {
		limit = 1
	}
	if limit > 100 {
		limit = 100
	}

	offset = queryInt(c, "offset", 0)
	if offset < 0 {
		offset = 0
	}

	return limit, offset
}

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
