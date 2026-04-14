package core

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Cursor is the opaque position marker used by every list endpoint for
// keyset pagination. It encodes the tuple (created_at, id) so clients
// can page stably under concurrent inserts.
//
// Field JSON tags are single-character ("t", "i") to keep the base64
// payload small — cursors ride in query strings on every paginated request.
type Cursor struct {
	CreatedAt time.Time `json:"t"`
	ID        uuid.UUID `json:"i"`
}

// IsZero reports whether the cursor is empty (first page).
func (c Cursor) IsZero() bool {
	return c.CreatedAt.IsZero() && c.ID == uuid.Nil
}

// EncodeCursor serializes a Cursor into an opaque base64 string.
func EncodeCursor(c Cursor) string {
	b, err := json.Marshal(c)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// DecodeCursor parses an opaque cursor string. An empty input returns a
// zero Cursor with no error — callers treat zero as "first page".
func DecodeCursor(s string) (Cursor, error) {
	if s == "" {
		return Cursor{}, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return Cursor{}, fmt.Errorf("core: invalid cursor: %w", err)
	}
	var c Cursor
	if err := json.Unmarshal(raw, &c); err != nil {
		return Cursor{}, fmt.Errorf("core: invalid cursor payload: %w", err)
	}
	return c, nil
}

// Page wraps a slice plus the next cursor. Used by list endpoints.
type Page[T any] struct {
	Data       []T     `json:"data"`
	NextCursor *string `json:"next_cursor,omitempty"`
	HasMore    bool    `json:"has_more"`
}
