package db

import (
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// nilIfEmpty returns nil for empty string, else a pointer. Used to
// convert "no filter" → sqlc.narg NULL.
func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// nilIfZero returns nil for a zero time, else a pointer. Used for
// cursor timestamps.
//
// Consumed by sqlc repo adapters landed in Tasks 3-19.
//
//nolint:unused // wired by upcoming sqlc adapter tasks
func nilIfZero(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// nilIfZeroID returns nil for a zero uuid, else a pointer. Used for
// cursor ids and optional id filters.
//
// Consumed by sqlc repo adapters landed in Tasks 3-19.
//
//nolint:unused // wired by upcoming sqlc adapter tasks
func nilIfZeroID(id uuid.UUID) *uuid.UUID {
	if id == uuid.Nil {
		return nil
	}
	return &id
}

// --- pgtype.UUID <-> core.ID[T] conversion ---
//
// sqlcgen emits every uuid column as pgtype.UUID (nullable or not —
// pgtype.UUID carries its own `.Valid bool` flag). Every core.ID[T]
// has underlying type [16]byte (via uuid.UUID). These helpers are the
// single translation seam between the two.
//
// Used at adapter boundaries:
//   - Reading:  id := idFromPgUUID[core.AccountID](row.AccountID)
//               ptr := nullableIDFromPgUUID[core.GrantID](row.GrantID)
//   - Writing:  params.AccountID = pgUUIDFromID(account.ID)
//               params.GrantID   = pgUUIDFromIDPtr(license.GrantID)

// idFromPgUUID converts a NOT-NULL pgtype.UUID row value to a typed core ID.
// Generic constraint ~[16]byte matches every core.*ID alias because
// core.ID[T] = uuid.UUID = [16]byte under the hood.
func idFromPgUUID[T ~[16]byte](v pgtype.UUID) T {
	return T(v.Bytes)
}

// nullableIDFromPgUUID converts a nullable pgtype.UUID row value to *T.
// Returns nil when .Valid is false.
func nullableIDFromPgUUID[T ~[16]byte](v pgtype.UUID) *T {
	if !v.Valid {
		return nil
	}
	id := T(v.Bytes)
	return &id
}

// pgUUIDFromID wraps a typed core ID as a pgtype.UUID (always Valid=true).
// Used when building sqlcgen params for INSERT / UPDATE with NOT-NULL uuid columns.
func pgUUIDFromID[T ~[16]byte](id T) pgtype.UUID {
	return pgtype.UUID{Bytes: [16]byte(id), Valid: true}
}

// pgUUIDFromIDPtr wraps a nullable typed core ID as a pgtype.UUID.
// nil → Valid=false. Used for nullable FK columns in INSERT / UPDATE params.
func pgUUIDFromIDPtr[T ~[16]byte](id *T) pgtype.UUID {
	if id == nil {
		return pgtype.UUID{}
	}
	return pgtype.UUID{Bytes: [16]byte(*id), Valid: true}
}
