package core

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCursor_RoundTrip(t *testing.T) {
	ts := time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC)
	id := uuid.New()

	encoded := EncodeCursor(Cursor{CreatedAt: ts, ID: id})
	assert.NotEmpty(t, encoded)

	decoded, err := DecodeCursor(encoded)
	require.NoError(t, err)
	assert.True(t, decoded.CreatedAt.Equal(ts))
	assert.Equal(t, id, decoded.ID)
}

func TestDecodeCursor_EmptyReturnsZero(t *testing.T) {
	c, err := DecodeCursor("")
	require.NoError(t, err)
	assert.True(t, c.CreatedAt.IsZero())
}

func TestDecodeCursor_Malformed(t *testing.T) {
	_, err := DecodeCursor("not-base64!!!")
	assert.Error(t, err)
}

func TestCursor_IsZero(t *testing.T) {
	assert.True(t, Cursor{}.IsZero())
	assert.False(t, Cursor{CreatedAt: time.Now(), ID: uuid.New()}.IsZero())
}
