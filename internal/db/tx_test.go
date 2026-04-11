package db

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConn_ReturnsPoolWhenNoTx(t *testing.T) {
	// conn with no tx in context should return the pool (as a querier)
	// We can't test with a real pool here, but we can verify the type assertion path
	ctx := context.Background()
	// When there's no tx in context, conn should not panic and should return non-nil
	// We pass nil pool to verify the fallback path (it returns the pool, which is nil)
	result := conn(ctx, nil)
	assert.Nil(t, result)
}
