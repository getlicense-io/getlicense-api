package middleware

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemoryRateLimiter_PrunesExpiredBuckets(t *testing.T) {
	limiter := NewMemoryRateLimiter().(*memoryRateLimiter)

	allowed, _, err := limiter.Hit(context.Background(), "expired", 1, time.Minute)
	require.NoError(t, err)
	require.True(t, allowed)

	limiter.mu.Lock()
	limiter.buckets["expired"] = memoryRateLimitBucket{
		count:   1,
		resetAt: time.Now().Add(-time.Second),
	}
	limiter.lastSweep = time.Now().Add(-2 * time.Minute)
	limiter.mu.Unlock()

	allowed, _, err = limiter.Hit(context.Background(), "active", 1, time.Minute)
	require.NoError(t, err)
	require.True(t, allowed)

	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	assert.NotContains(t, limiter.buckets, "expired")
	assert.Contains(t, limiter.buckets, "active")
}
