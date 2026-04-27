package auth

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlicense-io/getlicense-api/internal/core"
)

func TestMemoryPendingTokenStore_StoresOnlyHashedTokenKey(t *testing.T) {
	store := newMemoryPendingTokenStore()
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	token := "raw-pending-token"
	identityID := core.NewIdentityID()

	require.NoError(t, store.Put(context.Background(), token, identityID))

	for key := range store.m {
		assert.True(t, strings.HasPrefix(key, "pending_login:"))
		assert.NotContains(t, key, token)
	}
}

func TestMemoryPendingTokenStore_TakeConsumesOnce(t *testing.T) {
	store := newMemoryPendingTokenStore()
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	token := "raw-pending-token"
	identityID := core.NewIdentityID()

	require.NoError(t, store.Put(context.Background(), token, identityID))
	got, ok, err := store.Take(context.Background(), token)
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, identityID, got)

	_, ok, err = store.Take(context.Background(), token)
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestMemoryPendingTokenStore_SweepExpired(t *testing.T) {
	store := newMemoryPendingTokenStore()
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	token := "raw-pending-token"
	identityID := core.NewIdentityID()

	require.NoError(t, store.Put(context.Background(), token, identityID))
	store.sweepExpired(time.Now().UTC().Add(pendingLoginTTL + time.Second))

	_, ok, err := store.Take(context.Background(), token)
	require.NoError(t, err)
	assert.False(t, ok)
	assert.Empty(t, store.m)
}
