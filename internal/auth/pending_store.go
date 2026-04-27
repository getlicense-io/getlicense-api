package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/getlicense-io/getlicense-api/internal/core"
)

func pendingLoginKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return "pending_login:" + hex.EncodeToString(sum[:])
}

type memoryPendingLogin struct {
	identityID core.IdentityID
	expiresAt  time.Time
}

type memoryPendingTokenStore struct {
	mu        sync.Mutex
	m         map[string]memoryPendingLogin
	done      chan struct{}
	closeOnce sync.Once
}

func newMemoryPendingTokenStore() *memoryPendingTokenStore {
	store := &memoryPendingTokenStore{
		m:    map[string]memoryPendingLogin{},
		done: make(chan struct{}),
	}
	go store.sweepLoop()
	return store
}

func (p *memoryPendingTokenStore) Put(_ context.Context, token string, id core.IdentityID) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.m[pendingLoginKey(token)] = memoryPendingLogin{identityID: id, expiresAt: time.Now().UTC().Add(pendingLoginTTL)}
	return nil
}

func (p *memoryPendingTokenStore) Take(_ context.Context, token string) (core.IdentityID, bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	key := pendingLoginKey(token)
	pl, ok := p.m[key]
	if !ok || time.Now().UTC().After(pl.expiresAt) {
		delete(p.m, key)
		return core.IdentityID{}, false, nil
	}
	delete(p.m, key)
	return pl.identityID, true, nil
}

func (p *memoryPendingTokenStore) Close() error {
	p.closeOnce.Do(func() {
		close(p.done)
	})
	return nil
}

func (p *memoryPendingTokenStore) sweepLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-p.done:
			return
		case now := <-ticker.C:
			p.sweepExpired(now.UTC())
		}
	}
}

func (p *memoryPendingTokenStore) sweepExpired(now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for key, pending := range p.m {
		if !now.Before(pending.expiresAt) {
			delete(p.m, key)
		}
	}
}

type RedisPendingTokenStore struct {
	client redis.UniversalClient
}

func NewRedisPendingTokenStore(client redis.UniversalClient) *RedisPendingTokenStore {
	return &RedisPendingTokenStore{client: client}
}

func (p *RedisPendingTokenStore) Put(ctx context.Context, token string, id core.IdentityID) error {
	return p.client.SetArgs(ctx, pendingLoginKey(token), id.String(), redis.SetArgs{
		Mode: "NX",
		TTL:  pendingLoginTTL,
	}).Err()
}

func (p *RedisPendingTokenStore) Take(ctx context.Context, token string) (core.IdentityID, bool, error) {
	raw, err := p.client.GetDel(ctx, pendingLoginKey(token)).Result()
	if errors.Is(err, redis.Nil) {
		return core.IdentityID{}, false, nil
	}
	if err != nil {
		return core.IdentityID{}, false, err
	}
	id, err := core.ParseIdentityID(raw)
	if err != nil {
		return core.IdentityID{}, false, err
	}
	return id, true, nil
}

func (p *RedisPendingTokenStore) Close() error { return nil }
