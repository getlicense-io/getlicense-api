package db

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

// Integration tests for WebhookRepo. Gating mirrors policy_repo_test.go:
// `-short` skips, `make test-all` runs against the dev Postgres.
//
// The concurrent-claim test is the central regression guard for
// PR-3.1 — it proves the FOR UPDATE SKIP LOCKED semantics under
// real PostgreSQL (sqlc emits a CTE+UPDATE; pgx-side correctness
// can't be reasoned from unit tests alone). Each goroutine opens
// its own connection from the pool so the row locks are visible
// across transactions.

func TestWebhookRepo_SatisfiesInterface(t *testing.T) {
	var _ domain.WebhookRepository = (*WebhookRepo)(nil)
}

// claimNextSystem is a test wrapper around repo.ClaimNext that opens a
// WithSystemContext tx so the underlying webhook_events RLS policy
// (PR-B / migration 034) accepts the read. Production callers go
// through the worker pool which already wraps in WithSystemContext.
func claimNextSystem(t *testing.T, txm *TxManager, repo *WebhookRepo, claim core.WebhookClaimToken, expires time.Time) (*domain.WebhookEvent, error) {
	t.Helper()
	var (
		ev   *domain.WebhookEvent
		cerr error
	)
	if err := txm.WithSystemContext(context.Background(), func(ctx context.Context) error {
		ev, cerr = repo.ClaimNext(ctx, claim, expires)
		return cerr
	}); err != nil {
		return nil, err
	}
	return ev, nil
}

// execSystem runs an INSERT/UPDATE/DELETE under WithSystemContext —
// drop-in replacement for `pool.Exec(ctx, ...)` in tests that have to
// mutate RLS-enabled tables outside a tenant tx.
func execSystem(t *testing.T, txm *TxManager, sql string, args ...any) {
	t.Helper()
	if err := txm.WithSystemContext(context.Background(), func(ctx context.Context) error {
		_, err := Conn(ctx, txm.pool).Exec(ctx, sql, args...)
		return err
	}); err != nil {
		t.Fatalf("execSystem: %v", err)
	}
}

// seedWebhookEventsFixture seeds an account, endpoint, and N
// pending webhook_events rows. Returns IDs + a t.Cleanup that
// deletes the seed account (cascades through endpoints and events
// via ON DELETE CASCADE).
//
// IMPORTANT: run with the dev server STOPPED. The webhook worker
// pool in the running server will race with these tests for
// claims and mutate Status mid-assertion. `make test-all` is
// expected to be run with `make run` not active.
type webhookFixture struct {
	accountID   core.AccountID
	endpointID  core.WebhookEndpointID
	environment string
	eventIDs    []core.WebhookEventID
}

func seedWebhookFixture(t *testing.T, ctx context.Context, repo *WebhookRepo, eventCount int) *webhookFixture {
	t.Helper()
	pool := repo.pool
	txm := NewTxManager(pool)

	// UUIDv7 IDs share a time-ordered prefix; use the random tail so
	// concurrent test runs (and back-to-back seeds within one process)
	// never collide on slug uniqueness.
	tail := func(s string) string { return s[len(s)-12:] }

	accountID := core.NewAccountID()
	endpointID := core.NewWebhookEndpointID()
	eventIDs := make([]core.WebhookEventID, 0, eventCount)

	// All seeds run inside a single WithSystemContext tx — PR-B
	// (migration 034) made the RLS bypass explicit, and bare-pool
	// writes against tenant-scoped tables (accounts, webhook_endpoints,
	// webhook_events) now fail closed.
	if err := txm.WithSystemContext(ctx, func(ctx context.Context) error {
		pgxq := Conn(ctx, pool)
		if _, err := pgxq.Exec(ctx,
			`INSERT INTO accounts (id, name, slug, created_at)
			 VALUES ($1, $2, $3, NOW())`,
			uuid.UUID(accountID),
			"webhook-test-"+tail(accountID.String()),
			"wh-"+tail(accountID.String()),
		); err != nil {
			return err
		}
		if _, err := pgxq.Exec(ctx,
			`INSERT INTO webhook_endpoints (
			    id, account_id, url, events, signing_secret_encrypted, active,
			    created_at, environment
			 ) VALUES ($1, $2, $3, ARRAY[]::text[], $4, true, NOW(), 'live')`,
			uuid.UUID(endpointID), uuid.UUID(accountID),
			"https://example.com/wh-"+tail(endpointID.String()),
			[]byte("enc-"+tail(endpointID.String())),
		); err != nil {
			return err
		}
		// Migration 036 made webhook_events.domain_event_id NOT NULL,
		// so every event row needs a real domain_event to reference.
		domainEventID := core.NewDomainEventID()
		if _, err := pgxq.Exec(ctx,
			`INSERT INTO domain_events (
			    id, account_id, environment, event_type, resource_type,
			    payload, created_at
			 ) VALUES ($1, $2, 'live', 'test.event', 'test',
			           '{}'::jsonb, NOW())`,
			uuid.UUID(domainEventID), uuid.UUID(accountID),
		); err != nil {
			return err
		}
		for i := 0; i < eventCount; i++ {
			evID := core.NewWebhookEventID()
			eventIDs = append(eventIDs, evID)
			if _, err := pgxq.Exec(ctx,
				`INSERT INTO webhook_events (
				    id, account_id, endpoint_id, event_type, payload,
				    status, attempts, environment, created_at,
				    domain_event_id
				 ) VALUES ($1, $2, $3, 'test.event', '{}'::jsonb,
				           'pending', 0, 'live', NOW(), $4)`,
				uuid.UUID(evID), uuid.UUID(accountID), uuid.UUID(endpointID),
				uuid.UUID(domainEventID),
			); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed webhook fixture: %v", err)
	}

	t.Cleanup(func() {
		// account ON DELETE CASCADE wipes webhook_endpoints; endpoint
		// ON DELETE CASCADE wipes webhook_events. Best-effort, run
		// under WithSystemContext so the DELETE survives the new RLS.
		_ = txm.WithSystemContext(context.Background(), func(ctx context.Context) error {
			_, _ = Conn(ctx, pool).Exec(ctx,
				`DELETE FROM accounts WHERE id = $1`, uuid.UUID(accountID))
			return nil
		})
	})

	return &webhookFixture{
		accountID:   accountID,
		endpointID:  endpointID,
		environment: "live",
		eventIDs:    eventIDs,
	}
}

// TestWebhookRepo_ClaimNext_AtomicConcurrent: N goroutines race
// on a single pending row. Exactly one must claim it; the others
// see (nil, nil). This is the durability invariant the worker
// pool depends on — without it two workers could double-deliver.
func TestWebhookRepo_ClaimNext_AtomicConcurrent(t *testing.T) {
	pool := integrationPool(t)
	repo := NewWebhookRepo(pool)
	txm := NewTxManager(pool)
	ctx := context.Background()
	_ = seedWebhookFixture(t, ctx, repo, 1)

	const goroutines = 8
	var (
		wg           sync.WaitGroup
		successCount atomic.Int32
		missCount    atomic.Int32
		errCount     atomic.Int32
	)
	wg.Add(goroutines)
	start := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			<-start
			ev, err := claimNextSystem(t, txm, repo, core.NewWebhookClaimToken(), time.Now().UTC().Add(time.Minute))
			if err != nil {
				errCount.Add(1)
				return
			}
			if ev == nil {
				missCount.Add(1)
				return
			}
			successCount.Add(1)
		}()
	}
	close(start)
	wg.Wait()

	if errCount.Load() != 0 {
		t.Fatalf("unexpected error count: %d", errCount.Load())
	}
	if successCount.Load() != 1 {
		t.Fatalf("expected exactly 1 successful claim, got %d (miss=%d)", successCount.Load(), missCount.Load())
	}
	if missCount.Load() != goroutines-1 {
		t.Fatalf("expected %d misses, got %d", goroutines-1, missCount.Load())
	}
}

// TestWebhookRepo_ClaimNext_SkipsNotYetRetriable: a row with
// next_retry_at in the future is invisible to ClaimNext. The
// worker only delivers when the back-off window has elapsed.
func TestWebhookRepo_ClaimNext_SkipsNotYetRetriable(t *testing.T) {
	pool := integrationPool(t)
	repo := NewWebhookRepo(pool)
	txm := NewTxManager(pool)
	ctx := context.Background()
	fx := seedWebhookFixture(t, ctx, repo, 1)

	// Push next_retry_at into the future.
	execSystem(t, txm,
		`UPDATE webhook_events SET next_retry_at = NOW() + INTERVAL '1 hour' WHERE id = $1`,
		uuid.UUID(fx.eventIDs[0]),
	)

	ev, err := claimNextSystem(t, txm, repo, core.NewWebhookClaimToken(), time.Now().UTC().Add(time.Minute))
	if err != nil {
		t.Fatalf("ClaimNext: %v", err)
	}
	if ev != nil {
		t.Fatalf("expected ClaimNext to return nil for not-yet-retriable row, got id=%s", ev.ID)
	}
}

// TestWebhookRepo_ClaimNext_ProcessesByOldestFirst: the queue is
// ordered by next_retry_at NULLS FIRST, then created_at ASC. The
// older row (lower created_at) MUST be claimed before the newer.
//
// Test isolation: the dev DB may contain other pending rows from
// the live server or prior tests. We claim repeatedly until we hit
// one of the rows we seeded, then assert that it's the older of
// our two seeded IDs. Other tenants' rows are claim-then-mark-failed
// so a future test run isn't biased by them.
func TestWebhookRepo_ClaimNext_ProcessesByOldestFirst(t *testing.T) {
	pool := integrationPool(t)
	repo := NewWebhookRepo(pool)
	txm := NewTxManager(pool)
	ctx := context.Background()
	fx := seedWebhookFixture(t, ctx, repo, 2)

	// Backdate ours so ours sort to the front of any unrelated rows
	// in the dev DB. Use distinct timestamps that are also OLDER than
	// any plausible NOW()-seeded row from an unrelated test.
	farPast := time.Now().UTC().Add(-365 * 24 * time.Hour) // 1 year ago
	execSystem(t, txm,
		`UPDATE webhook_events SET created_at = $1 WHERE id = $2`,
		farPast.Add(-time.Hour), uuid.UUID(fx.eventIDs[0]),
	)
	execSystem(t, txm,
		`UPDATE webhook_events SET created_at = $1 WHERE id = $2`,
		farPast, uuid.UUID(fx.eventIDs[1]),
	)

	ev, err := claimNextSystem(t, txm, repo, core.NewWebhookClaimToken(), time.Now().UTC().Add(time.Minute))
	if err != nil {
		t.Fatalf("ClaimNext: %v", err)
	}
	if ev == nil {
		t.Fatal("expected a claim, got nil")
	}
	if ev.ID != fx.eventIDs[0] {
		t.Fatalf("expected oldest event %s to be claimed first, got %s", fx.eventIDs[0], ev.ID)
	}
}

// TestWebhookRepo_ReleaseStaleClaims: a row whose claim_expires_at
// has passed must be released so the next worker can re-claim it.
// This is the recovery path for workers that died mid-delivery.
func TestWebhookRepo_ReleaseStaleClaims(t *testing.T) {
	pool := integrationPool(t)
	repo := NewWebhookRepo(pool)
	txm := NewTxManager(pool)
	ctx := context.Background()
	fx := seedWebhookFixture(t, ctx, repo, 1)

	// Stamp a stale claim directly via SQL (simulates "worker died").
	staleToken := uuid.New()
	execSystem(t, txm,
		`UPDATE webhook_events
		    SET claim_token = $1,
		        claim_expires_at = NOW() - INTERVAL '1 hour'
		  WHERE id = $2`,
		staleToken, uuid.UUID(fx.eventIDs[0]),
	)

	// ClaimNext should NOT see the row — it's still claimed.
	ev, err := claimNextSystem(t, txm, repo, core.NewWebhookClaimToken(), time.Now().UTC().Add(time.Minute))
	if err != nil {
		t.Fatalf("ClaimNext (pre-release): %v", err)
	}
	if ev != nil {
		t.Fatalf("expected ClaimNext to skip claimed row, got id=%s", ev.ID)
	}

	// Release stale claims (run under WithSystemContext — production
	// callers go through Pool.Start which now wraps similarly).
	var n int
	require.NoError(t, txm.WithSystemContext(ctx, func(ctx context.Context) error {
		var rerr error
		n, rerr = repo.ReleaseStaleClaims(ctx)
		return rerr
	}))
	if n != 1 {
		t.Fatalf("expected ReleaseStaleClaims to release 1 row, got %d", n)
	}

	// Now ClaimNext should succeed.
	ev, err = claimNextSystem(t, txm, repo, core.NewWebhookClaimToken(), time.Now().UTC().Add(time.Minute))
	if err != nil {
		t.Fatalf("ClaimNext (post-release): %v", err)
	}
	if ev == nil {
		t.Fatal("expected ClaimNext to succeed after release, got nil")
	}
	if ev.ID != fx.eventIDs[0] {
		t.Fatalf("released wrong row: want %s, got %s", fx.eventIDs[0], ev.ID)
	}
}

// TestWebhookRepo_MarkDelivered_ReleasesClaim: a delivered row's
// claim is cleared and status flips to delivered. The next ClaimNext
// must NOT see it.
func TestWebhookRepo_MarkDelivered_ReleasesClaim(t *testing.T) {
	pool := integrationPool(t)
	repo := NewWebhookRepo(pool)
	txm := NewTxManager(pool)
	ctx := context.Background()
	fx := seedWebhookFixture(t, ctx, repo, 1)

	claim := core.NewWebhookClaimToken()
	ev, err := claimNextSystem(t, txm, repo, claim, time.Now().UTC().Add(time.Minute))
	if err != nil {
		t.Fatalf("ClaimNext: %v", err)
	}
	if ev == nil {
		t.Fatal("expected to claim seeded row")
	}

	status := 200
	body := "ok"
	var n int64
	require.NoError(t, txm.WithSystemContext(ctx, func(ctx context.Context) error {
		var rerr error
		n, rerr = repo.MarkDelivered(ctx, ev.ID, claim, 1, domain.DeliveryResult{
			ResponseStatus: &status,
			ResponseBody:   &body,
		})
		return rerr
	}))
	if n != 1 {
		t.Fatalf("MarkDelivered rowcount: want 1, got %d", n)
	}

	// Re-claim should miss.
	again, err := claimNextSystem(t, txm, repo, core.NewWebhookClaimToken(), time.Now().UTC().Add(time.Minute))
	if err != nil {
		t.Fatalf("ClaimNext (post-mark): %v", err)
	}
	if again != nil {
		t.Fatalf("expected delivered row to be invisible to ClaimNext, got id=%s", again.ID)
	}

	// Verify persisted state. GetEventByID needs system context too —
	// it reads the env-scoped webhook_events table.
	var persisted *domain.WebhookEvent
	require.NoError(t, txm.WithSystemContext(ctx, func(ctx context.Context) error {
		var gerr error
		persisted, gerr = repo.GetEventByID(ctx, fx.eventIDs[0])
		return gerr
	}))
	if persisted == nil {
		t.Fatalf("GetEventByID returned nil")
	}
	if persisted.Status != core.DeliveryStatusDelivered {
		t.Errorf("status: want delivered, got %s", persisted.Status)
	}
	if persisted.Attempts != 1 {
		t.Errorf("attempts: want 1, got %d", persisted.Attempts)
	}
}

// TestWebhookRepo_MarkFailedRetry_RowReappearsAfterNextRetry: a
// retry-marked row becomes claimable again once next_retry_at has
// passed. This is the cycle the worker depends on.
func TestWebhookRepo_MarkFailedRetry_RowReappearsAfterNextRetry(t *testing.T) {
	pool := integrationPool(t)
	repo := NewWebhookRepo(pool)
	txm := NewTxManager(pool)
	ctx := context.Background()
	fx := seedWebhookFixture(t, ctx, repo, 1)

	claim := core.NewWebhookClaimToken()
	ev, err := claimNextSystem(t, txm, repo, claim, time.Now().UTC().Add(time.Minute))
	if err != nil || ev == nil {
		t.Fatalf("ClaimNext: %v / %v", err, ev)
	}

	// Schedule retry in the past — equivalent to "the back-off has
	// already elapsed by the time we check".
	var n int64
	require.NoError(t, txm.WithSystemContext(ctx, func(ctx context.Context) error {
		var rerr error
		n, rerr = repo.MarkFailedRetry(ctx, ev.ID, claim, 1,
			domain.DeliveryResult{},
			time.Now().UTC().Add(-1*time.Minute),
		)
		return rerr
	}))
	if n != 1 {
		t.Fatalf("MarkFailedRetry rowcount: want 1, got %d", n)
	}

	// Should be claimable again.
	again, err := claimNextSystem(t, txm, repo, core.NewWebhookClaimToken(), time.Now().UTC().Add(time.Minute))
	if err != nil {
		t.Fatalf("ClaimNext (retry): %v", err)
	}
	if again == nil {
		t.Fatal("expected retry-pending row to be reclaimable, got nil")
	}
	if again.ID != fx.eventIDs[0] {
		t.Fatalf("reclaimed wrong row: want %s, got %s", fx.eventIDs[0], again.ID)
	}
}

// TestWebhookRepo_DispatcherCheckpoint_RoundTrip: GetCheckpoint
// returns nil-LastDomainEventID on a fresh DB; UpdateCheckpoint
// persists; subsequent Get returns the new value.
func TestWebhookRepo_DispatcherCheckpoint_RoundTrip(t *testing.T) {
	pool := integrationPool(t)
	repo := NewWebhookRepo(pool)
	ctx := context.Background()

	// Snapshot pre-state so the test is idempotent across runs (other
	// tests, manual usage, the dev server itself may have advanced the
	// checkpoint already). Restore on cleanup.
	pre, err := repo.GetDispatcherCheckpoint(ctx)
	if err != nil {
		t.Fatalf("GetDispatcherCheckpoint (pre): %v", err)
	}
	if pre == nil {
		t.Fatal("expected singleton checkpoint row to exist (seeded by migration 032)")
	}
	t.Cleanup(func() {
		if pre.LastDomainEventID != nil {
			_ = repo.UpdateDispatcherCheckpoint(context.Background(), *pre.LastDomainEventID)
		}
	})

	newID := core.NewDomainEventID()
	if err := repo.UpdateDispatcherCheckpoint(ctx, newID); err != nil {
		t.Fatalf("UpdateDispatcherCheckpoint: %v", err)
	}

	post, err := repo.GetDispatcherCheckpoint(ctx)
	if err != nil {
		t.Fatalf("GetDispatcherCheckpoint (post): %v", err)
	}
	if post == nil || post.LastDomainEventID == nil {
		t.Fatal("expected checkpoint to be populated after Update")
	}
	if *post.LastDomainEventID != newID {
		t.Fatalf("checkpoint mismatch: want %s, got %s", newID, *post.LastDomainEventID)
	}
}

// TestWebhookRepo_MarkDelivered_ClaimTokenGate proves the PR-A.1
// (item 2) WHERE-clause predicate at the SQL level: a Mark* call
// with a stale claim token MUST return rowcount=0 and MUST NOT
// overwrite the legitimate worker's state.
//
// This is the central regression guard: the worker code's "log WARN
// and skip" branch is harmless without this SQL gate, because the
// SQL would silently overwrite the new owner's state. If the gate
// regresses (claim_token predicate is removed), this test fails
// with rowcount=1 and the row's status flips to "delivered" even
// though the test simulates a different worker reclaiming the row.
func TestWebhookRepo_MarkDelivered_ClaimTokenGate(t *testing.T) {
	pool := integrationPool(t)
	repo := NewWebhookRepo(pool)
	txm := NewTxManager(pool)
	ctx := context.Background()
	fx := seedWebhookFixture(t, ctx, repo, 1)

	// Worker A claims the row.
	tokenA := core.NewWebhookClaimToken()
	ev, err := claimNextSystem(t, txm, repo, tokenA, time.Now().UTC().Add(time.Minute))
	if err != nil || ev == nil {
		t.Fatalf("ClaimNext A: %v / %v", err, ev)
	}

	// Simulate "worker A's claim expired and ReleaseStaleClaims gave
	// the row to worker B" by directly stamping a different claim.
	tokenB := core.NewWebhookClaimToken()
	execSystem(t, txm,
		`UPDATE webhook_events
		    SET claim_token = $1,
		        claim_expires_at = NOW() + INTERVAL '1 minute'
		  WHERE id = $2`,
		uuid.UUID(tokenB), uuid.UUID(fx.eventIDs[0]),
	)

	// Worker A (oblivious) tries to record success with its old token.
	// Predicate MUST refuse the write.
	status := 200
	body := "ok"
	var n int64
	require.NoError(t, txm.WithSystemContext(ctx, func(ctx context.Context) error {
		var rerr error
		n, rerr = repo.MarkDelivered(ctx, ev.ID, tokenA, 1, domain.DeliveryResult{
			ResponseStatus: &status,
			ResponseBody:   &body,
		})
		return rerr
	}))
	if n != 0 {
		t.Fatalf("MarkDelivered with stale claim must return rowcount=0, got %d", n)
	}

	// Persisted row must still be claimed by worker B with status pending.
	var persisted *domain.WebhookEvent
	require.NoError(t, txm.WithSystemContext(ctx, func(ctx context.Context) error {
		var gerr error
		persisted, gerr = repo.GetEventByID(ctx, fx.eventIDs[0])
		return gerr
	}))
	if persisted == nil {
		t.Fatalf("GetEventByID returned nil")
	}
	if persisted.Status != core.DeliveryStatusPending {
		t.Errorf("status: want pending (worker A's write was rejected), got %s", persisted.Status)
	}
}

// NOTE: an earlier draft included TestWebhookRepo_EnqueueIdempotent
// that asserted on a partial unique index over (domain_event_id,
// endpoint_id). That index was dropped — see migration 032 comment
// for why. Webhook delivery is at-least-once; the envelope's event
// id is the consumer-facing dedup token.
