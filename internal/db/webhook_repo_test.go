package db

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

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

	accountID := core.NewAccountID()
	if _, err := pool.Exec(ctx,
		`INSERT INTO accounts (id, name, slug, created_at)
		 VALUES ($1, $2, $3, NOW())`,
		uuid.UUID(accountID),
		"webhook-test-"+accountID.String()[:8],
		"wh-"+accountID.String()[:8],
	); err != nil {
		t.Fatalf("seed account: %v", err)
	}

	// We don't seed the environments table — webhook_events RLS uses
	// the NULLIF escape hatch and we set app.current_account_id /
	// app.current_environment when needed.

	endpointID := core.NewWebhookEndpointID()
	if _, err := pool.Exec(ctx,
		`INSERT INTO webhook_endpoints (
		    id, account_id, url, events, signing_secret, active,
		    created_at, environment
		 ) VALUES ($1, $2, $3, ARRAY[]::text[], $4, true, NOW(), 'live')`,
		uuid.UUID(endpointID), uuid.UUID(accountID),
		"https://example.com/wh-"+endpointID.String()[:8],
		"secret-"+endpointID.String()[:8],
	); err != nil {
		t.Fatalf("seed endpoint: %v", err)
	}

	eventIDs := make([]core.WebhookEventID, 0, eventCount)
	for i := 0; i < eventCount; i++ {
		evID := core.NewWebhookEventID()
		eventIDs = append(eventIDs, evID)
		if _, err := pool.Exec(ctx,
			`INSERT INTO webhook_events (
			    id, account_id, endpoint_id, event_type, payload,
			    status, attempts, environment, created_at
			 ) VALUES ($1, $2, $3, 'test.event', '{}'::jsonb,
			           'pending', 0, 'live', NOW())`,
			uuid.UUID(evID), uuid.UUID(accountID), uuid.UUID(endpointID),
		); err != nil {
			t.Fatalf("seed event %d: %v", i, err)
		}
	}

	t.Cleanup(func() {
		// account ON DELETE CASCADE wipes webhook_endpoints; endpoint
		// ON DELETE CASCADE wipes webhook_events. Best-effort.
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM accounts WHERE id = $1`, uuid.UUID(accountID))
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
			ev, err := repo.ClaimNext(ctx, core.NewWebhookClaimToken(), time.Now().UTC().Add(time.Minute))
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
	ctx := context.Background()
	fx := seedWebhookFixture(t, ctx, repo, 1)

	// Push next_retry_at into the future.
	if _, err := pool.Exec(ctx,
		`UPDATE webhook_events SET next_retry_at = NOW() + INTERVAL '1 hour' WHERE id = $1`,
		uuid.UUID(fx.eventIDs[0]),
	); err != nil {
		t.Fatalf("update next_retry_at: %v", err)
	}

	ev, err := repo.ClaimNext(ctx, core.NewWebhookClaimToken(), time.Now().UTC().Add(time.Minute))
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
	ctx := context.Background()
	fx := seedWebhookFixture(t, ctx, repo, 2)

	// Backdate ours so ours sort to the front of any unrelated rows
	// in the dev DB. Use distinct timestamps that are also OLDER than
	// any plausible NOW()-seeded row from an unrelated test.
	farPast := time.Now().UTC().Add(-365 * 24 * time.Hour) // 1 year ago
	if _, err := pool.Exec(ctx,
		`UPDATE webhook_events SET created_at = $1 WHERE id = $2`,
		farPast.Add(-time.Hour), uuid.UUID(fx.eventIDs[0]),
	); err != nil {
		t.Fatalf("backdate first event: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE webhook_events SET created_at = $1 WHERE id = $2`,
		farPast, uuid.UUID(fx.eventIDs[1]),
	); err != nil {
		t.Fatalf("forward-date second event: %v", err)
	}

	ev, err := repo.ClaimNext(ctx, core.NewWebhookClaimToken(), time.Now().UTC().Add(time.Minute))
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
	ctx := context.Background()
	fx := seedWebhookFixture(t, ctx, repo, 1)

	// Stamp a stale claim directly via SQL (simulates "worker died").
	staleToken := uuid.New()
	if _, err := pool.Exec(ctx,
		`UPDATE webhook_events
		    SET claim_token = $1,
		        claim_expires_at = NOW() - INTERVAL '1 hour'
		  WHERE id = $2`,
		staleToken, uuid.UUID(fx.eventIDs[0]),
	); err != nil {
		t.Fatalf("stamp stale claim: %v", err)
	}

	// ClaimNext should NOT see the row — it's still claimed.
	ev, err := repo.ClaimNext(ctx, core.NewWebhookClaimToken(), time.Now().UTC().Add(time.Minute))
	if err != nil {
		t.Fatalf("ClaimNext (pre-release): %v", err)
	}
	if ev != nil {
		t.Fatalf("expected ClaimNext to skip claimed row, got id=%s", ev.ID)
	}

	// Release stale claims.
	n, err := repo.ReleaseStaleClaims(ctx)
	if err != nil {
		t.Fatalf("ReleaseStaleClaims: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected ReleaseStaleClaims to release 1 row, got %d", n)
	}

	// Now ClaimNext should succeed.
	ev, err = repo.ClaimNext(ctx, core.NewWebhookClaimToken(), time.Now().UTC().Add(time.Minute))
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
	ctx := context.Background()
	fx := seedWebhookFixture(t, ctx, repo, 1)

	ev, err := repo.ClaimNext(ctx, core.NewWebhookClaimToken(), time.Now().UTC().Add(time.Minute))
	if err != nil {
		t.Fatalf("ClaimNext: %v", err)
	}
	if ev == nil {
		t.Fatal("expected to claim seeded row")
	}

	status := 200
	body := "ok"
	if err := repo.MarkDelivered(ctx, ev.ID, 1, domain.DeliveryResult{
		ResponseStatus: &status,
		ResponseBody:   &body,
	}); err != nil {
		t.Fatalf("MarkDelivered: %v", err)
	}

	// Re-claim should miss.
	again, err := repo.ClaimNext(ctx, core.NewWebhookClaimToken(), time.Now().UTC().Add(time.Minute))
	if err != nil {
		t.Fatalf("ClaimNext (post-mark): %v", err)
	}
	if again != nil {
		t.Fatalf("expected delivered row to be invisible to ClaimNext, got id=%s", again.ID)
	}

	// Verify persisted state.
	persisted, err := repo.GetEventByID(ctx, fx.eventIDs[0])
	if err != nil || persisted == nil {
		t.Fatalf("GetEventByID: %v / %v", persisted, err)
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
	ctx := context.Background()
	fx := seedWebhookFixture(t, ctx, repo, 1)

	ev, err := repo.ClaimNext(ctx, core.NewWebhookClaimToken(), time.Now().UTC().Add(time.Minute))
	if err != nil || ev == nil {
		t.Fatalf("ClaimNext: %v / %v", err, ev)
	}

	// Schedule retry in the past — equivalent to "the back-off has
	// already elapsed by the time we check".
	if err := repo.MarkFailedRetry(ctx, ev.ID, 1,
		domain.DeliveryResult{},
		time.Now().UTC().Add(-1*time.Minute),
	); err != nil {
		t.Fatalf("MarkFailedRetry: %v", err)
	}

	// Should be claimable again.
	again, err := repo.ClaimNext(ctx, core.NewWebhookClaimToken(), time.Now().UTC().Add(time.Minute))
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

// NOTE: an earlier draft included TestWebhookRepo_EnqueueIdempotent
// that asserted on a partial unique index over (domain_event_id,
// endpoint_id). That index was dropped — see migration 032 comment
// for why. Webhook delivery is at-least-once; the envelope's event
// id is the consumer-facing dedup token.
