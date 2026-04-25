package webhook

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

// passthroughTxManager runs fn directly without opening a transaction.
// Worker tests don't exercise the SQL layer — the repo is a stub —
// so the tx boundary is a no-op. Mirrors search/service_test.go.
type passthroughTxManager struct{}

func (passthroughTxManager) WithTargetAccount(ctx context.Context, _ core.AccountID, _ core.Environment, fn func(context.Context) error) error {
	return fn(ctx)
}

func (passthroughTxManager) WithTx(ctx context.Context, fn func(context.Context) error) error {
	return fn(ctx)
}

// stubWebhookRepo is a hand-rolled fake for the methods the worker
// pool exercises: ClaimNext, GetEndpointByID, ReleaseStaleClaims, and
// Mark{Delivered,FailedRetry,FailedFinal}. Other interface methods
// satisfy the type but panic if called — the worker shouldn't reach
// for them.
type stubWebhookRepo struct {
	mu sync.Mutex

	// Queue of events to hand back from ClaimNext (one per claim).
	// Drained in order; an empty queue returns (nil, nil).
	pending []*domain.WebhookEvent
	// Endpoint returned by GetEndpointByID. nil simulates "deleted".
	endpoint *domain.WebhookEndpoint
	// markRows controls the rowcount returned by every Mark* call.
	// Default 0 is treated as 1 (success). Set to a literal 0 via
	// markRowsLost=true to simulate a lost claim.
	markRowsLost bool

	// Recorded calls — assertions read these after the worker runs.
	deliveredCalls []markCall
	retryCalls     []markCall
	finalCalls     []markCall
	releaseCalls   atomic.Int32
}

type markCall struct {
	id         core.WebhookEventID
	claimToken core.WebhookClaimToken
	attempts   int
	result     domain.DeliveryResult
	nextRetry  *time.Time // populated only on retry
}

// markRowsAffected returns the rowcount the stub will report for a
// Mark* call. Default is 1 (claim still held); markRowsLost flips it
// to 0 so the worker takes the "lost claim" branch.
func (r *stubWebhookRepo) markRowsAffected() int64 {
	if r.markRowsLost {
		return 0
	}
	return 1
}

func (r *stubWebhookRepo) ClaimNext(_ context.Context, _ core.WebhookClaimToken, _ time.Time) (*domain.WebhookEvent, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.pending) == 0 {
		return nil, nil
	}
	ev := r.pending[0]
	r.pending = r.pending[1:]
	return ev, nil
}

func (r *stubWebhookRepo) ReleaseStaleClaims(context.Context) (int, error) {
	r.releaseCalls.Add(1)
	return 0, nil
}

func (r *stubWebhookRepo) MarkDelivered(_ context.Context, id core.WebhookEventID, claimToken core.WebhookClaimToken, attempts int, result domain.DeliveryResult) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.deliveredCalls = append(r.deliveredCalls, markCall{id: id, claimToken: claimToken, attempts: attempts, result: result})
	return r.markRowsAffected(), nil
}

func (r *stubWebhookRepo) MarkFailedRetry(_ context.Context, id core.WebhookEventID, claimToken core.WebhookClaimToken, attempts int, result domain.DeliveryResult, nextRetry time.Time) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	nr := nextRetry
	r.retryCalls = append(r.retryCalls, markCall{id: id, claimToken: claimToken, attempts: attempts, result: result, nextRetry: &nr})
	return r.markRowsAffected(), nil
}

func (r *stubWebhookRepo) MarkFailedFinal(_ context.Context, id core.WebhookEventID, claimToken core.WebhookClaimToken, attempts int, result domain.DeliveryResult) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.finalCalls = append(r.finalCalls, markCall{id: id, claimToken: claimToken, attempts: attempts, result: result})
	return r.markRowsAffected(), nil
}

func (r *stubWebhookRepo) GetEndpointByID(_ context.Context, _ core.WebhookEndpointID) (*domain.WebhookEndpoint, error) {
	return r.endpoint, nil
}

// Unused interface methods — present only to satisfy
// domain.WebhookRepository.
func (*stubWebhookRepo) CreateEndpoint(context.Context, *domain.WebhookEndpoint) error {
	panic("unused")
}

func (*stubWebhookRepo) ListEndpoints(context.Context, core.Cursor, int) ([]domain.WebhookEndpoint, bool, error) {
	panic("unused")
}

func (*stubWebhookRepo) DeleteEndpoint(context.Context, core.WebhookEndpointID) error {
	panic("unused")
}

func (*stubWebhookRepo) GetActiveEndpointsByEvent(context.Context, core.EventType) ([]domain.WebhookEndpoint, error) {
	panic("unused")
}

func (*stubWebhookRepo) CreateEvent(context.Context, *domain.WebhookEvent) error { panic("unused") }

func (*stubWebhookRepo) UpdateEventStatus(context.Context, core.WebhookEventID, core.DeliveryStatus, int, *int, *string, bool, json.RawMessage, *time.Time) error {
	panic("unused")
}

func (*stubWebhookRepo) GetEventByID(context.Context, core.WebhookEventID) (*domain.WebhookEvent, error) {
	panic("unused")
}

func (*stubWebhookRepo) ListEventsByEndpoint(context.Context, core.WebhookEndpointID, domain.WebhookDeliveryFilter, core.Cursor, int) ([]domain.WebhookEvent, bool, error) {
	panic("unused")
}

func (*stubWebhookRepo) GetDispatcherCheckpoint(context.Context) (*domain.WebhookDispatcherCheckpoint, error) {
	panic("unused")
}

func (*stubWebhookRepo) UpdateDispatcherCheckpoint(context.Context, core.DomainEventID) error {
	panic("unused")
}

func (*stubWebhookRepo) RotateSigningSecret(context.Context, core.WebhookEndpointID, []byte) error {
	panic("unused")
}

func (*stubWebhookRepo) ListEndpointsNeedingEncryption(context.Context) ([]domain.WebhookEndpointLegacySecret, error) {
	panic("unused")
}

func (*stubWebhookRepo) WriteEncryptedSigningSecret(context.Context, core.WebhookEndpointID, []byte) error {
	panic("unused")
}

// newTestEvent constructs a WebhookEvent with the minimal fields the
// worker reads (ID, AccountID, EndpointID, Environment, Attempts).
func newTestEvent(attempts int) *domain.WebhookEvent {
	return &domain.WebhookEvent{
		ID:          core.NewWebhookEventID(),
		AccountID:   core.NewAccountID(),
		EndpointID:  core.NewWebhookEndpointID(),
		Environment: core.Environment("live"),
		EventType:   core.EventType("test.event"),
		Status:      core.DeliveryStatusPending,
		Attempts:    attempts,
		CreatedAt:   time.Now().UTC(),
	}
}

// runOneIteration drives Pool.deliverClaimed directly. The full
// workerLoop sleeps when the queue is empty; tests prefer to drive
// one iteration deterministically. A fresh claim_token is minted per
// invocation, mirroring workerLoop's per-claim nonce.
func runOneIteration(t *testing.T, p *Pool, ev *domain.WebhookEvent) {
	t.Helper()
	p.deliverClaimed(context.Background(), 0, ev, core.NewWebhookClaimToken())
}

// TestPool_DeliverClaimed_HappyPath: a successful HTTP attempt
// → MarkDelivered with attempts=ev.Attempts+1.
func TestPool_DeliverClaimed_HappyPath(t *testing.T) {
	repo := &stubWebhookRepo{
		endpoint: &domain.WebhookEndpoint{ID: core.NewWebhookEndpointID(), URL: "https://example.com/hook"},
	}
	deliver := func(_ context.Context, _ *domain.WebhookEvent, _ domain.WebhookEndpoint) (deliveryResult, error) {
		status := 200
		body := "ok"
		return deliveryResult{StatusCode: status, ResponseBody: &body}, nil
	}
	pool := NewPool(1, repo, passthroughTxManager{}, deliver)
	ev := newTestEvent(0)

	runOneIteration(t, pool, ev)

	if got := len(repo.deliveredCalls); got != 1 {
		t.Fatalf("expected 1 delivered call, got %d (retry=%d, final=%d)", got, len(repo.retryCalls), len(repo.finalCalls))
	}
	got := repo.deliveredCalls[0]
	if got.id != ev.ID {
		t.Errorf("delivered call id mismatch: want %s, got %s", ev.ID, got.id)
	}
	if got.attempts != 1 {
		t.Errorf("delivered call attempts: want 1, got %d", got.attempts)
	}
	if got.result.ResponseStatus == nil || *got.result.ResponseStatus != 200 {
		t.Errorf("delivered call status: want *200, got %v", got.result.ResponseStatus)
	}
}

// TestPool_DeliverClaimed_RetryPath: a failure on attempt 1 (of 7
// total) → MarkFailedRetry with nextRetry == now + retrySchedule[0].
func TestPool_DeliverClaimed_RetryPath(t *testing.T) {
	repo := &stubWebhookRepo{
		endpoint: &domain.WebhookEndpoint{ID: core.NewWebhookEndpointID(), URL: "https://example.com/hook"},
	}
	deliver := func(context.Context, *domain.WebhookEvent, domain.WebhookEndpoint) (deliveryResult, error) {
		return deliveryResult{StatusCode: 500}, errors.New("server error")
	}
	pool := NewPool(1, repo, passthroughTxManager{}, deliver)
	ev := newTestEvent(0) // attempts=0 → nextAttempts=1, schedule index 0

	before := time.Now().UTC()
	runOneIteration(t, pool, ev)
	after := time.Now().UTC()

	if len(repo.retryCalls) != 1 {
		t.Fatalf("expected 1 retry call, got %d (delivered=%d, final=%d)", len(repo.retryCalls), len(repo.deliveredCalls), len(repo.finalCalls))
	}
	got := repo.retryCalls[0]
	if got.attempts != 1 {
		t.Errorf("retry attempts: want 1, got %d", got.attempts)
	}
	if got.nextRetry == nil {
		t.Fatal("retry nextRetry must be non-nil")
	}
	expectedMin := before.Add(retrySchedule[0])
	expectedMax := after.Add(retrySchedule[0])
	if got.nextRetry.Before(expectedMin) || got.nextRetry.After(expectedMax) {
		t.Errorf("retry nextRetry out of range: want [%v, %v], got %v", expectedMin, expectedMax, *got.nextRetry)
	}
}

// TestPool_DeliverClaimed_FinalFailurePath: a failure when the
// budget is exhausted → MarkFailedFinal. Setting attempts to
// len(retrySchedule) on the event means nextAttempts =
// len(retrySchedule)+1 which exceeds the schedule length.
func TestPool_DeliverClaimed_FinalFailurePath(t *testing.T) {
	repo := &stubWebhookRepo{
		endpoint: &domain.WebhookEndpoint{ID: core.NewWebhookEndpointID(), URL: "https://example.com/hook"},
	}
	deliver := func(context.Context, *domain.WebhookEvent, domain.WebhookEndpoint) (deliveryResult, error) {
		status := 500
		return deliveryResult{StatusCode: status}, errors.New("permanent failure")
	}
	pool := NewPool(1, repo, passthroughTxManager{}, deliver)

	// Event has already been retried len(retrySchedule) times. The next
	// failure (the (len+1)th total attempt) must land in MarkFailedFinal.
	ev := newTestEvent(len(retrySchedule))

	runOneIteration(t, pool, ev)

	if len(repo.finalCalls) != 1 {
		t.Fatalf("expected 1 final call, got %d (delivered=%d, retry=%d)", len(repo.finalCalls), len(repo.deliveredCalls), len(repo.retryCalls))
	}
	got := repo.finalCalls[0]
	wantAttempts := len(retrySchedule) + 1
	if got.attempts != wantAttempts {
		t.Errorf("final attempts: want %d, got %d", wantAttempts, got.attempts)
	}
	if got.result.ResponseStatus == nil || *got.result.ResponseStatus != 500 {
		t.Errorf("final status: want *500, got %v", got.result.ResponseStatus)
	}
}

// TestPool_DeliverClaimed_EndpointMissing: GetEndpointByID returns
// nil (endpoint deleted between enqueue and delivery) → MarkFailedFinal,
// no HTTP attempt. Nothing should hit the deliver func.
func TestPool_DeliverClaimed_EndpointMissing(t *testing.T) {
	repo := &stubWebhookRepo{endpoint: nil}
	deliveredCount := 0
	deliver := func(context.Context, *domain.WebhookEvent, domain.WebhookEndpoint) (deliveryResult, error) {
		deliveredCount++
		return deliveryResult{}, nil
	}
	pool := NewPool(1, repo, passthroughTxManager{}, deliver)
	ev := newTestEvent(0)

	runOneIteration(t, pool, ev)

	if deliveredCount != 0 {
		t.Errorf("deliver func must not be called when endpoint is missing, called %d times", deliveredCount)
	}
	if len(repo.finalCalls) != 1 {
		t.Errorf("expected 1 final call (endpoint-missing terminal), got %d", len(repo.finalCalls))
	}
}

// TestPool_WorkerLoop_EmptyQueue verifies the workerLoop sleeps
// and exits cleanly when ctx is cancelled while the queue is empty.
// No repo Mark* calls should be made; ClaimNext is the only repo
// method touched.
func TestPool_WorkerLoop_EmptyQueue(t *testing.T) {
	repo := &stubWebhookRepo{} // pending is empty, ClaimNext returns (nil, nil)
	deliver := func(context.Context, *domain.WebhookEvent, domain.WebhookEndpoint) (deliveryResult, error) {
		t.Fatal("deliver func must not be called when queue is empty")
		return deliveryResult{}, nil
	}
	pool := NewPool(1, repo, passthroughTxManager{}, deliver)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		pool.workerLoop(ctx, 0)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("workerLoop did not exit after ctx cancel")
	}

	if len(repo.deliveredCalls) != 0 || len(repo.retryCalls) != 0 || len(repo.finalCalls) != 0 {
		t.Errorf("no Mark* calls expected on empty queue, got delivered=%d retry=%d final=%d",
			len(repo.deliveredCalls), len(repo.retryCalls), len(repo.finalCalls))
	}
}

// TestPool_DeliverClaimed_LostClaim_DoesNotMarkOutcome simulates the
// race where a worker's claim has expired and been reissued by
// ReleaseStaleClaims to a different worker between the time we fired
// the HTTP POST and the time we tried to record the outcome. The
// repo Mark* call returns rowcount=0 (claim_token mismatch); the
// worker MUST log a WARN and move on without erroring or retrying.
//
// The stub records the call so we can verify the worker DID attempt
// the write (i.e. it didn't pre-check) — the protection is the SQL
// predicate, not application-side logic.
func TestPool_DeliverClaimed_LostClaim_DoesNotMarkOutcome(t *testing.T) {
	repo := &stubWebhookRepo{
		endpoint:     &domain.WebhookEndpoint{ID: core.NewWebhookEndpointID(), URL: "https://example.com/hook"},
		markRowsLost: true, // every Mark* returns (0, nil)
	}
	deliver := func(context.Context, *domain.WebhookEvent, domain.WebhookEndpoint) (deliveryResult, error) {
		status := 200
		body := "ok"
		return deliveryResult{StatusCode: status, ResponseBody: &body}, nil
	}
	pool := NewPool(1, repo, passthroughTxManager{}, deliver)
	ev := newTestEvent(0)

	// MUST NOT panic, error, or retry — losing a claim is normal.
	runOneIteration(t, pool, ev)

	// The worker DID attempt the write (the SQL predicate is what
	// rejects, not application code).
	if got := len(repo.deliveredCalls); got != 1 {
		t.Fatalf("expected 1 delivered call attempt even on lost claim, got %d", got)
	}
	// And no follow-up retry/final was scheduled — the worker accepts
	// the lost-claim outcome and moves on.
	if len(repo.retryCalls) != 0 || len(repo.finalCalls) != 0 {
		t.Errorf("lost claim must not trigger retry/final; got retry=%d final=%d", len(repo.retryCalls), len(repo.finalCalls))
	}
}

// TestPool_DeliverClaimed_PassesClaimToken verifies that the per-claim
// token threaded through deliverClaimed reaches every Mark* repo call.
// The token is the SQL gate that prevents stale-claim writes; if the
// worker forgets to pass it, the WHERE predicate would reject every
// legitimate write under the empty-uuid mismatch.
func TestPool_DeliverClaimed_PassesClaimToken(t *testing.T) {
	repo := &stubWebhookRepo{
		endpoint: &domain.WebhookEndpoint{ID: core.NewWebhookEndpointID(), URL: "https://example.com/hook"},
	}
	deliver := func(context.Context, *domain.WebhookEvent, domain.WebhookEndpoint) (deliveryResult, error) {
		return deliveryResult{StatusCode: 200}, nil
	}
	pool := NewPool(1, repo, passthroughTxManager{}, deliver)
	ev := newTestEvent(0)

	wantToken := core.NewWebhookClaimToken()
	pool.deliverClaimed(context.Background(), 0, ev, wantToken)

	if len(repo.deliveredCalls) != 1 {
		t.Fatalf("expected 1 delivered call, got %d", len(repo.deliveredCalls))
	}
	if got := repo.deliveredCalls[0].claimToken; got != wantToken {
		t.Errorf("claim token mismatch: want %s, got %s", wantToken, got)
	}
}

// TestDeliveryResultToDomain_StatusZeroBecomesNil documents the
// StatusCode==0 → ResponseStatus==nil semantics. A 0 status from
// doPost means "no HTTP response received" (network error, DNS,
// timeout); it must be persisted as NULL, not 0.
func TestDeliveryResultToDomain_StatusZeroBecomesNil(t *testing.T) {
	got := deliveryResultToDomain(deliveryResult{StatusCode: 0})
	if got.ResponseStatus != nil {
		t.Errorf("StatusCode=0 must map to nil ResponseStatus, got %v", got.ResponseStatus)
	}
}

func TestDeliveryResultToDomain_StatusNonZeroPreserved(t *testing.T) {
	got := deliveryResultToDomain(deliveryResult{StatusCode: 502})
	if got.ResponseStatus == nil || *got.ResponseStatus != 502 {
		t.Errorf("StatusCode=502 must map to *502, got %v", got.ResponseStatus)
	}
}
