package webhook

import (
	"context"
	"log/slog"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

// retrySchedule is the per-attempt delay before the next retry.
// Index = previous attempt count. After len(retrySchedule)+1 total
// attempts the row is marked failed (no further retries).
//
// Schedule from the spec: 1m, 5m, 30m, 2h, 12h, 24h. Six entries =
// six retries after the initial attempt = seven total attempts max.
//
// Behavior change vs the old in-process retry loop, which used
// 1s, 5s, 30s, 5m, 30m. The longer cadence reflects the durable
// model: a temporarily-down endpoint will recover within minutes,
// not seconds; rapid retries waste both ends. e2e tests do not
// assert on retry timing (24_webhook_deliveries.hurl asserts on
// status existence, not "delivered within X seconds").
var retrySchedule = [...]time.Duration{
	1 * time.Minute,
	5 * time.Minute,
	30 * time.Minute,
	2 * time.Hour,
	12 * time.Hour,
	24 * time.Hour,
}

// claimWindow is how long a worker holds a claim before the row is
// considered abandoned and reclaimable. Comfortably exceeds the HTTP
// delivery timeout (10s) + persistence + slack so a slow worker is
// not stolen from. A worker that crashes mid-delivery loses the
// claim after this window and ReleaseStaleClaims reaps it.
const claimWindow = 60 * time.Second

// staleClaimSweepInterval is how often the pool releases stale
// claims (workers that died mid-delivery without releasing). The
// startup sweep fires once at Pool.Start; this ticker handles the
// steady-state case where a long-running pod loses workers without
// restart.
const staleClaimSweepInterval = 30 * time.Second

// queuePollInterval is how long a worker sleeps when the queue is
// empty before checking again. Short enough that delivery latency
// for a single new event is reasonable (<= 2s); long enough that an
// idle fleet doesn't hammer the DB. With N workers the effective
// poll rate is N / queuePollInterval — tune via cfg.WebhookWorkers.
const queuePollInterval = 2 * time.Second

// DeliverFunc is the single-attempt HTTP delivery callback supplied
// to NewPool. Signature matches webhook.Service.AttemptDelivery so
// background.go can pass it without an adapter. Returns the response
// outcome on every call (even failure — captured response status
// and body are still useful for the delivery log).
type DeliverFunc func(ctx context.Context, event *domain.WebhookEvent, endpoint domain.WebhookEndpoint) (deliveryResult, error)

// Pool runs N workers consuming the webhook_events outbox via
// ClaimNext. Each worker is a long-lived goroutine that loops:
// claim → look up endpoint → deliver once → record outcome → repeat.
// The pool's lifetime is the process — Start blocks until ctx is
// cancelled (typically by SIGTERM in serve.go).
type Pool struct {
	workers     int
	repo        domain.WebhookRepository
	txManager   domain.TxManager
	deliverFunc DeliverFunc
}

// NewPool constructs a Pool with the given concurrency. Production
// callers wire workers from cfg.WebhookWorkers (default 4). Worker
// counts < 1 are clamped to 1 — a "0 workers" pool would silently
// drop all deliveries.
func NewPool(workers int, repo domain.WebhookRepository, txManager domain.TxManager, deliverFunc DeliverFunc) *Pool {
	if workers < 1 {
		workers = 1
	}
	return &Pool{
		workers:     workers,
		repo:        repo,
		txManager:   txManager,
		deliverFunc: deliverFunc,
	}
}

// Start launches the worker pool plus a stale-claim sweeper. Returns
// when ctx is cancelled. Caller (background.go) typically runs this
// in its own goroutine alongside the existing sweep loop.
//
// The startup ReleaseStaleClaims call recovers any rows still
// claimed from a previous process generation. Without it, a hard
// crash during the previous run could leave rows pinned with a
// claim_token that no live worker owns, blocking delivery until
// claim_expires_at passes (up to claimWindow seconds).
func (p *Pool) Start(ctx context.Context) {
	// ReleaseStaleClaims is a cross-tenant sweep on webhook_events; wrap
	// in WithSystemContext so RLS short-circuits explicitly (PR-B,
	// migration 034).
	releaseStale := func(label string) {
		err := p.txManager.WithSystemContext(ctx, func(ctx context.Context) error {
			n, rerr := p.repo.ReleaseStaleClaims(ctx)
			if rerr != nil {
				return rerr
			}
			if n > 0 {
				slog.Info("webhook worker: released stale claims", "label", label, "count", n)
			}
			return nil
		})
		if err != nil {
			slog.Error("webhook worker: stale-claim sweep failed", "label", label, "error", err)
		}
	}

	releaseStale("startup")

	sweepTicker := time.NewTicker(staleClaimSweepInterval)
	defer sweepTicker.Stop()

	workerCtx, cancelWorkers := context.WithCancel(ctx)
	defer cancelWorkers()

	for i := 0; i < p.workers; i++ {
		go p.workerLoop(workerCtx, i)
	}

	for {
		select {
		case <-ctx.Done():
			slog.Info("webhook worker pool stopped")
			return
		case <-sweepTicker.C:
			releaseStale("periodic")
		}
	}
}

// workerLoop is one worker's main loop. Claims a row, delivers it,
// records the outcome, then repeats. Sleeps queuePollInterval when
// the queue is empty so it's a self-throttling busy-loop rather
// than a tight spin against an empty DB.
func (p *Pool) workerLoop(ctx context.Context, workerID int) {
	for {
		if err := ctx.Err(); err != nil {
			return
		}

		claimToken := core.NewWebhookClaimToken()
		claimExpires := time.Now().UTC().Add(claimWindow)

		// Claim runs without tenant context — the worker pool is global.
		// WithSystemContext opens a tx with app.system_context='true' so
		// RLS short-circuits the tenant predicate on webhook_events.
		// The SKIP LOCKED row lock acquired by ClaimNext is held for
		// the duration of the UPDATE (released on commit).
		var ev *domain.WebhookEvent
		err := p.txManager.WithSystemContext(ctx, func(ctx context.Context) error {
			var cerr error
			ev, cerr = p.repo.ClaimNext(ctx, claimToken, claimExpires)
			return cerr
		})
		if err != nil {
			slog.Error("webhook worker: claim error", "worker", workerID, "error", err)
			if !sleep(ctx, queuePollInterval) {
				return
			}
			continue
		}
		if ev == nil {
			// Queue empty — sleep and retry.
			if !sleep(ctx, queuePollInterval) {
				return
			}
			continue
		}

		p.deliverClaimed(ctx, workerID, ev, claimToken)
	}
}

// deliverClaimed performs one delivery attempt for a claimed event,
// then records the outcome. Called once per workerLoop iteration.
//
// claimToken is the per-claim nonce minted by workerLoop and stamped
// on the row via ClaimNext. It is threaded through every Mark* call
// so the repo's WHERE-clause predicate refuses overwrites when a
// stale-claim sweep handed the row to a different worker mid-attempt.
//
// Endpoint lookup runs inside the event's tenant tx because
// webhook_endpoints is RLS-scoped on (account_id, environment) and
// would return zero rows under the worker's anonymous context.
func (p *Pool) deliverClaimed(ctx context.Context, workerID int, ev *domain.WebhookEvent, claimToken core.WebhookClaimToken) {
	var endpoint *domain.WebhookEndpoint
	err := p.txManager.WithTargetAccount(ctx, ev.AccountID, ev.Environment, func(ctx context.Context) error {
		var lerr error
		endpoint, lerr = p.repo.GetEndpointByID(ctx, ev.EndpointID)
		return lerr
	})
	if err != nil {
		slog.Error("webhook worker: endpoint lookup failed", "worker", workerID, "event_id", ev.ID, "error", err)
		// Treat as terminal — the row is in a bad state we can't recover from
		// in this attempt. Mark final so it doesn't loop forever; an operator
		// can redeliver after fixing the underlying state.
		p.recordFinalLogged(ctx, workerID, ev, claimToken, ev.Attempts+1, deliveryResult{})
		return
	}
	if endpoint == nil {
		// Endpoint deleted between enqueue and delivery — terminal.
		slog.Warn("webhook worker: endpoint missing", "worker", workerID, "event_id", ev.ID, "endpoint_id", ev.EndpointID)
		p.recordFinalLogged(ctx, workerID, ev, claimToken, ev.Attempts+1, deliveryResult{})
		return
	}

	result, postErr := p.deliverFunc(ctx, ev, *endpoint)
	nextAttempts := ev.Attempts + 1

	if postErr == nil {
		p.recordDeliveredLogged(ctx, workerID, ev, claimToken, nextAttempts, result)
		return
	}

	// Failure. Decide retry vs final based on the attempt budget.
	// nextAttempts is 1-indexed; retrySchedule[i] is the wait AFTER
	// attempt i+1 fails. We have len(retrySchedule)+1 total attempts.
	if nextAttempts > len(retrySchedule) {
		p.recordFinalLogged(ctx, workerID, ev, claimToken, nextAttempts, result)
		slog.Error("webhook worker: delivery failed permanently",
			"worker", workerID, "event_id", ev.ID, "endpoint", endpoint.URL,
			"attempts", nextAttempts, "error", postErr)
		return
	}

	nextRetry := time.Now().UTC().Add(retrySchedule[nextAttempts-1])
	p.recordRetryLogged(ctx, workerID, ev, claimToken, nextAttempts, result, nextRetry)
}

// recordDelivered / recordRetry / recordFinal wrap the repo calls in
// WithTargetAccount so RLS scopes the UPDATE to the event's tenant.
// The claim_token predicate (added in PR-A.1) layers on top: only the
// worker that currently owns the claim can write the outcome. A worker
// whose claim was reclaimed mid-attempt (slow delivery → claim expires
// → ReleaseStaleClaims hands the row to another worker) gets rowcount=0
// and silently moves on rather than overwriting the new owner's state.
func (p *Pool) recordDelivered(ctx context.Context, ev *domain.WebhookEvent, claimToken core.WebhookClaimToken, attempts int, result deliveryResult) (int64, error) {
	var n int64
	err := p.txManager.WithTargetAccount(ctx, ev.AccountID, ev.Environment, func(ctx context.Context) error {
		var rerr error
		n, rerr = p.repo.MarkDelivered(ctx, ev.ID, claimToken, attempts, deliveryResultToDomain(result))
		return rerr
	})
	return n, err
}

func (p *Pool) recordRetry(ctx context.Context, ev *domain.WebhookEvent, claimToken core.WebhookClaimToken, attempts int, result deliveryResult, nextRetry time.Time) (int64, error) {
	var n int64
	err := p.txManager.WithTargetAccount(ctx, ev.AccountID, ev.Environment, func(ctx context.Context) error {
		var rerr error
		n, rerr = p.repo.MarkFailedRetry(ctx, ev.ID, claimToken, attempts, deliveryResultToDomain(result), nextRetry)
		return rerr
	})
	return n, err
}

func (p *Pool) recordFinal(ctx context.Context, ev *domain.WebhookEvent, claimToken core.WebhookClaimToken, attempts int, result deliveryResult) (int64, error) {
	var n int64
	err := p.txManager.WithTargetAccount(ctx, ev.AccountID, ev.Environment, func(ctx context.Context) error {
		var rerr error
		n, rerr = p.repo.MarkFailedFinal(ctx, ev.ID, claimToken, attempts, deliveryResultToDomain(result))
		return rerr
	})
	return n, err
}

// recordDeliveredLogged / recordRetryLogged / recordFinalLogged are
// thin wrappers that translate the (rowcount, err) pair into structured
// logging. A nonzero err is a real DB failure; rowcount==0 with err==nil
// means the claim expired and another worker now owns the row — log at
// WARN and move on without erroring.
func (p *Pool) recordDeliveredLogged(ctx context.Context, workerID int, ev *domain.WebhookEvent, claimToken core.WebhookClaimToken, attempts int, result deliveryResult) {
	n, err := p.recordDelivered(ctx, ev, claimToken, attempts, result)
	if err != nil {
		slog.Error("webhook worker: mark delivered failed", "worker", workerID, "event_id", ev.ID, "error", err)
		return
	}
	if n == 0 {
		slog.Warn("webhook worker: lost claim before marking outcome", "worker", workerID, "event_id", ev.ID, "operation", "delivered")
	}
}

func (p *Pool) recordRetryLogged(ctx context.Context, workerID int, ev *domain.WebhookEvent, claimToken core.WebhookClaimToken, attempts int, result deliveryResult, nextRetry time.Time) {
	n, err := p.recordRetry(ctx, ev, claimToken, attempts, result, nextRetry)
	if err != nil {
		slog.Error("webhook worker: mark retry failed", "worker", workerID, "event_id", ev.ID, "error", err)
		return
	}
	if n == 0 {
		slog.Warn("webhook worker: lost claim before marking outcome", "worker", workerID, "event_id", ev.ID, "operation", "retry")
	}
}

func (p *Pool) recordFinalLogged(ctx context.Context, workerID int, ev *domain.WebhookEvent, claimToken core.WebhookClaimToken, attempts int, result deliveryResult) {
	n, err := p.recordFinal(ctx, ev, claimToken, attempts, result)
	if err != nil {
		slog.Error("webhook worker: mark final-failed failed", "worker", workerID, "event_id", ev.ID, "error", err)
		return
	}
	if n == 0 {
		slog.Warn("webhook worker: lost claim before marking outcome", "worker", workerID, "event_id", ev.ID, "operation", "final")
	}
}

// deliveryResultToDomain converts the package-private deliveryResult
// (HTTP-shaped) to the cross-package domain.DeliveryResult (DB-shaped).
// The two shapes diverge on response_status: deliveryResult uses 0
// to mean "no response received"; domain uses *int with nil for the
// same. ResponseHeaders narrows from json.RawMessage to nil-when-empty
// so the SQL writes NULL instead of an empty JSON object.
func deliveryResultToDomain(r deliveryResult) domain.DeliveryResult {
	var statusCode *int
	if r.StatusCode != 0 {
		sc := r.StatusCode
		statusCode = &sc
	}
	headers := r.ResponseHeaders
	if len(headers) == 0 {
		headers = nil
	}
	return domain.DeliveryResult{
		ResponseStatus:        statusCode,
		ResponseBody:          r.ResponseBody,
		ResponseBodyTruncated: r.BodyTruncated,
		ResponseHeaders:       headers,
	}
}

// sleep waits for d, returning false when ctx is cancelled before d
// elapses. Single helper for the two empty-queue / claim-error paths
// in workerLoop so they share exit semantics.
func sleep(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}
