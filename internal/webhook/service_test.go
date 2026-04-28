package webhook

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/crypto"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

// fanoutStubRepo is a focused stub for DeliverDomainEvents tests.
// Implements only the methods that path touches; everything else
// panics so an accidental call surfaces loudly.
type fanoutStubRepo struct {
	mu sync.Mutex

	// endpointsByEvent dictates what GetActiveEndpointsByEvent returns
	// per event type. Missing key returns nil (no subscribers).
	endpointsByEvent map[core.EventType][]domain.WebhookEndpoint
	// endpointsErrFor returns an error for the named event type — used
	// to simulate a transient lookup failure.
	endpointsErrFor map[core.EventType]error
	// createErrFor returns an error when CreateEvent is called for the
	// given (event_type, endpoint) pair — simulates a CreateEvent
	// failure mid-batch.
	createErrFor map[string]error

	// inserted records every successful CreateEvent — assertions read
	// this to verify atomicity of partial-failure cases.
	inserted []core.WebhookEventID
}

func (r *fanoutStubRepo) GetActiveEndpointsByEvent(_ context.Context, t core.EventType) ([]domain.WebhookEndpoint, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.endpointsErrFor[t]; err != nil {
		return nil, err
	}
	return r.endpointsByEvent[t], nil
}

func (r *fanoutStubRepo) CreateEvent(_ context.Context, ev *domain.WebhookEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := string(ev.EventType) + ":" + ev.EndpointID.String()
	if err := r.createErrFor[key]; err != nil {
		return err
	}
	r.inserted = append(r.inserted, ev.ID)
	return nil
}

// rest of domain.WebhookRepository — unused by this path
func (*fanoutStubRepo) CreateEndpoint(context.Context, *domain.WebhookEndpoint) error {
	panic("unused")
}
func (*fanoutStubRepo) GetEndpointByID(context.Context, core.WebhookEndpointID) (*domain.WebhookEndpoint, error) {
	panic("unused")
}
func (*fanoutStubRepo) ListEndpoints(context.Context, core.Cursor, int) ([]domain.WebhookEndpoint, bool, error) {
	panic("unused")
}
func (*fanoutStubRepo) DeleteEndpoint(context.Context, core.WebhookEndpointID) error {
	panic("unused")
}
func (*fanoutStubRepo) UpdateEventStatus(context.Context, core.WebhookEventID, core.DeliveryStatus, int, *int, *string, bool, json.RawMessage, *time.Time) error {
	panic("unused")
}
func (*fanoutStubRepo) GetEventByID(context.Context, core.WebhookEventID) (*domain.WebhookEvent, error) {
	panic("unused")
}
func (*fanoutStubRepo) ListEventsByEndpoint(context.Context, core.WebhookEndpointID, domain.WebhookDeliveryFilter, core.Cursor, int) ([]domain.WebhookEvent, bool, error) {
	panic("unused")
}
func (*fanoutStubRepo) ClaimNext(context.Context, core.WebhookClaimToken, time.Time) (*domain.WebhookEvent, error) {
	panic("unused")
}
func (*fanoutStubRepo) ReleaseStaleClaims(context.Context) (int, error) { panic("unused") }
func (*fanoutStubRepo) MarkDelivered(context.Context, core.WebhookEventID, core.WebhookClaimToken, int, domain.DeliveryResult) (int64, error) {
	panic("unused")
}
func (*fanoutStubRepo) MarkFailedRetry(context.Context, core.WebhookEventID, core.WebhookClaimToken, int, domain.DeliveryResult, time.Time) (int64, error) {
	panic("unused")
}
func (*fanoutStubRepo) MarkFailedFinal(context.Context, core.WebhookEventID, core.WebhookClaimToken, int, domain.DeliveryResult) (int64, error) {
	panic("unused")
}
func (*fanoutStubRepo) GetDispatcherCheckpoint(context.Context) (*domain.WebhookDispatcherCheckpoint, error) {
	panic("unused")
}
func (*fanoutStubRepo) UpdateDispatcherCheckpoint(context.Context, core.DomainEventID) error {
	panic("unused")
}
func (*fanoutStubRepo) RotateSigningSecret(context.Context, core.WebhookEndpointID, []byte, []byte, time.Time) error {
	panic("unused")
}
func (*fanoutStubRepo) FinishSigningSecretRotation(context.Context, core.WebhookEndpointID) error {
	panic("unused")
}

func newFanoutTestService(repo *fanoutStubRepo) *Service {
	return &Service{
		txManager: passthroughTxManager{},
		webhooks:  repo,
	}
}

func newFanoutEvent(typ core.EventType) domain.DomainEvent {
	return domain.DomainEvent{
		ID:          core.NewDomainEventID(),
		AccountID:   core.NewAccountID(),
		Environment: core.Environment("live"),
		EventType:   typ,
		Payload:     json.RawMessage(`{}`),
	}
}

func newFanoutEndpoint() domain.WebhookEndpoint {
	return domain.WebhookEndpoint{
		ID:          core.NewWebhookEndpointID(),
		AccountID:   core.NewAccountID(),
		URL:         "https://example.test/hook",
		Environment: core.Environment("live"),
	}
}

// TestDeliverDomainEvents_AdvancesPastFullySuccessful confirms the
// new return-value contract: if every event's atomic insert succeeds,
// the returned ID equals the last event's ID.
func TestDeliverDomainEvents_AdvancesPastFullySuccessful(t *testing.T) {
	ep1 := newFanoutEndpoint()
	ep2 := newFanoutEndpoint()
	repo := &fanoutStubRepo{
		endpointsByEvent: map[core.EventType][]domain.WebhookEndpoint{
			"license.created":   {ep1, ep2},
			"machine.activated": {ep1},
		},
	}
	svc := newFanoutTestService(repo)

	e1 := newFanoutEvent("license.created")
	e2 := newFanoutEvent("machine.activated")
	got := svc.DeliverDomainEvents(context.Background(), []domain.DomainEvent{e1, e2})

	assert.Equal(t, e2.ID, got, "should advance to last fully-enqueued event")
	assert.Len(t, repo.inserted, 3, "expected 2 inserts for e1 + 1 for e2")
}

// TestDeliverDomainEvents_HaltsOnEndpointLookupFailure confirms a
// transient endpoint-lookup error halts checkpoint advance at the
// last successful event.
func TestDeliverDomainEvents_HaltsOnEndpointLookupFailure(t *testing.T) {
	ep := newFanoutEndpoint()
	repo := &fanoutStubRepo{
		endpointsByEvent: map[core.EventType][]domain.WebhookEndpoint{
			"license.created": {ep},
		},
		endpointsErrFor: map[core.EventType]error{
			"machine.activated": errors.New("simulated DB error"),
		},
	}
	svc := newFanoutTestService(repo)

	e1 := newFanoutEvent("license.created")
	e2 := newFanoutEvent("machine.activated") // lookup fails
	e3 := newFanoutEvent("license.created")   // never reached
	got := svc.DeliverDomainEvents(context.Background(), []domain.DomainEvent{e1, e2, e3})

	assert.Equal(t, e1.ID, got, "checkpoint must halt at last successful event before failure")
	assert.Len(t, repo.inserted, 1, "only e1's row should be inserted; e2 failed lookup, e3 never reached")
}

// TestDeliverDomainEvents_HaltsOnAtomicInsertFailure confirms that
// when one endpoint's CreateEvent fails inside the per-event tx, the
// whole event's enqueue rolls back (no partial insert) AND the
// checkpoint halts at the last successful event.
func TestDeliverDomainEvents_HaltsOnAtomicInsertFailure(t *testing.T) {
	ep1 := newFanoutEndpoint()
	ep2 := newFanoutEndpoint()
	e2 := newFanoutEvent("machine.activated")
	repo := &fanoutStubRepo{
		endpointsByEvent: map[core.EventType][]domain.WebhookEndpoint{
			"license.created":   {ep1},
			"machine.activated": {ep1, ep2},
		},
		// Fail the SECOND endpoint's insert for e2 — the tx-style
		// passthroughTxManager doesn't actually roll back, so the test
		// exercises the return-value contract rather than the SQL
		// rollback. The first insert for e2 LOOKS like it succeeded in
		// the stub, but the function returns e1's ID because the tx
		// closure returned an error.
		createErrFor: map[string]error{
			"machine.activated:" + ep2.ID.String(): errors.New("simulated insert failure"),
		},
	}
	svc := newFanoutTestService(repo)

	e1 := newFanoutEvent("license.created")
	got := svc.DeliverDomainEvents(context.Background(), []domain.DomainEvent{e1, e2})

	assert.Equal(t, e1.ID, got, "checkpoint must halt at last fully-successful event")
}

// TestDeliverDomainEvents_ReturnsZeroOnFirstEventFailure confirms
// that when the very first event fails, the function returns the
// zero ID — the caller leaves the checkpoint unchanged so the same
// range is reprocessed next tick.
func TestDeliverDomainEvents_ReturnsZeroOnFirstEventFailure(t *testing.T) {
	repo := &fanoutStubRepo{
		endpointsErrFor: map[core.EventType]error{
			"license.created": errors.New("simulated lookup failure"),
		},
	}
	svc := newFanoutTestService(repo)

	e1 := newFanoutEvent("license.created")
	got := svc.DeliverDomainEvents(context.Background(), []domain.DomainEvent{e1})

	var zero core.DomainEventID
	assert.Equal(t, zero, got, "first-event failure should return zero ID so caller halts checkpoint")
	assert.Empty(t, repo.inserted, "no rows should be inserted")
}

// TestDeliverDomainEvents_AdvancesPastNoSubscriberEvents confirms an
// event with zero matching endpoints is treated as fully-enqueued
// (vacuously true) so the checkpoint advances past it.
func TestDeliverDomainEvents_AdvancesPastNoSubscriberEvents(t *testing.T) {
	repo := &fanoutStubRepo{
		// No endpoints registered for any type.
	}
	svc := newFanoutTestService(repo)

	e1 := newFanoutEvent("license.created")
	e2 := newFanoutEvent("machine.activated")
	got := svc.DeliverDomainEvents(context.Background(), []domain.DomainEvent{e1, e2})

	assert.Equal(t, e2.ID, got, "no-subscriber events should not block checkpoint advance")
	assert.Empty(t, repo.inserted, "nothing to enqueue when no endpoints subscribe")
}

// =====================================================================
// Redeliver test infrastructure
// =====================================================================
//
// The Redeliver path exercises a different surface than fanout — it
// touches GetEndpointByID, GetEventByID, CreateEvent, MarkDelivered /
// MarkFailedFinal, and the DomainEventRepository. It also performs a
// real signed HTTP attempt against the endpoint URL.
//
// The fixtures below build a minimal but complete environment:
//   - countingTxManager: tracks how many WithTargetAccount transactions
//     the service opens (Redeliver invariant: exactly 2).
//   - redeliverStubRepo: a fresh, focused fake of domain.WebhookRepository
//     that only implements the methods Redeliver touches; the rest panic.
//   - domainEventStub: a minimal domain.DomainEventRepository fake with a
//     single Get fixture.
//   - newRedeliverTestEnv: composes a Service with a real *crypto.MasterKey
//     so AttemptDelivery's signing/decryption path runs end-to-end.
//
// The service is constructed in dev mode (isDev=true) because the SSRF
// dial-time guard refuses loopback addresses in production mode and
// httptest.NewServer always binds 127.0.0.1.

// countingTxManager is a passthrough TxManager that counts how many
// WithTargetAccount calls the caller has issued. Used to assert
// Redeliver opens exactly two tenant-scoped transactions per call.
type countingTxManager struct {
	targetAccountCalls int
	txCalls            int
	systemContextCalls int
}

func (m *countingTxManager) WithTargetAccount(ctx context.Context, _ core.AccountID, _ core.Environment, fn func(context.Context) error) error {
	m.targetAccountCalls++
	return fn(ctx)
}

func (m *countingTxManager) WithTx(ctx context.Context, fn func(context.Context) error) error {
	m.txCalls++
	return fn(ctx)
}

func (m *countingTxManager) WithSystemContext(ctx context.Context, fn func(context.Context) error) error {
	m.systemContextCalls++
	return fn(ctx)
}

// redeliverStubRepo is a focused stub for the Redeliver path. It
// satisfies the full domain.WebhookRepository interface but only
// implements the methods Redeliver actually touches; everything else
// panics so an accidental call surfaces loudly. Mirrors the
// fanoutStubRepo pattern.
type redeliverStubRepo struct {
	mu sync.Mutex

	// Fixtures returned by Get* methods.
	endpoint        *domain.WebhookEndpoint // GetEndpointByID
	originalEvent   *domain.WebhookEvent    // GetEventByID for the original eventID
	postMarkEvent   *domain.WebhookEvent    // GetEventByID after Mark*; built lazily on first Mark call
	endpointReturns error                   // optional error from GetEndpointByID
	getEventReturns error                   // optional error from GetEventByID

	// CreateEvent capture: every successful insert is appended here.
	created []*domain.WebhookEvent

	// Mark behavior knobs.
	markDeliveredForceZero bool // simulate claim-token race on MarkDelivered
	markFailedForceZero    bool // simulate claim-token race on MarkFailedFinal

	// Recorded Mark calls — useful for asserting attempts/result.
	deliveredCalls []markCallRedeliver
	failedCalls    []markCallRedeliver

	// Counter for number of GetEventByID calls (so the post-mark re-read
	// returns the post-mark fixture).
	getEventByIDCalls atomic.Int32
}

// markCallRedeliver mirrors worker_test's markCall but is local to
// this file so the fixtures stay self-contained.
type markCallRedeliver struct {
	id         core.WebhookEventID
	claimToken core.WebhookClaimToken
	attempts   int
	result     domain.DeliveryResult
}

func (r *redeliverStubRepo) GetEndpointByID(_ context.Context, _ core.WebhookEndpointID) (*domain.WebhookEndpoint, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.endpointReturns != nil {
		return nil, r.endpointReturns
	}
	return r.endpoint, nil
}

func (r *redeliverStubRepo) GetEventByID(_ context.Context, id core.WebhookEventID) (*domain.WebhookEvent, error) {
	n := r.getEventByIDCalls.Add(1)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.getEventReturns != nil {
		return nil, r.getEventReturns
	}
	// First call: caller is loading the original event in Tx1.
	// Second call: caller is doing the post-mark re-read in Tx2 — return
	// the post-mark snapshot if it has been built.
	if n == 1 {
		return r.originalEvent, nil
	}
	if r.postMarkEvent != nil {
		return r.postMarkEvent, nil
	}
	return r.originalEvent, nil
}

func (r *redeliverStubRepo) CreateEvent(_ context.Context, ev *domain.WebhookEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	// Defensive copy so later mutations to ev don't change what the
	// stub captured at insert time.
	cp := *ev
	r.created = append(r.created, &cp)
	return nil
}

func (r *redeliverStubRepo) MarkDelivered(_ context.Context, id core.WebhookEventID, claimToken core.WebhookClaimToken, attempts int, result domain.DeliveryResult) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.deliveredCalls = append(r.deliveredCalls, markCallRedeliver{id: id, claimToken: claimToken, attempts: attempts, result: result})
	if r.markDeliveredForceZero {
		return 0, nil
	}
	// Build the post-mark snapshot for the next GetEventByID re-read.
	r.postMarkEvent = r.buildPostMark(id, core.DeliveryStatusDelivered, attempts, result)
	return 1, nil
}

func (r *redeliverStubRepo) MarkFailedFinal(_ context.Context, id core.WebhookEventID, claimToken core.WebhookClaimToken, attempts int, result domain.DeliveryResult) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failedCalls = append(r.failedCalls, markCallRedeliver{id: id, claimToken: claimToken, attempts: attempts, result: result})
	if r.markFailedForceZero {
		return 0, nil
	}
	r.postMarkEvent = r.buildPostMark(id, core.DeliveryStatusFailed, attempts, result)
	return 1, nil
}

// buildPostMark composes the WebhookEvent state the post-mark re-read
// should return. Mirrors what the SQL Mark* update would produce: the
// status, attempts, and response fields are written; claim_token and
// claim_expires_at are cleared; next_retry_at remains nil for one-shot
// redeliver semantics.
func (r *redeliverStubRepo) buildPostMark(id core.WebhookEventID, status core.DeliveryStatus, attempts int, result domain.DeliveryResult) *domain.WebhookEvent {
	if len(r.created) == 0 {
		return nil
	}
	// Locate the matching created event so we keep its IDs/payload.
	var src *domain.WebhookEvent
	for _, c := range r.created {
		if c.ID == id {
			src = c
			break
		}
	}
	if src == nil {
		return nil
	}
	now := time.Now().UTC()
	cp := *src
	cp.Status = status
	cp.Attempts = attempts
	cp.LastAttemptedAt = &now
	cp.ResponseStatus = result.ResponseStatus
	cp.ResponseBody = result.ResponseBody
	cp.ResponseBodyTruncated = result.ResponseBodyTruncated
	cp.ResponseHeaders = result.ResponseHeaders
	cp.ClaimToken = nil
	cp.ClaimExpiresAt = nil
	cp.NextRetryAt = nil
	return &cp
}

// Unused interface methods — present only to satisfy
// domain.WebhookRepository. Any accidental call from Redeliver will
// surface immediately.
func (*redeliverStubRepo) CreateEndpoint(context.Context, *domain.WebhookEndpoint) error {
	panic("unused")
}
func (*redeliverStubRepo) ListEndpoints(context.Context, core.Cursor, int) ([]domain.WebhookEndpoint, bool, error) {
	panic("unused")
}
func (*redeliverStubRepo) DeleteEndpoint(context.Context, core.WebhookEndpointID) error {
	panic("unused")
}
func (*redeliverStubRepo) GetActiveEndpointsByEvent(context.Context, core.EventType) ([]domain.WebhookEndpoint, error) {
	panic("unused")
}
func (*redeliverStubRepo) UpdateEventStatus(context.Context, core.WebhookEventID, core.DeliveryStatus, int, *int, *string, bool, json.RawMessage, *time.Time) error {
	panic("unused")
}
func (*redeliverStubRepo) ListEventsByEndpoint(context.Context, core.WebhookEndpointID, domain.WebhookDeliveryFilter, core.Cursor, int) ([]domain.WebhookEvent, bool, error) {
	panic("unused")
}
func (*redeliverStubRepo) ClaimNext(context.Context, core.WebhookClaimToken, time.Time) (*domain.WebhookEvent, error) {
	panic("unused")
}
func (*redeliverStubRepo) ReleaseStaleClaims(context.Context) (int, error) { panic("unused") }
func (*redeliverStubRepo) MarkFailedRetry(context.Context, core.WebhookEventID, core.WebhookClaimToken, int, domain.DeliveryResult, time.Time) (int64, error) {
	panic("unused")
}
func (*redeliverStubRepo) GetDispatcherCheckpoint(context.Context) (*domain.WebhookDispatcherCheckpoint, error) {
	panic("unused")
}
func (*redeliverStubRepo) UpdateDispatcherCheckpoint(context.Context, core.DomainEventID) error {
	panic("unused")
}
func (*redeliverStubRepo) RotateSigningSecret(context.Context, core.WebhookEndpointID, []byte, []byte, time.Time) error {
	panic("unused")
}
func (*redeliverStubRepo) FinishSigningSecretRotation(context.Context, core.WebhookEndpointID) error {
	panic("unused")
}

// domainEventStub is a focused stub for domain.DomainEventRepository.
// Only Get is exercised by Redeliver; other methods panic.
type domainEventStub struct {
	mu sync.Mutex

	// event returned by Get when its ID matches getID; nil otherwise.
	event *domain.DomainEvent
	// getReturns is an optional error returned by Get.
	getReturns error
	// forceNil makes Get return (nil, nil) regardless of fixture state.
	forceNil bool
}

func (d *domainEventStub) Get(_ context.Context, _ core.DomainEventID) (*domain.DomainEvent, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.getReturns != nil {
		return nil, d.getReturns
	}
	if d.forceNil {
		return nil, nil
	}
	return d.event, nil
}

func (*domainEventStub) Create(context.Context, *domain.DomainEvent) error { panic("unused") }
func (*domainEventStub) List(context.Context, domain.DomainEventFilter, core.Cursor, int) ([]domain.DomainEvent, bool, error) {
	panic("unused")
}
func (*domainEventStub) CountFiltered(context.Context, domain.DomainEventFilter) (int64, error) {
	panic("unused")
}
func (*domainEventStub) ListSince(context.Context, core.DomainEventID, int) ([]domain.DomainEvent, error) {
	panic("unused")
}
func (*domainEventStub) CountByDay(context.Context, time.Time, time.Time) ([]domain.DailyEventCount, error) {
	panic("unused")
}

// redeliverTestEnv bundles everything a Redeliver test needs: the
// service under test, the IDs to feed into Redeliver, the stubs for
// inspection/configuration, and the counting tx manager so each test
// can assert "exactly 2 tenant transactions opened".
type redeliverTestEnv struct {
	svc             *Service
	accountID       core.AccountID
	env             core.Environment
	endpointID      core.WebhookEndpointID
	originalEventID core.WebhookEventID
	domainEventID   core.DomainEventID
	repo            *redeliverStubRepo
	domainEventRepo *domainEventStub
	tx              *countingTxManager
}

// newRedeliverTestEnv composes a Service plus stubs primed with a
// realistic fixture: an endpoint with an encrypted signing secret, an
// original webhook_event row pointing at a real domain_event, and a
// domain_event whose payload is a simple JSON envelope.
//
// The endpoint URL is set to serverURL — the test server fronting the
// HTTP attempt. Pass the empty string when the test does not need a
// reachable server (e.g. EndpointNotFound short-circuits before the
// HTTP attempt).
func newRedeliverTestEnv(t *testing.T, serverURL string) *redeliverTestEnv {
	t.Helper()

	mk, err := crypto.NewMasterKey(redeliverTestHexKey, "", "")
	require.NoError(t, err, "construct test master key")

	accountID := core.NewAccountID()
	endpointID := core.NewWebhookEndpointID()
	originalEventID := core.NewWebhookEventID()
	domainEventID := core.NewDomainEventID()
	env := core.Environment("live")

	// Encrypt a deterministic signing secret bound to this endpoint's
	// AAD so AttemptDelivery's masterKey.Decrypt path succeeds.
	plainSecret := []byte("test-signing-secret-redeliver-1234567890")
	aad := crypto.WebhookSigningSecretAAD(endpointID)
	encryptedSecret, err := mk.Encrypt(plainSecret, aad)
	require.NoError(t, err, "encrypt signing secret")

	endpoint := &domain.WebhookEndpoint{
		ID:                     endpointID,
		AccountID:              accountID,
		URL:                    serverURL,
		Events:                 []core.EventType{"license.created"},
		SigningSecretEncrypted: encryptedSecret,
		Active:                 true,
		Environment:            env,
		CreatedAt:              time.Now().UTC().Add(-time.Hour),
	}

	originalEvent := &domain.WebhookEvent{
		ID:            originalEventID,
		AccountID:     accountID,
		EndpointID:    endpointID,
		EventType:     core.EventType("license.created"),
		Payload:       json.RawMessage(`{"original":true}`),
		Status:        core.DeliveryStatusFailed,
		Attempts:      7,
		DomainEventID: domainEventID,
		Environment:   env,
		CreatedAt:     time.Now().UTC().Add(-30 * time.Minute),
	}

	domainEvent := &domain.DomainEvent{
		ID:           domainEventID,
		AccountID:    accountID,
		Environment:  env,
		EventType:    core.EventType("license.created"),
		ResourceType: "license",
		Payload:      json.RawMessage(`{"id":"abc","fresh":"payload"}`),
		CreatedAt:    time.Now().UTC().Add(-time.Hour),
	}

	repo := &redeliverStubRepo{
		endpoint:      endpoint,
		originalEvent: originalEvent,
	}
	domainEventRepo := &domainEventStub{event: domainEvent}
	tx := &countingTxManager{}

	svc := &Service{
		txManager:    tx,
		webhooks:     repo,
		domainEvents: domainEventRepo,
		masterKey:    mk,
		isDev:        true, // bypass SSRF dial-time guard for httptest's 127.0.0.1
		httpClient:   newWebhookClient(true),
	}

	return &redeliverTestEnv{
		svc:             svc,
		accountID:       accountID,
		env:             env,
		endpointID:      endpointID,
		originalEventID: originalEventID,
		domainEventID:   domainEventID,
		repo:            repo,
		domainEventRepo: domainEventRepo,
		tx:              tx,
	}
}

// redeliverTestHexKey is a 64-byte (128 hex chars) deterministic master
// key used to bootstrap *crypto.MasterKey in Redeliver tests. Mirrors
// the crypto package's testHexKey but kept local so this file stays
// self-contained.
const redeliverTestHexKey = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20" +
	"2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40"

// =====================================================================
// Redeliver tests (9)
// =====================================================================

// TestRedeliver_Success — happy path. The endpoint returns 200, so the
// new row lands in the delivered terminal state with attempts=1 and
// the captured response status. Also asserts the 2-tx invariant.
func TestRedeliver_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	env := newRedeliverTestEnv(t, srv.URL)
	got, err := env.svc.Redeliver(context.Background(), env.accountID, env.env, env.endpointID, env.originalEventID)

	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, core.DeliveryStatusDelivered, got.Status, "successful 200 response yields delivered status")
	assert.Equal(t, 1, got.Attempts, "redeliver is one-shot: attempts=1 on success")
	require.NotNil(t, got.ResponseStatus, "ResponseStatus must be populated on success")
	assert.Equal(t, 200, *got.ResponseStatus)
	assert.Equal(t, 2, env.tx.targetAccountCalls, "redeliver should open exactly 2 WithTargetAccount transactions")
	assert.Len(t, env.repo.deliveredCalls, 1, "exactly one MarkDelivered call expected")
	assert.Empty(t, env.repo.failedCalls, "no MarkFailedFinal call expected on success")
}

// TestRedeliver_TransportFailure — the endpoint never accepts the
// connection. The new row lands in failed_final (no scheduled retry —
// one-shot semantics). ResponseStatus is nil because no HTTP response
// was received.
func TestRedeliver_TransportFailure(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	dead := "http://" + listener.Addr().String()
	require.NoError(t, listener.Close(), "close listener so the next dial gets connection-refused")

	env := newRedeliverTestEnv(t, dead)
	got, err := env.svc.Redeliver(context.Background(), env.accountID, env.env, env.endpointID, env.originalEventID)

	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, core.DeliveryStatusFailed, got.Status, "transport failure yields failed status")
	assert.Equal(t, 1, got.Attempts, "redeliver is one-shot even on failure")
	assert.Nil(t, got.ResponseStatus, "no HTTP response means ResponseStatus stays nil")
	assert.Nil(t, got.NextRetryAt, "redeliver one-shot: no scheduled retry")
	assert.Len(t, env.repo.failedCalls, 1, "exactly one MarkFailedFinal call expected")
}

// TestRedeliver_HTTPFailure_5xx — the endpoint returns a non-2xx
// status. The response body is captured and the row lands failed_final
// with no scheduled retry.
func TestRedeliver_HTTPFailure_5xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("bad gateway"))
	}))
	defer srv.Close()

	env := newRedeliverTestEnv(t, srv.URL)
	got, err := env.svc.Redeliver(context.Background(), env.accountID, env.env, env.endpointID, env.originalEventID)

	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, core.DeliveryStatusFailed, got.Status, "non-2xx response yields failed status")
	require.NotNil(t, got.ResponseStatus)
	assert.Equal(t, http.StatusBadGateway, *got.ResponseStatus)
	require.NotNil(t, got.ResponseBody, "response body should be captured")
	assert.Equal(t, "bad gateway", *got.ResponseBody)
	assert.Nil(t, got.NextRetryAt, "redeliver one-shot: no scheduled retry on HTTP failure")
}

// TestRedeliver_EndpointNotFound — GetEndpointByID returns nil. Tx1
// short-circuits before any new event row is created.
func TestRedeliver_EndpointNotFound(t *testing.T) {
	env := newRedeliverTestEnv(t, "")
	env.repo.endpoint = nil

	_, err := env.svc.Redeliver(context.Background(), env.accountID, env.env, env.endpointID, env.originalEventID)

	require.Error(t, err)
	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr, "expected typed AppError")
	assert.Equal(t, core.ErrWebhookEndpointNotFound, appErr.Code)
	assert.Empty(t, env.repo.created, "no webhook_event row should be created when endpoint is missing")
}

// TestRedeliver_OriginalEventNotFound — GetEventByID returns nil. Tx1
// short-circuits with the typed event-not-found error.
func TestRedeliver_OriginalEventNotFound(t *testing.T) {
	env := newRedeliverTestEnv(t, "")
	env.repo.originalEvent = nil

	_, err := env.svc.Redeliver(context.Background(), env.accountID, env.env, env.endpointID, env.originalEventID)

	require.Error(t, err)
	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrWebhookEventNotFound, appErr.Code)
	assert.Empty(t, env.repo.created)
}

// TestRedeliver_EndpointMismatch — the original event exists but
// belongs to a different endpoint. Surface as not-found (404) rather
// than 422 to prevent existence leakage of cross-endpoint deliveries.
func TestRedeliver_EndpointMismatch(t *testing.T) {
	env := newRedeliverTestEnv(t, "")
	// Mutate the original event to belong to a different endpoint.
	env.repo.originalEvent.EndpointID = core.NewWebhookEndpointID()

	_, err := env.svc.Redeliver(context.Background(), env.accountID, env.env, env.endpointID, env.originalEventID)

	require.Error(t, err)
	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrWebhookEventNotFound, appErr.Code, "endpoint mismatch must surface as 404, not 422 (existence-leak prevention)")
	assert.Empty(t, env.repo.created)
}

// TestRedeliver_DomainEventMissing — the linked domain_event has been
// purged (or never persisted). Surface as event_not_found.
func TestRedeliver_DomainEventMissing(t *testing.T) {
	env := newRedeliverTestEnv(t, "")
	env.domainEventRepo.forceNil = true

	_, err := env.svc.Redeliver(context.Background(), env.accountID, env.env, env.endpointID, env.originalEventID)

	require.Error(t, err)
	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrEventNotFound, appErr.Code)
	assert.Empty(t, env.repo.created, "no row should be created when the linked domain event is missing")
}

// TestRedeliver_ClaimTokenMismatch — Tx2's MarkDelivered claims to
// have updated zero rows (simulating a worker pool race that stole the
// claim). Surface as 500 with the diagnostic message intact.
func TestRedeliver_ClaimTokenMismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	env := newRedeliverTestEnv(t, srv.URL)
	env.repo.markDeliveredForceZero = true

	_, err := env.svc.Redeliver(context.Background(), env.accountID, env.env, env.endpointID, env.originalEventID)

	require.Error(t, err)
	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrInternalError, appErr.Code)
	assert.Contains(t, appErr.Message, "claim-token mismatch", "error message should pinpoint the race for operators")
}

// TestRedeliver_NewEventHasFreshClaimToken — invariant: the new row
// inserted by Tx1 carries a non-nil claim_token and a claim_expires_at
// ~60s in the future. Without these, a worker pool's ClaimNext could
// race in and double-deliver before Tx2 records the outcome.
func TestRedeliver_NewEventHasFreshClaimToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	env := newRedeliverTestEnv(t, srv.URL)
	before := time.Now().UTC()
	_, err := env.svc.Redeliver(context.Background(), env.accountID, env.env, env.endpointID, env.originalEventID)
	require.NoError(t, err)

	require.Len(t, env.repo.created, 1, "exactly one new webhook_event row should be inserted")
	created := env.repo.created[0]
	require.NotNil(t, created.ClaimToken, "new row must carry a fresh claim_token")
	require.NotNil(t, created.ClaimExpiresAt, "new row must carry claim_expires_at")
	expiresIn := created.ClaimExpiresAt.Sub(before)
	// Allow generous slack for slow CI: claimWindow is 60s, but if the
	// machine is busy a few seconds elapse between "before" and the
	// service's internal time.Now() call. 50-65s spans that comfortably.
	assert.GreaterOrEqual(t, expiresIn, 50*time.Second, "claim_expires_at should be ~60s ahead of insertion time")
	assert.LessOrEqual(t, expiresIn, 65*time.Second, "claim_expires_at should be ~60s ahead of insertion time")
}
