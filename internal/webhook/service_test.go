package webhook

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/getlicense-io/getlicense-api/internal/core"
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
