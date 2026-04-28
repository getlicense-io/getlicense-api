package testfakes

import (
	"context"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

// EventRepo is an in-memory domain.DomainEventRepository fake. Create
// captures every event so tests can assert which lifecycle events the
// service emitted via audit.Writer. All read methods are no-op stubs
// returning zero values.
type EventRepo struct {
	events []domain.DomainEvent
}

func NewEventRepo() *EventRepo { return &EventRepo{} }

// Compile-time check.
var _ domain.DomainEventRepository = (*EventRepo)(nil)

func (r *EventRepo) Create(_ context.Context, e *domain.DomainEvent) error {
	cp := *e
	r.events = append(r.events, cp)
	return nil
}

func (r *EventRepo) Get(_ context.Context, _ core.DomainEventID) (*domain.DomainEvent, error) {
	return nil, nil
}

func (r *EventRepo) List(_ context.Context, _ domain.DomainEventFilter, _ core.Cursor, _ int) ([]domain.DomainEvent, bool, error) {
	return nil, false, nil
}

func (r *EventRepo) CountFiltered(_ context.Context, _ domain.DomainEventFilter) (int64, error) {
	return 0, nil
}

func (r *EventRepo) ListSince(_ context.Context, _ core.DomainEventID, _ int) ([]domain.DomainEvent, error) {
	return nil, nil
}

func (r *EventRepo) CountByDay(_ context.Context, _, _ time.Time) ([]domain.DailyEventCount, error) {
	return nil, nil
}

// Events returns a copy of all captured events. Tests use this for
// assertions on the sequence of emitted lifecycle events.
func (r *EventRepo) Events() []domain.DomainEvent {
	out := make([]domain.DomainEvent, len(r.events))
	copy(out, r.events)
	return out
}

// EventTypes returns the EventType field of each captured event in
// insertion order. Convenience for tests that only care about the
// sequence of types emitted.
func (r *EventRepo) EventTypes() []core.EventType {
	out := make([]core.EventType, len(r.events))
	for i, e := range r.events {
		out[i] = e.EventType
	}
	return out
}
