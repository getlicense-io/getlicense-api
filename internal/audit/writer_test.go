package audit

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

// --- fake DomainEventRepository ---

type fakeEventRepo struct {
	events []*domain.DomainEvent
}

func (r *fakeEventRepo) Create(_ context.Context, e *domain.DomainEvent) error {
	r.events = append(r.events, e)
	return nil
}

func (r *fakeEventRepo) Get(_ context.Context, id core.DomainEventID) (*domain.DomainEvent, error) {
	for _, e := range r.events {
		if e.ID == id {
			return e, nil
		}
	}
	return nil, nil
}

func (r *fakeEventRepo) List(_ context.Context, _ domain.DomainEventFilter, _ core.Cursor, _ int) ([]domain.DomainEvent, bool, error) {
	return nil, false, nil
}

func (r *fakeEventRepo) CountFiltered(_ context.Context, _ domain.DomainEventFilter) (int64, error) {
	return 0, nil
}

func (r *fakeEventRepo) ListSince(_ context.Context, _ core.DomainEventID, _ int) ([]domain.DomainEvent, error) {
	return nil, nil
}

// --- tests ---

func TestWriter_Record_StampsIDAndCreatedAt(t *testing.T) {
	repo := &fakeEventRepo{}
	w := NewWriter(repo)

	before := time.Now().UTC()

	accountID := core.AccountID(uuid.New())
	event := domain.DomainEvent{
		AccountID:    accountID,
		Environment:  core.Environment("live"),
		EventType:    core.EventType("license.created"),
		ResourceType: "license",
		ActorKind:    core.ActorKindSystem,
		Payload:      json.RawMessage(`{"key":"value"}`),
	}

	err := w.Record(context.Background(), event)
	require.NoError(t, err)
	require.Len(t, repo.events, 1)

	recorded := repo.events[0]
	assert.NotEqual(t, core.DomainEventID{}, recorded.ID, "ID should be stamped")
	assert.False(t, recorded.CreatedAt.IsZero(), "CreatedAt should be stamped")
	assert.True(t, !recorded.CreatedAt.Before(before), "CreatedAt should be >= test start")
}

func TestWriter_Record_CoercesNilPayload(t *testing.T) {
	repo := &fakeEventRepo{}
	w := NewWriter(repo)

	accountID := core.AccountID(uuid.New())
	event := domain.DomainEvent{
		AccountID:    accountID,
		Environment:  core.Environment("live"),
		EventType:    core.EventType("license.revoked"),
		ResourceType: "license",
		ActorKind:    core.ActorKindSystem,
		Payload:      nil, // explicitly nil
	}

	err := w.Record(context.Background(), event)
	require.NoError(t, err)
	require.Len(t, repo.events, 1)

	assert.Equal(t, json.RawMessage(`{}`), repo.events[0].Payload)
}

func TestEventFrom_IdentityPath(t *testing.T) {
	accountID := core.AccountID(uuid.New())
	actingID := core.AccountID(uuid.New())
	identityID := core.IdentityID(uuid.New())

	attr := Attribution{
		AccountID:       accountID,
		Environment:     core.Environment("test"),
		ActingAccountID: &actingID,
		IdentityID:      &identityID,
		ActorKind:       core.ActorKindIdentity,
		ActorLabel:      "user@example.com",
	}

	payload := json.RawMessage(`{"name":"test"}`)
	event := EventFrom(attr, core.EventType("license.created"), "license", "abc-123", payload)

	assert.Equal(t, accountID, event.AccountID)
	assert.Equal(t, core.Environment("test"), event.Environment)
	assert.Equal(t, core.EventType("license.created"), event.EventType)
	assert.Equal(t, "license", event.ResourceType)
	require.NotNil(t, event.ResourceID)
	assert.Equal(t, "abc-123", *event.ResourceID)
	assert.Equal(t, &actingID, event.ActingAccountID)
	assert.Equal(t, &identityID, event.IdentityID)
	assert.Equal(t, core.ActorKindIdentity, event.ActorKind)
	assert.Equal(t, "user@example.com", event.ActorLabel)
	assert.Equal(t, payload, event.Payload)
}

func TestEventFrom_APIKeyPath(t *testing.T) {
	accountID := core.AccountID(uuid.New())
	actingID := core.AccountID(uuid.New())
	apiKeyID := core.APIKeyID(uuid.New())

	attr := Attribution{
		AccountID:       accountID,
		Environment:     core.Environment("live"),
		ActingAccountID: &actingID,
		ActorKind:       core.ActorKindAPIKey,
		APIKeyID:        &apiKeyID,
	}

	event := EventFrom(attr, core.EventType("machine.activated"), "machine", "xyz-789", nil)

	assert.Equal(t, accountID, event.AccountID)
	assert.Equal(t, core.ActorKindAPIKey, event.ActorKind)
	assert.Equal(t, &apiKeyID, event.APIKeyID)
	assert.Nil(t, event.IdentityID)
	assert.Nil(t, event.Payload, "nil payload should pass through to Writer")
}

func TestEventFrom_EmptyResourceID(t *testing.T) {
	attr := Attribution{
		AccountID:   core.AccountID(uuid.New()),
		Environment: core.Environment("live"),
		ActorKind:   core.ActorKindSystem,
	}

	event := EventFrom(attr, core.EventType("system.test"), "test", "", nil)
	assert.Nil(t, event.ResourceID, "empty resourceID should yield nil pointer")
}
