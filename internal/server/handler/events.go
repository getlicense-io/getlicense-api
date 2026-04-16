package handler

import (
	"context"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/getlicense-io/getlicense-api/internal/rbac"
)

// EventHandler handles domain event read endpoints.
type EventHandler struct {
	tx   domain.TxManager
	repo domain.DomainEventRepository
}

// NewEventHandler creates a new EventHandler.
func NewEventHandler(tx domain.TxManager, repo domain.DomainEventRepository) *EventHandler {
	return &EventHandler{tx: tx, repo: repo}
}

// List returns a cursor-paginated list of domain events.
func (h *EventHandler) List(c fiber.Ctx) error {
	auth, err := authz(c, rbac.EventsRead)
	if err != nil {
		return err
	}

	cursor, limit, err := cursorParams(c)
	if err != nil {
		return err
	}

	var filter domain.DomainEventFilter
	filter.ResourceType = c.Query("resource_type")
	filter.ResourceID = c.Query("resource_id")
	if raw := c.Query("event_type"); raw != "" {
		filter.EventType = core.EventType(raw)
	}
	if raw := c.Query("identity_id"); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			return core.NewAppError(core.ErrValidationError, "Invalid identity_id")
		}
		iid := core.IdentityID(id)
		filter.IdentityID = &iid
	}
	if raw := c.Query("grant_id"); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			return core.NewAppError(core.ErrValidationError, "Invalid grant_id")
		}
		gid := core.GrantID(id)
		filter.GrantID = &gid
	}
	if raw := c.Query("from"); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return core.NewAppError(core.ErrValidationError, "Invalid from timestamp (expected RFC3339)")
		}
		filter.From = &t
	}
	if raw := c.Query("to"); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return core.NewAppError(core.ErrValidationError, "Invalid to timestamp (expected RFC3339)")
		}
		filter.To = &t
	}

	var events []domain.DomainEvent
	var hasMore bool

	err = h.tx.WithTargetAccount(c.Context(), auth.TargetAccountID, auth.Environment, func(ctx context.Context) error {
		var e error
		events, hasMore, e = h.repo.List(ctx, filter, cursor, limit)
		return e
	})
	if err != nil {
		return err
	}

	return c.JSON(pageFromCursor(events, hasMore, func(e domain.DomainEvent) core.Cursor {
		return core.Cursor{CreatedAt: e.CreatedAt, ID: uuid.UUID(e.ID)}
	}))
}

// Get returns a single domain event by ID.
func (h *EventHandler) Get(c fiber.Ctx) error {
	auth, err := authz(c, rbac.EventsRead)
	if err != nil {
		return err
	}

	id, err := core.ParseDomainEventID(c.Params("id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "Invalid event ID")
	}

	var event *domain.DomainEvent

	err = h.tx.WithTargetAccount(c.Context(), auth.TargetAccountID, auth.Environment, func(ctx context.Context) error {
		var e error
		event, e = h.repo.Get(ctx, id)
		return e
	})
	if err != nil {
		return err
	}
	if event == nil {
		return core.NewAppError(core.ErrEventNotFound, "Event not found")
	}

	return c.JSON(event)
}
