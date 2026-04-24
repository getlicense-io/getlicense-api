package handler

import (
	"context"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/getlicense-io/getlicense-api/internal/rbac"
	"github.com/getlicense-io/getlicense-api/internal/server/middleware"
)

// applyEventAPIKeyProductScope silently restricts a domain-event filter
// for product-scoped API keys. Identity callers and account-wide API
// keys pass through untouched. For a product-scoped key, the filter's
// RestrictToLicenseProductID is forced to the bound product — this
// narrows the result set to license.* events about that product's
// licenses AND drops grant.* / invitation.* / webhook.* events entirely.
// There is no user-visible `?product_id=` on GET /v1/events, so we
// never see a client-provided value here; injecting unconditionally is
// safe and deliberate.
func applyEventAPIKeyProductScope(c fiber.Ctx, filter *domain.DomainEventFilter) error {
	auth := middleware.AuthFromContext(c)
	if auth == nil {
		return nil
	}
	if auth.ActorKind != middleware.ActorKindAPIKey {
		return nil
	}
	if auth.APIKeyScope != core.APIKeyScopeProduct {
		return nil
	}
	if auth.APIKeyProductID == nil {
		return core.NewAppError(core.ErrAPIKeyScopeMismatch,
			"API key is product-scoped but has no product binding")
	}
	pid := *auth.APIKeyProductID
	filter.RestrictToLicenseProductID = &pid
	return nil
}

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

	if err := applyEventAPIKeyProductScope(c, &filter); err != nil {
		return err
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
