package handler

import (
	"bufio"
	"context"
	"encoding/csv"
	"fmt"
	"strings"
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
	tx         domain.TxManager
	repo       domain.DomainEventRepository
	maxCSVRows int
}

// NewEventHandler creates a new EventHandler. maxCSVRows is the hard cap
// enforced BEFORE streaming by GET /v1/events?format=csv; a result set
// larger than this triggers a 413 export_too_large response. Pass
// config.EventsCSVMaxRows; see server/config.go for defaults and bounds.
func NewEventHandler(tx domain.TxManager, repo domain.DomainEventRepository, maxCSVRows int) *EventHandler {
	return &EventHandler{tx: tx, repo: repo, maxCSVRows: maxCSVRows}
}

// parseEventFilter builds a DomainEventFilter from query-string args.
// Used by both the JSON list path and the CSV export path so the two
// paths cannot drift on filter semantics. Returns a partial filter + a
// 422 ValidationError on malformed args.
func parseEventFilter(c fiber.Ctx) (domain.DomainEventFilter, error) {
	var filter domain.DomainEventFilter
	filter.ResourceType = c.Query("resource_type")
	filter.ResourceID = c.Query("resource_id")
	if raw := c.Query("event_type"); raw != "" {
		filter.EventType = core.EventType(raw)
	}
	if raw := c.Query("identity_id"); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			return filter, core.NewAppError(core.ErrValidationError, "Invalid identity_id")
		}
		iid := core.IdentityID(id)
		filter.IdentityID = &iid
	}
	if raw := c.Query("grant_id"); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			return filter, core.NewAppError(core.ErrValidationError, "Invalid grant_id")
		}
		gid := core.GrantID(id)
		filter.GrantID = &gid
	}
	if raw := c.Query("from"); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return filter, core.NewAppError(core.ErrValidationError, "Invalid from timestamp (expected RFC3339)")
		}
		filter.From = &t
	}
	if raw := c.Query("to"); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return filter, core.NewAppError(core.ErrValidationError, "Invalid to timestamp (expected RFC3339)")
		}
		filter.To = &t
	}
	return filter, nil
}

// List returns a cursor-paginated list of domain events. When the
// caller requests CSV — either via `?format=csv` or an `Accept:
// text/csv` header — the response is streamed via streamCSV with a
// pre-flight row cap check; otherwise the normal JSON page is served.
func (h *EventHandler) List(c fiber.Ctx) error {
	auth, err := authz(c, rbac.EventsRead)
	if err != nil {
		return err
	}

	filter, err := parseEventFilter(c)
	if err != nil {
		return err
	}
	if err := applyEventAPIKeyProductScope(c, &filter); err != nil {
		return err
	}

	if wantsCSV(c) {
		return h.streamCSV(c, auth, filter)
	}

	cursor, limit, err := cursorParams(c)
	if err != nil {
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

// wantsCSV returns true when the caller asks for a CSV response. The
// `?format=csv` query param is the canonical, dashboard-friendly form;
// `Accept: text/csv` is honored for curl / programmatic callers. Either
// path is sufficient — we do NOT require both.
func wantsCSV(c fiber.Ctx) bool {
	if strings.EqualFold(c.Query("format"), "csv") {
		return true
	}
	if strings.Contains(c.Get("Accept"), "text/csv") {
		return true
	}
	return false
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

// csvHeader is the frozen column list for the events CSV export. Order
// matches what dashboard / downstream importers expect; changing it is
// a breaking change for every consumer parsing this CSV.
var csvHeader = []string{
	"id", "created_at", "event_type", "resource_type", "resource_id",
	"actor_kind", "actor_label", "acting_account_id", "identity_id",
	"api_key_id", "grant_id", "request_id", "ip_address", "payload_json",
}

// streamCSV serves the events list as a streamed CSV download. The
// pre-count runs first and a result set larger than the configured cap
// returns 413 BEFORE any bytes go out — callers get a clean JSON error
// envelope, not a partial CSV. Once streaming begins, each 1000-row
// page runs in its own short-lived tx so no transaction is held open
// across the whole stream (and client disconnect aborts cleanly via
// c.Context().Err() at each page boundary).
func (h *EventHandler) streamCSV(c fiber.Ctx, auth *middleware.AuthContext, filter domain.DomainEventFilter) error {
	// Pre-count under the tenant context so RLS filters the total the
	// same way the subsequent pages will.
	var total int64
	if err := h.tx.WithTargetAccount(c.Context(), auth.TargetAccountID, auth.Environment, func(ctx context.Context) error {
		var e error
		total, e = h.repo.CountFiltered(ctx, filter)
		return e
	}); err != nil {
		return err
	}

	maxRows := h.maxCSVRows
	if maxRows <= 0 {
		maxRows = 100_000
	}
	if total > int64(maxRows) {
		return core.NewAppError(core.ErrExportTooLarge,
			fmt.Sprintf("Result set exceeds %d rows. Narrow your filter (e.g. tighter from/to range) and retry.", maxRows))
	}

	c.Set("Content-Type", "text/csv; charset=utf-8")
	c.Set("Content-Disposition", `attachment; filename="`+csvFilenameFor(filter)+`"`)

	// The closure passed to SendStreamWriter fires AFTER this handler
	// returns (fasthttp streams the response body asynchronously), at
	// which point Fiber has already recycled `c` back into its pool —
	// touching c.Context() or c.Locals() inside the closure is UB.
	// Capture everything we need up-front into local vars. The stream
	// uses a fresh context.Background() because Fiber v3's default
	// c.Context() is itself just context.Background() (it's not tied
	// to connection lifetime), so we lose nothing by re-deriving here.
	txMgr := h.tx
	repo := h.repo
	targetAccount := auth.TargetAccountID
	environment := auth.Environment

	return c.SendStreamWriter(func(w *bufio.Writer) {
		ctx := context.Background()
		cw := csv.NewWriter(w)
		defer cw.Flush()
		if err := cw.Write(csvHeader); err != nil {
			return
		}
		cur := core.Cursor{}
		for {
			var rows []domain.DomainEvent
			var hasMore bool
			err := txMgr.WithTargetAccount(ctx, targetAccount, environment, func(ctx context.Context) error {
				var e error
				rows, hasMore, e = repo.List(ctx, filter, cur, 1000)
				return e
			})
			if err != nil {
				return
			}
			for _, ev := range rows {
				if err := cw.Write(domainEventToCSVRow(ev)); err != nil {
					// Write failure means the client disconnected or
					// the underlying connection broke — bail out of the
					// stream cleanly. The partial bytes already on the
					// wire are acceptable since CSV is line-oriented.
					return
				}
			}
			cw.Flush()
			if err := cw.Error(); err != nil {
				return
			}
			if !hasMore || len(rows) == 0 {
				return
			}
			last := rows[len(rows)-1]
			cur = core.Cursor{CreatedAt: last.CreatedAt, ID: uuid.UUID(last.ID)}
		}
	})
}

// csvFilenameFor builds the Content-Disposition filename from the
// filter's from/to range. Unset dates become "all" so an unfiltered
// export yields "events_all_all.csv".
func csvFilenameFor(f domain.DomainEventFilter) string {
	from := "all"
	to := "all"
	if f.From != nil {
		from = f.From.UTC().Format("2006-01-02")
	}
	if f.To != nil {
		to = f.To.UTC().Format("2006-01-02")
	}
	return "events_" + from + "_" + to + ".csv"
}

// domainEventToCSVRow flattens a DomainEvent into the column order
// defined by csvHeader. encoding/csv handles RFC 4180 quoting of
// embedded commas / quotes / newlines (notably in payload_json).
func domainEventToCSVRow(ev domain.DomainEvent) []string {
	strPtr := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	resourceID := ""
	if ev.ResourceID != nil {
		resourceID = *ev.ResourceID
	}
	actingAccount := ""
	if ev.ActingAccountID != nil {
		actingAccount = ev.ActingAccountID.String()
	}
	identityID := ""
	if ev.IdentityID != nil {
		identityID = ev.IdentityID.String()
	}
	apiKeyID := ""
	if ev.APIKeyID != nil {
		apiKeyID = ev.APIKeyID.String()
	}
	grantID := ""
	if ev.GrantID != nil {
		grantID = ev.GrantID.String()
	}
	payload := ""
	if len(ev.Payload) > 0 {
		payload = string(ev.Payload)
	}
	return []string{
		ev.ID.String(),
		ev.CreatedAt.UTC().Format(time.RFC3339Nano),
		string(ev.EventType),
		ev.ResourceType,
		resourceID,
		string(ev.ActorKind),
		ev.ActorLabel,
		actingAccount,
		identityID,
		apiKeyID,
		grantID,
		strPtr(ev.RequestID),
		strPtr(ev.IPAddress),
		payload,
	}
}
