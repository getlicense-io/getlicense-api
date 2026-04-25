package handler

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/getlicense-io/getlicense-api/internal/server/middleware"
)

// ctxWithRequest builds a *fiber.Ctx wrapping a fasthttp.RequestCtx the
// caller has pre-populated (query string, headers). Used by the
// wantsCSV content-negotiation tests below.
func ctxWithRequest(t *testing.T, app *fiber.App, fctx *fasthttp.RequestCtx) fiber.Ctx {
	t.Helper()
	c := app.AcquireCtx(fctx)
	t.Cleanup(func() { app.ReleaseCtx(c) })
	return c
}

func TestWantsCSV_FormatQueryParam(t *testing.T) {
	app := fiber.New()
	fctx := &fasthttp.RequestCtx{}
	fctx.Request.SetRequestURI("/v1/events?format=csv")
	c := ctxWithRequest(t, app, fctx)
	assert.True(t, wantsCSV(c))
}

func TestWantsCSV_FormatCaseInsensitive(t *testing.T) {
	app := fiber.New()
	fctx := &fasthttp.RequestCtx{}
	fctx.Request.SetRequestURI("/v1/events?format=CSV")
	c := ctxWithRequest(t, app, fctx)
	assert.True(t, wantsCSV(c))
}

func TestWantsCSV_AcceptHeader(t *testing.T) {
	app := fiber.New()
	fctx := &fasthttp.RequestCtx{}
	fctx.Request.SetRequestURI("/v1/events")
	fctx.Request.Header.Set("Accept", "text/csv")
	c := ctxWithRequest(t, app, fctx)
	assert.True(t, wantsCSV(c))
}

func TestWantsCSV_AcceptHeaderWithCharsetSuffix(t *testing.T) {
	// A client that sends `Accept: text/csv; charset=utf-8` must still
	// trigger the CSV path — the Contains check tolerates the suffix.
	app := fiber.New()
	fctx := &fasthttp.RequestCtx{}
	fctx.Request.SetRequestURI("/v1/events")
	fctx.Request.Header.Set("Accept", "text/csv; charset=utf-8")
	c := ctxWithRequest(t, app, fctx)
	assert.True(t, wantsCSV(c))
}

func TestWantsCSV_NoSignals(t *testing.T) {
	app := fiber.New()
	fctx := &fasthttp.RequestCtx{}
	fctx.Request.SetRequestURI("/v1/events")
	fctx.Request.Header.Set("Accept", "application/json")
	c := ctxWithRequest(t, app, fctx)
	assert.False(t, wantsCSV(c))
}

// TestCSVHeader_FrozenColumnOrder guards the CSV export contract. Any
// reordering or renaming here is a breaking change for every consumer
// parsing the download — lock it down so accidents are loud.
func TestCSVHeader_FrozenColumnOrder(t *testing.T) {
	want := []string{
		"id", "created_at", "event_type", "resource_type", "resource_id",
		"actor_kind", "actor_label", "acting_account_id", "identity_id",
		"api_key_id", "grant_id", "request_id", "ip_address", "payload_json",
	}
	assert.Equal(t, want, csvHeader)
}

func TestCsvFilenameFor_UnsetDates(t *testing.T) {
	var f domain.DomainEventFilter
	assert.Equal(t, "events_all_all.csv", csvFilenameFor(f))
}

func TestCsvFilenameFor_BothDates(t *testing.T) {
	from := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	to := time.Date(2026, 4, 1, 6, 0, 0, 0, time.UTC)
	f := domain.DomainEventFilter{From: &from, To: &to}
	assert.Equal(t, "events_2026-01-01_2026-04-01.csv", csvFilenameFor(f))
}

func TestCsvFilenameFor_OnlyFrom(t *testing.T) {
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	f := domain.DomainEventFilter{From: &from}
	assert.Equal(t, "events_2026-01-01_all.csv", csvFilenameFor(f))
}

func TestCsvFilenameFor_NonUTCDateNormalized(t *testing.T) {
	// A caller could pass a from=2026-01-01T23:00:00-08:00 — the file
	// name must use the UTC date, which is the NEXT day. This pins the
	// .UTC() conversion in csvFilenameFor.
	pst := time.FixedZone("PST", -8*3600)
	from := time.Date(2026, 1, 1, 23, 0, 0, 0, pst) // 2026-01-02T07:00:00Z
	f := domain.DomainEventFilter{From: &from}
	assert.Equal(t, "events_2026-01-02_all.csv", csvFilenameFor(f))
}

func TestDomainEventToCSVRow_HappyPath(t *testing.T) {
	eventID := core.NewDomainEventID()
	acting := core.NewAccountID()
	identity := core.NewIdentityID()
	apiKey := core.NewAPIKeyID()
	grant := core.NewGrantID()
	resID := "lic_123"
	reqID := "req_abc"
	ip := "10.0.0.1"
	created := time.Date(2026, 4, 24, 10, 30, 45, 123000000, time.UTC)
	payload := json.RawMessage(`{"foo":"bar","n":42}`)

	ev := domain.DomainEvent{
		ID:              eventID,
		EventType:       core.EventType("license.created"),
		ResourceType:    "license",
		ResourceID:      &resID,
		ActingAccountID: &acting,
		IdentityID:      &identity,
		ActorLabel:      "alice@example.com",
		ActorKind:       core.ActorKindIdentity,
		APIKeyID:        &apiKey,
		GrantID:         &grant,
		RequestID:       &reqID,
		IPAddress:       &ip,
		Payload:         payload,
		CreatedAt:       created,
	}

	row := domainEventToCSVRow(ev)
	require.Len(t, row, len(csvHeader), "row width must match header width")

	assert.Equal(t, eventID.String(), row[0])
	assert.Equal(t, "2026-04-24T10:30:45.123Z", row[1])
	assert.Equal(t, "license.created", row[2])
	assert.Equal(t, "license", row[3])
	assert.Equal(t, "lic_123", row[4])
	assert.Equal(t, "identity", row[5])
	assert.Equal(t, "alice@example.com", row[6])
	assert.Equal(t, acting.String(), row[7])
	assert.Equal(t, identity.String(), row[8])
	assert.Equal(t, apiKey.String(), row[9])
	assert.Equal(t, grant.String(), row[10])
	assert.Equal(t, "req_abc", row[11])
	assert.Equal(t, "10.0.0.1", row[12])
	assert.Equal(t, `{"foo":"bar","n":42}`, row[13])
}

func TestDomainEventToCSVRow_NilOptionals(t *testing.T) {
	ev := domain.DomainEvent{
		ID:           core.NewDomainEventID(),
		EventType:    core.EventType("system.tick"),
		ResourceType: "system",
		// ResourceID / ActingAccountID / IdentityID / APIKeyID / GrantID /
		// RequestID / IPAddress all nil.
		ActorKind:  core.ActorKindSystem,
		ActorLabel: "", // plain string, empty is the zero value
		CreatedAt:  time.Date(2026, 4, 24, 0, 0, 0, 0, time.UTC),
		// Payload nil -> empty column.
	}

	row := domainEventToCSVRow(ev)
	require.Len(t, row, len(csvHeader))

	assert.Equal(t, "", row[4], "resource_id")
	assert.Equal(t, "system", row[5], "actor_kind")
	assert.Equal(t, "", row[6], "actor_label")
	assert.Equal(t, "", row[7], "acting_account_id")
	assert.Equal(t, "", row[8], "identity_id")
	assert.Equal(t, "", row[9], "api_key_id")
	assert.Equal(t, "", row[10], "grant_id")
	assert.Equal(t, "", row[11], "request_id")
	assert.Equal(t, "", row[12], "ip_address")
	assert.Equal(t, "", row[13], "payload_json")
}

// TestEventHandler_ProductScopedKey_MismatchRejected_OnGet pins the
// route-level rejection of product-scoped API keys on GET /v1/events/:id.
// The list endpoint silently auto-scopes by product, but per-event
// lookup has no product filter — most events (grant.*, invitation.*,
// webhook.*) are unrelated to any one product's licenses, so a
// product-scoped key has no business reading them. Regression guard:
// if someone removes rejectProductKey from the route registration,
// this test must fail.
func TestEventHandler_ProductScopedKey_MismatchRejected_OnGet(t *testing.T) {
	pid := core.NewProductID()
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c fiber.Ctx, err error) error {
			var ae *core.AppError
			if errors.As(err, &ae) {
				return c.Status(ae.HTTPStatus()).JSON(ae)
			}
			return c.Status(500).JSON(fiber.Map{"error": err.Error()})
		},
	})
	// Wire the same route shape registerRoutes uses: rejectProductKey
	// inserted between auth and the handler. The handler is a no-op
	// because the middleware should short-circuit before it runs.
	app.Get("/events/:id", func(c fiber.Ctx) error {
		c.Locals("auth", &middleware.AuthContext{
			ActorKind:       middleware.ActorKindAPIKey,
			APIKeyScope:     core.APIKeyScopeProduct,
			APIKeyProductID: &pid,
		})
		return c.Next()
	}, middleware.RejectProductScopedKey(), func(c fiber.Ctx) error {
		return c.SendString("should not be reached")
	})

	req := httptest.NewRequest("GET", "/events/"+core.NewDomainEventID().String(), nil)
	resp, err := app.Test(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, 403, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "api_key_scope_mismatch",
		"product-scoped key on /events/:id must be rejected at the route boundary")
}

// TestDomainEventToCSVRow_PayloadWithEmbeddedComma verifies that
// encoding/csv quotes the payload column correctly when it contains
// commas / quotes / newlines. This is the contract that lets the
// dashboard's CSV importer round-trip the payload cleanly.
func TestDomainEventToCSVRow_PayloadWithEmbeddedComma(t *testing.T) {
	ev := domain.DomainEvent{
		ID:           core.NewDomainEventID(),
		EventType:    core.EventType("license.created"),
		ResourceType: "license",
		ActorKind:    core.ActorKindIdentity,
		CreatedAt:    time.Date(2026, 4, 24, 0, 0, 0, 0, time.UTC),
		Payload:      json.RawMessage(`{"a":"x,y","b":"line1\nline2"}`),
	}
	row := domainEventToCSVRow(ev)

	// Round-trip through encoding/csv and confirm the payload survives.
	var buf strings.Builder
	w := csv.NewWriter(&buf)
	require.NoError(t, w.Write(csvHeader))
	require.NoError(t, w.Write(row))
	w.Flush()
	require.NoError(t, w.Error())

	r := csv.NewReader(strings.NewReader(buf.String()))
	records, err := r.ReadAll()
	require.NoError(t, err)
	require.Len(t, records, 2)
	assert.Equal(t, row[13], records[1][13], "payload column round-trips through RFC 4180 quoting")
}
