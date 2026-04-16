package db

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Integration tests for DomainEventRepo.
//
// Gating, harness, and cleanup conventions mirror policy_repo_test.go:
// `-short` skips, `make test-all` runs against the dev Postgres, each
// test begins its own top-level tx and rolls it back on cleanup so
// nothing survives.
//
// ListSince is the exception: it reads via the pool directly (bypassing
// the tx), so that test commits data and cleans up explicitly.

// domainEventFixture holds a fresh rollback-only tx with a seeded
// account plus RLS session vars. Suitable for Create/Get/List tests.
type domainEventFixture struct {
	ctx       context.Context
	accountID core.AccountID
}

func newDomainEventFixture(t *testing.T, pool *pgxpool.Pool) *domainEventFixture {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })

	accountID := core.NewAccountID()
	env := core.Environment("live")

	if _, err := tx.Exec(ctx,
		`SELECT set_config('app.current_account_id', $1, true)`, accountID.String()); err != nil {
		t.Fatalf("set_config account: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`SELECT set_config('app.current_environment', $1, true)`, string(env)); err != nil {
		t.Fatalf("set_config env: %v", err)
	}

	slug := "evt-" + accountID.String()[:8]
	if _, err := tx.Exec(ctx,
		`INSERT INTO accounts (id, name, slug, created_at) VALUES ($1, $2, $3, NOW())`,
		uuid.UUID(accountID), "Event Test Account", slug,
	); err != nil {
		t.Fatalf("seed account: %v", err)
	}

	ctx = context.WithValue(ctx, ctxKey{}, tx)
	return &domainEventFixture{
		ctx:       ctx,
		accountID: accountID,
	}
}

// newDomainEvent returns a fully-populated DomainEvent for the fixture's
// account. Callers override fields as needed.
func newDomainEvent(f *domainEventFixture, eventType core.EventType, resourceType string) *domain.DomainEvent {
	rid := uuid.NewString()
	actingID := core.AccountID(uuid.New())
	identityID := core.IdentityID(uuid.New())
	apiKeyID := core.APIKeyID(uuid.New())
	grantID := core.GrantID(uuid.New())
	reqID := "req-" + uuid.NewString()[:8]
	ip := "192.168.1.1"

	return &domain.DomainEvent{
		ID:              core.NewDomainEventID(),
		AccountID:       f.accountID,
		Environment:     core.Environment("live"),
		EventType:       eventType,
		ResourceType:    resourceType,
		ResourceID:      &rid,
		ActingAccountID: &actingID,
		IdentityID:      &identityID,
		ActorLabel:      "test@example.com",
		ActorKind:       core.ActorKindIdentity,
		APIKeyID:        &apiKeyID,
		GrantID:         &grantID,
		RequestID:       &reqID,
		IPAddress:       &ip,
		Payload:         json.RawMessage(`{"action":"test"}`),
		CreatedAt:       time.Now().UTC(),
	}
}

func TestDomainEventRepo_CreateAndGet(t *testing.T) {
	pool := integrationPool(t)
	f := newDomainEventFixture(t, pool)
	repo := NewDomainEventRepo(pool)

	e := newDomainEvent(f, core.EventTypeLicenseCreated, "license")
	if err := repo.Create(f.ctx, e); err != nil {
		t.Fatalf("create: %v", err)
	}

	got, err := repo.Get(f.ctx, e.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got == nil {
		t.Fatal("get: expected non-nil event")
	}

	// Round-trip all 16 fields.
	if got.ID != e.ID {
		t.Errorf("id = %v, want %v", got.ID, e.ID)
	}
	if got.AccountID != e.AccountID {
		t.Errorf("account_id = %v, want %v", got.AccountID, e.AccountID)
	}
	if got.Environment != e.Environment {
		t.Errorf("environment = %q, want %q", got.Environment, e.Environment)
	}
	if got.EventType != e.EventType {
		t.Errorf("event_type = %q, want %q", got.EventType, e.EventType)
	}
	if got.ResourceType != e.ResourceType {
		t.Errorf("resource_type = %q, want %q", got.ResourceType, e.ResourceType)
	}
	if got.ResourceID == nil || *got.ResourceID != *e.ResourceID {
		t.Errorf("resource_id = %v, want %v", got.ResourceID, *e.ResourceID)
	}
	if got.ActingAccountID == nil || *got.ActingAccountID != *e.ActingAccountID {
		t.Errorf("acting_account_id = %v, want %v", got.ActingAccountID, e.ActingAccountID)
	}
	if got.IdentityID == nil || *got.IdentityID != *e.IdentityID {
		t.Errorf("identity_id = %v, want %v", got.IdentityID, e.IdentityID)
	}
	if got.ActorLabel != e.ActorLabel {
		t.Errorf("actor_label = %q, want %q", got.ActorLabel, e.ActorLabel)
	}
	if got.ActorKind != e.ActorKind {
		t.Errorf("actor_kind = %q, want %q", got.ActorKind, e.ActorKind)
	}
	if got.APIKeyID == nil || *got.APIKeyID != *e.APIKeyID {
		t.Errorf("api_key_id = %v, want %v", got.APIKeyID, e.APIKeyID)
	}
	if got.GrantID == nil || *got.GrantID != *e.GrantID {
		t.Errorf("grant_id = %v, want %v", got.GrantID, e.GrantID)
	}
	if got.RequestID == nil || *got.RequestID != *e.RequestID {
		t.Errorf("request_id = %v, want %v", got.RequestID, e.RequestID)
	}
	// Postgres inet::text appends /32 for single hosts.
	if got.IPAddress == nil {
		t.Errorf("ip_address = nil, want %s", *e.IPAddress)
	} else if *got.IPAddress != *e.IPAddress && *got.IPAddress != *e.IPAddress+"/32" {
		t.Errorf("ip_address = %q, want %q", *got.IPAddress, *e.IPAddress)
	}
	if !jsonEqual(t, got.Payload, `{"action":"test"}`) {
		t.Errorf("payload = %s, want {\"action\":\"test\"}", string(got.Payload))
	}
	if got.CreatedAt.IsZero() {
		t.Error("created_at is zero")
	}
}

func TestDomainEventRepo_GetNotFound(t *testing.T) {
	pool := integrationPool(t)
	f := newDomainEventFixture(t, pool)
	repo := NewDomainEventRepo(pool)

	got, err := repo.Get(f.ctx, core.NewDomainEventID())
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got != nil {
		t.Errorf("expected (nil, nil); got %+v", got)
	}
}

func TestDomainEventRepo_List_FilterByResourceType(t *testing.T) {
	pool := integrationPool(t)
	f := newDomainEventFixture(t, pool)
	repo := NewDomainEventRepo(pool)

	// Seed 3 events with different resource_types.
	types := []string{"license", "machine", "product"}
	for _, rt := range types {
		e := newDomainEvent(f, core.EventTypeLicenseCreated, rt)
		if err := repo.Create(f.ctx, e); err != nil {
			t.Fatalf("create %s: %v", rt, err)
		}
	}

	// Filter by "license" — should get exactly 1.
	filter := domain.DomainEventFilter{ResourceType: "license"}
	got, hasMore, err := repo.List(f.ctx, filter, core.Cursor{}, 50)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if hasMore {
		t.Error("has_more = true, want false")
	}
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	if got[0].ResourceType != "license" {
		t.Errorf("resource_type = %q, want license", got[0].ResourceType)
	}
}

func TestDomainEventRepo_List_FilterByEventType(t *testing.T) {
	pool := integrationPool(t)
	f := newDomainEventFixture(t, pool)
	repo := NewDomainEventRepo(pool)

	// Seed 3 events with different event_types.
	eventTypes := []core.EventType{
		core.EventTypeLicenseCreated,
		core.EventTypeLicenseSuspended,
		core.EventTypeMachineActivated,
	}
	for _, et := range eventTypes {
		e := newDomainEvent(f, et, "license")
		if err := repo.Create(f.ctx, e); err != nil {
			t.Fatalf("create %s: %v", et, err)
		}
	}

	// Filter by license.suspended — should get exactly 1.
	filter := domain.DomainEventFilter{EventType: core.EventTypeLicenseSuspended}
	got, hasMore, err := repo.List(f.ctx, filter, core.Cursor{}, 50)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if hasMore {
		t.Error("has_more = true, want false")
	}
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	if got[0].EventType != core.EventTypeLicenseSuspended {
		t.Errorf("event_type = %q, want %q", got[0].EventType, core.EventTypeLicenseSuspended)
	}
}

func TestDomainEventRepo_List_Pagination(t *testing.T) {
	pool := integrationPool(t)
	f := newDomainEventFixture(t, pool)
	repo := NewDomainEventRepo(pool)

	// 7 events with strictly increasing created_at so the
	// (created_at DESC, id DESC) keyset ordering is deterministic.
	base := time.Now().UTC().Add(-time.Hour)
	want := make([]core.DomainEventID, 0, 7)
	for i := 0; i < 7; i++ {
		e := newDomainEvent(f, core.EventTypeLicenseCreated, "license")
		e.CreatedAt = base.Add(time.Duration(i) * time.Second)
		if err := repo.Create(f.ctx, e); err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
		// Descending order: newest first.
		want = append([]core.DomainEventID{e.ID}, want...)
	}

	// Page 1 (3 rows).
	page1, hasMore1, err := repo.List(f.ctx, domain.DomainEventFilter{}, core.Cursor{}, 3)
	if err != nil {
		t.Fatalf("page1: %v", err)
	}
	if len(page1) != 3 {
		t.Fatalf("page1 len = %d, want 3", len(page1))
	}
	if !hasMore1 {
		t.Error("page1 has_more = false, want true")
	}
	for i := 0; i < 3; i++ {
		if page1[i].ID != want[i] {
			t.Errorf("page1[%d] = %v, want %v", i, page1[i].ID, want[i])
		}
	}

	// Page 2 (3 rows).
	last1 := page1[len(page1)-1]
	cursor2 := core.Cursor{CreatedAt: last1.CreatedAt, ID: uuid.UUID(last1.ID)}
	page2, hasMore2, err := repo.List(f.ctx, domain.DomainEventFilter{}, cursor2, 3)
	if err != nil {
		t.Fatalf("page2: %v", err)
	}
	if len(page2) != 3 {
		t.Fatalf("page2 len = %d, want 3", len(page2))
	}
	if !hasMore2 {
		t.Error("page2 has_more = false, want true")
	}
	for i := 0; i < 3; i++ {
		if page2[i].ID != want[3+i] {
			t.Errorf("page2[%d] = %v, want %v", i, page2[i].ID, want[3+i])
		}
	}

	// Page 3 (1 row, tail).
	last2 := page2[len(page2)-1]
	cursor3 := core.Cursor{CreatedAt: last2.CreatedAt, ID: uuid.UUID(last2.ID)}
	page3, hasMore3, err := repo.List(f.ctx, domain.DomainEventFilter{}, cursor3, 3)
	if err != nil {
		t.Fatalf("page3: %v", err)
	}
	if len(page3) != 1 {
		t.Fatalf("page3 len = %d, want 1", len(page3))
	}
	if hasMore3 {
		t.Error("page3 has_more = true, want false")
	}
	if page3[0].ID != want[6] {
		t.Errorf("page3[0] = %v, want %v", page3[0].ID, want[6])
	}
}

func TestDomainEventRepo_ListSince(t *testing.T) {
	pool := integrationPool(t)

	// ListSince reads via pool directly (no tx), so we must commit data
	// and clean up explicitly. The RLS NULLIF escape hatch allows reads/
	// writes when app.current_account_id is unset.
	ctx := context.Background()
	accountID := core.NewAccountID()
	slug := "evt-ls-" + accountID.String()[:8]
	if _, err := pool.Exec(ctx,
		`INSERT INTO accounts (id, name, slug, created_at) VALUES ($1, $2, $3, NOW())`,
		uuid.UUID(accountID), "ListSince Test", slug,
	); err != nil {
		t.Fatalf("seed account: %v", err)
	}
	t.Cleanup(func() {
		cctx := context.Background()
		_, _ = pool.Exec(cctx, `DELETE FROM domain_events WHERE account_id = $1`, uuid.UUID(accountID))
		_, _ = pool.Exec(cctx, `DELETE FROM accounts WHERE id = $1`, uuid.UUID(accountID))
	})

	repo := NewDomainEventRepo(pool)

	// Seed 5 events. UUID v7 gives monotonic IDs when generated sequentially.
	ids := make([]core.DomainEventID, 5)
	base := time.Now().UTC().Add(-time.Hour)
	for i := 0; i < 5; i++ {
		id := core.NewDomainEventID()
		ids[i] = id
		e := &domain.DomainEvent{
			ID:           id,
			AccountID:    accountID,
			Environment:  core.Environment("live"),
			EventType:    core.EventTypeLicenseCreated,
			ResourceType: "license",
			ActorLabel:   "system",
			ActorKind:    core.ActorKindSystem,
			Payload:      json.RawMessage(`{}`),
			CreatedAt:    base.Add(time.Duration(i) * time.Second),
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO domain_events (`+domainEventColumns+`)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`,
			uuid.UUID(e.ID), uuid.UUID(e.AccountID), string(e.Environment),
			string(e.EventType), e.ResourceType, e.ResourceID,
			nil, nil, // acting_account_id, identity_id
			e.ActorLabel, string(e.ActorKind),
			nil, nil, // api_key_id, grant_id
			nil, nil, // request_id, ip_address
			e.Payload, e.CreatedAt,
		); err != nil {
			t.Fatalf("seed event %d: %v", i, err)
		}
	}

	// ListSince with the 3rd event's ID (index 2) should return events 4 and 5.
	got, err := repo.ListSince(ctx, ids[2], 100)
	if err != nil {
		t.Fatalf("list since: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	if got[0].ID != ids[3] {
		t.Errorf("got[0].ID = %v, want %v", got[0].ID, ids[3])
	}
	if got[1].ID != ids[4] {
		t.Errorf("got[1].ID = %v, want %v", got[1].ID, ids[4])
	}
}
