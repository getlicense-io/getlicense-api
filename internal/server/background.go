package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/audit"
	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/getlicense-io/getlicense-api/internal/webhook"
)

// expireGrantsBatchLimit caps the number of grants swept per tick so a
// large backlog doesn't turn the tick into a long-running tx. Additional
// rows settle on the next tick — the query is idempotent.
const expireGrantsBatchLimit = 500

// webhookFanoutBatchLimit caps the number of domain events handed to
// DeliverDomainEvents per tick. Bounds the per-tick tx fan-out so a
// huge replay backlog doesn't stall the sweep loop. Remaining rows
// settle on subsequent ticks via the durable checkpoint.
const webhookFanoutBatchLimit = 100

// StartBackgroundLoops launches a background goroutine that periodically:
//  1. Expires active licenses whose policy opts into REVOKE_ACCESS.
//  2. Sweeps machine leases: active → stale (lease expired) → dead (grace elapsed).
//  3. Flips grants whose expires_at has passed to GrantStatusExpired.
//  4. Polls domain_events for new rows and enqueues matching webhook
//     deliveries into the durable outbox (webhook_events). Actual
//     HTTP delivery is performed by the webhook worker pool also
//     started here — see internal/webhook/worker.go.
//
// It stops when the provided context is cancelled.
func StartBackgroundLoops(
	ctx context.Context,
	licenseRepo domain.LicenseRepository,
	machineRepo domain.MachineRepository,
	grantRepo domain.GrantRepository,
	domainEventRepo domain.DomainEventRepository,
	webhookRepo domain.WebhookRepository,
	txManager domain.TxManager,
	auditWriter *audit.Writer,
	webhookSvc *webhook.Service,
	webhookWorkers int,
) {
	// Worker pool: claims rows from webhook_events via FOR UPDATE SKIP
	// LOCKED, performs one HTTP attempt, records the outcome. Restart-
	// safe by construction — rows persist across restarts and the
	// pool's startup sweep reaps any stale claims from the previous
	// process generation.
	pool := webhook.NewPool(webhookWorkers, webhookRepo, txManager, webhookSvc.AttemptDelivery)
	go pool.Start(ctx)

	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()

		// Durable checkpoint: persisted in webhook_dispatcher_checkpoint
		// (singleton row, see migration 032). Replaces the in-memory
		// `var lastProcessedID core.DomainEventID` that used to
		// re-fanout the entire history on every restart.
		lastProcessedID := loadWebhookCheckpoint(ctx, webhookRepo)

		for {
			select {
			case <-ctx.Done():
				slog.Info("background loops stopped")
				return
			case <-ticker.C:
				// Expire licenses whose policy has REVOKE_ACCESS
				// strategy. RESTRICT and MAINTAIN strategies compute
				// expired-ness at validate time, not via a DB sweep.
				if expired, err := licenseRepo.ExpireActive(ctx); err != nil {
					slog.Error("license expiry error", "error", err)
				} else if len(expired) > 0 {
					slog.Info("expired licenses", "count", len(expired))
				}

				// Lease sweep: active → stale → dead.
				// Only touches machines whose policy has require_checkout=true.
				if n, err := machineRepo.MarkStaleExpired(ctx); err != nil {
					slog.Error("lease stale sweep error", "error", err)
				} else if n > 0 {
					slog.Info("marked machines stale", "count", n)
				}
				if n, err := machineRepo.MarkDeadExpired(ctx); err != nil {
					slog.Error("lease dead sweep error", "error", err)
				} else if n > 0 {
					slog.Info("marked machines dead", "count", n)
				}

				// Flip past-due grants to expired and emit grant.expired
				// events. Errors are logged, not propagated — the loop
				// continues.
				if n, err := expireGrantsTick(ctx, grantRepo, txManager, auditWriter); err != nil {
					slog.Error("grant expiry sweep error", "error", err)
				} else if n > 0 {
					slog.Info("expired grants", "count", n)
				}

				// Webhook outbox enqueue from domain_events. The unique
				// partial index on (domain_event_id, endpoint_id) makes
				// the enqueue idempotent — overlapping ticks or replay
				// after a crash before the checkpoint advances are safe.
				events, err := domainEventRepo.ListSince(ctx, lastProcessedID, webhookFanoutBatchLimit)
				if err != nil {
					slog.Error("webhook delivery sweep error", "error", err)
				} else if len(events) > 0 {
					webhookSvc.DeliverDomainEvents(ctx, events)
					newCheckpoint := events[len(events)-1].ID
					if err := webhookRepo.UpdateDispatcherCheckpoint(ctx, newCheckpoint); err != nil {
						// Don't advance the in-memory marker on persistence
						// failure — next tick will re-list the same range and
						// the unique constraint will silently dedupe.
						slog.Error("webhook checkpoint persist error", "error", err)
					} else {
						lastProcessedID = newCheckpoint
					}
					slog.Info("processed domain events for webhook delivery", "count", len(events))
				}
			}
		}
	}()
}

// loadWebhookCheckpoint reads the singleton dispatcher checkpoint
// row. Returns the zero DomainEventID on a fresh install (NULL
// last_domain_event_id) — DomainEventRepository.ListSince treats
// the zero ID as "from the beginning". Errors are logged and the
// zero value is returned; the unique constraint on
// (domain_event_id, endpoint_id) absorbs the resulting duplicate
// enqueue attempts on next tick.
func loadWebhookCheckpoint(ctx context.Context, webhookRepo domain.WebhookRepository) core.DomainEventID {
	cp, err := webhookRepo.GetDispatcherCheckpoint(ctx)
	if err != nil {
		slog.Error("webhook checkpoint load error", "error", err)
		return core.DomainEventID{}
	}
	if cp == nil || cp.LastDomainEventID == nil {
		return core.DomainEventID{}
	}
	return *cp.LastDomainEventID
}

// expireGrantsTick flips grants whose expires_at has passed and whose
// status is still non-terminal (pending/active/suspended) to the
// terminal 'expired' state, emitting core.EventTypeGrantExpired for
// each flipped grant.
//
// Runs without tenant context — GrantRepository.ListExpirable passes
// through the NULLIF escape hatch in the tenant_grants RLS policy so
// the sweep sees every account in a single pass. The entire batch
// commits atomically via WithTx; one failing row rolls back the batch,
// and the next tick retries all unprocessed rows (query is idempotent).
//
// Returns the number of grants flipped (0 if none were past due).
func expireGrantsTick(
	ctx context.Context,
	grants domain.GrantRepository,
	tx domain.TxManager,
	auditWriter *audit.Writer,
) (int, error) {
	var flipped int
	err := tx.WithTx(ctx, func(ctx context.Context) error {
		now := time.Now().UTC()
		rows, err := grants.ListExpirable(ctx, now, expireGrantsBatchLimit)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			return nil
		}
		// Payload is identical for every row in this batch; marshal once.
		var payload json.RawMessage
		if auditWriter != nil {
			payload, err = json.Marshal(map[string]any{"expired_at": now})
			if err != nil {
				return err // unreachable for a time.Time, but don't swallow
			}
		}
		for _, g := range rows {
			if err := grants.UpdateStatus(ctx, g.ID, domain.GrantStatusExpired); err != nil {
				return err
			}
			if auditWriter != nil {
				attr := audit.Attribution{
					AccountID:  g.GrantorAccountID,
					ActorKind:  core.ActorKindSystem,
					ActorLabel: "system",
				}
				if err := auditWriter.Record(ctx, audit.EventFrom(
					attr,
					core.EventTypeGrantExpired,
					"grant",
					g.ID.String(),
					payload,
				)); err != nil {
					return err
				}
			}
			flipped++
		}
		return nil
	})
	return flipped, err
}
