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
		lastProcessedID := loadWebhookCheckpoint(ctx, txManager, webhookRepo)

		// runSystem wraps each background sweep in its own
		// WithSystemContext tx so RLS short-circuits — these queries
		// span tenants by design. Each operation gets its own tx so a
		// slow sweep doesn't hold a connection across the entire tick.
		// PR-B (migration 034) replaced the implicit IS NULL bypass with
		// an explicit `app.system_context='true'` GUC; bare-pool calls
		// from background loops would now fail closed without this.
		runSystem := func(label string, fn func(context.Context) error) {
			if err := txManager.WithSystemContext(ctx, fn); err != nil {
				slog.Error("background sweep failed", "op", label, "error", err)
			}
		}

		for {
			select {
			case <-ctx.Done():
				slog.Info("background loops stopped")
				return
			case <-ticker.C:
				// Expire licenses whose policy has REVOKE_ACCESS
				// strategy. RESTRICT and MAINTAIN strategies compute
				// expired-ness at validate time, not via a DB sweep.
				runSystem("license_expiry", func(ctx context.Context) error {
					expired, err := licenseRepo.ExpireActive(ctx)
					if err != nil {
						return err
					}
					if len(expired) > 0 {
						slog.Info("expired licenses", "count", len(expired))
					}
					return nil
				})

				// Lease sweep: active → stale → dead.
				// Only touches machines whose policy has require_checkout=true.
				runSystem("lease_stale", func(ctx context.Context) error {
					n, err := machineRepo.MarkStaleExpired(ctx)
					if err != nil {
						return err
					}
					if n > 0 {
						slog.Info("marked machines stale", "count", n)
					}
					return nil
				})
				runSystem("lease_dead", func(ctx context.Context) error {
					n, err := machineRepo.MarkDeadExpired(ctx)
					if err != nil {
						return err
					}
					if n > 0 {
						slog.Info("marked machines dead", "count", n)
					}
					return nil
				})

				// Flip past-due grants to expired and emit grant.expired
				// events. Errors are logged, not propagated — the loop
				// continues.
				if n, err := expireGrantsTick(ctx, grantRepo, txManager, auditWriter); err != nil {
					slog.Error("grant expiry sweep error", "error", err)
				} else if n > 0 {
					slog.Info("expired grants", "count", n)
				}

				// Webhook outbox enqueue from domain_events. The
				// durable checkpoint (bumped immediately below) is the
				// only de-dup mechanism — the unique partial index on
				// (domain_event_id, endpoint_id) hinted at in earlier
				// drafts was dropped (see migration 032 header). At-
				// least-once delivery on the crash-before-checkpoint
				// edge is contractually expected; consumers dedupe via
				// envelope.id (= stable domain_event_id, PR-A.1).
				//
				// Failure handling (PR-3.1 fix): DeliverDomainEvents
				// returns the ID of the LAST fully-enqueued event. If
				// any event in the batch fails its endpoint lookup or
				// its atomic insert, we advance only as far as the
				// last successful event — events past the failure are
				// reprocessed on the next tick. This trades duplicate-
				// delivery risk for guaranteed at-least-once semantics
				// (the previous code advanced past failures, losing
				// events forever).
				runSystem("webhook_fanout", func(ctx context.Context) error {
					events, err := domainEventRepo.ListSince(ctx, lastProcessedID, webhookFanoutBatchLimit)
					if err != nil {
						return err
					}
					if len(events) == 0 {
						return nil
					}
					processed := webhookSvc.DeliverDomainEvents(ctx, events)
					var zeroID core.DomainEventID
					if processed == zeroID {
						// Nothing was fully enqueued — leave checkpoint.
						slog.Warn("webhook_fanout: no events fully enqueued; checkpoint unchanged",
							"batch_size", len(events))
						return nil
					}
					if err := webhookRepo.UpdateDispatcherCheckpoint(ctx, processed); err != nil {
						return err
					}
					// Count events actually advanced past so the operator
					// can spot partial failures (advanced < batch_size).
					advanced := 0
					for _, e := range events {
						advanced++
						if e.ID == processed {
							break
						}
					}
					lastProcessedID = processed
					slog.Info("processed domain events for webhook delivery",
						"advanced", advanced, "batch_size", len(events))
					return nil
				})
			}
		}
	}()
}

// loadWebhookCheckpoint reads the singleton dispatcher checkpoint
// row. Returns the zero DomainEventID on a fresh install (NULL
// last_domain_event_id) — DomainEventRepository.ListSince treats
// the zero ID as "from the beginning". Errors are logged and the
// zero value is returned; the duplicate enqueue attempts on the
// next tick are tolerated by consumer-side dedup on envelope.id
// (the stable domain_event_id, PR-A.1).
//
// The checkpoint table (webhook_dispatcher_checkpoint) does not have
// RLS enabled, but the read still goes through WithSystemContext so
// the pattern is uniform with the per-tick sweeps and the helper
// gracefully grows if RLS is added later.
func loadWebhookCheckpoint(ctx context.Context, txManager domain.TxManager, webhookRepo domain.WebhookRepository) core.DomainEventID {
	var out core.DomainEventID
	err := txManager.WithSystemContext(ctx, func(ctx context.Context) error {
		cp, err := webhookRepo.GetDispatcherCheckpoint(ctx)
		if err != nil {
			return err
		}
		if cp == nil || cp.LastDomainEventID == nil {
			return nil
		}
		out = *cp.LastDomainEventID
		return nil
	})
	if err != nil {
		slog.Error("webhook checkpoint load error", "error", err)
		return core.DomainEventID{}
	}
	return out
}

// expireGrantsTick flips grants whose expires_at has passed and whose
// status is still non-terminal (pending/active/suspended) to the
// terminal 'expired' state, emitting core.EventTypeGrantExpired for
// each flipped grant.
//
// Runs under WithSystemContext so the cross-tenant sweep bypasses RLS
// explicitly (PR-B / migration 034). The entire batch commits
// atomically; one failing row rolls back the batch, and the next tick
// retries all unprocessed rows (query is idempotent).
//
// Returns the number of grants flipped (0 if none were past due).
func expireGrantsTick(
	ctx context.Context,
	grants domain.GrantRepository,
	tx domain.TxManager,
	auditWriter *audit.Writer,
) (int, error) {
	var flipped int
	err := tx.WithSystemContext(ctx, func(ctx context.Context) error {
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
