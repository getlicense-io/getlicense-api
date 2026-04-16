package server

import (
	"context"
	"log/slog"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/getlicense-io/getlicense-api/internal/webhook"
)

// StartBackgroundLoops launches a background goroutine that periodically:
//  1. Expires active licenses whose policy opts into REVOKE_ACCESS.
//  2. Sweeps machine leases: active → stale (lease expired) → dead (grace elapsed).
//  3. Polls domain_events for new rows and delivers matching webhooks.
//
// It stops when the provided context is cancelled.
func StartBackgroundLoops(ctx context.Context, licenseRepo domain.LicenseRepository, machineRepo domain.MachineRepository, domainEventRepo domain.DomainEventRepository, webhookSvc *webhook.Service) {
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()

		// Track the last domain event we processed for webhook delivery.
		// Zero UUID ensures the first sweep picks up all existing events.
		var lastProcessedID core.DomainEventID

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

				// Webhook delivery from domain_events.
				events, err := domainEventRepo.ListSince(ctx, lastProcessedID, 100)
				if err != nil {
					slog.Error("webhook delivery sweep error", "error", err)
				} else if len(events) > 0 {
					webhookSvc.DeliverDomainEvents(ctx, events)
					lastProcessedID = events[len(events)-1].ID
					slog.Info("processed domain events for webhook delivery", "count", len(events))
				}
			}
		}
	}()
}
