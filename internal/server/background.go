package server

import (
	"context"
	"log/slog"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/domain"
)

// StartBackgroundLoops launches a background goroutine that periodically
// expires active licenses whose policy opts into REVOKE_ACCESS. It stops
// when the provided context is cancelled.
//
// NOTE: The old heartbeat-based stale-machine cleanup job was retired in
// L1. It joined against products.heartbeat_timeout, which migration 020
// dropped as part of the policies refactor. L2 reintroduces a lease-based
// replacement; until then, machines are not reaped in the background.
func StartBackgroundLoops(ctx context.Context, licenseRepo domain.LicenseRepository) {
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()

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
			}
		}
	}()
}
