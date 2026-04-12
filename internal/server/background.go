package server

import (
	"context"
	"log/slog"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/domain"
)

// StartBackgroundLoops launches a background goroutine that periodically:
// - expires active licenses that have passed their expiry date
// - deactivates stale machines that exceeded their product's heartbeat timeout
// It stops when the provided context is cancelled.
func StartBackgroundLoops(ctx context.Context, licenseRepo domain.LicenseRepository, machineRepo domain.MachineRepository) {
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				slog.Info("background loops stopped")
				return
			case <-ticker.C:
				// Expire licenses.
				if expired, err := licenseRepo.ExpireActive(ctx); err != nil {
					slog.Error("license expiry error", "error", err)
				} else if len(expired) > 0 {
					slog.Info("expired licenses", "count", len(expired))
				}

				// Deactivate stale machines.
				if count, err := machineRepo.DeactivateStale(ctx); err != nil {
					slog.Error("stale machine cleanup error", "error", err)
				} else if count > 0 {
					slog.Info("deactivated stale machines", "count", count)
				}
			}
		}
	}()
}
