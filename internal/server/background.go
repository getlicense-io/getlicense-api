package server

import (
	"context"
	"log/slog"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/domain"
)

// StartExpiryLoop launches a background goroutine that periodically expires
// active licenses that have passed their expiry date.
// It stops when the provided context is cancelled.
func StartExpiryLoop(ctx context.Context, licenseRepo domain.LicenseRepository) {
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				slog.Info("license expiry loop stopped")
				return
			case <-ticker.C:
				expired, err := licenseRepo.ExpireActive(ctx)
				if err != nil {
					slog.Error("license expiry loop error", "error", err.Error())
					continue
				}
				if len(expired) > 0 {
					slog.Info("expired licenses", "count", len(expired))
				}
			}
		}
	}()
}
