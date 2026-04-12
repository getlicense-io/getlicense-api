package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/getlicense-io/getlicense-api/internal/db"
	migrations "github.com/getlicense-io/getlicense-api/migrations"
)

func migrateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "migrate",
		Short: "Run database migrations and exit",
		RunE:  runMigrate,
	}
}

func runMigrate(_ *cobra.Command, _ []string) error {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		return fmt.Errorf("migrate: DATABASE_URL is required")
	}

	slog.Info("running migrations")
	if err := db.RunMigrations(dbURL, migrations.FS); err != nil {
		return err
	}
	slog.Info("migrations complete")
	return nil
}
