package db

import (
	"database/sql"
	"fmt"
	"io/fs"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

// RunMigrations runs all pending database migrations using the provided filesystem.
func RunMigrations(databaseURL string, migrationsFS fs.FS) error {
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return fmt.Errorf("opening database for migrations: %w", err)
	}
	defer func() { _ = db.Close() }()

	goose.SetBaseFS(migrationsFS)

	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("setting goose dialect: %w", err)
	}

	if err := goose.Up(db, "."); err != nil {
		return fmt.Errorf("running migrations: %w", err)
	}

	return nil
}
