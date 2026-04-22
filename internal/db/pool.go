package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

func NewPool(ctx context.Context, databaseURL string) (*pgxpool.Pool, error) {
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parsing database URL: %w", err)
	}

	config.MaxConns = 20
	config.MinConns = 2
	config.MaxConnLifetime = 30 * time.Minute
	config.MaxConnIdleTime = 5 * time.Minute
	config.HealthCheckPeriod = 30 * time.Second

	// Pin the session timezone to UTC on every new connection. Without
	// this, pgx renders `timestamptz` columns on reads using the Postgres
	// session TZ, so a POST response returns `...Z` (we always call
	// time.Now().UTC() in Go) while a subsequent GET for the same row
	// returns `...+05:30` when the host runs outside UTC.
	//
	// RuntimeParams["timezone"] only affects TEXT-format decoding.
	// pgx defaults to BINARY format for timestamptz, which decodes via
	// time.Unix() — that returns time.Local unless we override the
	// codec's ScanLocation. Registering a UTC-scanning TimestamptzCodec
	// (and its Timestamp sibling for timezone-naive columns) forces
	// both formats to hand back UTC-anchored time.Time values so the
	// JSON marshalling path produces `...Z` on every read.
	if config.ConnConfig.RuntimeParams == nil {
		config.ConnConfig.RuntimeParams = map[string]string{}
	}
	config.ConnConfig.RuntimeParams["timezone"] = "UTC"
	config.AfterConnect = func(_ context.Context, conn *pgx.Conn) error {
		tm := conn.TypeMap()
		tm.RegisterType(&pgtype.Type{
			Name:  "timestamptz",
			OID:   pgtype.TimestamptzOID,
			Codec: &pgtype.TimestamptzCodec{ScanLocation: time.UTC},
		})
		tm.RegisterType(&pgtype.Type{
			Name:  "timestamp",
			OID:   pgtype.TimestampOID,
			Codec: &pgtype.TimestampCodec{ScanLocation: time.UTC},
		})
		return nil
	}

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("creating connection pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pinging database: %w", err)
	}

	return pool, nil
}
