package main

import (
	"context"
	"fmt"
	"log/slog"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/getlicense-io/getlicense-api/internal/db"
	"github.com/getlicense-io/getlicense-api/internal/rbac"
	"github.com/getlicense-io/getlicense-api/internal/server"
)

func serveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Start the API server (default command)",
		RunE:  runServe,
	}
}

func runServe(_ *cobra.Command, _ []string) error {
	cfg, err := server.LoadConfig()
	if err != nil {
		return err
	}

	configureLogger(cfg)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := db.NewPool(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	txManager := db.NewTxManager(pool)

	redisClient, err := connectRedis(ctx, cfg)
	if err != nil {
		return err
	}
	if redisClient != nil {
		defer func() { _ = redisClient.Close() }()
	}

	repos := newServerRepositories(pool)
	adminRole, err := repos.roles.GetBySlug(ctx, nil, rbac.RoleSlugAdmin)
	if err != nil {
		return fmt.Errorf("loading admin role preset: %w", err)
	}
	if adminRole == nil {
		return fmt.Errorf("admin role preset not found — run migrations")
	}

	services, err := newServerServices(txManager, repos, cfg, redisClient)
	if err != nil {
		return err
	}
	deps := newServerDeps(txManager, repos, services, cfg, adminRole, redisClient)
	app := server.NewApp(deps)

	server.StartBackgroundLoops(
		ctx,
		repos.licenses, repos.machines, repos.grants, repos.domainEvents, repos.webhooks, repos.jwtRevocations,
		txManager, services.auditWriter, services.webhook,
		cfg.WebhookWorkers,
	)

	listenErr := make(chan error, 1)
	go func() {
		slog.Info("server starting", "addr", cfg.ListenAddr(), "env", cfg.Environment)
		listenErr <- app.Listen(cfg.ListenAddr())
	}()

	select {
	case <-ctx.Done():
		slog.Info("shutdown signal received")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), app.Config().WriteTimeout)
		defer cancel()
		if err := app.ShutdownWithContext(shutdownCtx); err != nil {
			slog.Error("error during graceful shutdown", "error", err)
		}
		<-listenErr
	case err := <-listenErr:
		if err != nil {
			return err
		}
	}

	slog.Info("server stopped")
	return nil
}
