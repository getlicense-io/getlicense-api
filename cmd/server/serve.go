package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/getlicense-io/getlicense-api/internal/auth"
	"github.com/getlicense-io/getlicense-api/internal/db"
	"github.com/getlicense-io/getlicense-api/internal/licensing"
	"github.com/getlicense-io/getlicense-api/internal/product"
	"github.com/getlicense-io/getlicense-api/internal/server"
	"github.com/getlicense-io/getlicense-api/internal/webhook"
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

	if cfg.IsDevelopment() {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})))
	} else {
		slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := db.NewPool(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	txManager := db.NewTxManager(pool)

	// Repositories.
	accountRepo := db.NewAccountRepo(pool)
	userRepo := db.NewUserRepo(pool)
	apiKeyRepo := db.NewAPIKeyRepo(pool)
	refreshTokenRepo := db.NewRefreshTokenRepo(pool)
	productRepo := db.NewProductRepo(pool)
	licenseRepo := db.NewLicenseRepo(pool)
	machineRepo := db.NewMachineRepo(pool)
	webhookRepo := db.NewWebhookRepo(pool)

	// Services.
	authSvc := auth.NewService(txManager, accountRepo, userRepo, apiKeyRepo, refreshTokenRepo, cfg.MasterKey)
	productSvc := product.NewService(txManager, productRepo, cfg.MasterKey)
	webhookSvc := webhook.NewService(txManager, webhookRepo, cfg.IsDevelopment())
	licenseSvc := licensing.NewService(txManager, licenseRepo, productRepo, machineRepo, cfg.MasterKey, webhookSvc)

	// Fiber app.
	deps := &server.Deps{
		AuthService:    authSvc,
		ProductService: productSvc,
		LicenseService: licenseSvc,
		WebhookService: webhookSvc,
		APIKeyRepo:     apiKeyRepo,
		MasterKey:      cfg.MasterKey,
		Config:         cfg,
	}
	app := server.NewApp(deps)

	server.StartBackgroundLoops(ctx, licenseRepo, machineRepo)

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
