package main

import (
	"context"
	"fmt"
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
	migrations "github.com/getlicense-io/getlicense-api/migrations"
)

func main() {
	root := buildRoot()
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

// buildRoot constructs the root Cobra command. The root command itself runs the
// serve logic so that `getlicense-server` (no subcommand) starts the server.
func buildRoot() *cobra.Command {
	root := &cobra.Command{
		Use:   "getlicense-server",
		Short: "GetLicense API server",
		Long:  "GetLicense API server — serves the REST API and manages license lifecycle.",
		// Running the root command directly is identical to running 'serve'.
		RunE: runServe,
		// Suppress default completion subcommand noise.
		CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
	}

	root.AddCommand(serveCmd(), migrateCmd())
	return root
}

func serveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Start the API server (default command)",
		RunE:  runServe,
	}
}

func migrateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "migrate",
		Short: "Run database migrations and exit",
		RunE:  runMigrate,
	}
}

// runServe is the composition root for the serve command.
func runServe(_ *cobra.Command, _ []string) error {
	// 1. Load config from environment.
	cfg, err := server.LoadConfig()
	if err != nil {
		return err
	}

	// 2. Configure structured logging.
	var logger *slog.Logger
	if cfg.IsDevelopment() {
		logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	} else {
		logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}
	slog.SetDefault(logger)

	// 3. Create a root context that cancels on SIGINT / SIGTERM.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// 4. Connect to the database.
	pool, err := db.NewPool(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	txManager := db.NewTxManager(pool)

	// 5. Create repositories.
	accountRepo := db.NewAccountRepo(pool)
	userRepo := db.NewUserRepo(pool)
	apiKeyRepo := db.NewAPIKeyRepo(pool)
	refreshTokenRepo := db.NewRefreshTokenRepo(pool)
	productRepo := db.NewProductRepo(pool)
	licenseRepo := db.NewLicenseRepo(pool)
	machineRepo := db.NewMachineRepo(pool)
	webhookRepo := db.NewWebhookRepo(pool)

	// 6. Create services.
	authSvc := auth.NewService(txManager, accountRepo, userRepo, apiKeyRepo, refreshTokenRepo, cfg.MasterKey)
	productSvc := product.NewService(txManager, productRepo, cfg.MasterKey)
	licenseSvc := licensing.NewService(txManager, licenseRepo, productRepo, machineRepo, cfg.MasterKey)
	webhookSvc := webhook.NewService(txManager, webhookRepo)

	// 7. Build the Fiber application.
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

	// 8. Start background jobs (license expiry).
	server.StartExpiryLoop(ctx, licenseRepo)

	// 9. Start listening in a goroutine so we can handle shutdown below.
	listenErr := make(chan error, 1)
	go func() {
		slog.Info("server starting", "addr", cfg.ListenAddr(), "env", cfg.Environment)
		listenErr <- app.Listen(cfg.ListenAddr())
	}()

	// 10. Wait for a signal or a listen error.
	select {
	case <-ctx.Done():
		slog.Info("shutdown signal received")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), app.Config().WriteTimeout)
		defer cancel()
		if err := app.ShutdownWithContext(shutdownCtx); err != nil {
			slog.Error("error during graceful shutdown", "error", err)
		}
		// Drain the listen goroutine.
		<-listenErr
	case err := <-listenErr:
		if err != nil {
			return err
		}
	}

	slog.Info("server stopped")
	return nil
}

// runMigrate reads DATABASE_URL from the environment and runs all pending
// SQL migrations using the embedded filesystem.
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
