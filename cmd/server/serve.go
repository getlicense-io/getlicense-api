package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/getlicense-io/getlicense-api/internal/account"
	"github.com/getlicense-io/getlicense-api/internal/analytics"
	"github.com/getlicense-io/getlicense-api/internal/audit"
	"github.com/getlicense-io/getlicense-api/internal/auth"
	"github.com/getlicense-io/getlicense-api/internal/customer"
	"github.com/getlicense-io/getlicense-api/internal/db"
	"github.com/getlicense-io/getlicense-api/internal/entitlement"
	"github.com/getlicense-io/getlicense-api/internal/environment"
	"github.com/getlicense-io/getlicense-api/internal/grant"
	"github.com/getlicense-io/getlicense-api/internal/identity"
	"github.com/getlicense-io/getlicense-api/internal/invitation"
	"github.com/getlicense-io/getlicense-api/internal/licensing"
	"github.com/getlicense-io/getlicense-api/internal/membership"
	"github.com/getlicense-io/getlicense-api/internal/policy"
	"github.com/getlicense-io/getlicense-api/internal/product"
	"github.com/getlicense-io/getlicense-api/internal/rbac"
	"github.com/getlicense-io/getlicense-api/internal/search"
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
	identityRepo := db.NewIdentityRepo(pool)
	membershipRepo := db.NewMembershipRepo(pool)
	roleRepo := db.NewRoleRepo(pool)
	apiKeyRepo := db.NewAPIKeyRepo(pool)
	refreshTokenRepo := db.NewRefreshTokenRepo(pool)
	jwtRevocationRepo := db.NewJWTRevocationRepo(pool)
	recoveryCodeRepo := db.NewRecoveryCodeRepo(pool)
	productRepo := db.NewProductRepo(pool)
	policyRepo := db.NewPolicyRepo(pool)
	customerRepo := db.NewCustomerRepo(pool)
	licenseRepo := db.NewLicenseRepo(pool)
	machineRepo := db.NewMachineRepo(pool)
	webhookRepo := db.NewWebhookRepo(pool)
	environmentRepo := db.NewEnvironmentRepo(pool)

	// Preload the admin role preset so auth middleware can attach it to
	// API key authentications without hitting the DB per request.
	adminRole, err := roleRepo.GetBySlug(ctx, nil, rbac.RoleSlugAdmin)
	if err != nil {
		return fmt.Errorf("loading admin role preset: %w", err)
	}
	if adminRole == nil {
		return fmt.Errorf("admin role preset not found — run migrations")
	}

	// Services.
	environmentSvc := environment.NewService(txManager, environmentRepo, licenseRepo)
	identitySvc := identity.NewService(identityRepo, recoveryCodeRepo, cfg.MasterKey)
	authSvc := auth.NewService(txManager, accountRepo, identityRepo, membershipRepo, roleRepo, apiKeyRepo, refreshTokenRepo, environmentRepo, productRepo, jwtRevocationRepo, cfg.MasterKey, identitySvc)
	policySvc := policy.NewService(policyRepo)
	customerSvc := customer.NewService(customerRepo)
	entitlementRepo := db.NewEntitlementRepo(pool)
	entitlementSvc := entitlement.NewService(entitlementRepo)
	productSvc := product.NewService(txManager, productRepo, licenseRepo, policySvc, cfg.MasterKey)
	domainEventRepo := db.NewDomainEventRepo(pool)
	webhookSvc := webhook.NewService(txManager, webhookRepo, domainEventRepo, cfg.MasterKey, cfg.IsDevelopment())

	// PR-C refinement: port any pre-PR-C ciphertexts (written without
	// associated data) to the AAD-required format BEFORE the HTTP
	// listener accepts traffic. Idempotent on a fresh DB (e2e), no-op
	// once production has fully rolled over. Errors abort startup so
	// we never serve from a half-encrypted dataset.
	if err := migrateLegacyAEADBlobs(ctx, pool, txManager, cfg.MasterKey); err != nil {
		return fmt.Errorf("server: legacy AEAD blob migration failed: %w", err)
	}

	// PR-3.2: encrypt any webhook signing secrets that pre-date the
	// at-rest encryption migration BEFORE the HTTP listener accepts
	// traffic. Idempotent on a fresh DB (e2e), no-op once production
	// has fully rolled over. Errors abort startup so we never serve
	// from a half-encrypted dataset.
	if err := webhookSvc.BackfillEncryptedSigningSecrets(ctx); err != nil {
		return fmt.Errorf("server: webhook signing secret backfill failed: %w", err)
	}
	auditWriter := audit.NewWriter(domainEventRepo)
	licenseSvc := licensing.NewService(
		txManager, licenseRepo, productRepo, machineRepo, policyRepo,
		customerSvc, entitlementSvc, cfg.MasterKey, auditWriter,
		cfg.DefaultValidationTTLSec,
	)

	analyticsSvc := analytics.NewService(pool, txManager)
	searchSvc := search.NewService(txManager, licenseRepo, machineRepo, customerRepo, productRepo)

	grantRepo := db.NewGrantRepo(pool)
	grantSvc := grant.NewService(txManager, grantRepo, productRepo, auditWriter)

	// account.Service backs the sharing v2 GET /v1/accounts/:id lookup.
	// Wired here so Task 26's handler can consume it; no handler
	// references it yet.
	accountSvc := account.NewService(accountRepo, txManager)

	invitationRepo := db.NewInvitationRepo(pool)
	var mailer invitation.Mailer
	switch cfg.MailerKind {
	case "log":
		mailer = invitation.NewLogMailer(!cfg.IsDevelopment())
	case "noop":
		mailer = invitation.NewNoopMailer()
	default:
		// LoadConfig validates this; defensive in case of future drift.
		return fmt.Errorf("unknown mailer kind: %s", cfg.MailerKind)
	}
	invitationSvc := invitation.NewService(
		txManager,
		invitationRepo,
		identityRepo,
		membershipRepo,
		roleRepo,
		accountRepo,
		grantRepo,
		cfg.MasterKey,
		mailer,
		cfg.DashboardURL,
		grantSvc,
		auditWriter,
	)

	// membership.Service backs the dashboard team-page list endpoint
	// (GET /v1/accounts/:id/members). Read-only — mutation surface
	// (invite, remove, change_role) lives in invitation/auth services.
	membershipSvc := membership.NewService(txManager, membershipRepo)

	// Fiber app.
	deps := &server.Deps{
		AuthService:        authSvc,
		IdentityService:    identitySvc,
		ProductService:     productSvc,
		PolicyService:      policySvc,
		LicenseService:     licenseSvc,
		CustomerService:    customerSvc,
		WebhookService:     webhookSvc,
		EnvironmentService: environmentSvc,
		InvitationService:  invitationSvc,
		GrantService:       grantSvc,
		MembershipService:  membershipSvc,
		AccountService:     accountSvc,
		EntitlementService: entitlementSvc,
		AnalyticsService:   analyticsSvc,
		SearchService:      searchSvc,
		TxManager:          txManager,
		LicenseRepo:        licenseRepo,
		PolicyRepo:         policyRepo,
		ProductRepo:        productRepo,
		DomainEventRepo:    domainEventRepo,
		APIKeyRepo:         apiKeyRepo,
		MembershipRepo:     membershipRepo,
		JWTRevocationRepo:  jwtRevocationRepo,
		AdminRole:          adminRole,
		MasterKey:          cfg.MasterKey,
		Config:             cfg,
	}
	app := server.NewApp(deps)

	server.StartBackgroundLoops(
		ctx,
		licenseRepo, machineRepo, grantRepo, domainEventRepo, webhookRepo, jwtRevocationRepo,
		txManager, auditWriter, webhookSvc,
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
