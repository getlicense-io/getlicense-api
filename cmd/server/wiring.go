package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/getlicense-io/getlicense-api/internal/account"
	"github.com/getlicense-io/getlicense-api/internal/analytics"
	"github.com/getlicense-io/getlicense-api/internal/audit"
	"github.com/getlicense-io/getlicense-api/internal/auth"
	"github.com/getlicense-io/getlicense-api/internal/customer"
	"github.com/getlicense-io/getlicense-api/internal/db"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/getlicense-io/getlicense-api/internal/entitlement"
	"github.com/getlicense-io/getlicense-api/internal/environment"
	"github.com/getlicense-io/getlicense-api/internal/grant"
	"github.com/getlicense-io/getlicense-api/internal/identity"
	"github.com/getlicense-io/getlicense-api/internal/invitation"
	"github.com/getlicense-io/getlicense-api/internal/licensing"
	"github.com/getlicense-io/getlicense-api/internal/membership"
	"github.com/getlicense-io/getlicense-api/internal/policy"
	"github.com/getlicense-io/getlicense-api/internal/product"
	"github.com/getlicense-io/getlicense-api/internal/search"
	"github.com/getlicense-io/getlicense-api/internal/server"
	"github.com/getlicense-io/getlicense-api/internal/webhook"
)

type serverRepositories struct {
	accounts       *db.AccountRepo
	identities     *db.IdentityRepo
	memberships    *db.MembershipRepo
	roles          *db.RoleRepo
	apiKeys        *db.APIKeyRepo
	refreshTokens  *db.RefreshTokenRepo
	jwtRevocations *db.JWTRevocationRepo
	recoveryCodes  *db.RecoveryCodeRepo
	products       *db.ProductRepo
	policies       *db.PolicyRepo
	customers      *db.CustomerRepo
	licenses       *db.LicenseRepo
	machines       *db.MachineRepo
	webhooks       *db.WebhookRepo
	environments   *db.EnvironmentRepo
	entitlements   *db.EntitlementRepo
	domainEvents   *db.DomainEventRepo
	grants         *db.GrantRepo
	invitations    *db.InvitationRepo
}

type serverServices struct {
	auth        *auth.Service
	identity    *identity.Service
	product     *product.Service
	policy      *policy.Service
	license     *licensing.Service
	customer    *customer.Service
	webhook     *webhook.Service
	environment *environment.Service
	invitation  *invitation.Service
	grant       *grant.Service
	membership  *membership.Service
	account     *account.Service
	entitlement *entitlement.Service
	analytics   *analytics.Service
	search      *search.Service
	auditWriter *audit.Writer
}

func configureLogger(cfg *server.Config) {
	if cfg.IsDevelopment() {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})))
		return
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))
}

func connectRedis(ctx context.Context, cfg *server.Config) (redis.UniversalClient, error) {
	if cfg.RedisURL == "" {
		return nil, nil
	}
	opts, err := redis.ParseURL(cfg.RedisURL)
	if err != nil {
		return nil, fmt.Errorf("parsing GETLICENSE_REDIS_URL: %w", err)
	}
	client := redis.NewClient(opts)
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("connecting to Redis/Valkey: %w", err)
	}
	return client, nil
}

func newServerRepositories(pool *pgxpool.Pool) serverRepositories {
	return serverRepositories{
		accounts:       db.NewAccountRepo(pool),
		identities:     db.NewIdentityRepo(pool),
		memberships:    db.NewMembershipRepo(pool),
		roles:          db.NewRoleRepo(pool),
		apiKeys:        db.NewAPIKeyRepo(pool),
		refreshTokens:  db.NewRefreshTokenRepo(pool),
		jwtRevocations: db.NewJWTRevocationRepo(pool),
		recoveryCodes:  db.NewRecoveryCodeRepo(pool),
		products:       db.NewProductRepo(pool),
		policies:       db.NewPolicyRepo(pool),
		customers:      db.NewCustomerRepo(pool),
		licenses:       db.NewLicenseRepo(pool),
		machines:       db.NewMachineRepo(pool),
		webhooks:       db.NewWebhookRepo(pool),
		environments:   db.NewEnvironmentRepo(pool),
		entitlements:   db.NewEntitlementRepo(pool),
		domainEvents:   db.NewDomainEventRepo(pool),
		grants:         db.NewGrantRepo(pool),
		invitations:    db.NewInvitationRepo(pool),
	}
}

func newServerServices(
	txManager *db.TxManager,
	repos serverRepositories,
	cfg *server.Config,
	redisClient redis.UniversalClient,
) (serverServices, error) {
	environmentSvc := environment.NewService(txManager, repos.environments, repos.licenses)
	identitySvc := identity.NewService(repos.identities, repos.recoveryCodes, cfg.MasterKey)
	var pendingStores []auth.PendingTokenStore
	if redisClient != nil {
		pendingStores = append(pendingStores, auth.NewRedisPendingTokenStore(redisClient))
	}
	authSvc := auth.NewService(
		txManager,
		repos.accounts,
		repos.identities,
		repos.memberships,
		repos.roles,
		repos.apiKeys,
		repos.refreshTokens,
		repos.environments,
		repos.products,
		repos.jwtRevocations,
		cfg.MasterKey,
		identitySvc,
		pendingStores...,
	)
	policySvc := policy.NewService(repos.policies)
	customerSvc := customer.NewService(repos.customers)
	entitlementSvc := entitlement.NewService(repos.entitlements)
	productSvc := product.NewService(txManager, repos.products, repos.licenses, policySvc, cfg.MasterKey)
	webhookSvc := webhook.NewService(txManager, repos.webhooks, repos.domainEvents, cfg.MasterKey, cfg.IsDevelopment())
	auditWriter := audit.NewWriter(repos.domainEvents)
	licenseSvc := licensing.NewService(
		txManager,
		repos.licenses,
		repos.products,
		repos.machines,
		repos.policies,
		customerSvc,
		entitlementSvc,
		cfg.MasterKey,
		auditWriter,
		cfg.DefaultValidationTTLSec,
	)
	analyticsSvc := analytics.NewService(
		txManager,
		repos.licenses,
		repos.machines,
		repos.customers,
		repos.grants,
		repos.domainEvents,
	)
	searchSvc := search.NewService(txManager, repos.licenses, repos.machines, repos.customers, repos.products)
	grantSvc := grant.NewService(txManager, repos.grants, repos.products, auditWriter)
	mailer, err := newServerMailer(cfg)
	if err != nil {
		return serverServices{}, err
	}
	invitationSvc := invitation.NewService(
		txManager,
		repos.invitations,
		repos.identities,
		repos.memberships,
		repos.roles,
		repos.accounts,
		repos.grants,
		cfg.MasterKey,
		mailer,
		cfg.DashboardURL,
		grantSvc,
		auditWriter,
	)
	membershipSvc := membership.NewService(txManager, repos.memberships)
	accountSvc := account.NewService(repos.accounts, txManager)

	return serverServices{
		auth:        authSvc,
		identity:    identitySvc,
		product:     productSvc,
		policy:      policySvc,
		license:     licenseSvc,
		customer:    customerSvc,
		webhook:     webhookSvc,
		environment: environmentSvc,
		invitation:  invitationSvc,
		grant:       grantSvc,
		membership:  membershipSvc,
		account:     accountSvc,
		entitlement: entitlementSvc,
		analytics:   analyticsSvc,
		search:      searchSvc,
		auditWriter: auditWriter,
	}, nil
}

func newServerMailer(cfg *server.Config) (invitation.Mailer, error) {
	switch cfg.MailerKind {
	case "log":
		return invitation.NewLogMailer(!cfg.IsDevelopment()), nil
	case "noop":
		return invitation.NewNoopMailer(), nil
	default:
		return nil, fmt.Errorf("unknown mailer kind: %s", cfg.MailerKind)
	}
}

func newServerDeps(
	txManager *db.TxManager,
	repos serverRepositories,
	services serverServices,
	cfg *server.Config,
	adminRole *domain.Role,
	redisClient redis.UniversalClient,
) *server.Deps {
	deps := &server.Deps{
		AuthService:        services.auth,
		IdentityService:    services.identity,
		ProductService:     services.product,
		PolicyService:      services.policy,
		LicenseService:     services.license,
		CustomerService:    services.customer,
		WebhookService:     services.webhook,
		EnvironmentService: services.environment,
		InvitationService:  services.invitation,
		GrantService:       services.grant,
		MembershipService:  services.membership,
		AccountService:     services.account,
		EntitlementService: services.entitlement,
		AnalyticsService:   services.analytics,
		SearchService:      services.search,
		TxManager:          txManager,
		LicenseRepo:        repos.licenses,
		PolicyRepo:         repos.policies,
		ProductRepo:        repos.products,
		DomainEventRepo:    repos.domainEvents,
		APIKeyRepo:         repos.apiKeys,
		MembershipRepo:     repos.memberships,
		JWTRevocationRepo:  repos.jwtRevocations,
		AdminRole:          adminRole,
		MasterKey:          cfg.MasterKey,
		Config:             cfg,
	}
	if redisClient != nil {
		deps.RateLimiter = server.NewRedisRateLimiter(redisClient, "rate_limit:")
	}
	return deps
}
